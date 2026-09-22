#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <execinfo.h>
#include <time.h>

// Malloc function pointers
static void* (*real_malloc)(size_t) = NULL;
static void* (*real_calloc)(size_t, size_t) = NULL;
static void* (*real_realloc)(void*, size_t) = NULL;

// Free function pointer
static void  (*real_free)(void*) = NULL;

// I/O function pointers
static ssize_t (*real_read)(int, void*, size_t) = NULL;
static ssize_t (*real_write)(int, const void*, size_t) = NULL;

// Avoiding recursion in hooks in malloc/free calls
static __thread int in_hook = 0;

#define BUFFER_SIZE 8192
static char log_buffer[BUFFER_SIZE];
static int buffer_offset = 0;
static int log_fd = -1;

// Timestamp function
static double get_timestamp() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

static void flush_buffer() {
    if (buffer_offset > 0) {
        if (log_fd != -1) {
            if (real_write) real_write(log_fd, log_buffer, buffer_offset);
            else write(log_fd, log_buffer, buffer_offset);
        }
        buffer_offset = 0;
    }
}

static void log_event(const char* event_str) {
    size_t len = strlen(event_str);
    if (buffer_offset + len >= BUFFER_SIZE) {
        flush_buffer();
    }

    memcpy(log_buffer + buffer_offset, event_str, len);
    buffer_offset += len;
}

__attribute__((constructor)) static void clean_memtrack() {
    const char *out_file = getenv("MEMTRACK_OUT");
    if (!out_file) out_file = "trace.jsonl";

    log_fd = open(out_file, O_CREAT | O_WRONLY | O_TRUNC, 0666);

    if (log_fd != -1) {
        const char* msg = "\n[MEMTRACKER] libmemtrack.so injected successfully !\n";
        write(1, msg, strlen(msg));
    } else {
        const char* err = "\n[MEMTRACKER] Error opening log file for writing !\n";
        write(2, err, strlen(err));
    }
}

__attribute__((destructor)) static void cleanup_memtrack() {
    flush_buffer();

    if (log_fd != -1) {
        close(log_fd);
    }
}

// Memory malloc Hooks
void* malloc(size_t size){
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free"); 
    
    if (in_hook) return real_malloc(size);

    in_hook = 1;
    void *ptr = real_malloc(size);

    void *callstack[10];
    int frames = backtrace(callstack, 10);
    char **strs = backtrace_symbols(callstack, frames);
    
    const char* caller = (strs && frames > 1) ? strs[1] : "unknown";
    
    char temp[512]; 
    snprintf(temp, sizeof(temp), "{\"action\":\"malloc\",\"ts\":%.3f,\"size\":%zu,\"ptr\":\"%p\",\"caller\":\"%s\"}\n", get_timestamp(), size, ptr, caller);

    log_event(temp); 

    if (strs) real_free(strs);
    in_hook = 0;
    return ptr;
}

void* realloc(void *ptr, size_t size) {
    if (!real_realloc) real_realloc = dlsym(RTLD_NEXT, "realloc");
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free"); 
    
    if (in_hook) return real_realloc(ptr, size);

    in_hook = 1;
    void *new_ptr = real_realloc(ptr, size);

    char temp[512]; 
    snprintf(temp, sizeof(temp), "{\"action\":\"realloc\",\"ts\":%.3f,\"old_ptr\":\"%p\",\"new_ptr\":\"%p\",\"size\":%zu}\n", get_timestamp(), ptr, new_ptr, size);
    
    log_event(temp); 

    in_hook = 0;
    return new_ptr;
}

void* calloc(size_t nmemb, size_t size) {
    if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free"); 
    
    if (in_hook) return real_calloc(nmemb, size);

    in_hook = 1;
    void *ptr = real_calloc(nmemb, size);

    char temp[512]; 
    snprintf(temp, sizeof(temp), "{\"action\":\"calloc\",\"ts\":%.3f,\"nmemb\":%zu,\"size\":%zu,\"ptr\":\"%p\"}\n", get_timestamp(), nmemb, size, ptr);
    
    log_event(temp); 

    in_hook = 0;
    return ptr;
}


// Memory free Hook
void free(void *ptr) {
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
    if (in_hook || !ptr) {
        if (real_free) real_free(ptr);
        return;
    }

    in_hook = 1;
    char temp[128];
    snprintf(temp, sizeof(temp), "{\"action\":\"free\",\"ts\":%.3f,\"ptr\":\"%p\"}\n", get_timestamp(), ptr);
    log_event(temp);
    
    real_free(ptr);
    in_hook = 0;
}

// I/O Hooks
ssize_t write(int fd, const void *buf, size_t count) {
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    if (in_hook) return real_write(fd, buf, count);

    in_hook = 1;
    ssize_t ret = real_write(fd, buf, count);

    // Check to avoid writing on log file 
    if (fd != log_fd) {
        char temp[128];
        snprintf(temp, sizeof(temp), "{\"action\":\"write\",\"fd\":%d,\"count\":%zu}\n", fd, count);
        log_event(temp);
    }

    in_hook = 0;
    return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    if (in_hook) return real_read(fd, buf, count);

    in_hook = 1;
    ssize_t ret = real_read(fd, buf, count);

    // Check to avoid writing on log file 
    if (fd != log_fd) {
        char temp[128];
        snprintf(temp, sizeof(temp), "{\"action\":\"read\",\"fd\":%d,\"count\":%zu}\n", fd, count);
        log_event(temp);
    }

    in_hook = 0;
    return ret;
}