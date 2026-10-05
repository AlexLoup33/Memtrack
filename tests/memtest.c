/*
 * memtest.c — Comprehensive test for the memtracker profiler. *
 *
 * Run under memtracker:
 *   python memtrack.py run ./tests/memtest
 *   python memtrack.py export trace.jsonl report.html
 *
 * Scenarios covered
 * -----------------
 *  1. Clean alloc/free pairs            — should produce zero user leaks
 *  2. Definite leaks                    — malloc with no free at all
 *  3. Conditional free (CLI flag)       — freed only when FIX_LEAKS=1
 *  4. Realloc chain                     — realloc + final free
 *  5. Bulk churn                        — many small alloc/free cycles
 *  6. I/O — read                        — fread from /dev/urandom
 *  7. I/O — write                       — fwrite to /dev/null
 *  8. File open/close                   — triggers _IO_file_doallocate (system alloc)
 *  9. String duplication via strdup     — __GI___strdup system alloc
 * 10. pthread_create                    — thread stack system alloc
 * 11. dlopen / dlclose                  — dynamic library system alloc
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <fcntl.h>

/* ── Colour helpers for the terminal output ─────────────────────────────── */
#define GRN "\033[32m"
#define RED "\033[31m"
#define YEL "\033[33m"
#define BLU "\033[34m"
#define DIM "\033[2m"
#define RST "\033[0m"

#define SECTION(name) \
    printf("\n" BLU "─── " name " " RST "\n")

#define OK(msg)   printf("  " GRN "✓" RST "  %s\n", msg)
#define LEAK(msg) printf("  " RED "✗" RST "  %s\n", msg)
#define INFO(msg) printf("  " DIM "·" RST "  %s\n", msg)

/* ─────────────────────────────────────────────────────────────────────────
 * 1. Clean alloc / free pairs
 * ───────────────────────────────────────────────────────────────────────── */
static void test_clean_allocs(void)
{
    SECTION("1 · Clean alloc/free pairs");

    /* Single scalar */
    int *n = malloc(sizeof(int));
    *n = 42;
    free(n);
    OK("single int malloc/free");

    /* Array */
    double *arr = malloc(64 * sizeof(double));
    for (int i = 0; i < 64; i++) arr[i] = (double)i * 0.5;
    free(arr);
    OK("double[64] malloc/free");

    /* calloc */
    char *buf = calloc(128, sizeof(char));
    strncpy(buf, "hello memtracker", 127);
    free(buf);
    OK("calloc(128) + free");

    /* Nested: alloc inside a loop, free before next iteration */
    for (int i = 0; i < 16; i++) {
        void *tmp = malloc(32 + i * 8);
        memset(tmp, i, 32 + i * 8);
        free(tmp);
    }
    OK("16 × loop malloc/free");
}

/* ─────────────────────────────────────────────────────────────────────────
 * 2. Definite leaks — malloc without free
 * ───────────────────────────────────────────────────────────────────────── */
static void test_definite_leaks(void)
{
    SECTION("2 · Definite leaks (intentional)");

    /* Small leak */
    char *s = malloc(64);
    snprintf(s, 64, "leaked string #1");
    /* deliberately not freed */
    LEAK("64 B — small string, no free");

    /* Medium leak */
    int *matrix = malloc(32 * 32 * sizeof(int));
    for (int i = 0; i < 32 * 32; i++) matrix[i] = i;
    /* deliberately not freed */
    LEAK("4 KB — int matrix, no free");

    /* Leak inside a function scope — common real-world pattern */
    void *opaque = malloc(256);
    memset(opaque, 0xAB, 256);
    /* deliberately not freed */
    LEAK("256 B — opaque buffer, no free");
}

/* ─────────────────────────────────────────────────────────────────────────
 * 3. Conditional free — freed only when FIX_LEAKS env var is set
 *    Run once without FIX_LEAKS → leak shows up
 *    Run again with FIX_LEAKS=1 → clean
 * ───────────────────────────────────────────────────────────────────────── */
static void test_conditional_free(void)
{
    SECTION("3 · Conditional free  (set FIX_LEAKS=1 to repair)");

    int fix = (getenv("FIX_LEAKS") != NULL);

    char *cfg  = malloc(512);
    char *data = malloc(1024);

    snprintf(cfg,  512,  "config_buffer (fix=%d)", fix);
    snprintf(data, 1024, "data_buffer   (fix=%d)", fix);

    if (fix) {
        free(cfg);
        free(data);
        OK("cfg  512 B — freed (FIX_LEAKS=1)");
        OK("data 1 KB  — freed (FIX_LEAKS=1)");
    } else {
        LEAK("cfg  512 B — leaked (FIX_LEAKS not set)");
        LEAK("data 1 KB  — leaked (FIX_LEAKS not set)");
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * 4. Realloc chain
 * ───────────────────────────────────────────────────────────────────────── */
static void test_realloc(void)
{
    SECTION("4 · Realloc chain");

    char *buf = malloc(64);
    snprintf(buf, 64, "initial 64 B");
    INFO("malloc(64)");

    buf = realloc(buf, 256);
    snprintf(buf, 256, "grown to 256 B");
    INFO("realloc → 256 B");

    buf = realloc(buf, 1024);
    snprintf(buf, 1024, "grown to 1 KB");
    INFO("realloc → 1 KB");

    free(buf);
    OK("final free after realloc chain");
}

/* ─────────────────────────────────────────────────────────────────────────
 * 5. Bulk churn — many small alloc/free pairs
 *    Creates a dense cluster of events on the timeline.
 * ───────────────────────────────────────────────────────────────────────── */
static void test_bulk_churn(void)
{
    SECTION("5 · Bulk churn  (200 × alloc/free)");

#define CHURN_N 200
    void *ptrs[CHURN_N];

    /* Phase 1 — allocate all */
    for (int i = 0; i < CHURN_N; i++) {
        size_t sz = 16 + (i % 32) * 8;   /* 16 … 264 B */
        ptrs[i] = malloc(sz);
        memset(ptrs[i], i & 0xFF, sz);
    }

    /* Phase 2 — free even indices */
    for (int i = 0; i < CHURN_N; i += 2)
        free(ptrs[i]);

    /* Phase 3 — free odd indices */
    for (int i = 1; i < CHURN_N; i += 2)
        free(ptrs[i]);

    OK("200 allocs + 200 frees (two-phase)");
#undef CHURN_N
}

/* ─────────────────────────────────────────────────────────────────────────
 * 6. I/O — read  (/dev/urandom)
 * ───────────────────────────────────────────────────────────────────────── */
static void test_io_read(void)
{
    SECTION("6 · I/O — read");

    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { INFO("cannot open /dev/urandom — skipped"); return; }

    unsigned char *entropy = malloc(4096);
    size_t n = fread(entropy, 1, 4096, f);
    fclose(f);
    free(entropy);

    char msg[64];
    snprintf(msg, sizeof(msg), "fread %zu B from /dev/urandom", n);
    OK(msg);

    /* A second, smaller read to produce multiple read events */
    f = fopen("/dev/urandom", "rb");
    if (f) {
        unsigned char tiny[128];
        fread(tiny, 1, sizeof(tiny), f);
        fclose(f);
        OK("fread 128 B from /dev/urandom (second call)");
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * 7. I/O — write  (/dev/null)
 * ───────────────────────────────────────────────────────────────────────── */
static void test_io_write(void)
{
    SECTION("7 · I/O — write");

    FILE *f = fopen("/dev/null", "wb");
    if (!f) { INFO("cannot open /dev/null — skipped"); return; }

    /* Large write */
    char *payload = malloc(8192);
    memset(payload, 'X', 8192);
    size_t w = fwrite(payload, 1, 8192, f);
    free(payload);

    /* Small write */
    const char *msg = "memtrack write test\n";
    fwrite(msg, 1, strlen(msg), f);

    fclose(f);

    char info[64];
    snprintf(info, sizeof(info), "fwrite %zu B + 20 B to /dev/null", w);
    OK(info);
}

/* ─────────────────────────────────────────────────────────────────────────
 * 8. File open/close — triggers _IO_file_doallocate (system / false positive)
 * ───────────────────────────────────────────────────────────────────────── */
static void test_file_io(void)
{
    SECTION("8 · File open/close  (_IO_file_doallocate — system alloc)");

    /* Write a small temp file then read it back */
    const char *path = "/tmp/memtrack_test_tmp.txt";

    FILE *w = fopen(path, "w");
    if (w) {
        fprintf(w, "line 1: memtracker test\n");
        fprintf(w, "line 2: testing file I/O\n");
        fprintf(w, "line 3: done\n");
        fclose(w);
        OK("fopen/fprintf/fclose  (/tmp write)");
    }

    FILE *r = fopen(path, "r");
    if (r) {
        char line[128];
        int count = 0;
        while (fgets(line, sizeof(line), r)) count++;
        fclose(r);

        char msg[64];
        snprintf(msg, sizeof(msg), "fopen/fgets/fclose — read %d lines", count);
        OK(msg);
    }

    remove(path);
}

/* ─────────────────────────────────────────────────────────────────────────
 * 9. strdup — __GI___strdup (system alloc, caller must free)
 * ───────────────────────────────────────────────────────────────────────── */
static void test_strdup(void)
{
    SECTION("9 · strdup  (__GI___strdup — system alloc)");

    const char *original = "memtracker strdup test string";
    char *copy = strdup(original);

    char msg[128];
    snprintf(msg, sizeof(msg), "strdup(\"%s\")", original);
    INFO(msg);

    /* strdup caller is responsible for free() */
    free(copy);
    OK("free(strdup result)");

    /* One intentional strdup leak to show the system-alloc classification */
    char *leaked_copy = strdup("this strdup result is intentionally not freed");
    (void)leaked_copy;
    LEAK("strdup — not freed  → system alloc bucket");
}

/* ─────────────────────────────────────────────────────────────────────────
 * 10. pthread_create — thread stack system alloc
 * ───────────────────────────────────────────────────────────────────────── */
static void *thread_worker(void *arg)
{
    int id = *(int *)arg;

    /* Each thread does a small alloc/free to generate events */
    size_t sz = 128 * (id + 1);
    void  *buf = malloc(sz);
    memset(buf, id, sz);
    usleep(1000 * id);   /* stagger events on the timeline */
    free(buf);

    return NULL;
}

static void test_threads(void)
{
    SECTION("10 · pthread_create  (thread stack — system alloc)");

#define NUM_THREADS 4
    pthread_t tids[NUM_THREADS];
    int       ids[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        pthread_create(&tids[i], NULL, thread_worker, &ids[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(tids[i], NULL);

    OK("4 threads created, joined, each did malloc/free");
#undef NUM_THREADS
}

/* ─────────────────────────────────────────────────────────────────────────
 * 11. dlopen / dlclose — dynamic library system alloc
 * ───────────────────────────────────────────────────────────────────────── */
static void test_dlopen(void)
{
    SECTION("11 · dlopen / dlclose  (system alloc)");

    /* libm.so is always present on Linux */
    void *handle = dlopen("libm.so.6", RTLD_LAZY);
    if (!handle) {
        INFO("dlopen(libm.so.6) failed — skipped");
        return;
    }

    /* Resolve a symbol to make the load real */
    void *sym = dlsym(handle, "sin");
    if (sym) INFO("dlsym(sin) resolved");

    dlclose(handle);
    OK("dlopen(libm) + dlclose");

    /* One intentional dlopen without dlclose */
    void *leaked_handle = dlopen("libm.so.6", RTLD_LAZY);
    if (leaked_handle) {
        LEAK("dlopen without dlclose  → system alloc bucket");
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * main
 * ───────────────────────────────────────────────────────────────────────── */
int main(void)
{
    printf(GRN "\n╔══════════════════════════════════════╗\n");
    printf(    "║     memtracker — test suite          ║\n");
    printf(    "╚══════════════════════════════════════╝\n" RST);

    int fix_leaks = (getenv("FIX_LEAKS") != NULL);
    if (fix_leaks)
        printf(YEL "  FIX_LEAKS=1 — conditional leaks will be freed\n" RST);
    else
        printf(DIM "  FIX_LEAKS not set — conditional leaks will remain\n" RST);

    test_clean_allocs();
    test_definite_leaks();
    test_conditional_free();
    test_realloc();
    test_bulk_churn();
    test_io_read();
    test_io_write();
    test_file_io();
    test_strdup();
    test_threads();
    test_dlopen();

    printf(BLU "\n─── Summary ───────────────────────────\n" RST);
    printf("  Scenarios run : 11\n");
    if (fix_leaks) {
        printf("  Expected user leaks   : " GRN "3" RST
               "  (definite: 3, conditional: 0)\n");
    } else {
        printf("  Expected user leaks   : " RED "5" RST
               "  (definite: 3, conditional: 2)\n");
    }
    printf("  Expected system allocs: " YEL "~4" RST
           "  (_IO_file_doallocate, strdup, pthread, dlopen)\n");
    printf("\n  Run: python memtrack.py export trace.jsonl -o report.html\n\n");

    return 0;
}