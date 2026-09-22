#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void test_normal_malloc_free() {
    printf("\n[Test] Clean allocation of 100 000 octets...\n");
    char* ptr = malloc(100000);
    if (ptr) {
        memset(ptr, 'A', 100000);
        printf("[Test] Memory allocated and used. Liberation in progress...\n");
        free(ptr);
        printf("[Test] Liberation successful.\n");
    }
}

void test_memory_leak_zebi() {
    printf("\n[Test] Creating a 4KB memory leak...\n");
    char* leak = malloc(4096);
    if (leak) {
        strcpy(leak, "Donnees perdues");
        printf("[Test] Memory allocated but never freed (Leak) !\n");
    }
}

void test_io_read_write() {
    printf("\n[Test] Test of I/O (Read / Write)...\n");
    const char* filename = "dummy_io_test.txt";
    const char* data = "Ceci est un test d'ecriture pour le profiler I/O.\n";

    // Test du hook 'write'
    int fd_out = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_out != -1) {
        write(fd_out, data, strlen(data));
        close(fd_out);
        printf("[Test] > Writing %zu bytes to %s.\n", strlen(data), filename);
    }

    // Test du hook 'read'
    int fd_in = open(filename, O_RDONLY);
    if (fd_in != -1) {
        char buffer[128] = {0};
        ssize_t bytes_read = read(fd_in, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            printf("[Test] > Reading %zd bytes : %s", bytes_read, buffer);
        }
        close(fd_in);
    }
}

int main() {
    int choice;
    
    printf("=========================================\n");
    printf("    MEMTRACKER - COBAYE INTERACTIF       \n");
    printf("=========================================\n");

    while (1) {
        printf("\nWhat would you like to trigger ?\n");
        printf("  1. Clean cycle (Malloc + Free)\n");
        printf("  2. Memory leak (Memory Leak)\n");
        printf("  3. System calls (Read + Write)\n");
        printf("  4. Quit\n");
        printf("Your choice : ");

        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("Invalid input.\n");
            continue;
        }

        switch (choice) {
            case 1:
                test_normal_malloc_free();
                break;
            case 2:
                test_memory_leak_zebi();
                break;
            case 3:
                test_io_read_write();
                break;
            case 4:
                printf("Fin du programme. Le profiler devrait générer le rapport final.\n");
                return 0;
            default:
                printf("Invalid choice. Please enter a number between 1 and 4.\n");
        }
    }
    return 0;
}