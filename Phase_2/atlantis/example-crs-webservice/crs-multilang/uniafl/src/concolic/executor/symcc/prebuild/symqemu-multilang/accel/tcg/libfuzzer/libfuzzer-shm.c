#include "libfuzzer-shm.h"
#include <semaphore.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>

typedef struct LibFuzzerShm {
    sem_t *start_sem;
    sem_t *end_sem;
    uint8_t *input_buffer;
    size_t input_size;
} LibFuzzerShm;

static LibFuzzerShm libfuzzer_shm;

extern void sym_commit(void);

int libfuzzer_shm_init(void) {
    const char *shm_key_str, *worker_id_str;
    char buf[256];
    struct stat sb;
    if (!(shm_key_str = getenv("SYMQEMU_SHM"))) {
        fprintf(stderr, "[LIBFUZZER] SYMQEMU_SHM is not set\n");
        exit(-1);
    }
    if (!(worker_id_str = getenv("SYMQEMU_WORKER_IDX"))) {
        fprintf(stderr, "[LIBFUZZER] SYMQEMU_WORKER_IDX is not set\n");
        exit(-1);
    }
    int shm_fd = shm_open(shm_key_str, 0, 0666);
    if (fstat(shm_fd, &sb) == -1) {
        perror("fstat");
        exit(-1);
    }
    libfuzzer_shm.input_size = sb.st_size;
    libfuzzer_shm.input_buffer =
        mmap(NULL, libfuzzer_shm.input_size, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (libfuzzer_shm.input_buffer == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }
    snprintf(buf, sizeof(buf), "symqemu-%s.start", worker_id_str);
    libfuzzer_shm.start_sem = sem_open(buf, 0, 0666, 0);
    if (!libfuzzer_shm.start_sem) {
        fprintf(stderr, "[LIBFUZZER] sem_open(start) failed\n");
        exit(-1);
    }
    snprintf(buf, sizeof(buf), "symqemu-%s.end", worker_id_str);
    libfuzzer_shm.end_sem = sem_open(buf, 0, 0666, 0);
    if (!libfuzzer_shm.end_sem) {
        fprintf(stderr, "[LIBFUZZER] sem_open(end) failed\n");
        exit(-1);
    }
    fprintf(stderr, "[LIBFUZZER] libfuzzer_shm_init done (input_size=%lx)\n",
            sb.st_size);
    return 0;
}

int libfuzzer_shm_fini(void) {
    sym_commit();
    if (!libfuzzer_shm.end_sem) {
        fprintf(stderr, "[LIBFUZZER] libfuzzer_shm_fini: end_sem is NULL\n");
        return -1;
    }
    if (sem_post(libfuzzer_shm.end_sem) == -1) {
        fprintf(stderr, "[LIBFUZZER] sem_post(end) failed\n");
        return -1;
    }
    fprintf(stderr, "[LIBFUZZER] dumped symbolic trace\n");
    return 0;
}

int libfuzzer_shm_exit(void) {
    // We must check if the semaphore was initialized. There is no guarantee
    // that libfuzzer_shm_init was called before libfuzzer_shm_exit.

    // We do need to explicitly call sym_commit here, 
    // If the harness exits due to reasons such as SIGABRT, it will exit_group
    // and not exit, bypassing the handler registered via atexit in concolic_executor/lib.rs
    sym_commit();
    if (!libfuzzer_shm.end_sem) {
        fprintf(stderr, "[LIBFUZZER] libfuzzer_shm_exit: end_sem is NULL\n");
        return -1;
    }
    if (sem_post(libfuzzer_shm.end_sem) == -1) {
        fprintf(stderr, "[LIBFUZZER] sem_post(end) failed\n");
        return -1;
    };
    fprintf(stderr, "[LIBFUZZER] harness exited (incorrect behavior)\n");
    return 0;
}

int libfuzzer_shm_recv(uint8_t **data, size_t *size) {
    fprintf(stderr, "[LIBFUZZER] libfuzzer_shm_recv\n");
    if (!libfuzzer_shm.start_sem) {
        fprintf(stderr, "[LIBFUZZER] libfuzzer_shm_recv: start_sem is NULL\n");
        return -1;
    }
    if (sem_wait(libfuzzer_shm.start_sem) == -1) {
        fprintf(stderr, "[LIBFUZZER] sem_wait(start) failed\n");
        return -1;
    }
    *size = *(size_t *)libfuzzer_shm.input_buffer;
    *data = libfuzzer_shm.input_buffer + sizeof(size_t);
    fprintf(stderr, "[LIBFUZZER] libfuzzer_shm_recv done (size=%lx)\n", *size);
    return 0;
}
