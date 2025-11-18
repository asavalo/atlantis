#include <stdint.h>
#include <stdlib.h>

int libfuzzer_shm_init(void);
int libfuzzer_shm_fini(void);
int libfuzzer_shm_exit(void);
int libfuzzer_shm_recv(uint8_t **data, size_t *size);
