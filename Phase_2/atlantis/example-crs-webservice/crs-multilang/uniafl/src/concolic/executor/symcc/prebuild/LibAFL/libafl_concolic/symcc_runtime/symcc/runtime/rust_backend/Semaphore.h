#include <semaphore.h>

extern "C" {
void init_sema();
void post_end();
void wait_start();
void post_exited();
}
