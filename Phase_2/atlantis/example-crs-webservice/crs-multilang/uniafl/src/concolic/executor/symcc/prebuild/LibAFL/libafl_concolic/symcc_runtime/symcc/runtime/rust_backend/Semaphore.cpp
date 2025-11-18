// clang-format off
#include <Config.h>
#include "Semaphore.h"
#include <iostream>
// clang-format on

static sem_t *startSem = nullptr;
static sem_t *endSem = nullptr;
static sem_t *exitedSem = nullptr;

void init_sema() {
  if (g_config.fullTrace) {
    std::string startSemName = g_config.semName + ".start";
    std::string endSemName = g_config.semName + ".end";
    std::string exitedSemName = g_config.semName + ".exited";
    startSem = sem_open(startSemName.c_str(), 0);
    if (startSem == SEM_FAILED) {
      std::cerr << "Failed to open semaphore " << g_config.semName << ": "
                << strerror(errno) << std::endl;
      exit(1);
    }
    endSem = sem_open(endSemName.c_str(), 0);
    if (endSem == SEM_FAILED) {
      std::cerr << "Failed to open semaphore " << g_config.semName << ": "
                << strerror(errno) << std::endl;
      exit(1);
    }
    exitedSem = sem_open(exitedSemName.c_str(), 0);
    if (exitedSem == SEM_FAILED) {
      std::cerr << "Failed to open semaphore " << g_config.semName << ": "
                << strerror(errno) << std::endl;
      exit(1);
    }
    wait_start();
    post_end();
  }
}

void post_end() {
  if (g_config.fullTrace) {
    sem_post(endSem);
  }
}

void wait_start() {
  if (g_config.fullTrace) {
    sem_wait(startSem);
  }
}

void post_exited() {
  if (g_config.fullTrace) {
    sem_post(exitedSem);
  }
}
