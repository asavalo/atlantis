#include "libmsa/cpu/affinity.h"
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>

void CpuAffinity::setCpuAffinity(const std::vector<int>& cpus) {
    pid_t pid = getpid();

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    for (int cpu : cpus) {
        CPU_SET(cpu, &cpuset);
    }

    sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
}