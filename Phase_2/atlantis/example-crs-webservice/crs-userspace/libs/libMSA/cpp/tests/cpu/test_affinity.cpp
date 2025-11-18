#include "libmsa/cpu/affinity.h"
#include <gtest/gtest.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <vector>

std::vector<int> get_process_affinity() {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    if (sched_getaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
        throw std::runtime_error("Failed to get CPU affinity");
    }

    std::vector<int> cpus;
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, &cpuset)) {
            cpus.push_back(i);
        }
    }
    return cpus;
}

TEST(CpuAffinityTest, SetCpuAffinity) {
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    ASSERT_GT(num_cpus, 1);

    int num_tests = 10;
    for (int i = 0; i < num_tests; ++i) {
        int target_cpu = rand() % num_cpus;
        std::vector<int> target_cpus = {target_cpu};

        CpuAffinity::setCpuAffinity(target_cpus);

        std::vector<int> process_affinity = get_process_affinity();
        ASSERT_EQ(process_affinity, target_cpus);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}