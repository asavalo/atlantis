#ifndef CPU_AFFINITY_H
#define CPU_AFFINITY_H

#include <vector>

class CpuAffinity {
public:
    static void setCpuAffinity(const std::vector<int>& cpus);
};

#endif // CPU_AFFINITY_H