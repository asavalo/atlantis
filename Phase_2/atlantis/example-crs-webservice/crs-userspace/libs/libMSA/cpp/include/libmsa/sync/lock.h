#ifndef LOCKED_FUNCTION_RUNNER_H
#define LOCKED_FUNCTION_RUNNER_H

#include <zookeeper/zookeeper.h>
#include <string>
#include <mutex>

class LockedFunctionRunner {
public:
    LockedFunctionRunner(const std::string& zk_hosts, const std::string& lock_path);
    ~LockedFunctionRunner();

    template <typename Func, typename... Args>
    auto run_with_lock(Func&& func, Args&&... args) -> decltype(func(args...));

    void close();

private:
    zhandle_t* zk_handle;
    std::string lock_path;
    std::mutex lock_mutex;

    bool acquire_lock();
    void release_lock();
};

#endif // LOCKED_FUNCTION_RUNNER_H