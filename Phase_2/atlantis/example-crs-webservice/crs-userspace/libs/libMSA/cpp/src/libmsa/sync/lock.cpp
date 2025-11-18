#include "libmsa/sync/lock.h"
#include <iostream>
#include <stdexcept>

void watcher_callback(zhandle_t* zh, int type, int state, const char* path, void* watcherCtx) {
    if (state == ZOO_CONNECTED_STATE) {
        std::cout << "Connected to Zookeeper" << std::endl;
    } else if (state == ZOO_EXPIRED_SESSION_STATE) {
        std::cerr << "Zookeeper session expired" << std::endl;
    }
}

LockedFunctionRunner::LockedFunctionRunner(const std::string& zk_hosts, const std::string& lock_path)
    : zk_handle(nullptr), lock_path(lock_path) {
    zk_handle = zookeeper_init(zk_hosts.c_str(), watcher_callback, 30000, 0, nullptr, 0);
    if (!zk_handle) {
        throw std::runtime_error("Failed to connect to Zookeeper");
    }
}

LockedFunctionRunner::~LockedFunctionRunner() {
    close();
}

bool LockedFunctionRunner::acquire_lock() {
    std::lock_guard<std::mutex> guard(lock_mutex);

    int rc = zoo_create(zk_handle, lock_path.c_str(), nullptr, 0,
                        &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, nullptr, 0);
    if (rc == ZOK) {
        std::cout << "Lock acquired: " << lock_path << std::endl;
        return true;
    } else if (rc == ZNODEEXISTS) {
        std::cerr << "Lock already exists: " << lock_path << std::endl;
        return false;
    } else {
        std::cerr << "Error acquiring lock: " << rc << std::endl;
        return false;
    }
}

void LockedFunctionRunner::release_lock() {
    std::lock_guard<std::mutex> guard(lock_mutex);

    int rc = zoo_delete(zk_handle, lock_path.c_str(), -1);
    if (rc == ZOK) {
        std::cout << "Lock released: " << lock_path << std::endl;
    } else {
        std::cerr << "Error releasing lock: " << rc << std::endl;
    }
}

template <typename Func, typename... Args>
auto LockedFunctionRunner::run_with_lock(Func&& func, Args&&... args) -> decltype(func(args...)) {
    if (acquire_lock()) {
        auto result = func(std::forward<Args>(args)...);
        release_lock();
        return result;
    } else {
        throw std::runtime_error("Failed to acquire lock");
    }
}

void LockedFunctionRunner::close() {
    if (zk_handle) {
        zookeeper_close(zk_handle);
        zk_handle = nullptr;
        std::cout << "Zookeeper connection closed" << std::endl;
    }
}