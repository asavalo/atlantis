#ifndef ELECTION_H
#define ELECTION_H

#include <zookeeper/zookeeper.h>
#include <string>
#include <vector>

class ZookeeperLeader {
public:
    ZookeeperLeader(const std::string &zk_hosts);
    ~ZookeeperLeader();

    bool am_i_leader(const std::string &leader_path);

private:
    zhandle_t *zh;
    std::string zk_hosts;

    std::string create_znode(const std::string &path, bool ephemeral, bool sequential);
    std::vector<std::string> get_children(const std::string &path);
    bool path_exists(const std::string &path);
    void ensure_path(const std::string &path);
    static void watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);
};

#endif // ELECTION_H