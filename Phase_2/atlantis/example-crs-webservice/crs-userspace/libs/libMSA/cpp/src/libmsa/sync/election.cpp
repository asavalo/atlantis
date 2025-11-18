#include "libmsa/sync/election.h"
#include <iostream>
#include <algorithm>

ZookeeperLeader::ZookeeperLeader(const std::string &zk_hosts) : zk_hosts(zk_hosts) {
    zh = zookeeper_init(zk_hosts.c_str(), watcher, 30000, nullptr, nullptr, 0);
    if (!zh) {
        std::cerr << "Error connecting to Zookeeper!" << std::endl;
        exit(EXIT_FAILURE);
    }
}

ZookeeperLeader::~ZookeeperLeader() {
    if (zh) {
        zookeeper_close(zh);
    }
}

bool ZookeeperLeader::am_i_leader(const std::string &leader_path) {
    if (!path_exists(leader_path)) {
        ensure_path(leader_path);
    }

    std::string my_znode = create_znode(leader_path + "/node-", false, true);
    std::string my_znode_name = my_znode.substr(my_znode.find_last_of('/') + 1);

    std::vector<std::string> children = get_children(leader_path);
    std::sort(children.begin(), children.end());

    return (children[0] == my_znode_name);
}

std::string ZookeeperLeader::create_znode(const std::string &path, bool ephemeral, bool sequential) {
    int flags = 0;
    if (ephemeral) flags |= ZOO_EPHEMERAL;
    if (sequential) flags |= ZOO_SEQUENCE;

    char buffer[512];
    int buffer_len = sizeof(buffer);
    int rc = zoo_create(zh, path.c_str(), nullptr, -1, &ZOO_OPEN_ACL_UNSAFE, flags, buffer, buffer_len);

    if (rc != ZOK) {
        std::cerr << "Error creating znode: " << zerror(rc) << std::endl;
        exit(EXIT_FAILURE);
    }

    return std::string(buffer);
}

std::vector<std::string> ZookeeperLeader::get_children(const std::string &path) {
    struct String_vector children;
    int rc = zoo_get_children(zh, path.c_str(), 0, &children);

    if (rc != ZOK) {
        std::cerr << "Error fetching children znodes: " << zerror(rc) << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<std::string> result(children.count);
    for (int i = 0; i < children.count; ++i) {
        result[i] = std::string(children.data[i]);
    }
    return result;
}

bool ZookeeperLeader::path_exists(const std::string &path) {
    struct Stat stat;
    int rc = zoo_exists(zh, path.c_str(), 0, &stat);

    return (rc == ZOK);
}

void ZookeeperLeader::ensure_path(const std::string &path) {
    std::string current_path;
    size_t pos = 0;

    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        current_path = path.substr(0, pos);
        if (!path_exists(current_path)) {
            create_znode(current_path, false, false);
        }
    }

    if (!path_exists(path)) {
        create_znode(path, false, false);
    }
}

void ZookeeperLeader::watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx) {}