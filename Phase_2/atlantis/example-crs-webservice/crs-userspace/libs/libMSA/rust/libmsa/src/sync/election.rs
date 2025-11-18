use zookeeper::{Acl, CreateMode, WatchedEvent, Watcher, ZooKeeper};

struct NoopWatcher;

impl Watcher for NoopWatcher {
    fn handle(&self, _event: WatchedEvent) {
        // No operation on events
    }
}

pub fn am_i_leader(zk_hosts: &str, leader_path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let zk = ZooKeeper::connect(zk_hosts, std::time::Duration::from_secs(15), NoopWatcher)?;

    if zk.exists(leader_path, false)?.is_none() {
        zk.create(leader_path, vec![], Acl::open_unsafe().clone(), CreateMode::Persistent)?;
    }

    let my_znode = zk.create(
        &format!("{}/node-", leader_path),
        vec![],
        Acl::open_unsafe().clone(),
        CreateMode::PersistentSequential,
    )?;

    let my_znode_name = my_znode.split('/').last().unwrap().to_string();

    let mut children = zk.get_children(leader_path, false)?;
    children.sort();

    let is_leader = children.first().map_or(false, |child| child == &my_znode_name);

    zk.close()?;

    Ok(is_leader)
}