from kazoo.client import KazooClient


def am_i_leader(zk_hosts: str, leader_path: str) -> bool:
    zk = KazooClient(hosts=zk_hosts)
    zk.start()

    if not zk.exists(leader_path):
        zk.ensure_path(leader_path)

    my_znode = zk.create(f"{leader_path}/node-", sequence=True, ephemeral=False)
    my_znode_name = my_znode.split("/")[-1]

    children = zk.get_children(leader_path)
    children.sort()

    if children[0] == my_znode_name:
        is_leader = True
    else:
        is_leader = False

    zk.stop()

    return is_leader
