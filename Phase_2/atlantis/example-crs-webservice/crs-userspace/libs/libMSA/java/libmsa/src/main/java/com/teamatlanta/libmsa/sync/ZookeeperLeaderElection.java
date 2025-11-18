package com.teamatlanta.libmsa.sync;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.ExponentialBackoffRetry;
import org.apache.zookeeper.CreateMode;
import java.util.Collections;
import java.util.List;

public class ZookeeperLeaderElection {

    public static boolean amILeader(String zkHosts, String leaderPath) throws Exception {
        // Create Curator client
        CuratorFramework client = CuratorFrameworkFactory.newClient(
                zkHosts, new ExponentialBackoffRetry(1000, 3));
        client.start();

        // Ensure leader path exists
        if (client.checkExists().forPath(leaderPath) == null) {
            client.create().creatingParentsIfNeeded().forPath(leaderPath);
        }

        // Create a sequential znode
        String myZnode = client.create()
                .withMode(CreateMode.PERSISTENT_SEQUENTIAL)
                .forPath(leaderPath + "/node-", new byte[0]);
        String myZnodeName = myZnode.substring(myZnode.lastIndexOf("/") + 1);

        // Get the list of child znodes and sort them
        List<String> children = client.getChildren().forPath(leaderPath);
        Collections.sort(children);

        // Check if the current znode is the leader
        boolean isLeader = children.get(0).equals(myZnodeName);

        // Stop the client
        client.close();

        return isLeader;
    }
}
