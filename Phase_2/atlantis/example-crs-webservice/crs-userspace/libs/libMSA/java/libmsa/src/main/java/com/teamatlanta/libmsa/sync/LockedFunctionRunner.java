package com.teamatlanta.libmsa.sync;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.framework.recipes.locks.InterProcessMutex;
import org.apache.curator.retry.ExponentialBackoffRetry;

import java.util.concurrent.Callable;

public class LockedFunctionRunner {

    private CuratorFramework client;
    private InterProcessMutex lock;

    public LockedFunctionRunner(String zkHosts, String lockPath) {
        // Create a Zookeeper client with a retry policy
        this.client = CuratorFrameworkFactory.newClient(zkHosts, new ExponentialBackoffRetry(1000, 3));
        this.client.start();
        
        // Create a distributed lock on the given path
        this.lock = new InterProcessMutex(client, lockPath);
    }

    public <T> T runWithLock(Callable<T> func) throws Exception {
        try {
            lock.acquire();
            return func.call(); // Call the function while the lock is held
        } finally {
            lock.release();
        }
    }

    public void close() {
        // Stop the client
        if (client != null) {
            client.close();
        }
    }
}