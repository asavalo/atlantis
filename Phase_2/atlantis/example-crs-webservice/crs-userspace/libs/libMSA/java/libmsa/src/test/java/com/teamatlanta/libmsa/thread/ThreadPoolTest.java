package com.teamatlanta.libmsa.thread;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ThreadPoolTest {
    private ThreadPool<Integer> pool;

    @BeforeEach
    public void setUp() {
        pool = null;
    }

    // Mock function that simulates a processing time of 0.0001 seconds
    private void mockFunction(Integer data) {
        try {
            TimeUnit.MICROSECONDS.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    public void testBroadcastEnqueue() {
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.BROADCAST, this::mockFunction);

        assertEquals(numThreads, pool.getNumWorkQueues());

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
            assertEquals(numData, queue.size());
        }
    }
    
    @Test
    public void testGlobalEnqueue() {
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.GLOBAL, this::mockFunction);

        assertEquals(1, pool.getNumWorkQueues());

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        assertEquals(numData, pool.getWorkQueues()[0].size());
    }

    @Test
    public void testRoundRobinEnqueue() {
        int numThreads = 3;
        int numData = 3000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.ROUND_ROBIN, this::mockFunction);

        assertEquals(numThreads, pool.getNumWorkQueues());

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
            assertEquals(numData / numThreads, queue.size());
        }
    }

    @Test
    public void testBroadcastDequeue() throws InterruptedException {
        int numRepetitions = 2;
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.BROADCAST, this::mockFunction);

        pool.execute();

        for (int t = 0; t < numRepetitions; t++){
            for (int i = 0; i < numData; i++) {
                pool.enqueue(i);
            }
    
            TimeUnit.SECONDS.sleep(3);
    
            for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
                assertEquals(0, queue.size());
            }
        }
    }

    @Test
    public void testGlobalDequeue() throws InterruptedException {
        int numRepetitions = 2;
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.GLOBAL, this::mockFunction);

        pool.execute();

        for (int t = 0; t < numRepetitions; t++){ 
            for (int i = 0; i < numData; i++) {
                pool.enqueue(i);
            }
    
            TimeUnit.SECONDS.sleep(3);
    
            assertEquals(0, pool.getWorkQueues()[0].size());
        }
    }

    @Test
    public void testRoundRobinDequeue() throws InterruptedException {
        int numRepetitions = 2;
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.ROUND_ROBIN, this::mockFunction);

        pool.execute();

        for (int t = 0; t < numRepetitions; t++){ 
            for (int i = 0; i < numData; i++) {
                pool.enqueue(i);
            }
    
            TimeUnit.SECONDS.sleep(3);
    
            for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
                assertEquals(0, queue.size());
            }
        }
    }
    
    @Test
    public void testBroadcastEnqueueAdditionalThreads() {
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.BROADCAST, this::mockFunction);

        assertEquals(numThreads, pool.getNumWorkQueues());

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        int additionalThreads = 2;
        int additionalData = 500;
        pool.createMoreThreads(additionalThreads);

        assertEquals(numThreads + additionalThreads, pool.getNumWorkQueues());

        for (int i = 0; i < additionalData; i++) {
            pool.enqueue(i);
        }

        int cnt1 = 0;
        int cnt2 = 0;

        for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
            if (queue.size() == numData + additionalData) {
                cnt1++;
            } else if (queue.size() == additionalData) {
                cnt2++;
            }
        }

        assertEquals(cnt1, numThreads);
        assertEquals(cnt2, additionalThreads);
    }

    @Test
    public void testGlobalEnqueueAdditionalThreads() {
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.GLOBAL, this::mockFunction);

        assertEquals(1, pool.getNumWorkQueues());

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        int additionalThreads = 2;
        int additionalData = 500;
        pool.createMoreThreads(additionalThreads);

        assertEquals(1, pool.getNumWorkQueues());

        for (int i = 0; i < additionalData; i++) {
            pool.enqueue(i);
        }

        assertEquals(numData + additionalData, pool.getWorkQueues()[0].size());
    }

    @Test
    public void testRoundRobinEnqueueAdditionalThreads() {
        int numThreads = 3;
        int numData = 3000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.ROUND_ROBIN, this::mockFunction);

        assertEquals(numThreads, pool.getNumWorkQueues());

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        int additionalThreads = 2;
        int additionalData = 500;
        pool.createMoreThreads(additionalThreads);

        assertEquals(numThreads + additionalThreads, pool.getNumWorkQueues());

        for (int i = 0; i < additionalData; i++) {
            pool.enqueue(i);
        }

        int cnt1 = 0;
        int cnt2 = 0;

        for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
            if (queue.size() == numData / numThreads + additionalData / (numThreads + additionalThreads)) {
                cnt1++;
            } else if (queue.size() == additionalData / (numThreads + additionalThreads)) {
                cnt2++;
            }
        }

        assertEquals(cnt1, numThreads);
        assertEquals(cnt2, additionalThreads);
    }

    @Test
    public void testBroadcastDequeueAdditionalThreads() throws InterruptedException {
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.BROADCAST, this::mockFunction);

        pool.execute();

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        int additionalThreads = 2;
        int additionalData = 500;
        pool.createMoreThreads(additionalThreads);

        assertEquals(numThreads + additionalThreads, pool.getNumWorkQueues());

        for (int i = 0; i < additionalData; i++) {
            pool.enqueue(i);
        }

        TimeUnit.SECONDS.sleep(3);

        for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
            assertEquals(0, queue.size());
        }
    }

    @Test
    public void testGlobalDequeueAdditionalThreads() throws InterruptedException {
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.GLOBAL, this::mockFunction);

        pool.execute();

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        int additionalThreads = 2;
        int additionalData = 500;
        pool.createMoreThreads(additionalThreads);

        assertEquals(1, pool.getNumWorkQueues());

        for (int i = 0; i < additionalData; i++) {
            pool.enqueue(i);
        }

        TimeUnit.SECONDS.sleep(3);

        assertEquals(0, pool.getWorkQueues()[0].size());
    }

    @Test
    public void testRoundRobinDequeueAdditionalThreads() throws InterruptedException {
        int numThreads = 3;
        int numData = 1000;
        pool = new ThreadPool<>(numThreads, ThreadPool.QueuePolicy.ROUND_ROBIN, this::mockFunction);

        pool.execute();

        for (int i = 0; i < numData; i++) {
            pool.enqueue(i);
        }

        int additionalThreads = 2;
        int additionalData = 500;
        pool.createMoreThreads(additionalThreads);

        assertEquals(numThreads + additionalThreads, pool.getNumWorkQueues());

        for (int i = 0; i < additionalData; i++) {
            pool.enqueue(i);
        }

        TimeUnit.SECONDS.sleep(3);

        for (EventfulQueue<Integer> queue : pool.getWorkQueues()) {
            assertEquals(0, queue.size());
        }
    }
}