package com.teamatlanta.libmsa.thread;

import org.junit.jupiter.api.*;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class EventfulQueueTest {
    private EventfulQueue<Integer> workQueue;
    private volatile boolean terminate;

    @BeforeEach
    public void setUp() {
        workQueue = new EventfulQueue<>();
        terminate = false;
    }

    @AfterEach
    public void tearDown() {
        workQueue = null;
    }

    private void enqueueWorker() {
        Random random = new Random();
        for (int i = 0; i < 100000; i++) {
            Integer data = random.nextInt(100000);
            workQueue.enqueue(data);
        }
    }

    private void dequeueWorker() {
        while (!terminate || workQueue.dequeue() != null) {
            Integer data;
            while ((data = workQueue.dequeue()) != null) {
                // Simulate some processing delay
                try { Thread.sleep(1); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
        }
    }

    @Test
    public void testSingleThreadBasic() {
        Integer data = 1;

        Assertions.assertFalse(workQueue.dequeue() != null);
        workQueue.enqueue(data);
        Integer ret = workQueue.dequeue();
        Assertions.assertEquals(data, ret);
        Assertions.assertNull(workQueue.dequeue());
    }

    @Test
    public void testMultipleThreadBasic() throws InterruptedException {
        ExecutorService enqueuePool = Executors.newFixedThreadPool(1);
        ExecutorService dequeuePool = Executors.newFixedThreadPool(10);

        enqueuePool.submit(this::enqueueWorker);

        for (int i = 0; i < 10; i++) {
            dequeuePool.submit(this::dequeueWorker);
        }

        enqueuePool.shutdown();
        dequeuePool.shutdown();

        while (!enqueuePool.isTerminated()) {
            Thread.sleep(100); // wait for threads to finish
        }
        terminate = true;
        while (!dequeuePool.isTerminated()) {
            Thread.sleep(100); // wait for threads to finish
        }

        Assertions.assertNull(workQueue.dequeue());
    }
}