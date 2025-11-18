package com.teamatlanta.libmsa.thread;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

public class ThreadPool<T> {

    @FunctionalInterface
    public interface TaskFunction<T> {
        void process(T data);
    }

    private int numThreads;
    private QueuePolicy queuePolicy;
    private TaskFunction<T> func;
    private int numQueues;
    private EventfulQueue<T>[] workQueues;
    private int curQueue = 0;
    private List<Thread> threads = new ArrayList<>();
    private boolean executed = false;

    public enum QueuePolicy {
        GLOBAL, ROUND_ROBIN, BROADCAST
    }

    public ThreadPool(int numThreads, QueuePolicy queuePolicy, TaskFunction<T> func) {
        this.numThreads = numThreads;
        this.queuePolicy = queuePolicy;
        this.func = func;

        this.numQueues = queuePolicy == QueuePolicy.GLOBAL ? 1 : numThreads;
        this.workQueues = new EventfulQueue[numQueues];
        for (int i = 0; i < numQueues; i++) {
            this.workQueues[i] = new EventfulQueue<>();
        }

        createThreads();
    }

    private void createThreads() {
        for (int i = 0; i < numThreads; i++) {
            final int threadId = i; 
            EventfulQueue<T> workQueue = (queuePolicy == QueuePolicy.GLOBAL) ? workQueues[0] : workQueues[i];
            Thread thread = new Thread(() -> worker(threadId, workQueue));
            thread.setDaemon(true);
            threads.add(thread);
        }
    }

    public void enqueue(T data) {
        switch (queuePolicy) {
            case GLOBAL:
                enqueueGlobal(data);
                break;
            case ROUND_ROBIN:
                enqueueRoundRobin(data);
                break;
            case BROADCAST:
                enqueueBroadcast(data);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + queuePolicy);
        }
    }

    private void enqueueGlobal(T data) {
        workQueues[0].enqueue(data);
    }

    private void enqueueRoundRobin(T data) {
        workQueues[curQueue].enqueue(data);
        curQueue = (curQueue + 1) % numThreads;
    }

    private void enqueueBroadcast(T data) {
        for (int i = 0; i < numThreads; i++) {
            workQueues[i].enqueue(data);
        }
    }

    private void worker(int threadId, EventfulQueue<T> workQueue) {
        ReentrantLock lock = workQueue.getLock();
        Condition condition = workQueue.getCondition();
        while (true) {
            lock.lock();
            try {
                if (workQueue.size() == 0) {
                    condition.await();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                lock.unlock();
            }

            while (true) {
                T data = workQueue.dequeue();
                if (data == null) {
                    break;
                }
                func.process(data); 
            }
        }
    }

    public void execute() {
        for (Thread thread : threads) {
            thread.start();
        }
        executed = true;
    }

    public void createMoreThreads(int numThreads) {
        if (numThreads <= 0) {
            return;
        }

        if (queuePolicy != QueuePolicy.GLOBAL) {
            EventfulQueue<T>[] temp = new EventfulQueue[this.numQueues + numThreads];
            for (int i = 0; i < this.numQueues; i++){
                temp[i] = workQueues[i];
            }
            workQueues = temp;

            for (int i = this.numThreads; i < this.numThreads + numThreads; i++) {
                workQueues[i] = new EventfulQueue<>();
            }
        }

        for (int i = this.numThreads; i < this.numThreads + numThreads; i++) {
            final int threadId = i; 
            EventfulQueue<T> workQueue = (queuePolicy == QueuePolicy.GLOBAL) ? workQueues[0] : workQueues[i];
            Thread thread = new Thread(() -> worker(threadId, workQueue));
            thread.setDaemon(true);
            threads.add(thread);
            if (executed) {
                thread.start();
            }
        }

        this.numThreads += numThreads;
        if (queuePolicy != QueuePolicy.GLOBAL) {
            this.numQueues += numThreads;
        }
    }

    public int getNumWorkQueues(){
        return workQueues.length;
    }

    public EventfulQueue<T>[] getWorkQueues(){
        return workQueues;
    }
}