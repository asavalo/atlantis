package com.teamatlanta.libmsa.thread;

import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Condition;
import java.util.LinkedList;

class EventfulQueue<T> {
    private LinkedList<T> queue = new LinkedList<>();
    private ReentrantLock lock = new ReentrantLock();
    private Condition condition = lock.newCondition();

    public void enqueue(T data) {
        lock.lock();
        try {
            queue.add(data);
            condition.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public T dequeue() {
        lock.lock();
        try {
            if (!queue.isEmpty()) {
                return queue.removeFirst();
            }
            return null;
        } finally {
            lock.unlock();
        }
    }

    public Condition getCondition() {
        return condition;
    }

    public ReentrantLock getLock() {
        return lock;
    }

    public int size() {
        return queue.size();
    }
}