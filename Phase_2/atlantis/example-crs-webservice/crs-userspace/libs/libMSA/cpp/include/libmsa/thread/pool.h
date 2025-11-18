#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <condition_variable>
#include <mutex>
#include <vector>
#include <thread>
#include <functional>
#include <cassert>
#include "libmsa/thread/equeue.h"

enum class QueuePolicy {
    GLOBAL,
    ROUND_ROBIN,
    BROADCAST
};

template <typename T>
class ThreadPool {
public:
    ThreadPool(int num_threads, QueuePolicy queue_policy, std::function<void(T&)> func)
        : num_threads_(num_threads), queue_policy_(queue_policy), func_(func),
          num_queues_(queue_policy == QueuePolicy::GLOBAL ? 1 : num_threads), cur_queue_(0), executed(false) {
        
        for (int i = 0; i < num_queues_; i++) {
            work_queues_.push_back(new EventfulQueue<T>());
        }
    }

    ~ThreadPool() {}

    void enqueue(const T& data) {
        if (queue_policy_ == QueuePolicy::GLOBAL) {
            _enqueue_global(data);
        } else if (queue_policy_ == QueuePolicy::ROUND_ROBIN) {
            _enqueue_round_robin(data);
        } else if (queue_policy_ == QueuePolicy::BROADCAST) {
            _enqueue_broadcast(data);
        } else {
            assert(false);
        }
    }

    void execute() {
        _create_threads();
        executed = true;
    }

    void create_more_threads(int num_threads) {
        if (num_threads <= 0) return;

        for (int i = num_threads_; i < num_threads_ + num_threads; ++i) {
            if (queue_policy_ != QueuePolicy::GLOBAL) {
                work_queues_.push_back(new EventfulQueue<T>());
            }
            if (executed) {
                EventfulQueue<T>* work_queue = (queue_policy_ == QueuePolicy::GLOBAL) ? work_queues_[0] : work_queues_[i];
                threads_.emplace_back(new std::thread(&ThreadPool::worker, this, i, work_queue));
            }
        }

        num_threads_ += num_threads;
        if (queue_policy_ != QueuePolicy::GLOBAL) {
            num_queues_ += num_threads;
        }
    }

    std::vector<EventfulQueue<T>*>& get_queues() {
        return work_queues_;
    }

private:
    int num_threads_;
    QueuePolicy queue_policy_;
    std::function<void(T&)> func_;
    int num_queues_;
    int cur_queue_;
    std::vector<EventfulQueue<T>*> work_queues_;
    std::vector<std::thread*> threads_;
    bool executed;

    void _create_threads() {
        for (int i = 0; i < num_threads_; ++i) {
            EventfulQueue<T>* work_queue = (queue_policy_ == QueuePolicy::GLOBAL) ? work_queues_[0] : work_queues_[i];
            threads_.emplace_back(new std::thread(&ThreadPool::worker, this, i, work_queue));
        }
    }

    void _enqueue_global(const T& data) {
        work_queues_[0]->enqueue(&data);
    }

    void _enqueue_round_robin(const T& data) {
        work_queues_[cur_queue_]->enqueue(&data);
        cur_queue_ = (cur_queue_ + 1) % num_queues_;
    }

    void _enqueue_broadcast(const T& data) {
        for (int i = 0; i < num_queues_; ++i) {
            work_queues_[i]->enqueue(&data);
        }
    }

    void worker(int thread_id, EventfulQueue<T>* work_queue) {
        std::mutex* mutex = work_queue->mutex();
        std::condition_variable* cv = work_queue->conditional_variable();
        T* data = nullptr;

        while (true) {
            std::unique_lock<std::mutex> lock(*mutex);
            cv->wait(lock);
            lock.unlock();
            while ((data = work_queue->dequeue()) != nullptr) {
                func_(*data);
                work_queue->task_done(data);
            }
        }
    }
};

#endif // THREADPOOL_H