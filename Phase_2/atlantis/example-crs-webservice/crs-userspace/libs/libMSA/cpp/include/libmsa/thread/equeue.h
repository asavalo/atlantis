#ifndef EQUEUE_H
#define EQUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class EventfulQueue {
public:
    EventfulQueue();
    ~EventfulQueue();

    void enqueue(const T* data);
    T* dequeue();

    void task_done(T* data);

    std::mutex* mutex();
    std::condition_variable* conditional_variable();

    int size();

private:
    std::queue<T*> queue_;
    std::mutex mutex_;
    std::condition_variable cond_var_;
};

template <typename T>
EventfulQueue<T>::EventfulQueue() {}

template <typename T>
EventfulQueue<T>::~EventfulQueue() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!queue_.empty()) {
        delete queue_.front();
        queue_.pop();
    }
}

template <typename T>
void EventfulQueue<T>::enqueue(const T* data) {
    T* new_data = new T();
    new_data->CopyFrom(*data);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        queue_.push(new_data);
    }
    cond_var_.notify_all();
}

template <typename T>
T* EventfulQueue<T>::dequeue() {
    std::unique_lock<std::mutex> lock(mutex_);
    if (queue_.empty()) {
        lock.unlock();
        return nullptr;
    }

    T* data = queue_.front();
    queue_.pop();
    lock.unlock();
    return data;
}

template <typename T>
void EventfulQueue<T>::task_done(T* data) {
    std::lock_guard<std::mutex> lock(mutex_);
    delete data;
}

template <typename T>
std::mutex* EventfulQueue<T>::mutex() {
    return &mutex_;
}

template <typename T>
std::condition_variable* EventfulQueue<T>::conditional_variable() {
    return &cond_var_;
}

template <typename T>
int EventfulQueue<T>::size() {
    return queue_.size();
}


#endif // EQUEUE_H