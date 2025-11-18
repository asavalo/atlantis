#include <gtest/gtest.h>
#include "libmsa/thread/pool.h"
#include "test.pb.h"

void mock_function(userspace::TestRequest& data) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

TEST(ThreadPoolTest, BroadcastEnqueue) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::BROADCAST, mock_function);
    userspace::TestRequest data;
    data.set_team_name("Team-Atlanta");

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    for (auto& queue : pool.get_queues()) {
        ASSERT_EQ(queue->size(), num_data);
    }
}

TEST(ThreadPoolTest, GlobalEnqueue) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::GLOBAL, mock_function);
    userspace::TestRequest data;

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    ASSERT_EQ(pool.get_queues()[0]->size(), num_data);
}

TEST(ThreadPoolTest, RoundRobinEnqueue) {
    int num_threads = 3;
    int num_data = 3000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::ROUND_ROBIN, mock_function);
    userspace::TestRequest data;

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    for (auto& queue : pool.get_queues()) {
        ASSERT_EQ(queue->size(), num_data / num_threads);
    }
}

TEST(ThreadPoolTest, BroadcastDequeue) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::BROADCAST, mock_function);
    userspace::TestRequest data;
    data.set_team_name("Team-Atlanta");

    pool.execute();

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    for (auto& queue : pool.get_queues()) {
        ASSERT_EQ(queue->size(), 0);
    }
}

TEST(ThreadPoolTest, GlobalDequeue) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::GLOBAL, mock_function);
    userspace::TestRequest data;
    data.set_team_name("Team-Atlanta");

    pool.execute();

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    ASSERT_EQ(pool.get_queues()[0]->size(), 0);
}

TEST(ThreadPoolTest, RoundRobinDequeue) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::ROUND_ROBIN, mock_function);
    userspace::TestRequest data;
    data.set_team_name("Team-Atlanta");

    pool.execute();

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    for (auto& queue : pool.get_queues()) {
        ASSERT_EQ(queue->size(), 0);
    }
}

TEST(ThreadPoolTest, BroadcastEnqueueAdditionalThreads) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::BROADCAST, mock_function);
    userspace::TestRequest data;

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    int additional_threads = 2;
    int additional_data = 500;
    pool.create_more_threads(additional_threads);
    ASSERT_EQ(pool.get_queues().size(), num_threads + additional_threads);

    for (int i = 0; i < additional_data; ++i) {
        pool.enqueue(data);
    }

    int cnt1 = 0;
    int cnt2 = 0;
    for (auto& queue : pool.get_queues()) {
        if (queue->size() == num_data + additional_data) {
            cnt1++;
        } else if (queue->size() == additional_data) {
            cnt2++;
        }
    }

    ASSERT_EQ(cnt1, num_threads);
    ASSERT_EQ(cnt2, additional_threads);
}

TEST(ThreadPoolTest, GlobalEnqueueAdditionalThreads) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::GLOBAL, mock_function);
    userspace::TestRequest data;

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    int additional_threads = 2;
    int additional_data = 500;
    pool.create_more_threads(additional_threads);
    ASSERT_EQ(pool.get_queues().size(), 1);

    for (int i = 0; i < additional_data; ++i) {
        pool.enqueue(data);
    }

    ASSERT_EQ(pool.get_queues()[0]->size(), num_data + additional_data);
}

TEST(ThreadPoolTest, RoundRobinEnqueueAdditionalThreads) {
    int num_threads = 3;
    int num_data = 3000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::ROUND_ROBIN, mock_function);
    userspace::TestRequest data;

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    int additional_threads = 2;
    int additional_data = 500;
    pool.create_more_threads(additional_threads);
    ASSERT_EQ(pool.get_queues().size(), num_threads + additional_threads);

    for (int i = 0; i < additional_data; ++i) {
        pool.enqueue(data);
    }

    int cnt1 = 0;
    int cnt2 = 0;
    for (auto& queue : pool.get_queues()) {
        if (queue->size() == num_data / num_threads + additional_data / (num_threads + additional_threads)) {
            cnt1++;
        } else if (queue->size() == additional_data / (num_threads + additional_threads)) {
            cnt2++;
        }
    }

    ASSERT_EQ(cnt1, num_threads);
    ASSERT_EQ(cnt2, additional_threads);
}

TEST(ThreadPoolTest, BroadcastDequeueAdditionalThreads) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::BROADCAST, mock_function);
    userspace::TestRequest data;

    pool.execute();

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    int additional_threads = 2;
    int additional_data = 500;
    pool.create_more_threads(additional_threads);
    ASSERT_EQ(pool.get_queues().size(), num_threads + additional_threads);

    for (int i = 0; i < additional_data; ++i) {
        pool.enqueue(data);
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    for (auto& queue : pool.get_queues()) {
        ASSERT_EQ(queue->size(), 0);
    }
}

TEST(ThreadPoolTest, GlobalDequeueAdditionalThreads) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::GLOBAL, mock_function);
    userspace::TestRequest data;

    pool.execute();

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    int additional_threads = 2;
    int additional_data = 500;
    pool.create_more_threads(additional_threads);
    ASSERT_EQ(pool.get_queues().size(), 1);

    for (int i = 0; i < additional_data; ++i) {
        pool.enqueue(data);
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    ASSERT_EQ(pool.get_queues()[0]->size(), 0);
}

TEST(ThreadPoolTest, RoundRobinDequeueAdditionalThreads) {
    int num_threads = 3;
    int num_data = 1000;
    ThreadPool<userspace::TestRequest> pool(num_threads, QueuePolicy::ROUND_ROBIN, mock_function);
    userspace::TestRequest data;

    pool.execute();

    for (int i = 0; i < num_data; ++i) {
        pool.enqueue(data);
    }

    int additional_threads = 2;
    int additional_data = 500;
    pool.create_more_threads(additional_threads);
    ASSERT_EQ(pool.get_queues().size(), num_threads + additional_threads);

    for (int i = 0; i < additional_data; ++i) {
        pool.enqueue(data);
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    for (auto& queue : pool.get_queues()) {
        ASSERT_EQ(queue->size(), 0);
    }
}