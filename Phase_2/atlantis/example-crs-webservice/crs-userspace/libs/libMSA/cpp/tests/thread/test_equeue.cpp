#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include "libmsa/thread/equeue.h"
#include "test.pb.h"

class TestEventfulQueue : public ::testing::Test {
protected:
    EventfulQueue<userspace::TestRequest> work_queue;
    std::atomic<bool> terminate;
    const char* payload;

    void SetUp() override {
        terminate = false;
        payload = "Team-Atlanta";
    }

    void TearDown() override {

    }
public:
    void enqueue_worker() {
        for (int i = 0; i < 100000; ++i) {
            userspace::TestRequest request;
            request.set_team_name(payload);
            work_queue.enqueue(&request);
        }
    }

    void dequeue_worker() {
        while (!terminate.load()) {
            for(;;){
                userspace::TestRequest* data = work_queue.dequeue();
                if (data == nullptr) {
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
};

TEST_F(TestEventfulQueue, SingleThreadBasic) {
    userspace::TestRequest* request;
    userspace::TestRequest* dequeued_data;

    dequeued_data = work_queue.dequeue();
    EXPECT_EQ(dequeued_data, nullptr);

    request = new userspace::TestRequest();
    request->set_team_name(payload);

    work_queue.enqueue(request);

    delete request;

    dequeued_data = work_queue.dequeue();
    EXPECT_EQ(dequeued_data->team_name(), payload);
    work_queue.task_done(dequeued_data);

    dequeued_data = work_queue.dequeue();
    EXPECT_EQ(dequeued_data, nullptr);
}

TEST_F(TestEventfulQueue, MultipleThreadBasic) {
    const int num_enqueue_threads = 1;
    const int num_dequeue_threads = 10;

    std::vector<std::thread> enqueue_threads;
    std::vector<std::thread> dequeue_threads;

    for (int i = 0; i < num_enqueue_threads; ++i) {
        enqueue_threads.emplace_back(&TestEventfulQueue::enqueue_worker, this);
    }

    for (auto& thread : enqueue_threads) {
        thread.join();
    }

    for (int i = 0; i < num_dequeue_threads; ++i) {
        dequeue_threads.emplace_back(&TestEventfulQueue::dequeue_worker, this);
    }

    terminate.store(true);

    for (auto& thread : dequeue_threads) {
        thread.join();
    }

    EXPECT_EQ(work_queue.dequeue(), nullptr);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}