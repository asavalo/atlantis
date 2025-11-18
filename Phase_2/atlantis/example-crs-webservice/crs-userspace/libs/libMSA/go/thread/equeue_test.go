package thread

import (
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestEventfulQueueSingleThread(t *testing.T) {
	queue := NewEventfulQueue[int]()

	if queue.Dequeue() != nil {
		t.Error("Expected queue to be empty initially")
	}

	data := 1
	queue.Enqueue(data)
	result := queue.Dequeue()

	if result == nil {
		t.Error("Expected item to be dequeued, but got nil")
	} else if *result != data {
		t.Errorf("Expected %d, but got %d", data, *result)
	}

	if queue.Dequeue() != nil {
		t.Error("Expected queue to be empty after dequeue")
	}
}

func TestEventfulQueueMultipleThreads(t *testing.T) {
	queue := NewEventfulQueue[int]()
	var wg sync.WaitGroup
	numEnqueueThreads := 1
	numDequeueThreads := 10
	totalItems := 10000

	wg.Add(numEnqueueThreads)
	for i := 0; i < numEnqueueThreads; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < totalItems; j++ {
				queue.Enqueue(rand.Intn(100000))
			}
		}()
	}

	wg.Add(numDequeueThreads)
	for i := 0; i < numDequeueThreads; i++ {
		go func() {
			defer wg.Done()
			for {
				data := queue.Dequeue()
				if data == nil {
					time.Sleep(1 * time.Millisecond)
                    break
				} else {
					time.Sleep(100 * time.Microsecond)
                }
			}
		}()
	}
	wg.Wait()

	result := queue.Dequeue()
	if result != nil {
		t.Error("Expected queue to be empty after all enqueuing and dequeuing is done")
	}
}