package thread

import (
	"testing"
	"time"
)

func mockFunction(data any) {
	time.Sleep(10 * time.Microsecond) // Simulates some processing
}

func TestBroadcastEnqueue(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, BROADCAST, mockFunction)
	
	if len(pool.workQueues) != numThreads {
		t.Errorf("Expected %d work queues, got %d", numThreads, len(pool.workQueues))
	}

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	for _, queue := range pool.workQueues {
		if queue.queue.Len() != 1000 {
			t.Errorf("Expected queue size %d, got %d", numData, queue.queue.Len())
		}
	}
}

func TestGlobalEnqueue(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, GLOBAL, mockFunction)
	
	if len(pool.workQueues) != 1 {
		t.Errorf("Expected 1 work queue, got %d", len(pool.workQueues))
	}

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	if pool.workQueues[0].queue.Len() != numData {
		t.Errorf("Expected queue size %d, got %d", numData, pool.workQueues[0].queue.Len())
	}
}

func TestRoundRobinEnqueue(t *testing.T) {
	numThreads := 3
	numData := 3000
	pool := NewThreadPool(numThreads, ROUND_ROBIN, mockFunction)
	
	if len(pool.workQueues) != numThreads {
		t.Errorf("Expected %d work queues, got %d", numThreads, len(pool.workQueues))
	}

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	for _, queue := range pool.workQueues {
		expectedSize := numData / numThreads
		if queue.queue.Len() != expectedSize {
			t.Errorf("Expected queue size %d, got %d", expectedSize, queue.queue.Len())
		}
	}
}

func TestBroadcastDequeue(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, BROADCAST, mockFunction)
	pool.Start()

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	time.Sleep(3 * time.Second) // Wait for processing to finish

	for _, queue := range pool.workQueues {
		if queue.queue.Len() != 0 {
			t.Errorf("Expected queue size 0 after processing, got %d", queue.queue.Len())
		}
	}
}

func TestGlobalDequeue(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, GLOBAL, mockFunction)
	pool.Start()

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	time.Sleep(3 * time.Second) // Wait for processing to finish

	if pool.workQueues[0].queue.Len() != 0 {
		t.Errorf("Expected queue size 0 after processing, got %d", pool.workQueues[0].queue.Len())
	}
}

func TestRoundRobinDequeue(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, ROUND_ROBIN, mockFunction)
	pool.Start()

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	time.Sleep(3 * time.Second) // Wait for processing to finish

	for _, queue := range pool.workQueues {
		if queue.queue.Len() != 0 {
			t.Errorf("Expected queue size 0 after processing, got %d", queue.queue.Len())
		}
	}
}

func TestBroadcastEnqueueAdditionalThreads(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, BROADCAST, mockFunction)

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	additionalThreads := 2
	additionalData := 500
	pool.AddThreads(additionalThreads)

	if len(pool.workQueues) != numThreads+additionalThreads {
		t.Errorf("Expected %d work queues, got %d", numThreads+additionalThreads, len(pool.workQueues))
	}

	for i := 0; i < additionalData; i++ {
		pool.Enqueue(i)
	}

	cnt1 := 0
	cnt2 := 0
	for i, queue := range pool.workQueues {
		queueSize := queue.queue.Len()
		if i < numThreads && queueSize == numData+additionalData {
			cnt1++
		} else if i >= numThreads && queueSize == additionalData {
			cnt2++
		}
	}

	if cnt1 != numThreads || cnt2 != additionalThreads {
		t.Errorf("Expected %d queues with size %d, got %d; expected %d queues with size %d, got %d",
			numThreads, numData+additionalData, cnt1, additionalThreads, additionalData, cnt2)
	}
}

func TestGlobalEnqueueAdditionalThreads(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, GLOBAL, mockFunction)

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	additionalThreads := 2
	additionalData := 500
	pool.AddThreads(additionalThreads)

	if len(pool.workQueues) != 1 {
		t.Errorf("Expected 1 work queue, got %d", len(pool.workQueues))
	}

	for i := 0; i < additionalData; i++ {
		pool.Enqueue(i)
	}

	expectedSize := numData + additionalData
	if pool.workQueues[0].queue.Len() != expectedSize {
		t.Errorf("Expected queue size %d, got %d", expectedSize, pool.workQueues[0].queue.Len())
	}
}

func TestRoundRobinEnqueueAdditionalThreads(t *testing.T) {
	numThreads := 3
	numData := 3000
	pool := NewThreadPool(numThreads, ROUND_ROBIN, mockFunction)

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	additionalThreads := 2
	additionalData := 500
	pool.AddThreads(additionalThreads)

	if len(pool.workQueues) != numThreads+additionalThreads {
		t.Errorf("Expected %d work queues, got %d", numThreads+additionalThreads, len(pool.workQueues))
	}

	for i := 0; i < additionalData; i++ {
		pool.Enqueue(i)
	}

	cnt1 := 0
	cnt2 := 0
	for i, queue := range pool.workQueues {
		expectedSize := numData/numThreads + additionalData/(numThreads+additionalThreads)
		if queue.queue.Len() == expectedSize {
			cnt1++
		} else if i >= numThreads && queue.queue.Len() == additionalData/(numThreads+additionalThreads) {
			cnt2++
		}
	}

	if cnt1 != numThreads || cnt2 != additionalThreads {
		t.Errorf("Expected %d queues with size %d, got %d; expected %d queues with size %d, got %d",
			numThreads, numData/numThreads+additionalData/(numThreads+additionalThreads), cnt1,
			additionalThreads, additionalData/(numThreads+additionalThreads), cnt2)
	}
}

func TestBroadcastDequeueAdditionalThreads(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, BROADCAST, mockFunction)
	pool.Start()

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	additionalThreads := 2
	additionalData := 500
	pool.AddThreads(additionalThreads)

	for i := 0; i < additionalData; i++ {
		pool.Enqueue(i)
	}

	time.Sleep(3 * time.Second) // Wait for processing to finish

	for _, queue := range pool.workQueues {
		if queue.queue.Len() != 0 {
			t.Errorf("Expected queue size 0 after processing, got %d", queue.queue.Len())
		}
	}
}

func TestGlobalDequeueAdditionalThreads(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, GLOBAL, mockFunction)
	pool.Start()

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	additionalThreads := 2
	additionalData := 500
	pool.AddThreads(additionalThreads)

	for i := 0; i < additionalData; i++ {
		pool.Enqueue(i)
	}

	time.Sleep(3 * time.Second) // Wait for processing to finish

	if pool.workQueues[0].queue.Len() != 0 {
		t.Errorf("Expected queue size 0 after processing, got %d", pool.workQueues[0].queue.Len())
	}
}

func TestRoundRobinDequeueAdditionalThreads(t *testing.T) {
	numThreads := 3
	numData := 1000
	pool := NewThreadPool(numThreads, ROUND_ROBIN, mockFunction)
	pool.Start()

	for i := 0; i < numData; i++ {
		pool.Enqueue(i)
	}

	additionalThreads := 2
	additionalData := 500
	pool.AddThreads(additionalThreads)

	for i := 0; i < additionalData; i++ {
		pool.Enqueue(i)
	}

	time.Sleep(3 * time.Second) // Wait for processing to finish

	for _, queue := range pool.workQueues {
		if queue.queue.Len() != 0 {
			t.Errorf("Expected queue size 0 after processing, got %d", queue.queue.Len())
		}
	}
}