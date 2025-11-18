package thread

import (
	//"fmt"
)

type QueuePolicy int

const (
	GLOBAL QueuePolicy = iota
	ROUND_ROBIN
	BROADCAST
)

type ThreadPool struct {
	numThreads   int
	queuePolicy  QueuePolicy
	taskFunction func(data any)
	numQueues    int
	workQueues   []*EventfulQueue[any]
	curQueue     int
	threads      []*threadWorker
	executed     bool
}

type threadWorker struct {
	id        int
	workQueue *EventfulQueue[any]
}

func NewThreadPool(numThreads int, queuePolicy QueuePolicy, taskFunction func(data any)) *ThreadPool {
	tp := &ThreadPool{
		numThreads:   numThreads,
		queuePolicy:  queuePolicy,
		taskFunction: taskFunction,
		curQueue:     0,
		executed:     false,
	}

	if queuePolicy == GLOBAL {
		tp.numQueues = 1
		tp.workQueues = []*EventfulQueue[any]{NewEventfulQueue[any]()}
	} else {
		tp.numQueues = numThreads
		tp.workQueues = make([]*EventfulQueue[any], numThreads)
		for i := 0; i < numThreads; i++ {
			tp.workQueues[i] = NewEventfulQueue[any]()
		}
	}

	tp.createThreads()

	return tp
}

func (tp *ThreadPool) createThreads() {
	for i := 0; i < tp.numThreads; i++ {
		workQueue := tp.workQueues[0]
		if tp.queuePolicy != GLOBAL {
			workQueue = tp.workQueues[i]
		}

		worker := &threadWorker{id: i, workQueue: workQueue}
		tp.threads = append(tp.threads, worker)
	}
}


func (tp *ThreadPool) Enqueue(data any) {
	switch tp.queuePolicy {
		case GLOBAL:
			tp.workQueues[0].Enqueue(data)
		case ROUND_ROBIN:
			tp.workQueues[tp.curQueue].Enqueue(data)
			tp.curQueue = (tp.curQueue + 1) % tp.numQueues
		case BROADCAST:
			for _, queue := range tp.workQueues {
				queue.Enqueue(data)
			}
	}
}

func (tp *ThreadPool) Start() {
	for _, worker := range tp.threads {
		go worker.run(tp.taskFunction)
	}
	tp.executed = true
}

func (tw *threadWorker) run(taskFunction func(data any)) {
	lock := tw.workQueue.GetLock()
	cond := tw.workQueue.GetCond()
	for {
		lock.Lock()
		if tw.workQueue.queue.Len() == 0{
			cond.Wait()
		}
		lock.Unlock()

		for {
			event := tw.workQueue.Dequeue()
			if event == nil {
				break
			}
			taskFunction(*event)
		}
	}
}

func (tp *ThreadPool) AddThreads(numThreads int) {
	if numThreads <= 0 {
		return
	}

	for i := tp.numThreads; i < tp.numThreads+numThreads; i++ {
		var workQueue *EventfulQueue[any]
		if tp.queuePolicy != GLOBAL {
			workQueue = NewEventfulQueue[any]()
			tp.workQueues = append(tp.workQueues, workQueue)
		} else {
			workQueue = tp.workQueues[0]
		}

		worker := &threadWorker{id: i, workQueue: workQueue}
		tp.threads = append(tp.threads, worker)

		if tp.executed {
			go worker.run(tp.taskFunction)
		}
	}

	tp.numThreads += numThreads
	if tp.queuePolicy != GLOBAL {
		tp.numQueues += numThreads
	}
}