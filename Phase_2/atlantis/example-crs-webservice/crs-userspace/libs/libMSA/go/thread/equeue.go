package thread

import (
	"container/list"
	"sync"
	//"fmt"
)

type EventfulQueue[T any] struct {
	queue *list.List
	lock  sync.Mutex
	cond  *sync.Cond
}

func NewEventfulQueue[T any]() *EventfulQueue[T] {
	q := &EventfulQueue[T]{queue: list.New()}
	q.cond = sync.NewCond(&q.lock)
	return q
}

func (eq *EventfulQueue[T]) Enqueue(data T) {
	eq.lock.Lock()
	eq.queue.PushBack(data)
	eq.cond.Broadcast()
	eq.lock.Unlock()
}

func (eq *EventfulQueue[T]) Dequeue() *T {
	eq.lock.Lock()
	defer eq.lock.Unlock()

	if eq.queue.Len() > 0 {
		elem := eq.queue.Front()
		eq.queue.Remove(elem)
		data := elem.Value.(T)
		return &data
	}
	return nil
}

func (eq *EventfulQueue[T]) GetLock() *sync.Mutex {
	return &eq.lock
}

func (eq *EventfulQueue[T]) GetCond() *sync.Cond {
	return eq.cond
}