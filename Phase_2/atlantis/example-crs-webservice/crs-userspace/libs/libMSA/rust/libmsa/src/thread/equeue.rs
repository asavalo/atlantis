use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::{Condvar, Mutex};

pub struct EventfulQueue<T> {
    queue: Mutex<VecDeque<T>>,
    cond_var: Condvar,
    terminate: AtomicBool,
}

impl<T> EventfulQueue<T> {
    pub fn new() -> Self {
        EventfulQueue {
            queue: Mutex::new(VecDeque::new()),
            cond_var: Condvar::new(),
            terminate: AtomicBool::new(false),
        }
    }

    pub fn enqueue(&self, data: T) {
        let mut queue_guard = self.queue.lock().unwrap();
        queue_guard.push_back(data);
        self.cond_var.notify_all();
    }

    pub fn dequeue(&self) -> Option<T> {
        loop {
            let mut queue_guard = self.queue.lock().unwrap();
            if let Some(item) = queue_guard.pop_front() {
                return Some(item);
            }
            if self.terminate.load(std::sync::atomic::Ordering::SeqCst) {
                return None;
            }
            queue_guard = self.cond_var.wait(queue_guard).unwrap();
            drop(queue_guard);
        }
    }

    pub fn size(&self) -> usize {
        let queue_guard = self.queue.lock().unwrap();
        queue_guard.len()
    }

    pub fn terminate(&self) {
        self.terminate
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.cond_var.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    struct TestEventfulQueue {
        work_queue: EventfulQueue<i32>,
    }

    impl TestEventfulQueue {
        fn new() -> Self {
            TestEventfulQueue {
                work_queue: EventfulQueue::new(),
            }
        }

        fn enqueue_worker(&self) {
            for _ in 0..10000 {
                let data = rand::thread_rng().gen_range(0..100000);
                self.work_queue.enqueue(data);
            }
        }

        fn dequeue_worker(&self) {
            loop {
                let _data = self.work_queue.dequeue().unwrap();
                thread::sleep(Duration::from_micros(100));
            }
        }
    }

    #[test]
    fn test_single_thread_basic() {
        let test_queue = TestEventfulQueue::new();

        assert_eq!(test_queue.work_queue.size(), 0);

        let data = 1;
        test_queue.work_queue.enqueue(data);
        assert_eq!(test_queue.work_queue.size(), 1);

        let ret = test_queue.work_queue.dequeue().unwrap();
        assert_eq!(ret, data);

        assert_eq!(test_queue.work_queue.size(), 0);
    }

    #[test]
    fn test_multiple_thread_basic() {
        let test_queue = Arc::new(TestEventfulQueue::new());
        let num_enqueue_threads = 1;
        let num_dequeue_threads = 10;

        let mut enqueue_threads = vec![];
        let mut dequeue_threads = vec![];

        for _ in 0..num_enqueue_threads {
            let queue = test_queue.clone();
            enqueue_threads.push(thread::spawn(move || {
                queue.enqueue_worker();
            }));
        }

        for _ in 0..num_dequeue_threads {
            let queue = test_queue.clone();
            dequeue_threads.push(thread::spawn(move || {
                queue.dequeue_worker();
            }));
        }

        thread::sleep(Duration::from_secs(3));

        assert_eq!(test_queue.work_queue.size(), 0);
    }
}
