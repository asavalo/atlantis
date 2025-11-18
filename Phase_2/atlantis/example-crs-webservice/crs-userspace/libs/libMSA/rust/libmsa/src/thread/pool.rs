use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use super::equeue::EventfulQueue;
use prost::Message;
use tokio;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum QueuePolicy {
    Global,
    RoundRobin,
    Broadcast,
}

pub struct ThreadPool<T, C>
where
    T: Message + Send + 'static,
    C: Send + Sync + 'static,
{
    num_threads: usize,
    queue_policy: QueuePolicy,
    work_queues: Vec<Arc<EventfulQueue<T>>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    func: Arc<
        dyn Fn(T, usize, Option<Arc<Mutex<C>>>) -> Pin<Box<dyn Future<Output = ()> + Send>>
            + Send
            + Sync,
    >,
    cur_queue: usize,
    executed: bool,
    contexts: Option<Vec<Arc<Mutex<C>>>>,
}

impl<T, C> ThreadPool<T, C>
where
    T: Message + Send + 'static,
    C: Send + Sync + 'static,
{
    pub fn new<F, Fut>(
        num_threads: usize,
        queue_policy: QueuePolicy,
        func: F,
        contexts: Option<Vec<Arc<Mutex<C>>>>,
    ) -> Self
    where
        F: Fn(T, usize, Option<Arc<Mutex<C>>>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let num_queues = if queue_policy == QueuePolicy::Global {
            1
        } else {
            num_threads
        };

        let work_queues = (0..num_queues)
            .map(|_| Arc::new(EventfulQueue::new()))
            .collect::<Vec<_>>();

        let func = Arc::new(
            move |task: T, thread_id: usize, context: Option<Arc<Mutex<C>>>| {
                Box::pin(func(task, thread_id, context)) as Pin<Box<dyn Future<Output = ()> + Send>>
            },
        );

        if let Some(valid_contexts) = &contexts {
            assert!(
                valid_contexts.len() == num_threads,
                "Expected {} elements, but got {} elements",
                num_threads,
                valid_contexts.len()
            );
        }

        ThreadPool {
            num_threads,
            queue_policy,
            work_queues,
            handles: Vec::new(),
            func,
            cur_queue: 0,
            executed: false,
            contexts,
        }
    }

    fn _enqueue_global(&self, data: T) {
        self.work_queues[0].enqueue(data);
    }

    fn _enqueue_round_robin(&mut self, data: T) {
        self.work_queues[self.cur_queue].enqueue(data);
        self.cur_queue = (self.cur_queue + 1) % self.work_queues.len();
    }

    fn _enqueue_broadcast(&self, data: T)
    where
        T: Clone,
    {
        for queue in &self.work_queues {
            queue.enqueue(data.clone());
        }
    }

    pub fn enqueue(&mut self, data: T)
    where
        T: Clone,
    {
        match self.queue_policy {
            QueuePolicy::Global => self._enqueue_global(data),
            QueuePolicy::RoundRobin => self._enqueue_round_robin(data),
            QueuePolicy::Broadcast => self._enqueue_broadcast(data),
        }
    }

    async fn worker(
        work_queue: Arc<EventfulQueue<T>>,
        func: Arc<
            dyn Fn(T, usize, Option<Arc<Mutex<C>>>) -> Pin<Box<dyn Future<Output = ()> + Send>>
                + Send
                + Sync,
        >,
        thread_id: usize,
        context: Option<Arc<Mutex<C>>>,
    ) where
        T: Send + 'static,
    {
        loop {
            if let Some(valid_task) = work_queue.dequeue() {
                if let Some(valid_context) = &context {
                    func(valid_task, thread_id, Some(Arc::clone(valid_context))).await;
                } else {
                    func(valid_task, thread_id, None).await;
                }
            } else {
                println!("Thread {} finished!", thread_id);
                return;
            }
        }
    }

    pub fn execute(&mut self) {
        if self.executed {
            return;
        }

        for i in 0..self.num_threads {
            let work_queue = if self.queue_policy == QueuePolicy::Global {
                Arc::clone(&self.work_queues[0])
            } else {
                Arc::clone(&self.work_queues[i])
            };

            let func = Arc::clone(&self.func);
            let context = if let Some(valid_contexts) = &self.contexts {
                Some(Arc::clone(valid_contexts.get(i).unwrap()))
            } else {
                None
            };

            let handle = tokio::spawn(async move {
                ThreadPool::<T, C>::worker(work_queue, func, i, context).await;
            });
            self.handles.push(handle);
        }

        self.executed = true;
    }

    pub fn create_more_threads(
        &mut self,
        num_threads: usize,
        additional_contexts: Option<Vec<Arc<Mutex<C>>>>,
    ) {
        if num_threads == 0 {
            return;
        }

        if additional_contexts.is_none() != self.contexts.is_none() {
            assert!(
                false,
                "Contexts none {}, additional contexts none {}",
                self.contexts.is_none(),
                additional_contexts.is_none()
            );
        }

        if let Some(valid_contexts) = additional_contexts {
            assert!(
                valid_contexts.len() == num_threads,
                "Expected {} elements, but got {} elements",
                num_threads,
                valid_contexts.len()
            );
            for context in valid_contexts {
                self.contexts.as_mut().unwrap().push(context);
            }
        }

        for i in 0..num_threads {
            if self.queue_policy != QueuePolicy::Global {
                let work_queue = Arc::new(EventfulQueue::new());
                self.work_queues.push(work_queue.clone());
            }

            if self.executed {
                let thread_id = i + self.num_threads;
                let work_queue = if self.queue_policy == QueuePolicy::Global {
                    Arc::clone(&self.work_queues[0])
                } else {
                    Arc::clone(&self.work_queues[thread_id])
                };

                let func = Arc::clone(&self.func);
                let context = if let Some(valid_contexts) = &self.contexts {
                    Some(Arc::clone(valid_contexts.get(thread_id).unwrap()))
                } else {
                    None
                };

                let handle = tokio::spawn(async move {
                    ThreadPool::<T, C>::worker(work_queue, func, thread_id, context).await;
                });
                self.handles.push(handle);
            }
        }

        self.num_threads += num_threads;
    }

    pub fn get_queues(&self) -> &Vec<Arc<EventfulQueue<T>>> {
        &self.work_queues
    }

    pub async fn wait_for_termination(&mut self) {
        for handle in &mut self.handles {
            if let Err(e) = handle.await {
                eprintln!("Task failed: {:?}", e);
            }
        }
    }

    pub fn drop_runtime(&mut self) {
        for handle in &mut self.handles {
            handle.abort();
        }
        for queue in &self.work_queues {
            queue.terminate();
        }
        self.executed = false;
    }
}

#[cfg(test)]
pub struct MockContext {
    pub data: i32,
}

#[cfg(test)]
impl MockContext {
    pub fn new() -> Self {
        MockContext { data: -1 }
    }

    pub fn get(&self) -> i32 {
        self.data
    }

    pub fn set(&mut self, val: i32) {
        self.data = val;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tokio::time::Duration;
    use userspace::TestRequest;

    mod userspace {
        include!(concat!(env!("OUT_DIR"), "/userspace.rs"));
    }

    async fn mock_function(
        _data: TestRequest,
        thread_id: usize,
        context: Option<Arc<Mutex<MockContext>>>,
    ) {
        let valid_context = context.unwrap();
        {
            let mut guard = valid_context.lock().unwrap();
            guard.set(thread_id as i32);
            let num = guard.get();
            assert_eq!(num as usize, thread_id);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_global_enqueue() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Global,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        assert_eq!(pool.get_queues()[0].size(), num_data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_round_robin_enqueue() {
        let num_threads = 3;
        let num_data = 3000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::RoundRobin,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        let expected_size = num_data / num_threads;
        for queue in pool.get_queues() {
            assert_eq!(queue.size(), expected_size);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_broadcast_enqueue() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Broadcast,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        for queue in pool.get_queues() {
            assert_eq!(queue.size(), num_data);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_broadcast_dequeue() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Broadcast,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        pool.execute();

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        thread::sleep(Duration::from_secs(3));

        for queue in pool.get_queues() {
            assert_eq!(queue.size(), 0);
        }

        pool.drop_runtime();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_global_dequeue() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Global,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        pool.execute();

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        thread::sleep(Duration::from_secs(3));

        assert_eq!(pool.get_queues()[0].size(), 0);

        pool.drop_runtime();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_round_robin_dequeue() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::RoundRobin,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        pool.execute();

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        thread::sleep(Duration::from_secs(3));

        for queue in pool.get_queues() {
            assert_eq!(queue.size(), 0);
        }

        pool.drop_runtime();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_broadcast_enqueue_additional_threads() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Broadcast,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        let additional_threads = 2;
        let additional_data = 500;
        let additional_contexts: Vec<Arc<Mutex<MockContext>>> = (0..additional_threads)
            .map(|_| Arc::clone(&context))
            .collect();
        pool.create_more_threads(additional_threads, Some(additional_contexts));

        assert_eq!(pool.get_queues().len(), num_threads + additional_threads);

        for _ in 0..additional_data {
            pool.enqueue(data.clone());
        }

        for (i, queue) in pool.get_queues().iter().enumerate() {
            if i < num_threads {
                assert_eq!(queue.size(), num_data + additional_data);
            } else {
                assert_eq!(queue.size(), additional_data);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_global_enqueue_additional_threads() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Global,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        let additional_threads = 2;
        let additional_data = 500;
        let additional_contexts: Vec<Arc<Mutex<MockContext>>> = (0..additional_threads)
            .map(|_| Arc::clone(&context))
            .collect();
        pool.create_more_threads(additional_threads, Some(additional_contexts));

        assert_eq!(pool.get_queues().len(), 1);

        for _ in 0..additional_data {
            pool.enqueue(data.clone());
        }

        assert_eq!(pool.get_queues()[0].size(), num_data + additional_data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_round_robin_enqueue_additional_threads() {
        let num_threads = 3;
        let num_data = 3000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::RoundRobin,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        let additional_threads = 2;
        let additional_data = 500;
        let additional_contexts: Vec<Arc<Mutex<MockContext>>> = (0..additional_threads)
            .map(|_| Arc::clone(&context))
            .collect();
        pool.create_more_threads(additional_threads, Some(additional_contexts));

        assert_eq!(pool.get_queues().len(), num_threads + additional_threads);

        for _ in 0..additional_data {
            pool.enqueue(data.clone());
        }

        let total_threads = num_threads + additional_threads;
        let expected_initial_size = num_data / num_threads;
        let expected_additional_size = additional_data / total_threads;

        for queue in pool.get_queues() {
            let size = queue.size();
            assert!(
                size == expected_initial_size + expected_additional_size
                    || size == expected_additional_size
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_broadcast_dequeue_additional_threads() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Broadcast,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        pool.execute();

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        let additional_threads = 2;
        let additional_data = 500;
        let additional_contexts: Vec<Arc<Mutex<MockContext>>> = (0..additional_threads)
            .map(|_| Arc::clone(&context))
            .collect();
        pool.create_more_threads(additional_threads, Some(additional_contexts));

        assert_eq!(pool.get_queues().len(), num_threads + additional_threads);

        for _ in 0..additional_data {
            pool.enqueue(data.clone());
        }

        thread::sleep(Duration::from_secs(3));

        for queue in pool.get_queues() {
            assert_eq!(queue.size(), 0);
        }

        pool.drop_runtime();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_global_dequeue_additional_threads() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::Global,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        pool.execute();

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        let additional_threads = 2;
        let additional_data = 500;
        let additional_contexts: Vec<Arc<Mutex<MockContext>>> = (0..additional_threads)
            .map(|_| Arc::clone(&context))
            .collect();
        pool.create_more_threads(additional_threads, Some(additional_contexts));

        assert_eq!(pool.get_queues().len(), 1);

        for _ in 0..additional_data {
            pool.enqueue(data.clone());
        }

        thread::sleep(Duration::from_secs(3));

        assert_eq!(pool.get_queues()[0].size(), 0);

        pool.drop_runtime();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn test_round_robin_dequeue_additional_threads() {
        let num_threads = 3;
        let num_data = 1000;
        let context = Arc::new(Mutex::new(MockContext::new()));
        let contexts: Vec<Arc<Mutex<MockContext>>> =
            (0..num_threads).map(|_| Arc::clone(&context)).collect();
        let mut pool = ThreadPool::new(
            num_threads,
            QueuePolicy::RoundRobin,
            mock_function,
            Some(contexts),
        );
        let data = TestRequest {
            team_name: "Team-Atlanta".to_string(),
        };

        pool.execute();

        for _ in 0..num_data {
            pool.enqueue(data.clone());
        }

        let additional_threads = 2;
        let additional_data = 500;
        let additional_contexts: Vec<Arc<Mutex<MockContext>>> = (0..additional_threads)
            .map(|_| Arc::clone(&context))
            .collect();
        pool.create_more_threads(additional_threads, Some(additional_contexts));

        assert_eq!(pool.get_queues().len(), num_threads + additional_threads);

        for _ in 0..additional_data {
            pool.enqueue(data.clone());
        }

        thread::sleep(Duration::from_secs(3));

        for queue in pool.get_queues() {
            assert_eq!(queue.size(), 0);
        }

        pool.drop_runtime();
    }
}
