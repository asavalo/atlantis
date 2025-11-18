use super::kafka::consumer::Consumer;
use super::kafka::producer::Producer;
use super::thread::pool::QueuePolicy;
use super::thread::pool::ThreadPool;
use prost::Message;
use std::sync::{Arc, Mutex};

pub struct Runner<T, R, C>
where
    T: Message + std::default::Default + Send + Clone + 'static,
    R: Message + std::default::Default + Send + 'static,
    C: Send + Sync + 'static,
{
    input_topic: String,
    group_id: String,
    output_topic: String,
    num_threads: usize,
    queue_policy: QueuePolicy,
    thread_pool: ThreadPool<T, C>,
    consumer: Consumer<T>,
    producer: Arc<Producer<R>>,
}

impl<T, R, C> Runner<T, R, C>
where
    T: Message + std::default::Default + Send + Clone + 'static,
    R: Message + std::default::Default + Send + 'static,
    C: Send + Sync + 'static,
{
    pub fn new<F>(
        input_topic: String,
        group_id: String,
        output_topic: String,
        num_threads: usize,
        queue_policy: QueuePolicy,
        func: F,
        contexts: Option<Vec<Arc<Mutex<C>>>>,
    ) -> Self
    where
        F: Fn(T, usize, Option<Arc<Mutex<C>>>) -> Option<R> + Send + Sync + 'static,
    {
        let kafka_server_addr = std::env::var("KAFKA_SERVER_ADDR").expect("KAFKA_SERVER_ADDR is not set");
        let consumer = Consumer::new(
            kafka_server_addr.clone(),
            input_topic.clone(),
            group_id.clone(),
        );
        let producer = Arc::new(Producer::new(
            kafka_server_addr.clone(),
            output_topic.clone(),
        ));

        let func = Arc::new(func);
        let wrapped_func = {
            let producer = producer.clone();
            let func = func.clone();
            move |input: T, thread_id: usize, context: Option<Arc<Mutex<C>>>| {
                let producer = producer.clone();
                let func = func.clone();
                async move {
                    if let Some(output) = func(input, thread_id, context) {
                        producer.send_message(output).await;
                    }
                }
            }
        };
        let thread_pool = ThreadPool::new(num_threads, queue_policy, wrapped_func, contexts);

        Runner {
            input_topic,
            group_id,
            output_topic,
            num_threads,
            queue_policy,
            thread_pool,
            consumer,
            producer,
        }
    }

    pub async fn execute(&mut self) {
        self.thread_pool.execute();
        loop {
            let input_message = self.consumer.recv_message().await;
            self.thread_pool.enqueue(input_message);
        }
    }
}
