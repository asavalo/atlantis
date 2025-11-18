use prost::Message;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;

pub struct Producer<M>
where
    M: Message,
{
    bootstrap_server_addr: String,
    topic: String,
    key: String,
    producer: FutureProducer,
    _marker: std::marker::PhantomData<M>,
}

impl<M> Producer<M>
where
    M: Message,
{
    pub fn new(bootstrap_server_addr: String, topic: String) -> Self {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", bootstrap_server_addr.clone())
            .create()
            .expect("Producer creation failed");
        let key = String::from("default_key"); //Use default key
        Self {
            bootstrap_server_addr,
            topic,
            key,
            producer,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn send_message(&self, message: M) {
        let mut buf = Vec::new();
        match message.encode(&mut buf) {
            Ok(_) => println!("Message serialized successfully"),
            Err(e) => {
                println!("Failed to serialize protobuf message: {:?}", e);
                return;
            }
        }

        let record = FutureRecord::to(&self.topic).payload(&buf).key(&self.key);

        match self.producer.send(record, Timeout::Never).await {
            Ok(confirmation) => {
                println!("Message sent successfully: {:?}", confirmation);
            }
            Err((e, _)) => {
                println!("Failed to send message: {:?}", e);
            }
        }
    }
}
