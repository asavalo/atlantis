use prost::Message;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{CommitMode, Consumer as KafkaConsumer, StreamConsumer};
use rdkafka::message::Message as KafkaMessage;

pub struct Consumer<M>
where
    M: Message + std::default::Default,
{
    bootstrap_server_addr: String,
    topic: String,
    group_id: String,
    consumer: StreamConsumer,
    _marker: std::marker::PhantomData<M>,
}

impl<M> Consumer<M>
where
    M: Message + std::default::Default,
{
    pub fn new(bootstrap_server_addr: String, topic: String, group_id: String) -> Self {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", group_id.clone())
            .set("bootstrap.servers", bootstrap_server_addr.clone())
            .set("enable.partition.eof", "false")
            .set("auto.offset.reset", "earliest")
            .set("enable.auto.commit", "false")
            .set("session.timeout.ms", "6000")
            .set("heartbeat.interval.ms", "2000")
            .create()
            .expect("Consumer creation failed");

        consumer
            .subscribe(&[&topic])
            .expect("Failed to subscribe to topic");

        Self {
            bootstrap_server_addr,
            topic,
            group_id,
            consumer,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn recv_message(&self) -> M {
        loop {
            match self.consumer.recv().await {
                Ok(msg) => {
                    if let Some(payload) = msg.payload() {
                        match M::decode(payload) {
                            Ok(proto_message) => {
                                self.consumer
                                    .commit_message(&msg, CommitMode::Sync)
                                    .unwrap();
                                return proto_message;
                            }
                            Err(e) => {
                                println!("Failed to decode protobuf message: {:?}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Error receiving message: {:?}", e);
                }
            }
        }
    }
}
