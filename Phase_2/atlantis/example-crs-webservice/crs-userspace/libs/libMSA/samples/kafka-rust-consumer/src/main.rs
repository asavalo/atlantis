use prost::Message;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message as KafkaMessage;
use std::env;

pub mod userspace {
    include!(concat!(env!("OUT_DIR"), "/userspace.rs"));
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <input_topic>", args[0]);
        return;
    }
    let input_topic = args[1].clone();

    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", "kafka-consumer")
        .set("bootstrap.servers", "localhost:29092")
        .set("enable.partition.eof", "false")
        .set("auto.offset.reset", "earliest")
        .set("enable.auto.commit", "false")
        .create()
        .expect("Consumer creation failed");

    consumer
        .subscribe(&[input_topic.as_str()])
        .expect("Failed to subscribe to topic");

    loop {
        match consumer.recv().await {
            Ok(msg) => {
                if let Some(payload) = msg.payload() {
                    match userspace::MessageThree::decode(payload) {
                        Ok(proto_message) => {
                            println!("Received message: {:#?}", proto_message);
                            consumer.commit_message(&msg, CommitMode::Sync).unwrap();
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
