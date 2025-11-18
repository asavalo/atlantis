use prost::Message;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use std::env;

pub mod userspace {
    include!(concat!(env!("OUT_DIR"), "/userspace.rs"));
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <message> <output_topic>", args[0]);
        return;
    }

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", "localhost:29092")
        .create()
        .expect("Producer creation failed");

    let message = userspace::MessageOne {
        name: args[1].clone(),
    };

    let mut buf = Vec::new();
    match message.encode(&mut buf) {
        Ok(_) => println!("Message serialized successfully"),
        Err(e) => println!("Failed to serialize protobuf message: {:?}", e),
    }

    let topic = args[2].as_str();
    let record = FutureRecord::to(topic).payload(&buf).key("default_key");

    match producer.send(record, Timeout::Never).await {
        Ok(confirmation) => {
            println!("Message sent successfully: {:?}", confirmation);
        }
        Err((e, _)) => {
            println!("Failed to send message: {:?}", e);
        }
    }
}
