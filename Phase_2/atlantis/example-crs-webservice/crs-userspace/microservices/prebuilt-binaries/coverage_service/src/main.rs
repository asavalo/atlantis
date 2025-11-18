mod app;
mod executor;
mod output_generator;
mod protobuf;
mod util;

use std::{
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use libmsa::{
    kafka::consumer::Consumer,
    kafka::producer::Producer,
    runner::Runner,
    thread::pool::QueuePolicy,
};

use crate::app::{App, SeedRequestInterface};

/// Atlantis source-level coverage service.
///
/// This service listens for seeds from LibAFL instances over Kafka, and
/// re-runs them in a challenge project build instrumented to collect
/// source-level code coverage. It provides a Kafka-based API to answer
/// queries about the fuzzer's source-level coverage status based on
/// this data.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Number of threads to use for responding to queries
    num_threads: usize,
    /// Topic to subscribe to to receive harness-builder build requests
    harness_builder_requests_topic: String,
    /// Group ID for the harness-builder build requests topic
    harness_builder_requests_group_id: String,
    /// Topic to subscribe to to receive harness-builder build responses
    harness_builder_responses_topic: String,
    /// Group ID for the harness-builder build responses topic
    harness_builder_responses_group_id: String,
    /// Topic to subscribe to to receive fuzzer launch announcements
    fuzzer_launch_announcements_topic: String,
    /// Group ID for the fuzzer launch announcements topic
    fuzzer_launch_announcements_group_id: String,
    /// Topic to publish requests for seed updates on
    seed_requests_topic: String,
    /// Topic to subscribe to to receive seeds from the fuzzer
    seed_updates_topic: String,
    /// Group ID for the seed-updates topic
    seed_updates_group_id: String,
    /// Topic to subscribe to to receive coverage requests
    requests_topic: String,
    /// Group ID for the requests topic
    requests_group_id: String,
    /// Topic to publish coverage responses on
    responses_topic: String,
    /// Directory to save intermediate results to
    cache_directory: PathBuf,
}

struct KafkaSeedRequester {
    producer: Producer::<protobuf::coverage_service::FuzzerSeedRequest>,
}

impl KafkaSeedRequester {
    fn new(producer: Producer::<protobuf::coverage_service::FuzzerSeedRequest>) -> Self {
        Self { producer }
    }
}

impl SeedRequestInterface for KafkaSeedRequester {
    async fn request_seeds(&self, request: protobuf::coverage_service::FuzzerSeedRequest) {
        self.producer.send_message(request).await;
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();

    let kafka_bootstrap_server = std::env::var("KAFKA_SERVER_ADDR")
        .expect("KAFKA_SERVER_ADDR is not set");

    println!("**********************************************");
    println!("Executing coverage service with {} threads.", cli.num_threads);
    println!("Harness Builder Requests Topic: {} (group {})", cli.harness_builder_requests_topic, cli.harness_builder_requests_group_id);
    println!("Harness Builder Responses Topic: {} (group {})", cli.harness_builder_responses_topic, cli.harness_builder_responses_group_id);
    println!("Fuzzer Launch Announcements Topic: {} (group {})", cli.fuzzer_launch_announcements_topic, cli.fuzzer_launch_announcements_group_id);
    println!("Fuzzer Seed Requests Topic: {}", cli.seed_requests_topic);
    println!("Fuzzer Seed Updates Topic: {} (group {})", cli.seed_updates_topic, cli.seed_updates_group_id);
    println!("Requests Topic: {} (group {})", cli.requests_topic, cli.requests_group_id);
    println!("Responses Topic: {}", cli.responses_topic);
    println!("Cache Directory: {}", cli.cache_directory.display());
    println!("**********************************************");

    // Create the SeedRequester
    let requester = KafkaSeedRequester::new(Producer::new(
        kafka_bootstrap_server.clone(),
        cli.seed_requests_topic.clone(),
    ));

    // Create the App
    let app = App::new_arc(requester, &cli.cache_directory);

    // Manually subscribe for harness-builder request messages
    let consumer = Consumer::<protobuf::harness_builder::BuildRequest>::new(
        kafka_bootstrap_server.to_string(),
        cli.harness_builder_requests_topic,
        cli.harness_builder_requests_group_id,
    );
    let app_clone = Arc::clone(&app);
    tokio::spawn(async move {
        loop {
            let msg = consumer.recv_message().await;
            app_clone.process_harness_builder_request(msg).await;
        }
    });

    // Manually subscribe for harness-builder response messages
    let consumer = Consumer::<protobuf::harness_builder::BuildRequestResponse>::new(
        kafka_bootstrap_server.to_string(),
        cli.harness_builder_responses_topic,
        cli.harness_builder_responses_group_id,
    );
    let app_clone = Arc::clone(&app);
    tokio::spawn(async move {
        loop {
            let msg = consumer.recv_message().await;
            app_clone.process_harness_builder_response(msg).await;
        }
    });

    // Manually subscribe for fuzzer launch announcement messages
    let consumer = Consumer::<protobuf::fuzzer_manager::FuzzerLaunchAnnouncement>::new(
        kafka_bootstrap_server.to_string(),
        cli.fuzzer_launch_announcements_topic,
        cli.fuzzer_launch_announcements_group_id,
    );
    let app_clone = Arc::clone(&app);
    tokio::spawn(async move {
        loop {
            let msg = consumer.recv_message().await;
            app_clone.process_fuzzer_launch_announcement(msg).await;
        }
    });

    // Manually subscribe for seed updates from the fuzzer
    let consumer = Consumer::<protobuf::coverage_service::FuzzerSeedUpdate>::new(
        kafka_bootstrap_server.to_string(),
        cli.seed_updates_topic,
        cli.seed_updates_group_id,
    );
    let app_clone = Arc::clone(&app);
    tokio::spawn(async move {
        loop {
            let msg = consumer.recv_message().await;
            app_clone.process_seed_update(msg).await;
        }
    });

    // Connect the App to the libMSA interface for requests/responses,
    // and launch the service
    let process_message = move |
        input_message: protobuf::coverage_service::CoverageRequest,
        _thread_id: usize,
        _context: Option<Arc<std::sync::Mutex<()>>>,
    | -> Option<protobuf::coverage_service::CoverageResponse> {
        app.process_request(input_message)
    };
    let mut runner = Runner::new(
        cli.requests_topic,
        cli.requests_group_id,
        cli.responses_topic,
        cli.num_threads,
        QueuePolicy::RoundRobin,
        process_message,
        None,
    );
    runner.execute().await;
}
