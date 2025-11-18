use std::env;
use std::sync::{Arc, Mutex};
use tokio;

use libmsa::runner::Runner;

pub mod userspace {
    include!(concat!(env!("OUT_DIR"), "/userspace.rs"));
}

pub struct JobContext {
    pub job: String,
}

impl JobContext {
    pub fn new(job: String, thread_id: usize) -> Self {
        let job_with_thread = format!("{}_{}", job, thread_id);
        JobContext {
            job: job_with_thread,
        }
    }

    pub fn get(&self) -> String {
        self.job.clone()
    }
}

fn initialize(job: String, num_threads: usize) -> Vec<Arc<Mutex<JobContext>>> {
    (0..num_threads)
        .map(|i| {
            let job_context = JobContext::new(job.clone(), i);
            Arc::new(Mutex::new(job_context))
        })
        .collect()
}

fn process_message(
    input_message: userspace::MessageOne,
    thread_id: usize,
    context: Option<Arc<Mutex<JobContext>>>,
) -> Option<userspace::MessageTwo> {
    let input_name = input_message.name;
    let job = context.unwrap().lock().unwrap().get();

    let new_name = format!("{}&{}", input_name, job);

    Some(userspace::MessageTwo {
        name: new_name,
        value: thread_id as i32,
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    //Parse args
    let args: Vec<String> = env::args().collect();

    if args.len() != 6 {
        eprintln!(
            "Usage: {} <job_name> <num_threads> <input_topic> <group_id> <output_topic>",
            args[0]
        );
        return;
    }

    let job = args[1].clone();

    let num_threads: usize = match args[2].parse() {
        Ok(num) => num,
        Err(_) => {
            eprintln!("Error: First argument must be a valid unsigned integer.");
            return;
        }
    };

    let input_topic = args[3].clone();
    let group_id = args[4].clone();
    let output_topic = args[5].clone();

    println!("**********************************************");
    println!("Executing runner with {} threads.", num_threads);
    println!("Job: {}", job);
    println!("Input Topic: {}", input_topic);
    println!("Group Id: {}", group_id);
    println!("Output Topic: {}", output_topic);
    println!("**********************************************");

    //Create contexts
    let contexts = initialize(job, num_threads);

    //Create runner
    let mut runner = Runner::new(
        input_topic,
        group_id,
        output_topic,
        num_threads,
        libmsa::thread::pool::QueuePolicy::RoundRobin,
        process_message,
        Some(contexts),
    );
    //Execute runner
    runner.execute().await;
}
