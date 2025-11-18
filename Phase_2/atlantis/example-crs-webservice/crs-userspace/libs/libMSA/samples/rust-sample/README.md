# MSA Rust Program Setup

This guide outlines the steps to create a Microservices Architecture (MSA) program in Rust.

---

## 1. Import `libmsa`

Ensure the `libmsa` library is accessible in your project. (In this case libmsa is under project) Add the following entry to your `Cargo.toml`:
```
[dependencies]
libmsa = { path = "./libmsa" }
```
---

## 2. Set Up Protobuf Support

1. Create a `proto` directory inside your project.
2. Add `.proto` files to the `proto` directory.
3. Update `Cargo.toml`:
```
[dependencies]
prost = "0.13"

[build-dependencies]
prost-build = "0.13"
```
---

## 3. Compile Protobuf Files

Create a `build.rs` file in the root of your project to compile `.proto` files:
```
use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &["proto/message_one.proto", "proto/message_two.proto"],
        &["proto/"],
    )
    .unwrap();
    Ok(())
}
```
---

## 4. Include Generated Protobuf Files

Include the generated Protobuf modules in your `main.rs`:
```
pub mod userspace {
    include!(concat!(env!("OUT_DIR"), "/userspace.rs"));
}
```
---

## 5. Divide Program into Two Phases

### Initialization Phase

- Parse command-line arguments.
- Create contexts for each thread (can be `None` or shared).
```
fn initialize(job: String, num_threads: usize) -> Vec<Arc<Mutex<JobContext>>>
```
### Logic Phase

- Process input messages received via Kafka.
- This function will be executed everytime message is received via kafka
- Function take input protobuf message and returns output protobuf message
- Context can be provided
- Thread ID exists for debugging
```
fn process_message(
    input_message: userspace::MessageOne,
    thread_id: usize,
    context: Option<Arc<Mutex<JobContext>>>,
) -> Option<userspace::MessageTwo>
```
---

## 6. Add Tokio Dependency

Add Tokio for asynchronous runtime support by updating `Cargo.toml`:
```
[dependencies]
tokio = { version = "1.0", features = ["full"] }
```
---

## 7. Set Up the Main Function

Use the Tokio runtime for asynchronous operations. Define the `main` function as follows:
```
#[tokio::main(flavor = "multi_thread")]
async fn main()
```
---

## 8. Combine Initialization and Logic in `main`

1. Call the `initialize` function to create thread contexts.
2. Pass the message processing function (`process_message`) and contexts to the runner.

---