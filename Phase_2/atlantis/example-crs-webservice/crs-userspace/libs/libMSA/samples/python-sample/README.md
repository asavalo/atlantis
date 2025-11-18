# MSA Python Program Setup

This guide outlines the steps to create a Microservices Architecture (MSA) program in Python.

---

## 1. Install `libmsa`

Ensure the `libmsa` library is installed. You can run the following command in python libmsa directory.
```
pip install .
```
---

## 2. Compile Protobuf Files
1. Create a `proto` directory inside your project.
2. Add `.proto` files to the `proto` directory.
3. Compile each proto file
```
protoc --python_out=. --mypy_out=. message_two.proto
```
---

## 3. Include Generated Protobuf Files

Include the generated Protobuf modules in your `run.py`:
```
from proto.message_two_pb2 import MessageTwo
```
---

## 4. Divide Program into Two Phases

### Initialization Phase

- Parse command-line arguments.
- Create contexts for each thread (can be `None` or shared).
```
@dataclass
class JobContext:
    job: str


def create_contexts(job: str, num_threads: int):
    return [JobContext(job=f"{job}_{thread_id}") for thread_id in range(num_threads)]
```
### Logic Phase

- Process input messages received via Kafka.
- This function will be executed everytime message is received via kafka
- Function take input protobuf message and returns output protobuf message
- Context can be provided
- Thread ID exists for debugging
```
def process_message(input_message, thread_id, context):
    input_name = input_message.name
    job = context.job

    new_name = f"{input_name}&{job}"
    indicator = thread_id == input_message.value

    return MessageThree(name=new_name, value=thread_id, indicator=indicator)
```
---

## 5. Combine Initialization and Logic in `main`

1. Call the `initialize` function to create thread contexts.
2. Pass the message processing function (`process_message`) and contexts to the runner.

---
