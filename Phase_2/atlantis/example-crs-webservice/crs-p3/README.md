# CRS-P3 🚀

**CRS-P3** is a high-performance serving framework for Hugging Face language models with comprehensive observability support. Built on top of vLLM, it provides LoRA adapter training capabilities, OpenTelemetry integration, and enterprise-ready model serving infrastructure.

## ✨ Features

- **🔧 LoRA Adapter Training**: On-demand fine-tuning of language models using Parameter-Efficient Fine-Tuning (PEFT)
- **📊 OpenTelemetry Integration**: Full observability with custom middleware for request tracing and metrics
- **⚡ vLLM-Powered Serving**: High-throughput, low-latency model inference with tensor parallelism
- **🔄 Runtime LoRA Updates**: Dynamic adapter loading without server restarts
- **🐳 Containerized Deployment**: Docker-ready with optimized CUDA support
- **📈 Multi-GPU Support**: Efficient tensor and pipeline parallelism across multiple GPUs

## 🏗️ Architecture

The system consists of two main services managed by Supervisord:

1. **Model Server** (vLLM): Serves the base model with LoRA adapter support
2. **Adapter Service** (FastAPI): Handles LoRA training requests and adapter management

## 🛠️ Prerequisites

- **Python**: 3.12 or higher
- **CUDA**: 12.0 or higher
- **GPU Memory**: Minimum 16GB VRAM (recommended: 32GB+)
- **System Memory**: 32GB+ RAM recommended
- **Storage**: SSD with sufficient space for models and adapters

## 📦 Installation

### Using UV (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd p3

# Install dependencies
uv sync
```

### Using Docker

```bash
# Build the container
./docker-build.sh

# Push to registry (optional)
./docker-img-push.sh
```

## 🚀 Quick Start

### 1. Set Environment Variables

```bash
export HF_TOKEN="<your-huggingface_token>"
export MODEL="<your-model-id>"
export SERVER_PORT=8000
export ADAPTER_PORT=8001
```

### 2. Start the Services

```bash
uv run supervisord
```

The system will start both services:

- **Model Server**: Available at `http://localhost:8000`
- **Adapter Service**: Available at `http://localhost:8001`

### 3. Train a LoRA Adapter

```bash
curl -X POST "http://localhost:8001/adapt" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "my-adapter",
    "text": "Your training text here...",
    "learning_rate": 1e-8,
    "num_train_epochs": 64,
    "lora_rank": 16,
    "lora_alpha": 16
  }'
```

### 4. Load the Adapter

```bash
curl -X POST "http://localhost:8000/load_lora_adapter" \
  -H "Content-Type: application/json" \
  -d '{
    "lora_name": "my-adapter",
    "lora_path": "./adapters/my-adapter"
  }'
```

### 5. Use the Model with Adapter

```bash
curl -X POST "http://localhost:8000/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-foobar" \
  -d '{
    "model": "<your-lora-adapter-name>",
    "messages": [{"role": "user", "content": "Hello!"}],
  }'
```

### 6. Unload the Adapter

```bash
curl -X POST "http://localhost:8000/unload_lora_adapter" \
  -H "Content-Type: application/json" \
  -d '{
    "lora_name": "my-adapter"
  }'
```

## 📋 API Reference

### Adapter Training API

#### `POST /adapt`

Train a new LoRA adapter for the base model.

**Request Body:**

```json
{
  "id": "string",                    // Unique adapter identifier
  "text": "string",                  // Training text
  "block_size": 256,                // Token block size (optional)
  "learning_rate": 1e-8,            // Learning rate (optional)
  "per_device_train_batch_size": 8, // Batch size (optional)
  "num_train_epochs": 64,           // Training epochs (optional)
  "lora_rank": 16,                  // LoRA rank (optional)
  "lora_alpha": 16,                 // LoRA alpha (optional)
  "lora_dropout": 0.1               // LoRA dropout (optional)
}
```

**Response:**

```json
{
  "lora_path": "string"  // Path to the trained adapter
}
```

### Model Serving API

The model server provides OpenAI-compatible endpoints:

- `POST /v1/chat/completions` - Chat completions
- `POST /v1/completions` - Text completions
- `GET /v1/models` - List available models

#### LoRA Adapter Management

##### `POST /load_lora_adapter`

Load a trained LoRA adapter into the model server.

**Request Body:**

```json
{
  "lora_name": "string",  // Unique name for the adapter
  "lora_path": "string"   // File system path to the adapter
}
```

##### `POST /unload_lora_adapter`

Unload a LoRA adapter from the model server.

**Request Body:**

```json
{
  "lora_name": "string"  // Name of the adapter to unload
}
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `HF_TOKEN` | Hugging Face authentication token | - | ✅ |
| `MODEL` | Base model identifier | - | ✅ |
| `SERVER_PORT` | Model server port | 8000 | ❌ |
| `ADAPTER_PORT` | Adapter service port | 8001 | ❌ |
| `CUDA_VISIBLE_DEVICES` | GPU device assignment | "0,1,2,3" | ❌ |

### Training Parameters

| Parameter | Description | Default | Range |
|-----------|-------------|---------|-------|
| `block_size` | Token sequence length | 256 | 128-2048 |
| `learning_rate` | Optimizer learning rate | 1e-8 | 1e-9 to 1e-3 |
| `lora_rank` | LoRA decomposition rank | 16 | 1-64 |
| `lora_alpha` | LoRA scaling parameter | 16 | 1-128 |
| `num_train_epochs` | Training epochs | 64 | 1-100 |

## 📊 Monitoring & Observability

CRS-P3 includes comprehensive observability through OpenTelemetry:

### Metrics Collected

- **Request Duration**: `gen_ai.server.request.duration`
- **Token Usage**: `gen_ai.client.token.usage`
- **Time to First Token**: `gen_ai.server.time_to_first_token`
- **Time per Output Token**: `gen_ai.server.time_per_output_token`

### Trace Events

- User messages, system messages, assistant responses
- Model choices and generation parameters
- Error tracking and performance insights

### Configuration

Set these environment variables to enable telemetry export:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://your-collector:4317"
export OTEL_EXPORTER_OTLP_PROTOCOL="grpc"  # or "http/protobuf"
export OTEL_SERVICE_NAME="crs-p3"
```

## 📝 License

See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [vLLM](https://github.com/vllm-project/vllm) for high-performance inference
- [Hugging Face](https://huggingface.co/) for model ecosystem
- [PEFT](https://github.com/huggingface/peft) for parameter-efficient fine-tuning
- [OpenTelemetry](https://opentelemetry.io/) for observability standards
