# List of Atlantis CRS Modules

- **[crs_webserver](./crs_webserver/)** - CRS API webservice implementing AFC procedures for receiving tasks from Competition Framework
- **[cp_manager](./cp_manager/)** - Challenge Project manager for building and managing docker containers
- **[crs-java](./crs-java/)** - Sinkpoint-centered Java vulnerability detection framework with ensemble fuzzing
- **[crs-multilang](./crs-multilang/)** - Multi-language vulnerability detection system with LLM integration
- **[crs-p3](./crs-p3/)** - High-performance serving framework for Hugging Face models with LoRA adapter training
- **[crs-patch](./crs-patch/)** - Crete patch generation system with LLM tracing support
- **[crs-sarif](./crs-sarif/)** - SARIF-based vulnerability analysis including generation, validation, and reachability analysis
- **[crs-userspace](./crs-userspace/)** - Microservice-based CRS for C/C++ with Kafka workflow
- **[litellm](./litellm/)** - LLM Gateway for calling all LLM APIs using OpenAI format


# How to build
```
./build.py build --target crs_webserver
```

Build & Push
```
./build-all.py build --target crs_webserver --push <docker registry base> --version <version>
```


Build All & Push
```
./build-all.py build --push <docker registry base> <version>
```