# Custom Fuzzers used by Userspace

## Metadata

Metadata is organized in a few yaml files.
`fuzzers.yaml`:
```
directory_name (target_type):
  targets:
    - target_project_1
    - target_project_2
  fuzzers:
    - fuzzer_1
    - fuzzer_2
```

Within each directory,
`config.yaml`:
```
fuzzer_name:
  targets:
    - target_project_1
    - target_project_2
  src_path: <path to copy src into>
  oss_fuzz_path: <path to oss-fuzz>
  build_path: <path to build artifacts from oss-fuzz>
  corpus_path: <path where corpus will accumulate>
  crashes_path: <path where crashes will accumulate>
  env_vars: <env_vars that are supported>
    - "ENV_VAR_1"
    - "ENV_VAR_2"
  build_cmd: <cmd to setup fuzzer>
  fuzz_cmd: <cmd to run fuzzer>
  type: <type of integration (custom, aflplusplus, lpm)>
```
Currently, the env_vars that can be passed are `CORES, CP_NAME, TARGET_NAME`.

## Export Tarball Format

The tarball for the custom fuzzers is structured as
`custom_fuzzers.tar.zst`:
```
├── directory_1
│   ├── config.yaml
│   ├── fuzzer_1_image.tar
│   └── fuzzer_2_image.tar
├── directory_2
│   ├── config.yaml
│   ├── fuzzer_1_image.tar
│   └── fuzzer_2_image.tar
└── fuzzers.yaml
```

## How to Run

To run a custom fuzzer, clone the src of the target directly into `scratch/src` and run `./run.py --fuzzer <fuzzer_name>`

# Reference

The custom fuzzers are from the following projects.
Some of them were slightly modified to fit our purpose.
All of the original licenses are included.
- [sqlancer](https://github.com/sqlancer/sqlancer)
- [squirrel](https://github.com/s3team/Squirrel)
- [grammarinator](https://github.com/renatahodovan/grammarinator)
- [fuzzilli](https://github.com/googleprojectzero/fuzzilli)
- [flowfusion](https://github.com/php/flowfusion)
- [wasm-tools](https://github.com/bytecodealliance/wasm-tools)
- [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator)
  - from oss-fuzz: jsoncpp


# License

All the projects used are under either MIT or Apache 2.0.
