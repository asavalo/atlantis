# Bullseye

Bullseye is a directed fuzzing tool that uses the LLVM compiler infrastructure to generate test cases that target specific lines of code in a program.

## Usage
Build the docker image:
```bash
docker build -t bullseye:latest .
```

Run the fuzzer on an LLVM BC file with a given target location (absolute paths, as of now).
There is an example BC in the `examples_workdir` folder.
The target location is a line in the decompile.c file of the libming project, which is used as an example.
The target location is passed as an environment variable `BULLSEYE_TARGET` to the docker container.

```bash
docker run -v $(pwd)/example_workdir:/atlantis/workdir --rm -it \
    -e BULLSEYE_TARGET=/home/fabiano/src/directed-fuzzing/bullseye-experiments/programs/libming/target-1/build-llvm-11/util/decompile.c:3202 \
    -e BULLSEYE_BC_PATH=/atlantis/workdir/swftophp.bc \
    bullseye:latest
```

## Debug
To debug, you can get a shell in the container, set the environment variables, and launch the run script (`/atlantis/run.sh`):
```bash
docker run -v $(pwd)/example_workdir:/atlantis/workdir --rm -it \
    bullseye:latest /bin/bash
```

Then, inside the container:
```bash
export BULLSEYE_TARGET=/home/fabiano/src/directed-fuzzing/bullseye-experiments/programs/libming/target-1/build-llvm-11/util/decompile.c:3202
export BULLSEYE_BC_PATH=/atlantis/workdir/swftophp.bc
/atlantis/run.sh
```

## Credit
Mansour Alharthi

# CRS-Userspace Integration

## Wllvm and LLVM-18 inside CP Build Environment

The first step is downloading a compatible version wllvm and llvm-18.
This is done with `microservices/directed_fuzzing/archive_llvm.py` being used in
`bootstrap/Dockerfile`.
The wllvm venv and apt depedencies are copied to a shared `/artifacts` directory
that is mounted to other containers.

## Extracting bitcode and link flags

In `microservices/harness_builder/builder_impl.py:build`,
we run the `microservices/directed_fuzzing/custom_compile.sh` script
_inside_ the CP build container.
This is the step where wllvm is actually run.
Another round of compiling is done with `CC=extract_linker_flags.py`
to write the collected flags to `linker_flags.txt`

Extracting libraries (i.e. `.so`) is yet to be implemented.

My debugging loop is as follows
```
# enter harness_builder docker container
docker exec -it <HARNESS_BUILDER_ID> bash

# for debugging, copy oss_fuzz to a writable location
cp -r /oss_fuzz /crs_scratch/oss_fuzz

# create CP builder image if doesn't exist. Project name example: aixcc/c/libxml2
cd /crs_scratch/oss_fuzz
python3 infra/helper.py build_image <PROJECT_NAME>

# enter CP builder container. 
# you should be able to see a log from the CRS starting with "Ran command", use that docker run command
/usr/local/bin/docker run --rm ...

# try to compile, or do whatever
/work/directed_build_deps/custom_compile.sh
```

## Directed Fuzzing Service

This directory has the service implemented in the following files:
- `context.py`: real logic implemented in context classes
- `__init__.py`: receiving messages
- `__main__.py`: entrypoint

We need the DirectedFuzzerRunRequest and DirectedFuzzerStopRequest implemented.
Please refer to `context.py` for actionable items in TODO annotations.
