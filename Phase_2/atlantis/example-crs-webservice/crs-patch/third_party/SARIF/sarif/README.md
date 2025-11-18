## Install
```sh
poetry install

# Make .env and fill contents
cp .env_example .env

# Optionally to use sarif validator
bash ./scripts/install_sarif_multitools.sh
```

- Check if CodeQL is installed on your host. [ref](./docs/codeql.md)

## Usage

### Activate
```sh
$ poetry shell

# Generate sarif report
$ python ./scripts/generator.py

# Validate sarif report
$ python ./scripts/validator.py

# Run codeql analysis for all benchmarks
$ ./scripts/run_codeql_analysis.sh
```

### Create harness call-graph
```sh
pushd <SARIF>/sarif
poetry run python ./scripts/svf.py mock-c c /home/user/work/oss-fuzz/projects/aixcc/c/mock-c/.aixcc/config.yaml run-svf-in-docker --mode ander | tee /home/user/out/mock-c/SVF/svf_run.log
popd
```

#### SootUp
```sh
cp -r ../sootup .
BUILD_DIR=/home/user/work/oss-fuzz/build/out OUT_DIR=/home/user/work/oss-fuzz/build/out/aixcc/jvm SRC_DIR=/home/user/work/oss-fuzz/build/out OSS_FUZZ_DIR=/home/user/work/oss-fuzz python ./scripts/sootup.py mock-java java /home/user/work/oss-fuzz/projects/aixcc/jvm/mock-java/.aixcc/config.yaml run-sootup-in-docker --mode cha | tee /home/user/out/mock-java/SootUp/svf_run.log

/usr/lib/jvm/java-17-openjdk-amd64/bin/java -jar /opt/sootup/target/sootup-reachability.jar get-all-reachable-methods --output-dir /out/Sootup --dump-callgraph /out/jars
```

#### CodeQL
- Build database
```sh
BUILD_DIR=/home/user/work/oss-fuzz/build/out OUT_DIR=/home/user/work/oss-fuzz/build/out/aixcc/jvm SRC_DIR=/home/user/work/oss-fuzz/build/out OSS_FUZZ_DIR=/home/user/work/oss-fuzz python ./scripts/codeql.py imaging java /home/user/work/oss-fuzz/projects/aixcc/jvm/imaging/.aixcc/config.yaml build-codeql-database
```

```sh
pushd <SARIF>/sarif
poetry run python ./scripts/validator.py mock-c c /home/user/work/oss-fuzz/projects/aixcc/c/mock-c/.aixcc/config.yaml run-reachability-analysis --tool svf --mode ander ../sarif/data/c/out/sarif/mock-c_cpv-0.sarif
popd
```
```sh
BUILD_DIR=/home/user/work/oss-fuzz/build/out/codeql-db OUT_DIR=/home/user/work/oss-fuzz/build/out/aixcc/jvm SRC_DIR=/home/user/work/oss-fuzz/build/out OSS_FUZZ_DIR=/home/user/work/oss-fuzz python ./scripts/validator.py imaging java /home/user/work/oss-fuzz/projects/aixcc/jvm/imaging/.aixcc/config.yaml run-reachability-analysis --tool codeql --mode callgraph ../sarif/data/java/out/sarif/imaging_ImagingOneCPVOne.sarif
```

### Generator
- [docs](./docs/generator.md)

### Validator
- [docs](./docs/validator.md)

### Reachability Analysis
- [docs](./docs/reachability_analysis.md)


## Recommendation

- Install VSCode [SARIF extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) for debugging.
