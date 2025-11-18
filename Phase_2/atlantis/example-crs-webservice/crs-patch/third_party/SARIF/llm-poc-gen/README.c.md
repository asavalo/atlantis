# llm-poc-gen-C Guide

1. Rebuild joern
```bash
$ cd crs/joern/Joern; \
    git pull; \
    git checkout main; \
    SBT_OPTS="-Xmx12G" sbt clean update stage;
```

2. Build cpg
```bash
$ cd crs/llm-poc-gen/cp_full_src; \
    ./build_cpg.sh;

```
use cpg built under cp_full_src/cpg/.


## Example to Run in Local

At the first run, ` ./dev.sh build-cp cps $CP ` must be done.

```
$ poetry run python3 -m vuli.main \
    --jazzer=... \
    --joern_dir=... \
    --sarif=sarif/c/simple-switch_sarif.json \
    --cp_meta=metadata/c/simple-switch.json \
    --output=... \
    --model_cache=... \
    --dev
```