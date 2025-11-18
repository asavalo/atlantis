### USAGE

0. Build SootUp: `cd crs/src/crs-cp-java/fuzzers/atl-jazzer-directed/third_party/SootUp && mvn install -DskipTests`

1. Build SinkFinder: `mvn package`

1. Run: `java -jar target/sink-finder-1.0-SNAPSHOT.jar <class_dir> <src_dir> <output_filepath>`

### NOTE

Below files were copied from atl-jazzer-directed, which was difficult to integrate now, so they will need to be integrated later.

```
crs/src/crs-cp-java/fuzzers/atl-jazzer-directed/src/main/java/com/code_intelligence/jazzer/driver/directed
->
crs/src/crs-cp-java/llm-poc-gen/sink_finder/src/main/java/sr/parser
```
