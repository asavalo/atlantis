# Fuzzers used by Atlantis CRS


- [Directed Fuzzer based on AFL (legacy AFL, not afl++)](./directed_fuzzing/Bullseye)


# An example to instrument libpng

Does not work due to `.cc` harness

```
docker rm -f mylibpng_container && docker build -t mylibpng . && docker run -it --name mylibpng_container mylibpng
```
