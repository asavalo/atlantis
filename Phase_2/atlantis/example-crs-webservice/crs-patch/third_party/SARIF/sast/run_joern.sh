#!/bin/bash -x

# Build cpg
if [ $LANGUAGE == "java" ]; then
    javasrc2cpg /src --exclude=/src/aflplusplus --exclude=/src/fuzztest --exclude=/src/honggfuzz --exclude=/src/libfuzzer --output=cpg.bin --output=$OUT/joern
elif [ $LANGUAGE == "c" ] || [ $LANGUAGE == "cpp" ]; then
    c2cpg.sh /src --exclude=/src/aflplusplus --exclude=/src/fuzztest --exclude=/src/honggfuzz --exclude=/src/libfuzzer --output=cpg.bin --output=$OUT/joern
else
    echo "Unsupported language: $LANGUAGE"
    exit 1
fi

# Run joern-scan
joern-scan --cpg $OUT/joern/cpg.bin --output $OUT/joern/joern-scan.json