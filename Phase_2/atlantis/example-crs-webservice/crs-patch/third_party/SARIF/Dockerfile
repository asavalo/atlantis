#################################################################################
## Build CRS deps
#################################################################################

FROM ghcr.io/aixcc-finals/base-runner:v1.1.0 AS crs-sarif-builder

RUN apt-get update && \
    apt-get install -y openjdk-21-jdk libssl1.1 curl cargo && \
    apt-get install -y zlib1g-dev && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get install -y python3.12 python3.12-dev python3.12-venv && \
    python3.12 -m ensurepip --upgrade && \
    python3.12 -m pip install virtualenv && \
    apt-get clean

## Maven
ENV MAVEN_INSTALL_DIR=/opt/maven

ENV PATH=$PATH:$MAVEN_INSTALL_DIR/bin
RUN cd /tmp && \
    echo "Installing maven" && \
    curl -L -O https://dlcdn.apache.org/maven/maven-3/3.9.7/binaries/apache-maven-3.9.7-bin.tar.gz && \
    tar xzvf apache-maven-3.9.7-bin.tar.gz && \
    mv apache-maven-3.9.7 $MAVEN_INSTALL_DIR && \
    rm -f apache-maven-3.9.7-bin.tar.gz

## Poetry
ENV PATH="/root/.local/bin:${PATH}"
RUN curl -sSL https://install.python-poetry.org | python3 - --version 1.8.5

## CodeQL
ENV CODEQL_INSTALL_DIR=/opt/codeql
ENV CODEQL_VERSION=v2.20.4

RUN cd /tmp && \
    wget https://github.com/github/codeql-cli-binaries/releases/download/$CODEQL_VERSION/codeql-linux64.zip --no-check-certificate && \
    unzip codeql-linux64.zip && \
    mv codeql $CODEQL_INSTALL_DIR

RUN ln -s $CODEQL_INSTALL_DIR/codeql /usr/local/bin/codeql

# Install CodeQL Pack
RUN codeql pack download codeql/java-queries:codeql-java && \
    codeql pack download codeql/cpp-queries:codeql-cpp && \
    codeql resolve qlpacks

## Joern
ENV SBT_DIR=/opt/sbt
ENV POC_GEN_DIR=/app/llm-poc-gen
ENV JOERN_DIR=/opt/joern
COPY joern $JOERN_DIR

RUN cd /tmp && \
    wget https://github.com/sbt/sbt/releases/download/v1.8.0/sbt-1.8.0.zip --no-check-certificate && \
    unzip sbt-1.8.0.zip -d $SBT_DIR && \
    cd $JOERN_DIR && \
    SBT_OPTS="-Xmx12G -XX:+UseG1GC -Dsbt.ci=true" $SBT_DIR/sbt/bin/sbt -DskipTests=true clean update stage

RUN cd $JOERN_DIR/joern-cli && \
    rm -rf frontends/csharpsrc2cpg \
        frontends/ghidra2cpg frontends/gosrc2cpg \
        frontends/jimple2cpg frontends/jssrc2cpg \
        frontends/kotlin2cpg frontends/php2cpg \
        frontends/pysrc2cpg frontends/rubysrc2cpg \
        frontends/swiftsrc2cpg frontends/x2cpg

## Custom packages
WORKDIR /app

## Corpus hash engine
ENV CORPUS_HASH_ENGINE_HOME=/app/corpus_hash_engine
ENV CORPUS_HASH_ENGINE_PATH=$CORPUS_HASH_ENGINE_HOME/target/release/libafl_hash
COPY corpus_hash $CORPUS_HASH_ENGINE_HOME

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    cd $CORPUS_HASH_ENGINE_HOME && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    rustup install nightly && \
    rustup run nightly cargo build --release

RUN chmod +x $CORPUS_HASH_ENGINE_PATH

## Build Sootup reachability analyzer
COPY sootup /opt/sootup
RUN cd /opt/sootup/deps/SootUp && \
    mvn install -DskipTests
RUN cd /opt/sootup && \
    mvn package

## SARIF package
COPY sarif /app/sarif
COPY api/vapi-client/ /app/api/vapi-client
COPY libCRS /app/libCRS
COPY crs_sarif /app/crs_sarif
COPY libFDP /app/libFDP
COPY llm-poc-gen /app/llm-poc-gen

RUN cp /opt/sootup/target/sootup-reachability.jar /app/sarif/static

## Install CodeQL Pack
RUN cd /app/sarif/sarif/tools/codeql/ql/c && \
    codeql pack install

RUN cd /app/sarif/sarif/tools/codeql/ql/java && \
    codeql pack install


## llm-poc-gen python deps
COPY llm-poc-gen/requirements.txt /tmp
RUN cd /tmp && \
    pip3.12 install setuptools && \
    pip3.12 install -r requirements.txt

## Sarif python deps
COPY pyproject.toml poetry.lock ./
RUN poetry export --without-hashes -f requirements.txt -o requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip python3.10 -m pip install -r requirements.txt

#################################################################################
## CRS setup
#################################################################################

FROM ghcr.io/aixcc-finals/base-runner:v1.1.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y openjdk-21-jdk libssl1.1 curl cargo && \
    apt-get install -y zlib1g-dev && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get install -y python3.12 python3.12-dev python3.12-venv && \
    python3.12 -m ensurepip --upgrade && \
    python3.12 -m pip install virtualenv && \
    apt-get clean

## Git config
RUN git config --global user.email "atlanta@team.com"
RUN git config --global user.name "Team Atlanta"

# GDB
RUN apt install -y wget build-essential libmpfr-dev python3-dev python3-pip && \
    wget https://sourceware.org/pub/gdb/releases/gdb-16.2.tar.gz && \
    tar -xvf gdb-16.2.tar.gz && \
    cd gdb-16.2 && \
    ln -s /usr/bin/python3 python && \
    ./configure --with-python=$(pwd) && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf gdb-16.2 gdb-16.2.tar.gz

## Copy pre-built CodeQL
ENV CODEQL_INSTALL_DIR=/opt/codeql

COPY --from=crs-sarif-builder /opt/codeql $CODEQL_INSTALL_DIR
COPY --from=crs-sarif-builder /root/.codeql /root/.codeql

RUN ln -s $CODEQL_INSTALL_DIR/codeql /usr/local/bin/codeql

## Copy pre-built Joern
ENV SBT_DIR=/opt/sbt
ENV POC_GEN_DIR=/app/llm-poc-gen
ENV JOERN_DIR=/opt/joern

COPY --from=crs-sarif-builder /opt/joern $JOERN_DIR

ENV PATH=$PATH:$JOERN_DIR/joern-cli

## Install CRS-SARIF
WORKDIR /app

# Copy libafl_hash
ENV CORPUS_HASH_ENGINE_HOME=/app/corpus_hash_engine
ENV CORPUS_HASH_ENGINE_PATH=$CORPUS_HASH_ENGINE_HOME/target/release/libafl_hash

COPY --from=crs-sarif-builder $CORPUS_HASH_ENGINE_PATH $CORPUS_HASH_ENGINE_PATH

RUN chmod +x $CORPUS_HASH_ENGINE_PATH

# Copy SARIF package
COPY --from=crs-sarif-builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages
COPY --from=crs-sarif-builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=crs-sarif-builder /app/libCRS /app/libCRS
COPY --from=crs-sarif-builder /app/libFDP /app/libFDP
COPY --from=crs-sarif-builder /app/api /app/api
COPY --from=crs-sarif-builder /app/llm-poc-gen /app/llm-poc-gen
COPY --from=crs-sarif-builder /app/sarif /app/sarif
COPY --from=crs-sarif-builder /app/crs_sarif /app/crs_sarif

EXPOSE 80

CMD ["python3.10", "-m", "uvicorn", "crs_sarif.main:app", "--host", "0.0.0.0", "--port", "80", "--log-level", "info"]