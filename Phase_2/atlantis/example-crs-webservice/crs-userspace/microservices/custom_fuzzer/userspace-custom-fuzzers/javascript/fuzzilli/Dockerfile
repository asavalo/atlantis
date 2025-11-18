FROM swift:6.1.2-jammy

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y git python3 python3-pip python3-virtualenv libpcre2-dev \
    build-essential cmake ninja-build 

#RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 100
#RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100

COPY . /root/fuzzilli

WORKDIR /root/fuzzilli
RUN swift test && swift build -c release
RUN cp .build/release/FuzzilliCli ./Fuzzilli
RUN cp .build/release/REPRLRun ./REPRLRun