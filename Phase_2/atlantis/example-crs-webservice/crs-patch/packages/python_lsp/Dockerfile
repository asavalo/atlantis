ARG IMG_TAG
FROM ghcr.io/aixcc-finals/base-builder:${IMG_TAG}

# Download apt packages in .deb format
ENV PACKAGES="socat bear clangd-18"
RUN apt-get update
RUN mkdir -p /work/deb-pkgs && \
    apt-get -o Dir::Cache::archives="/work/deb-pkgs" \
    -o Debug::NoLocking=true \
    --download-only \
    --reinstall \
    install -y $PACKAGES
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Download Eclipse JDT Language Server
ENV ECLIPSE_JDT_LS_HOME=/work/eclipse-jdt-ls
RUN apt-get install -y curl tar
RUN mkdir -p $ECLIPSE_JDT_LS_HOME && \
    curl -L 'https://www.eclipse.org/downloads/download.php?file=/jdtls/milestones/1.34.0/jdt-language-server-1.34.0-202404031240.tar.gz' | tar -xz -C $ECLIPSE_JDT_LS_HOME

# Copy scripts
COPY scripts/prepare.sh /work/prepare.sh
COPY scripts/run.sh /work/run.sh

WORKDIR /work
ENTRYPOINT ["/bin/bash"]
