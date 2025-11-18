ARG VERSION="latest"

FROM openjdk:17-jdk-slim AS java17

FROM nixos/nix:2.28.3 AS nix-builder

WORKDIR /app
RUN nix-env -iA nixpkgs.docker
RUN nix-env -iA nixpkgs.glibc
RUN nix-env -iA nixpkgs.patchelf
RUN nix-env -iA nixpkgs.python3


COPY libs/userspace-code-browser/Cargo.toml /app/
COPY libs/userspace-code-browser/Cargo.lock /app/
COPY libs/userspace-code-browser/flake.nix /app/
COPY libs/userspace-code-browser/deny.toml /app/
COPY libs/userspace-code-browser/taplo.toml /app/
COPY libs/userspace-code-browser/build.rs /app/
COPY libs/userspace-code-browser/proto /app/proto
COPY libs/userspace-code-browser/src /app/src
COPY microservices/deepgen_service/patch.py /app/patch.py
RUN chmod +x /app/patch.py

ENV PATH="/root/.cargo/bin:${PATH}"
RUN nix develop --extra-experimental-features 'flakes nix-command' -c cargo install --path .
RUN /app/patch.py /root/.cargo/bin/code-browser-server

WORKDIR /app

# --------------------------
# Final image
# --------------------------
FROM microservice-base:$VERSION AS final
LABEL name="deepgen_service"
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=US \
    JAVA_HOME=/usr/local/openjdk-17 \
    JAVA_15_HOME=/usr/local/openjdk-15 \
    PATH="/usr/local/openjdk-17/bin:/usr/local/openjdk-15/bin:/root/.local/bin:/usr/local/bin:/deepgen_service:$PATH" \
    PYTHONUNBUFFERED=1

COPY --from=java17 /usr/local/openjdk-17 /usr/local/openjdk-17
COPY --from=nix-builder /app/out /deepgen_service/
COPY ./libs/userspace-code-browser/ /libs/userspace-code-browser/
COPY ./libs/claude-code-sdk-python/ /libs/claude-code-sdk-python/
COPY ./libs/libAgents /libs/libAgents
COPY ./libs/libDeepGen /libs/libDeepGen
COPY ./microservices/deepgen_service /deepgen_service

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        ripgrep \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@latest \
    && npm install -g @openai/codex \
    && npm install -g @anthropic-ai/claude-code \
    && cd /libs/libAgents \
    && /venv/bin/pip3 install --no-cache-dir \
      -r /deepgen_service/requirements.txt \
      /libs/claude-code-sdk-python \
      /libs/userspace-code-browser/python-client \
      "anyio[trio]>=4.0.0" \
      apscheduler>=3.11.0 \
      aider-chat>=0.80.2 \
      aiofiles>=24.1.0 \
      dotenv>=0.9.9 \
      filelock>=3.12.0 \
      google-genai>=1.9.0 \
      litellm>=1.65.1 \
      pocketflow>=0.0.2 \
      psutil>=5.9.0 \
      pydantic>=2.11.1 \
      pytest-asyncio>=0.26.0 \
      tree-sitter==0.24.0 \
      tree-sitter-cpp==0.23.4 \
  && /venv/bin/pip3 install --no-deps . \
  && cd /libs/libDeepGen \
  && /venv/bin/pip3 install --no-cache-dir \
      atomics>=1.0.3 \
      protobuf>=5.29.0 \
      psutil>=7.0.0 \
      zmq>=pyzmq>=26.4.0 \
  && /venv/bin/pip3 install --no-cache-dir \
      git+https://github.com/renatahodovan/grammarinator.git@68b0350 \
  && /venv/bin/pip3 install --no-deps . \
  && cd /deepgen_service \
  && /venv/bin/pip3 install --no-cache-dir .

WORKDIR /deepgen_service

CMD ["/venv/bin/python3", "-m", "deepgen_service"]