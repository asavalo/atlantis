ARG VERSION="latest"
FROM microservice-base:$VERSION
LABEL name="osv_analyzer"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

# Copy large_data
RUN mkdir -p /data
COPY ./large_data/osv_analyzer /data

# COPY --from=java17 /usr/local/openjdk-17 /usr/local/openjdk-17
COPY ./libs/userspace-code-browser/ /libs/userspace-code-browser/
COPY ./libs/claude-code-sdk-python/ /libs/claude-code-sdk-python/
COPY ./libs/libAgents /libs/libAgents
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
  && /venv/bin/pip3 install --no-deps .

# Copy package 
COPY ./microservices/osv_analyzer /osv_analyzer

# Install the package
RUN pip install --no-cache-dir /osv_analyzer

WORKDIR /osv_analyzer

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "osv_analyzer"]
