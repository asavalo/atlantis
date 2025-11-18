ARG VERSION="latest"
FROM microservice-slim:$VERSION
LABEL name="c_llm"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

# NOTE Could not find lldb in pypi so using system package and inserting into venv
# NOTE pre-release depended on miniconda, but uncertain about TOS update
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    build-essential \
    rsync \
    lldb-19 \
    python3-lldb-19 \
    && rm -rf /var/lib/apt/lists/*

RUN echo '/usr/lib/python3/dist-packages' > /venv/lib/python3.12/site-packages/system-packages.pth
RUN echo "$(lldb-19 -P)" > /venv/lib/python3.12/site-packages/system-packages.pth
RUN ln -s /usr/lib/python3/dist-packages/lldb/_lldb.so \
    /usr/lib/llvm-19/lib/python3.11/site-packages/lldb/_lldb.so

# Copy package
COPY ./microservices/c_llm /c_llm

# Install the package
RUN pip3 install --no-cache-dir /c_llm

WORKDIR /c_llm

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "c_llm"]