FROM python:3.12-slim AS builder
ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/venv/bin:$PATH"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential python3-dev wget unzip protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

# create venv, install tooling, build everything
RUN python3 -m venv /venv \
 && /venv/bin/pip install --upgrade pip setuptools mypy-protobuf==3.6.0
COPY ./libs /libs
RUN /libs/libatlantis/build.sh \
 && /venv/bin/pip install --no-cache-dir /libs/libCRS /libs/libMSA/python hatch /libs/libatlantis

#–– final ––
FROM python:3.12-slim
ENV PATH="/venv/bin:$PATH" TZ=US DEBIAN_FRONTEND=noninteractive
# copy only the ready-to-go venv
COPY --from=builder /venv /venv

# install only tiny runtime deps (no compilers, no headers)
RUN apt-get update \
 && apt-get install -y --no-install-recommends rsync \
 && rm -rf /var/lib/apt/lists/*