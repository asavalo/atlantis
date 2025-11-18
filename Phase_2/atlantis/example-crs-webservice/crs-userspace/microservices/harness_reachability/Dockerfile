ARG VERSION="latest"
FROM microservice-slim:$VERSION
LABEL name="harness_reachability"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

# Copy libsarif
RUN mkdir -p /libs
COPY ./libs/libSarif /libs/libSarif
RUN pip install --no-cache-dir /libs/libSarif

# Copy package
COPY ./microservices/harness_reachability /harness_reachability
RUN pip install --no-cache-dir /harness_reachability

WORKDIR /harness_reachability

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "harness_reachability"]
