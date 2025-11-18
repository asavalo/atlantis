ARG VERSION="latest"
FROM microservice-slim:$VERSION
LABEL name="telemetry_logger"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

# Copy package
COPY ./microservices/telemetry_logger /telemetry_logger

# Install the package
RUN pip install --no-cache-dir /telemetry_logger

WORKDIR /telemetry_logger

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "telemetry_logger"]
