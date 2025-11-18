ARG VERSION="latest"
FROM microservice-slim:$VERSION
LABEL name="controller"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

# Copy package
COPY ./microservices/controller /controller

# Install the package
RUN pip install --no-cache-dir /controller

WORKDIR /controller

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "controller"]
