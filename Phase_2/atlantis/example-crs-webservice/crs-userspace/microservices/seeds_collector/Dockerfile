ARG VERSION="latest"
FROM microservice-slim:$VERSION
LABEL name="seeds_collector"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

COPY ./microservices/seeds_collector /seeds_collector
RUN pip install --no-cache-dir /seeds_collector

WORKDIR /seeds_collector

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "seeds_collector"]