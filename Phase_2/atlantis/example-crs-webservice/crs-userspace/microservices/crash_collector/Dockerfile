FROM microservice-slim:latest
COPY ./microservices/crash_collector /crash_collector
WORKDIR /crash_collector
RUN pip install --no-cache-dir .
CMD ["./run.sh"]