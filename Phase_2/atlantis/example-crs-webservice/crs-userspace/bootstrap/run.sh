#!/bin/bash


if [[ -z "$KAFKA_SERVER_ADDR" ]]; then
  echo "Error: KAFKA_SERVER_ADDR environment variable is not set!"
  exit 1
fi

KAFKA_HOST=$(echo "$KAFKA_SERVER_ADDR" | cut -d':' -f1)
KAFKA_PORT=$(echo "$KAFKA_SERVER_ADDR" | cut -d':' -f2)

MAX_RETRIES=300
RETRY_INTERVAL=1

echo "Waiting for Kafka broker at $KAFKA_HOST:$KAFKA_PORT to accept connections..."

for ((i=1;i<=MAX_RETRIES;i++)); do
  if (echo > /dev/tcp/$KAFKA_HOST/$KAFKA_PORT) >/dev/null 2>&1; then
    echo "Kafka broker is accepting TCP connections (after $i attempt(s))!"
    break
  else
    echo "Kafka not ready yet (attempt $i/$MAX_RETRIES)... retrying in $RETRY_INTERVAL seconds"
    sleep $RETRY_INTERVAL
  fi
done

source /venv/bin/activate
export PYTHONUNBUFFERED=1
python3 -m run

status=$?

if [ $status -ne 0 ]; then
  exit $status
else
  echo "[Bootstrap] Complete and sleeping..."
  sleep infinity
fi
