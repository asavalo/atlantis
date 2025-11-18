#!/bin/bash

docker ps -a --filter "name=crs-patch" --format "{{.ID}}" | xargs -r docker rm -f