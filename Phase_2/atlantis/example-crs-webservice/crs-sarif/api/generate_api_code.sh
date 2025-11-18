# !/bin/bash

set -e

mkdir -p api/ssapi-server
mkdir -p api/vapi-client

pip install fastapi-code-generator

fastapi-codegen --input api/ssapi-swagger.yaml --output api/ssapi-server --output-model-type pydantic_v2.BaseModel

echo "copy and paste the ssapi-server to your crs-sarif project"

# docker run --rm -v $PWD:/local openapitools/openapi-generator-cli generate \
#           -i /local/api/ssapi-swagger.yaml \
#           -g  python-fastapi \
#           -o /local/api/ssapi-server

docker run --rm -v $PWD:/local openapitools/openapi-generator-cli generate \
          -i /local/api/vapi-swagger.yaml \
          -g  python \
          -o /local/api/vapi-client

GROUP=$(id -g)
USER=$(id -u)
sudo chown -R $USER:$GROUP api/vapi-client

echo "install the vapi-client with $ python api/vapi-client/setup.py install"
