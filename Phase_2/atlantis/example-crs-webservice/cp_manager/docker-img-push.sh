#!/bin/bash
docker image tag cp_manager $1/cp_manager:$2
docker image push $1/cp_manager:$2
