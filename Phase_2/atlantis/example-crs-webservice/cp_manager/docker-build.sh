#!/bin/bash
BASEDIR=$(dirname $0)
docker build -f $BASEDIR/Dockerfile -t cp_manager $BASEDIR/../