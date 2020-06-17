#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-tiajians/tiajiansd-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/tiajiansd docker/bin/
cp $BUILD_DIR/src/tiajians-cli docker/bin/
cp $BUILD_DIR/src/tiajians-tx docker/bin/
strip docker/bin/tiajiansd
strip docker/bin/tiajians-cli
strip docker/bin/tiajians-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
