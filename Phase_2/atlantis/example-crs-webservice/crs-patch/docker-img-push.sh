#!/bin/bash

docker_img_push() {
    IMAGE_NAME=$1

    REGISTRY=$2
    IMAGE_VERSION=$3

    docker tag $IMAGE_NAME $REGISTRY/$IMAGE_NAME:$IMAGE_VERSION
    docker push $REGISTRY/$IMAGE_NAME:$IMAGE_VERSION
}

main() {
    REGISTRY=$1
    IMAGE_VERSION=$2
    docker_img_push "crs-patch-main" $REGISTRY $IMAGE_VERSION
    docker_img_push "crs-patch-sub" $REGISTRY $IMAGE_VERSION
    docker_img_push "crete-lsp" $REGISTRY $IMAGE_VERSION
    # dockerimgpush "rr-backtracer" $REGISTRY $IMAGE_VERSION
}

main "$@"
