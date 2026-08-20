DOCKER_IMAGE_OWNER = 'free5gc'
DOCKER_IMAGE_NAME = 'base'
DOCKER_IMAGE_TAG = 'latest'

.PHONY: base all-base nfs
nfs: all-base

base:
	docker build -t ${DOCKER_IMAGE_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} ./dockerfiles/base
	docker image ls ${DOCKER_IMAGE_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}

# Builds every NF binary plus the webconsole binary + frontend in a single
# image, so all their Go module downloads/compiles share one cache instead of
# each NF re-downloading the same overlapping dependencies from scratch.
all-base: base
	docker build -t ${DOCKER_IMAGE_OWNER}/all-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.all .
	docker image ls ${DOCKER_IMAGE_OWNER}/all-base:${DOCKER_IMAGE_TAG}
