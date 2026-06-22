DOCKER_IMAGE_OWNER = 'free5gc'
DOCKER_IMAGE_NAME = 'base'
DOCKER_IMAGE_TAG = 'latest'

.PHONY: base
nfs: base upf nrf amf ausf nssf pcf smf udm udr chf nef webconsole

base:
	docker build -t ${DOCKER_IMAGE_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} ./dockerfiles/base
	docker image ls ${DOCKER_IMAGE_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}

smf: base
	docker build --build-arg F5GC_MODULE=smf -t ${DOCKER_IMAGE_OWNER}/smf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
amf: base
	docker build --build-arg F5GC_MODULE=amf -t ${DOCKER_IMAGE_OWNER}/amf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
upf: base
	docker build --build-arg F5GC_MODULE=upf -t ${DOCKER_IMAGE_OWNER}/upf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
udr: base
	docker build --build-arg F5GC_MODULE=udr -t ${DOCKER_IMAGE_OWNER}/udr-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
udm: base
	docker build --build-arg F5GC_MODULE=udm -t ${DOCKER_IMAGE_OWNER}/udm-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
nrf: base
	docker build --build-arg F5GC_MODULE=nrf -t ${DOCKER_IMAGE_OWNER}/nrf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
nssf: base
	docker build --build-arg F5GC_MODULE=nssf -t ${DOCKER_IMAGE_OWNER}/nssf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
pcf: base
	docker build --build-arg F5GC_MODULE=pcf -t ${DOCKER_IMAGE_OWNER}/pcf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
ausf: base
	docker build --build-arg F5GC_MODULE=ausf -t ${DOCKER_IMAGE_OWNER}/ausf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
chf: base
	docker build --build-arg F5GC_MODULE=chf -t ${DOCKER_IMAGE_OWNER}/chf-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .
nef: base
	docker build --build-arg F5GC_MODULE=nef -t ${DOCKER_IMAGE_OWNER}/nef-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf .

webconsole: base
	docker build -t ${DOCKER_IMAGE_OWNER}/webconsole-base:${DOCKER_IMAGE_TAG} -f ./dockerfiles/base/Dockerfile.nf.webconsole .