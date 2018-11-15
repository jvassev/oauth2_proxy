IMAGE               ?= csp-rc-docker-local.artifactory.eng.vmware.com/dev-platform/oauth2-proxy
PUBLIC_IMAGE        ?= vmware-docker-vdp.bintray.io/dev-platform/oauth2-proxy


TAG ?= latest

build:
	go build -v .

build-image: build
	docker build . -t $(IMAGE):$(TAG)

push-image: build-image
	docker push $(IMAGE):$(TAG)

	docker tag $(IMAGE):$(TAG) $(PUBLIC_IMAGE):$(TAG)
	docker push $(PUBLIC_IMAGE):$(TAG)

shell:
	docker run -ti --rm -v `pwd`:/workspace --net=host --entrypoint=/bin/bash \
	  $(IMAGE):$(TAG)

guess-tag:
	@echo "TAG=v`git describe --always`"

