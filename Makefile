NAME=gcr.io/signing-demo-project/argocd-interlace-controller
VERSION=dev5

.PHONY: build build-cli build-core

build-linux:
	@echo building binary for image
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)

build:
	@echo building binary for image
	CGO_ENABLED=0  GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)


build-core-linux:
	@echo building binary for core
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core



build-core:
	@echo building binary for core
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core
