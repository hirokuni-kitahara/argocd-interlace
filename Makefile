IMG_NAME=ghcr.io/argoproj-labs/argocd-interlace-controller
IMG_VERSION ?= 
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
ifeq ($(IMG_VERSION), )
    IMG_VERSION = $(GIT_VERSION)
endif

ARGOCD_NAMESPACE ?= argocd
USE_EXAMPLE_KEYS ?= false

TMP_DIR=/tmp/


build-dry:
	@echo $(IMG_NAME):$(IMG_VERSION)

.PHONY: lint bin image build deploy undeploy check-argocd

lint:
	@golangci-lint version
	@echo linting go code...
	@golangci-lint run --fix --timeout 6m

bin:
	@echo building binary for image
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core

image:
	@echo building image
	docker build -t $(IMG_NAME):$(IMG_VERSION) .
	docker push $(IMG_NAME):$(IMG_VERSION)
	yq w -i  deploy/deployment.yaml 'spec.template.spec.containers.(name==argocd-interlace-controller).image' $(IMG_NAME):$(IMG_VERSION)

build: bin image

deploy: check-argocd
	@echo ---------------------------------
	@echo deploying argocd-interlace
	@echo ---------------------------------
	kustomize build deploy | kubectl apply -f -
	@echo ---------------------------------
	@echo configuring argocd-interlace
	@echo ---------------------------------
	@./scripts/setup.sh $(ARGOCD_NAMESPACE) $(USE_EXAMPLE_KEYS)
	@echo ---------------------------------
	@echo done!

undeploy:
	@echo deleting argocd-interlace
	kustomize build deploy | kubectl delete -f -

check-argocd:
	@podnum=$$(kubectl get pod -n $(ARGOCD_NAMESPACE) | grep application-controller-0 | grep Running | wc -l) && \
	if [ $$podnum -eq 1 ]; then \
		echo "ArgoCD pod is found."; \
	else \
		echo "ArgoCD pods are not running in \"$(ARGOCD_NAMESPACE)\" namespace."; \
		echo "ArgoCD is a prerequisite for argocd-interlace."; \
		exit 1; \
    fi
	

lint-init:
	 golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck > $(TMP_DIR)lint_results_interlace.txt

lint-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)lint_results_interlace.txt | grep "FAIL:"))
	cat  $(TMP_DIR)lint_results_interlace.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)