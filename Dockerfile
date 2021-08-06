#
# Copyright 2020 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#FROM registry.access.redhat.com/ubi8/ubi-minimal:8.1

#RUN mkdir -p /ishield-app && mkdir -p /ishield-app/public

#RUN chgrp -R 0 /ishield-app && chmod -R g=u /ishield-app

#COPY build/_bin/argocd-interlace /usr/local/bin/argocd-interlace

#WORKDIR /ishield-app

#ENTRYPOINT ["argocd-interlace"]

# Build Container
FROM golang:latest as builder
WORKDIR /go/src/github.com/sigstore/k8s-manifest-sigstore
COPY . .
# Set Environment Variable
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
# Build
#RUN go build -o kubectl-sigstore ./cmd/kubectl-sigstore
COPY build/_bin/argocd-interlace /usr/local/bin/argocd-interlace

# Runtime Container
FROM alpine
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/local/bin/argocd-interlace /usr/local/bin/argocd-interlace
ENTRYPOINT ["argocd-interlace"]
