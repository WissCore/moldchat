# syntax=docker/dockerfile:1.24@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

# Build stage: full Go toolchain + gcc for CGO (required by go-sqlcipher).
# Base images are pinned by digest (Renovate keeps them fresh per
# config:best-practices -> docker:pinDigests).
ARG GO_VERSION=1.26.2
ARG BUILDER_IMAGE=golang:${GO_VERSION}-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:e2d29aec8061843706b7e484c444f78fafb05bfe47745505252b1769a05d14f1

FROM ${BUILDER_IMAGE} AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid=" \
    -o /out/moldd ./cmd/moldd

# Runtime stage: distroless with glibc + libgcc (CGO needs libc, no shell, no package manager).
FROM ${RUNTIME_IMAGE} AS runtime

COPY --from=builder /out/moldd /usr/local/bin/moldd

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/moldd"]
