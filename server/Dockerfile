# syntax=docker/dockerfile:1.7

# Build stage: full Go toolchain + gcc for CGO (required by go-sqlcipher).
ARG GO_VERSION=1.26.2
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot

FROM golang:${GO_VERSION}-bookworm AS builder

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
