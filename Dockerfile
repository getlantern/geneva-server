# Build/runtime image for the geneva-server sidecar. Mirrors the lantern-box /
# datacap / httpproxy pattern: a golang builder producing a static binary, then
# a debian-slim runtime carrying only nftables (for the runtime-owned steering
# rules) and CA certificates.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder
ARG TARGETOS TARGETARCH
ARG VERSION=""
ARG COMMIT=""

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Pure-Go build (netlink + gopacket layers need no cgo), so the binary is static
# and runs on the slim runtime unchanged across architectures.
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/geneva-server ./cmd/geneva-server

FROM debian:bookworm-slim
RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends nftables ethtool ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/geneva-server /usr/local/bin/geneva-server
ENTRYPOINT ["/usr/local/bin/geneva-server"]
