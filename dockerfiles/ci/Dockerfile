FROM alonza0314/free-ran-ue:latest as fru

FROM golang:1.26.2

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /root

# Install essential packages and dependencies
RUN apt-get update && \
    apt-get install -y \
    curl \
    jq \
    iputils-ping \
    net-tools \
    iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy free-ran-ue binary
COPY --from=fru /free-ran-ue/free-ran-ue /free-ran-ue/free-ran-ue

# Pre-download Go module dependencies into the image so `go test` doesn't
# re-fetch them on every container start. test/goTest is bind-mounted over
# /root/test at runtime, but the module cache (GOMODCACHE, default
# /root/go/pkg/mod) lives outside that path, so it survives the mount.
COPY test/goTest/go.mod test/goTest/go.sum /root/test/goTest/
RUN cd /root/test/goTest && go mod download
