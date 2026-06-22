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
