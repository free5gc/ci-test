FROM free5gc/all-base:latest AS builder
FROM alpine:3.15

LABEL description="Free5GC open source 5G Core Network" \
    version="Stage 3"

ENV F5GC_MODULE=scp
ARG DEBUG_TOOLS

# Install debug tools ~ 100MB (if DEBUG_TOOLS is set to true)
RUN if [ "$DEBUG_TOOLS" = "true" ] ; then apk add -U vim strace net-tools curl netcat-openbsd ; fi

# Set working dir
WORKDIR /free5gc
RUN mkdir -p config/ log/ cert/

# Copy executable (SCP runs on http in CI, so no default certs are shipped)
COPY --from=builder /free5gc/bin/${F5GC_MODULE} ./

# Config files volume
VOLUME [ "/free5gc/config" ]

# Certificates (if not using default) volume
VOLUME [ "/free5gc/cert" ]

# Exposed ports
EXPOSE 8000
