# Stage 1: Builder
FROM golang:1.25.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache make git gcc musl-dev

# Add this environment variable to handle sqlite3 on Alpine/musl
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"

WORKDIR /app

# Clone the repository
RUN git clone https://github.com/johanix/tdns.git .

# Build the application
RUN make all

# Create the expected directory before installing
RUN mkdir -p /usr/local/libexec /usr/local/bin \
    && find . -type f -name "tdns*" -executable -exec cp {} /usr/local/bin/ \;

# Run install
RUN make install

# Stage 2: Runtime (Final Image)
FROM alpine:latest

# Install CA certificates for TLS
RUN apk add --no-cache ca-certificates openssl

WORKDIR /etc/tdns

# Copy only the compiled binaries from the builder
COPY --from=builder /usr/local/bin/tdns-* /usr/local/bin/

# Set up configuration and certificates
RUN mkdir -p /etc/tdns/certs

COPY --from=builder /app/agent/tdns-agent.sample.yaml /etc/tdns/tdns-agent.yaml
COPY --from=builder /app/agent/agent-zones.yaml /etc/tdns/
COPY --from=builder /app/cli/tdns-cli.sample.yaml /etc/tdns/tdns-cli.yaml
COPY --from=builder /app/utils/ /tmp/utils/

# Run the cert generation using the local openssl.cnf and create the db
RUN tdns-cli db init -f /var/tmp/tdns-agent.db \
    && cd /tmp/utils \
    && for cn in localhost. agent.provider. ; do echo $cn | sh gen-cert.sh ; done \
    && cp *.key *.crt /etc/tdns/certs/ \
    && rm -rf /tmp/utils

ENTRYPOINT ["tdns-agent"]
CMD ["--config", "/etc/tdns/tdns-agent.yaml"]

