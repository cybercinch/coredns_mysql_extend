# Create minimal production image
FROM alpine:3.21

ARG TARGETARCH
ARG TARGETOS

# Set default environment variables
ENV MYSQL_USER="coredns" \
    MYSQL_PASSWORD="password" \
    MYSQL_HOST="localhost" \
    MYSQL_PORT="3306" \
    MYSQL_DATABASE="coredns" \
    MYSQL_TABLE_PREFIX="coredns_" \
    # Paths for secrets and configs
    MYSQL_USER_FILE="" \
    MYSQL_PASSWORD_FILE="" \
    MYSQL_HOST_FILE="" \
    MYSQL_DATABASE_FILE="" \
    MYSQL_QUERY_FILE=""

# Add non-root user
RUN adduser -D -u 1000 coredns

# Install required runtime dependencies
RUN apk add --no-cache bash gettext

# Copy only the built binary from the builder stage
COPY dist/coredns-${TARGETOS}-${TARGETARCH}/coredns /usr/local/bin/

# Create directories for configuration, data, and secrets
RUN mkdir -p /etc/coredns /var/lib/coredns /run/secrets && \
    chown -R coredns:coredns /etc/coredns /var/lib/coredns /run/secrets

# Create default configuration directory structure
WORKDIR /etc/coredns

# Create a template Corefile - making sure it has no newlines at start
RUN printf '. {\n\
    mysql {\n\
        dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DATABASE}"\n\
    }\n\
    cache {\n\
        success 3600\n\
        denial 300\n\
        prefetch 10 60s 60%%\n\
    }\n\
    log\n\
    errors\n\
}' > /etc/coredns/Corefile.template

# Copy entrypoint script from build context
COPY entrypoint.sh /usr/local/bin/

# Make entrypoint executable and set ownership
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    chown coredns:coredns /usr/local/bin/entrypoint.sh /etc/coredns/Corefile.template

# Set volumes for configuration and data
VOLUME ["/etc/coredns", "/var/lib/coredns"]

# Switch to non-root user
USER coredns

# Expose DNS ports
EXPOSE 53/tcp 53/udp

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]