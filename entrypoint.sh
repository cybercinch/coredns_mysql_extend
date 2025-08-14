#!/bin/bash

# Function to read either from file or fallback to env var
read_secret() {
    local file_var="${1}_FILE"
    local env_var="$1"
    local default="$2"
    
    if [[ -n "${!file_var}" && -f "${!file_var}" ]]; then
        # Read from secret file if specified and exists
        value=$(cat "${!file_var}" | tr -d "\n")
        echo "$value"
    elif [[ -n "${!env_var}" ]]; then
        # Use environment variable if defined
        echo "${!env_var}"
    else
        # Fallback to default value
        echo "$default"
    fi
}

# Read configuration from secrets or environment variables
export MYSQL_USER=$(read_secret MYSQL_USER "coredns")
export MYSQL_PASSWORD=$(read_secret MYSQL_PASSWORD "password")
export MYSQL_HOST=$(read_secret MYSQL_HOST "localhost")
export MYSQL_DATABASE=$(read_secret MYSQL_DATABASE "coredns")
export MYSQL_QUERY=$(read_secret MYSQL_QUERY "SELECT content FROM records WHERE name='%s' AND type='%s'")

# Process the Corefile template with environment variables
if [ ! -f /etc/coredns/Corefile ] && [ -f /etc/coredns/Corefile.template ]; then
    echo "Generating Corefile from template with current configuration..."
    envsubst < /etc/coredns/Corefile.template > /etc/coredns/Corefile.tmp
    # Remove any empty lines to prevent parsing errors
    grep -v '^$' /etc/coredns/Corefile.tmp > /etc/coredns/Corefile
    rm /etc/coredns/Corefile.tmp
    echo "Configuration generated."
    # Debug - show the final Corefile configuration
    echo "=== Final Corefile configuration ==="
    cat /etc/coredns/Corefile
    echo "==================================="
fi

echo "Starting CoreDNS..."
# Start CoreDNS with the processed configuration
exec /usr/local/bin/coredns -conf /etc/coredns/Corefile "$@"