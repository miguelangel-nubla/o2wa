#!/bin/bash
set -euo pipefail

# Variables
NON_ROOT_USER=${NON_ROOT_USER:-ubuntu}
TRUSTED_CA_PATH=${TRUSTED_CA_PATH:-}
INIT_SCRIPT_PATH=${INIT_SCRIPT_PATH:-}

log() {
    echo "[entrypoint.sh] $*" >&2
}

# Create non-root user if it doesn't exist
if ! id "$NON_ROOT_USER" >/dev/null 2>&1; then
    log "Creating non-root user '$NON_ROOT_USER'..."
    adduser --disabled-password --gecos "" --uid 1000 "$NON_ROOT_USER"
else
    log "User '$NON_ROOT_USER' already exists."
fi

# Add user-provided certificates if available
if [ -n "$TRUSTED_CA_PATH" ] && [ -d "$TRUSTED_CA_PATH" ]; then
    log "Adding user-provided certificates from '$TRUSTED_CA_PATH'..."
    find "$TRUSTED_CA_PATH" -type f -name '*.crt' -o -name '*.pem' | while read -r cert; do
        cp "$cert" /usr/local/share/ca-certificates/
    done
    update-ca-certificates
else
    log "No trusted CA path provided or directory not found."
fi

# Run user initialization script if present
if [ -n "$INIT_SCRIPT_PATH" ] && [ -f "$INIT_SCRIPT_PATH" ]; then
    log "Running initialization script '$INIT_SCRIPT_PATH'..."
    chmod +x "$INIT_SCRIPT_PATH"
    "$INIT_SCRIPT_PATH"
else
    log "No initialization script found."
fi

# Drop privileges and run main process
log "Switching to non-root user '$NON_ROOT_USER' and starting application: $*"
exec su -s /bin/sh "$NON_ROOT_USER" -c "$*"
