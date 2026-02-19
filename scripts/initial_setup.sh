#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

TIMESTAMP=$(date +%Y%m%dT%H%M%S)
IPTABLES_BACKUP=/tmp/spip-iptables-nat-backup-$TIMESTAMP.rules

echo_header() {
    printf "\n==== %s ===\n" "$1"
}

err() { echo "ERROR: $*" >&2; }

require_root() {
    if [ "$EUID" -ne 0 ]; then
        err "This script must be run as root. Re-run with sudo."; exit 1
    fi
}

detect_default_ip() {
    # Try to get a sensible outbound IP
    ip_out=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' | head -n1)
    if [ -z "$ip_out" ]; then
        ip_out=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    echo "${ip_out:-127.0.0.1}"
}

detect_ssh_port() {
    # Try to parse sshd_config, fallback to 22
    if [ -f /etc/ssh/sshd_config ]; then
        port=$(awk '/^\s*Port\s+/ {print $2; exit}' /etc/ssh/sshd_config || true)
    fi
    echo "${port:-22}"
}

detect_default_name() {
    # Suggest a short hostname as the agent name
    local hn
    hn=$(hostname -s 2>/dev/null || true)
    echo "${hn:-spip-agent}"
}

prompt() {
    local prompt_msg=$1 default=$2
    if [ -n "$default" ]; then
        read -rp "$prompt_msg [$default]: " val
        val=${val:-$default}
    else
        read -rp "$prompt_msg: " val
    fi
    echo "$val"
}

confirm() {
    # return 0 for yes, 1 for no
    read -rp "$1 [y/N]: " yn
    case "${yn,,}" in
        y|yes) return 0;;
        *) return 1;;
    esac
}

write_config() {
    local cfgpath="$REPO_ROOT/config.toml"
    echo_header "Writing config to $cfgpath"
    cat > "$cfgpath" <<EOF
# Configuration for spip-agent
# Edit this file with values appropriate for your environment.

name = "${CFG_NAME}"
ip = "${CFG_IP}"
port = ${CFG_PORT}
EOF

    if [ -n "${CFG_CERT_PATH:-}" ] && [ -n "${CFG_KEY_PATH:-}" ]; then
        cat >> "$cfgpath" <<EOF
cert_path = "${CFG_CERT_PATH}"
key_path = "${CFG_KEY_PATH}"
EOF
    fi

    if [ -n "${CFG_LOG_FILE:-}" ]; then
        echo "log_file = \"${CFG_LOG_FILE}\"" >> "$cfgpath"
    fi

    if [ -n "${CFG_READ_TIMEOUT:-}" ]; then
        echo "read_timeout_seconds = ${CFG_READ_TIMEOUT}" >> "$cfgpath"
    fi
    if [ -n "${CFG_WRITE_TIMEOUT:-}" ]; then
        echo "write_timeout_seconds = ${CFG_WRITE_TIMEOUT}" >> "$cfgpath"
    fi
    if [ -n "${CFG_RPS:-}" ]; then
        echo "rate_limit_per_second = ${CFG_RPS}" >> "$cfgpath"
    fi
    if [ -n "${CFG_BURST:-}" ]; then
        echo "rate_limit_burst = ${CFG_BURST}" >> "$cfgpath"
    fi

    # Optional: Community ID v1 seed (omit or 0 for default). Fingerprinting is always on.
    echo "# community_id_seed = 0" >> "$cfgpath"

    if [ "${CFG_LOOM_ENABLED:-0}" = "1" ] && [ -n "${CFG_LOOM_URL:-}" ] && [ -n "${CFG_LOOM_SENSOR_ID:-}" ] && [ -n "${CFG_LOOM_TOKEN:-}" ]; then
        cat >> "$cfgpath" <<EOF

# Ship logs to central Loom server
[loom]
enabled = true
url = "${CFG_LOOM_URL}"
sensor_id = "${CFG_LOOM_SENSOR_ID}"
token = "${CFG_LOOM_TOKEN}"
batch_size = ${CFG_LOOM_BATCH_SIZE:-50}
flush_interval = "${CFG_LOOM_FLUSH_INTERVAL:-10s}"
insecure_skip_verify = ${CFG_LOOM_INSECURE_SKIP_VERIFY:-false}
EOF
    fi

    echo "Wrote $cfgpath"
}

backup_iptables() {
    echo_header "Backing up current iptables NAT table to $IPTABLES_BACKUP"
    iptables-save -t nat > "$IPTABLES_BACKUP" || { err "Failed to save nat table"; exit 1; }
}

apply_iptables() {
    echo_header "Applying iptables NAT redirect rules (PREROUTING)"
    # Flush nat table first (backup already saved)
    iptables -t nat -F || { err "Failed to flush nat table"; return 1; }

    # Exclude SSH port from PREROUTING so we don't interfere with SSH
    iptables -t nat -A PREROUTING -p tcp --dport "$SSH_PORT" -j RETURN || true

    # Redirect all other TCP PREROUTING traffic to the configured local port
    iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port "$CFG_PORT" || true

    echo "Applied PREROUTING rules: excluded SSH port $SSH_PORT, redirected TCP to local port $CFG_PORT"
}

restore_iptables_prompt() {
    if confirm "Do you want to restore the previous iptables NAT rules from backup?"; then
        if [ -f "$IPTABLES_BACKUP" ]; then
            iptables-restore < "$IPTABLES_BACKUP" || err "Failed to restore iptables NAT table"
            echo "Restored NAT table from $IPTABLES_BACKUP"
        else
            err "Backup file not found: $IPTABLES_BACKUP"
        fi
    fi
}

generate_keys() {
    echo_header "Generating self-signed certificate and key"
    # Create certs dir
    local certdir="$REPO_ROOT/certs-$TIMESTAMP"
    mkdir -p "$certdir"
    local cert="$certdir/cert.pem"
    local key="$certdir/key.pem"

    if ! command -v openssl >/dev/null 2>&1; then
        err "openssl is not installed. Install it and rerun the script to generate keys."; return 1
    fi

    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
        -subj "/CN=localhost" -keyout "$key" -out "$cert" >/dev/null 2>&1 || {
        err "openssl failed to generate certificate"; return 1
    }

    chmod 640 "$key" || true
    echo "Generated cert: $cert and key: $key"
    # Use paths relative to repo root (where config.toml lives) so they work wherever spip is run from
    CFG_CERT_PATH="certs-$TIMESTAMP/cert.pem"
    CFG_KEY_PATH="certs-$TIMESTAMP/key.pem"
}

main() {
    echo_header "Spip initial setup"
    require_root

    DEFAULT_IP=$(detect_default_ip)
    SUGGESTED_SSH_PORT=$(detect_ssh_port)

    echo "Suggested listen IPs: 0.0.0.0 (bind all), detected host IP: $DEFAULT_IP"
    # Recommend binding to all interfaces by default so redirects work as expected
    CFG_IP=$(prompt "Enter the IP address the agent should listen on" "0.0.0.0")

    DEFAULT_NAME=$(detect_default_name)
    CFG_NAME=$(prompt "Enter a name to identify this agent (used in logs)" "$DEFAULT_NAME")

    while true; do
        CFG_PORT=$(prompt "Enter the port the agent should listen on" "8080")
        if [[ "$CFG_PORT" =~ ^[0-9]+$ ]] && [ "$CFG_PORT" -ge 1 ] && [ "$CFG_PORT" -le 65535 ]; then
            break
        fi
        echo "Invalid port. Please enter a number between 1 and 65535."
    done

    SSH_PORT=$(prompt "Enter SSH port to exclude from redirect" "$SUGGESTED_SSH_PORT")

    # Additional optional fields
    if confirm "Do you want to enable TLS (generate a self-signed cert)?"; then
        if generate_keys; then
            echo "TLS keys generated and paths set in config";
        else
            echo "Skipping TLS generation";
        fi
    fi

    CFG_LOG_FILE=""
    if confirm "Do you want to set a log file path (otherwise logs go to stdout)?"; then
        CFG_LOG_FILE=$(prompt "Log file path" "/var/log/spip-agent.log")
    fi

    CFG_LOOM_ENABLED=0
    if confirm "Do you want to enable Loom (ship logs to a central server)?"; then
        CFG_LOOM_URL=$(prompt "Loom ingest URL" "https://loom.example.com/api/v1/ingest")
        CFG_LOOM_SENSOR_ID=$(prompt "Loom sensor ID (e.g. agent name)" "$CFG_NAME")
        CFG_LOOM_TOKEN=$(prompt "Loom API token" "")
        if [ -z "$CFG_LOOM_TOKEN" ]; then
            echo "Loom requires an API token. Skipping Loom config; you can add [loom] to config.toml later."
        else
            CFG_LOOM_ENABLED=1
            CFG_LOOM_BATCH_SIZE=$(prompt "Loom batch size" "50")
            CFG_LOOM_FLUSH_INTERVAL=$(prompt "Loom flush interval (e.g. 10s)" "10s")
            if confirm "Skip TLS verification for Loom server (insecure)?"; then
                CFG_LOOM_INSECURE_SKIP_VERIFY=true
            else
                CFG_LOOM_INSECURE_SKIP_VERIFY=false
            fi
        fi
    fi

    echo_header "Optional runtime tuning"
    if confirm "Set read/write timeouts?"; then
        CFG_READ_TIMEOUT=$(prompt "Read timeout in seconds" "30")
        CFG_WRITE_TIMEOUT=$(prompt "Write timeout in seconds" "30")
    fi

    if confirm "Set rate limiter (requests per second)?"; then
        CFG_RPS=$(prompt "Rate limit per second" "100")
        CFG_BURST=$(prompt "Rate limit burst" "200")
    fi

    echo_header "Iptables changes"
    echo "This script will modify the NAT table using PREROUTING rules to redirect incoming TCP traffic to local port $CFG_PORT, excluding SSH port $SSH_PORT."
    echo "Proposed commands (for reference):"
    echo "  iptables -t nat -F"
    echo "  iptables -t nat -A PREROUTING -p tcp --dport $SSH_PORT -j RETURN"
    echo "  iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port $CFG_PORT"
    if ! confirm "Proceed to modify iptables now?"; then
        echo "Skipping iptables changes. You can run them later with the instructions printed below.";
        write_config
        exit 0
    fi

    backup_iptables

    # Apply iptables rules, but be careful with syntax: use explicit ordering
    apply_iptables || { err "Failed to apply iptables rules"; restore_iptables_prompt; exit 1; }

    write_config

    echo_header "Done"
    echo "Configuration written to: $REPO_ROOT/config.toml"
    if [ -n "${CFG_CERT_PATH:-}" ]; then
        echo "TLS cert: $CFG_CERT_PATH"; echo "TLS key: $CFG_KEY_PATH"
    fi
    if [ "${CFG_LOOM_ENABLED:-0}" = "1" ]; then
        echo "Loom: enabled (url=$CFG_LOOM_URL, sensor_id=$CFG_LOOM_SENSOR_ID)"
    fi
    echo
    echo "If you want to undo iptables changes, run this script again and choose to restore the backup when prompted, or run:" 
    echo "  sudo iptables-restore < $IPTABLES_BACKUP"
}

main "$@"
