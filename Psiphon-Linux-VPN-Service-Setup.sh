#!/bin/bash

# Psiphon Linux VPN Service - Zero Trust Network Security Implementation
# Security-First TUN Interface Setup with Kill Switch
#
# Features:
# - Zero-trust networking model with comprehensive kill switch
# - Native TUN interface support for secure packet tunneling
# - Automated binary verification and secure updates
# - Full IPv4/IPv6 traffic isolation through VPN tunnel
# - DNS leak prevention with secure resolution handling
#
# Security measures:
# - Default-deny firewall policy (fail-closed model)
# - Dedicated non-root user isolation
# - Secure process capability restrictions
# - Comprehensive traffic routing enforcement

set -euo pipefail
IFS=$'\n\t'

readonly INSTALLER_VERSION="1.3.1"
# Security and Configuration Parameters
# These values are critical for the security model - DO NOT MODIFY without understanding implications
readonly PSIPHON_USER="psiphon-user"     # Dedicated non-root user for process isolation
readonly PSIPHON_GROUP="psiphon-group"   # Restricted group for secure operations
readonly SOCKS_PORT=1081                 # Local SOCKS proxy port for tunneled traffic
readonly HTTP_PORT=8081                  # Local HTTP proxy port for tunneled traffic
readonly INSTALL_DIR="/opt/psiphon-tun"  # Base installation directory with restricted access
readonly PSIPHON_DIR="$INSTALL_DIR/psiphon" # Secure binary and config storage location
readonly PSIPHON_BINARY="$PSIPHON_DIR/psiphon-tunnel-core"
readonly PSIPHON_CONFIG_FILE="$PSIPHON_DIR/psiphon.config"
readonly LOG_FILE="$INSTALL_DIR/psiphon-tun.log"
readonly PSIPHON_LOG_FILE="$INSTALL_DIR/psiphon-core.log"
readonly PSIPHON_SPONSOR_HOMEPAGE_PATH="$INSTALL_DIR/data/ca.psiphon.PsiphonTunnel.tunnel-core/homepage"
readonly LOCK_FILE="/run/psiphon-tun.lock"
readonly PID_FILE="/run/psiphon-tun.pid"

readonly GITHUB_API="https://api.github.com/repos/Psiphon-Labs/psiphon-tunnel-core-binaries"
readonly PSIPHON_BINARY_URL="https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/raw/master/linux/psiphon-tunnel-core-x86_64"

readonly SERVICE_CONFIGURE_NAME="psiphon-tun"
readonly SERVICE_BINARY_NAME="psiphon-binary"
readonly SERVICE_HOMEPAGE_MONITOR="psiphon-homepage-monitor"
readonly SERVICE_HOMEPAGE_TRIGGER="psiphon-homepage-trigger"

# Network Security Configuration
readonly TUN_INTERFACE="PsiphonTUN"      # Dedicated TUN interface for isolated traffic
readonly TUN_SUBNET="10.200.3.0/24"      # IPv4 subnet for tunnel traffic isolation
readonly TUN_IP="10.200.3.1"             # IPv4 gateway address for tunnel
readonly TUN_PEER_IP="10.200.3.2"        # IPv4 peer address for point-to-point tunnel
readonly TUN_SUBNET6="fd42:42:42::/64"   # IPv6 subnet (ULA) for tunnel traffic isolation
readonly TUN_IP6="fd42:42:42::1"         # IPv6 gateway address for tunnel
readonly TUN_DNS_SERVERS="8.8.8.8,8.8.4.4" # Google DNS
readonly TUN_DNS_SERVERS6="2001:4860:4860::8888,2001:4860:4860::8844" # Google DNS IPv6

# WARP Integration Configuration
readonly WARP_CLI_PATH="/usr/bin/warp-cli"      # Path to WARP CLI executable
readonly WARP_SVC_PROCESS="warp-svc"            # WARP service process name
readonly WARP_STATUS_CONNECTED="Status update: Connected"       # Expected WARP status when connected
readonly WARP_INTERFACE="CloudflareWARP"                  # WARP interface name

# Secure fallback for interface selection: default route with non-loopback fallback
TUN_BYPASS_INTERFACE=$(ip -json route get 8.8.8.8 2>/dev/null | jq -r '.[0].dev // empty' ||
                              ip -json link show | jq -r '.[] | select(.link_type!="loopback") | .ifname' | head -n1)

SERVICE_MODE="false" # Set to true when running as a systemd service

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
function log() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${BLUE}[$timestamp]${NC} $message"
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] $message" >> "$LOG_FILE" 2>/dev/null || true
}

function error() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${RED}[$timestamp][ERROR]${NC} $message" >&2
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] ERROR: $message" >> "$LOG_FILE" 2>/dev/null || true
}

function success() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${GREEN}[$timestamp][SUCCESS]${NC} $message"
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] $message" >> "$LOG_FILE" 2>/dev/null || true
}

function warning() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${YELLOW}[$timestamp][WARNING]${NC} $message"
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] WARNING: $message" >> "$LOG_FILE" 2>/dev/null || true
}

# Security Validation Functions

# Verify root privileges for secure operations
# Required for network configuration and process management
function check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Process isolation through file locking
# Prevents race conditions and ensures single instance execution
function acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid
        lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            error "Another instance is already running (PID: $lock_pid)"
            exit 1
        else
            # Remove stale lock file
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
    trap 'rm -f "$LOCK_FILE"' EXIT
}

# Check for required tools
function check_dependencies() {
    local missing_tools=()

    for tool in wget curl unzip ip iptables ip6tables; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        log "Installing missing tools..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y "${missing_tools[@]}"
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "${missing_tools[@]}"
        elif command -v pacman >/dev/null 2>&1; then
            pacman -S --noconfirm "${missing_tools[@]}"
        else
            error "Cannot install missing tools. Please install manually: ${missing_tools[*]}"
            exit 1
        fi
    fi
}

# Create user and group
function create_user() {
    if ! getent group "$PSIPHON_GROUP" >/dev/null 2>&1; then
        log "Creating group $PSIPHON_GROUP..."
        groupadd --system "$PSIPHON_GROUP"
    fi

    if ! getent passwd "$PSIPHON_USER" >/dev/null 2>&1; then
        log "Creating user $PSIPHON_USER..."
        useradd --system --no-create-home --shell /bin/false \
                --home-dir /nonexistent --gid "$PSIPHON_GROUP" "$PSIPHON_USER"
    fi
}

# Create directory structure
function create_directories() {
    log "Creating directory structure..."

    mkdir -p "$INSTALL_DIR" "$PSIPHON_DIR" "$INSTALL_DIR/data"
    chown -R "$PSIPHON_USER:$PSIPHON_GROUP" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR" "$PSIPHON_DIR"
    chmod 700 "$INSTALL_DIR/data"
}


# Psiphon version management
function get_latest_psiphon_info() {
    local commits_api="$GITHUB_API/commits?path=linux/psiphon-tunnel-core-x86_64&per_page=1"
    local latest_commit

    if ! latest_commit=$(curl -s --connect-timeout 7 --max-time 60 "$commits_api"); then
        error "Failed to fetch commit info from GitHub"
        return 1
    fi

    if [[ -z "$latest_commit" ]] || [[ "$latest_commit" == "null" ]] || ! echo "$latest_commit" | jq empty 2>/dev/null; then
        error "Invalid response from GitHub API"
        return 1
    fi
    # We want to avoid errors if jq fails. We check later if commit_message is empty
    # shellcheck disable=SC2155
    local commit_message=$(echo "$latest_commit" | jq -r '.[0].commit.message' 2>/dev/null || echo "") || true

    if [[ -z "$commit_message" ]] || [[ "$commit_message" == "null" ]]; then
        error "Failed to parse commit information"
        return 1
    fi

    echo "$commit_message"
}

function get_binary_version_info() {
    if [[ ! -f "$PSIPHON_BINARY" ]]; then
        echo "|"
        return
    fi

    local version_output

    if ! version_output=$(exec runuser -u "$PSIPHON_USER" -- "$PSIPHON_BINARY" -v 2>/dev/null); then
        echo "|"
        return
    fi
    # We want to avoid errors if grep or sed fails. It's okay if build_date or revision is empty
    # shellcheck disable=SC2155
    local revision=$(echo "$version_output" | grep "Revision:" | sed 's/Revision: //' | xargs || echo "")

    echo "$revision"
}

# Secure binary download and validation
function download_psiphon() {
    local temp_file
    temp_file=$(mktemp)

    log "Downloading latest Psiphon binary..."

    if ! wget -q --connect-timeout 7 --timeout=567 --tries=3 "$PSIPHON_BINARY_URL" -O "$temp_file"; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Failed to download Psiphon binary"
        return 1
    fi

    # Verify it's a valid binary
    if ! file "$temp_file" | grep -q "ELF.*executable"; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Downloaded file is not a valid Linux executable"
        return 1
    fi

    # Make it executable and test version
    chmod +x "$temp_file"
    local version_output
    if ! version_output=$("$temp_file" -v 2>/dev/null); then
        rm -f "$temp_file" 2>/dev/null || true
        error "Downloaded binary cannot be executed or is invalid"
        return 1
    fi

    if ! echo "$version_output" | grep -q "Psiphon Console Client"; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Downloaded binary does not appear to be Psiphon"
        return 1
    fi

    # Extract version info
    local build_date revision
    build_date=$(echo "$version_output" | grep "Build Date:" | sed 's/Build Date: //' | xargs || echo "")
    revision=$(echo "$version_output" | grep "Revision:" | sed 's/Revision: //' | xargs || echo "")

    if [[ -z "$build_date" ]] || [[ -z "$revision" ]]; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Cannot extract version information from binary"
        return 1
    fi

    log "Downloaded binary info:"
    log "  Build Date: $build_date"
    log "  Revision: $revision"

    # Install the binary securely
    # cp -f "$temp_file" "$PSIPHON_BINARY"
    # chmod 750 "$PSIPHON_BINARY"
    # chown "$PSIPHON_USER:$PSIPHON_GROUP" "$PSIPHON_BINARY"
    install -m 750 -o "$PSIPHON_USER" -g "$PSIPHON_GROUP" "$temp_file" "$PSIPHON_BINARY"


    # Clean up temp file before successful return
    rm -f "$temp_file" 2>/dev/null || true

    success "Psiphon binary installed successfully"
}

function check_and_update_psiphon() {
    log "Checking for Psiphon updates..."

    # Get latest commit info from GitHub
    local latest_commit_msg
    if ! latest_commit_msg=$(get_latest_psiphon_info); then
        warning "Failed to fetch latest Psiphon commit info from GitHub"
    fi

    # Get current binary info
    # We want to avoid errors if get_binary_version_info fails
    # We download anyway if we cannot determine current version
    # shellcheck disable=SC2155
    local current_revision=$(get_binary_version_info) || true

    log "Latest revision: $latest_commit_msg"
    log "Current binary Revision: $current_revision"

    # Check if we need to update
    local needs_update=false

    if [[ ! -f "$PSIPHON_BINARY" ]]; then
        log "Binary not found, downloading..."
        needs_update=true
    elif [[ -z "$current_revision" ]]; then
        log "Cannot determine current version, updating..."
        needs_update=true
    else
        if [[ "$latest_commit_msg" != *"$current_revision"* ]]; then
            # If timestamps are close or equal, check if revisions are different
            log "Different revision detected, updating..."
            needs_update=true
        fi
    fi

    if [[ "$needs_update" == true ]]; then
        log "Updating Psiphon binary..."
        if download_psiphon; then
            success "Psiphon updated successfully"

            # Show new version info
            local new_info new_build_date new_revision
            new_info=$(get_binary_version_info)
            new_build_date=$(echo "$new_info" | cut -d'|' -f1)
            new_revision=$(echo "$new_info" | cut -d'|' -f2)
            log "New version: Build Date: $new_build_date, Revision: $new_revision"

            return 0
        else
            error "Failed to update Psiphon"
            return 1
        fi
    else
        log "Psiphon is already up to date"
        return 0
    fi
}

# Create Psiphon configuration
function create_psiphon_config() {
    log "Creating Psiphon configuration..."

    # See the AvailableEgressRegions in Psiphon logs for valid region codes
    # Example:
    # Change to `"EgressRegion": "US",` if you want to force to choose US servers
    cat > "$PSIPHON_CONFIG_FILE" << 'EOF'
{
    "LocalHttpProxyPort": 8081,
    "LocalSocksProxyPort": 1081,
    "EgressRegion": "",
    "PropagationChannelId": "FFFFFFFFFFFFFFFF",
    "RemoteServerListDownloadFilename": "remote_server_list",
    "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
    "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
    "SponsorId": "FFFFFFFFFFFFFFFF",
    "UseIndistinguishableTLS": true
}
EOF

    ## removed parts:
    # ,
    # "EstablishTunnelTimeoutSeconds": 360,
    # "TunnelPoolSize": 1

    chown "$PSIPHON_USER:$PSIPHON_GROUP" "$PSIPHON_CONFIG_FILE"
    chmod 600 "$PSIPHON_CONFIG_FILE"
}

# Systemd service
function create_systemd_services() {
    log "Creating systemd service..."

    local service_script="$INSTALL_DIR/psiphon-tun-service.sh"

    # Create service wrapper script
    tee "$service_script" >/dev/null <<EOF
#!/bin/bash
set -euo pipefail

INSTALL_DIR="$INSTALL_DIR"
SERVICE_SCRIPT="$INSTALL_DIR/psiphon-tun.sh"

case "\${1:-}" in
    start)
        "\$SERVICE_SCRIPT" systemd_start
        ;;
    stop)
        "\$SERVICE_SCRIPT" systemd_stop
        ;;
    reload)
        "\$SERVICE_SCRIPT" systemd_reload
        ;;
    restart)
        "\$SERVICE_SCRIPT" systemd_restart
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|reload}"
        exit 1
        ;;
esac
EOF

    chmod 755 "$service_script"
    chown root:root "$service_script"

    # Create main systemd service file
    tee /etc/systemd/system/$SERVICE_CONFIGURE_NAME.service >/dev/null <<EOF
[Unit]
Description=Psiphon TUN Service (Network Configuration)
After=network-online.target
Wants=network-online.target
Before=$SERVICE_BINARY_NAME.service
Documentation=https://github.com/boilingoden/psiphon-client-linux-service

[Service]
Type=simple
RemainAfterExit=yes
ExecStart=$service_script start
ExecStop=$service_script stop
ExecReload=$service_script reload
# TimeoutStartSec=120
# TimeoutStopSec=30
User=root
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$INSTALL_DIR /run /var/log /etc/resolv.conf /etc/systemd/resolved.conf.d
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE CAP_IPC_LOCK
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE CAP_IPC_LOCK
SecureBits=keep-caps-locked

[Install]
WantedBy=multi-user.target
EOF

    # Create tunnel service file
    tee /etc/systemd/system/$SERVICE_BINARY_NAME.service >/dev/null <<EOF
[Unit]
Description=Psiphon Binary Process
After=network-online.target $SERVICE_CONFIGURE_NAME.service
Requires=$SERVICE_CONFIGURE_NAME.service
Documentation=https://github.com/boilingoden/psiphon-client-linux-service
StartLimitIntervalSec=10
StartLimitBurst=3

[Service]
Type=exec
# ExecStartPre=/bin/sleep 2
ExecStart=$PSIPHON_BINARY -config $PSIPHON_CONFIG_FILE -dataRootDirectory $INSTALL_DIR/data \\
    -tunDevice $TUN_INTERFACE -tunBindInterface $TUN_BYPASS_INTERFACE \\
    -tunDNSServers $TUN_DNS_SERVERS,$TUN_DNS_SERVERS6 -formatNotices -useNoticeFiles
# ExecStop=/bin/kill -TERM \$MAINPID
# ExecReload=/bin/systemctl --no-block restart %n
User=$PSIPHON_USER
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=7s

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$INSTALL_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
SecureBits=noroot-locked

[Install]
WantedBy=multi-user.target
EOF

    # Create homepage monitor service
    tee /etc/systemd/system/$SERVICE_HOMEPAGE_MONITOR.path >/dev/null <<EOF
[Unit]
Description=Psiphon Homepage Monitor

[Path]
PathModified=$PSIPHON_SPONSOR_HOMEPAGE_PATH
Unit=$SERVICE_HOMEPAGE_TRIGGER.service

[Install]
WantedBy=multi-user.target
EOF

    # Get the active logged-in user
    # This checks for the active display manager session.
    ACTIVE_USER=$(logname)
    ACTIVE_USER_ID=$(id -u "$ACTIVE_USER" 2>/dev/null || echo "1000")
    # Create the trigger service
    tee /etc/systemd/system/$SERVICE_HOMEPAGE_TRIGGER.service >/dev/null <<EOF
[Unit]
Description=Psiphon Homepage Change Handler
# The service should only run after a graphical session has started.
PartOf=graphical.target
Requires=graphical.target

[Service]
Type=oneshot
Environment="DISPLAY=:0"
Environment="DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$ACTIVE_USER_ID/bus"
ExecStart=notify-send -a "$SERVICE_CONFIGURE_NAME" -u critical -i applications-internet -t 15000 "Psiphon connectivity has changed!" "run: 'systemctl status $SERVICE_BINARY_NAME' to check connection status"
User=$ACTIVE_USER

# TODO: Make this open the URL in the user's default browser **securely**
# ExecStart=/bin/sh -c 'URL=\$(runuser -pu "$PSIPHON_USER" -- jq -r ".data.url" "$PSIPHON_SPONSOR_HOMEPAGE_PATH");echo "$\URL"; runuser -pu "$ACTIVE_USER" -- systemd-run --user xdg-open "\$URL" 2>/dev/null &'
# User=root

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# ProtectHome=true
EOF

    # Copy this script to install directory
    cp -f "$0" "$INSTALL_DIR/psiphon-tun.sh"
    chmod 755 "$INSTALL_DIR/psiphon-tun.sh"
    chown root:root "$INSTALL_DIR/psiphon-tun.sh"

    systemctl daemon-reload

    success "Systemd service created"
}

# Change DNS Configuration
function change_dns_config() {
    log "Setting up DNS configuration..."

    # Backup original resolv.conf
    if [ ! -f /etc/resolv.conf.original ]; then
        cp -P /etc/resolv.conf /etc/resolv.conf.original &
        wait
    fi

    # Check if systemd-resolved is running
    if ! systemctl is-active systemd-resolved >/dev/null 2>&1; then
        # Configure DNS servers
    cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 2001:4860:4860::8888
nameserver 2001:4860:4860::8844
EOF

    # Set proper permissions
    chmod 644 /etc/resolv.conf

    # # Setup routing table for DNS
    # for dns in 8.8.8.8 8.8.4.4; do
    #     ip route add $dns via $(ip route | grep default | grep -v $TUN_INTERFACE | awk '{print $3}') dev $TUN_BYPASS_INTERFACE proto static
    # done

    else

        if [ -f /etc/systemd/resolved.conf.d/psiphon-tun.conf ]; then

            # Create resolved.conf drop-in directory if it doesn't exist
            mkdir -p /etc/systemd/resolved.conf.d/

            # Create custom configuration for DNS
            cat > /etc/systemd/resolved.conf.d/psiphon-tun.conf <<EOF
[Resolve]
DNS=8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844
DNSOverTLS=no
DNSSEC=no
Domains=~.
EOF
        fi
        # Set DNS routing for the TUN interface
        resolvectl dns "$TUN_INTERFACE" 8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844
        resolvectl domain "$TUN_INTERFACE" "~."
        resolvectl default-route "$TUN_INTERFACE" yes

        # Restart systemd-resolved to apply changes
        systemctl restart systemd-resolved
    fi
    success "TUN interface configured with IPv4 and IPv6"

}

# Setup TUN interface
function setup_tun_interface() {
    log "Setting up TUN interface..."

    # Create TUN interface if it doesn't exist
    if ! ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        if ! ip tuntap add dev "$TUN_INTERFACE" mode tun user "$PSIPHON_USER" group "$PSIPHON_GROUP"; then
            error "Failed to create TUN interface"
            cleanup_routing
            return 1
        fi
    fi

    # Configure IPv4 interface
    if ! ip addr flush dev "$TUN_INTERFACE" 2>&1; then
        warning "Failed to flush TUN interface: $?"
    fi

    # Configure IPv4 point-to-point addresses
    if ! ip addr add "$TUN_IP" peer "$TUN_PEER_IP" dev "$TUN_INTERFACE" 2>&1; then
        error "Failed to add IPv4 point-to-point address to TUN interface"
        cleanup_routing
        return 1
    fi

    # Configure IPv6 interface with unique local address
    if ! ip -6 addr add "$TUN_IP6/64" dev "$TUN_INTERFACE" 2>&1; then
        warning "Failed to add IPv6 address to TUN interface: $?"
    fi

    # Bring up interface and wait for it to be ready
    ip link set "$TUN_INTERFACE" up

    # Wait for interface to be ready (both IPv4 and IPv6)
    local timeout=10
    local count=0
    while [ $count -lt $timeout ]; do
        if ip addr show dev "$TUN_INTERFACE" | grep -q "inet.*$TUN_IP" && \
           ip addr show dev "$TUN_INTERFACE" | grep -q "inet6.*$TUN_IP6"; then
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    if [ $count -eq $timeout ]; then
        warning "Timeout waiting for TUN interface to be fully ready"
    else
        log "TUN interface ready with both IPv4 and IPv6 addresses"
    fi

    # DON'T add default routes here - wait for RA processing
    log "TUN interface configured (routes will be added after RA processing)"

    # Update DNS configuration after routes are established
    change_dns_config

    success "TUN interface configured with IPv4 and IPv6 addresses"
}

# Network Security and Kill Switch Implementation
# Configures comprehensive traffic isolation and routing enforcement
function setup_routing() {
    log "Setting up routing and firewall rules..."


    # === WARP Integration Check === (WARP is optional)
    if is_warp_connected; then
        log "WARP detected and connected via interface: $WARP_INTERFACE"
        log "Configuring Psiphon → WARP → Internet routing chain"
        log "May not work very well for now"
    fi

    # === IPv4 Security Configuration ===
    # Enable controlled forwarding for tunnel operations
    # Required for proper VPN functionality while maintaining security
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Add to sysctl.conf for persistence
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
    fi

    # Setup iptables rules for TUN interface
    if ! iptables -F 2>&1; then
        warning "Failed to flush IPv4 rules: $?"
    fi
    if ! iptables -t nat -F 2>&1; then
        warning "Failed to flush IPv4 NAT rules: $?"
    fi
    # Show current tables for debugging
    log "Current IPv4 iptables rules:"
    iptables -L -v -n

    # Kill Switch: Block all traffic that is not going through the TUN interface
    log "Implementing IPv4 kill switch..."
    # Set default policy to DROP for output.
    if ! iptables -P OUTPUT DROP 2>&1; then
        error "Failed to set IPv4 OUTPUT policy to DROP"
        cleanup_routing
        return 1
    fi

    # # Allow established and related connections to prevent breaking existing sessions.
    # iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow loopback traffic for local services.
    iptables -A OUTPUT -o lo -j ACCEPT

    # # Allow traffic to local private networks.
    # iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
    # iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
    # iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT

    # Allow traffic for the psiphon user to establish the tunnel
    # and ensure it can access network resources
    iptables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -j ACCEPT

    # TODO: iptables --cmd-owner and --pid-owner are not supported on most of the systems
    #       so we can't use them for now
    #
    # if is_warp_connected && [[ -n "$WARP_INTERFACE" ]]; then
    #     # Route psiphon-user traffic through WARP interface for chained VPN
    #     log "Configuring psiphon-user to route through WARP interface"
    #     iptables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -o "$warp_interface" -j ACCEPT
    # else
    #     # Standard direct routing for psiphon-user
    #     iptables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -j ACCEPT
    # fi
    #
    # # Allow WARP service to connect if WARP is connected
    # if is_warp_connected; then
    #     local warp_pid
    #     if warp_pid=$(get_warp_svc_pid); then
    #         log "WARP detected - allowing warp-svc process (PID: $warp_pid) to access internet"
    #         # Use PID-based rule only (warp-svc runs as root, so can't use UID-based fallback)
    #         if iptables -A OUTPUT -m owner --pid-owner "$warp_pid" -j ACCEPT 2>/dev/null; then
    #             log "WARP allowed via PID-based rule"
    #         else
    #             warning "Failed to create WARP firewall rule - PID-based rules not supported"
    #         fi
    #     else
    #         warning "WARP status is Connected but warp-svc process not found"
    #     fi
    # else
    #     log "WARP not available - maintaining strict kill switch"
    # fi

    # Allow all traffic going through the TUN interface.
    iptables -A OUTPUT -o "$TUN_INTERFACE" -j ACCEPT

    # # Allow established connections
    # iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Setup iptables rules for TUN interface
    # Allow traffic from TUN interface
    iptables -A FORWARD -i "$TUN_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -o "$TUN_INTERFACE" -j ACCEPT 2>/dev/null || true

    # NAT traffic from TUN interface
    iptables -t nat -A POSTROUTING -s "$TUN_SUBNET" -o "$TUN_BYPASS_INTERFACE" -j MASQUERADE 2>/dev/null || true

    # # Redirect DNS traffic to force it through the tunnel, excluding psiphon-user
    # log "Redirecting DNS traffic through TUN..."
    # local DNS_SERVER_IP
    # DNS_SERVER_IP=$(echo "$TUN_DNS_SERVERS" | cut -d',' -f1)
    # iptables -t nat -A OUTPUT -p udp --dport 53 -m owner ! --uid-owner "$PSIPHON_USER" -j DNAT --to-destination "$DNS_SERVER_IP"
    # iptables -t nat -A OUTPUT -p tcp --dport 53 -m owner ! --uid-owner "$PSIPHON_USER" -j DNAT --to-destination "$DNS_SERVER_IP"

    # === IPv6 setup ===
    setup_ipv6_routing

    success "IPv4 and IPv6 Routing configured"
}

# setting up IPv6 routing
function setup_ipv6_routing() {
    log "Setting up IPv6 routing..."

    # Enable IPv6 forwarding
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    echo 1 > /proc/sys/net/ipv6/conf/default/forwarding

    # Ensure IPv6 is enabled on the TUN interface
    echo 0 > /proc/sys/net/ipv6/conf/"$TUN_INTERFACE"/disable_ipv6

    # # Lower the IPv6 route preference for all other interfaces
    # for interface in /proc/sys/net/ipv6/conf/*; do
    #     if [[ "$(basename "$interface")" != "$TUN_INTERFACE" && "$(basename "$interface")" != "all" && "$(basename "$interface")" != "default" ]]; then
    #         echo 100 > "$interface/route_pref" 2>/dev/null || true
    #     fi
    # done

    # Add to sysctl.conf for persistence
    if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
    fi

    # Setup ip6tables rules for TUN interface
    ip6tables -F 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true

    # Kill Switch: Block all IPv6 traffic that is not going through the TUN interface
    log "Implementing IPv6 kill switch..."
    # Set default policy to DROP for output.
    if ! ip6tables -P OUTPUT DROP 2>&1; then
        error "Failed to set IPv6 OUTPUT policy to DROP"
        cleanup_routing
        return 1
    fi

    # # Allow established and related connections.
    # ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow loopback traffic.
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # # Allow link-local addresses for local network discovery.
    # ip6tables -A OUTPUT -d fe80::/10 -j ACCEPT

    # Allow traffic for the psiphon user to establish the tunnel
    # and ensure it can access network resources
    ip6tables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -j ACCEPT

    # TODO: iptables --cmd-owner and --pid-owner are not supported on most of the systems
    #       so we can't use them for now
    #
    # if is_warp_connected && [[ -n "$WARP_INTERFACE" ]]; then
    #     # Route psiphon-user IPv6 traffic through WARP interface for chained VPN
    #     log "Configuring psiphon-user IPv6 to route through WARP interface"
    #     ip6tables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -o "$WARP_INTERFACE" -j ACCEPT
    # else
    #     # Standard direct routing for psiphon-user IPv6
    #     ip6tables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -j ACCEPT
    # fi
    #
    # # Allow WARP service to connect if WARP is connected (IPv6)
    # if is_warp_connected; then
    #     local warp_pid
    #     if warp_pid=$(get_warp_svc_pid); then
    #         log "WARP detected - allowing warp-svc process (PID: $warp_pid) to access internet (IPv6)"
    #         # Use PID-based rule only (warp-svc runs as root, so can't use UID-based fallback)
    #         if ip6tables -A OUTPUT -m owner --pid-owner "$warp_pid" -j ACCEPT 2>/dev/null; then
    #             log "WARP IPv6 allowed via PID-based rule"
    #         else
    #             warning "Failed to create WARP IPv6 firewall rule - PID-based rules not supported"
    #         fi
    #     else
    #         warning "WARP status is Connected but warp-svc process not found"
    #     fi
    # else
    #     log "WARP not available - maintaining strict IPv6 kill switch"
    # fi

    # Allow all traffic going through the TUN interface.
    ip6tables -A OUTPUT -o "$TUN_INTERFACE" -j ACCEPT

    # # Allow established connections
    # ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Setup ip6tables rules for TUN interface
    ip6tables -A FORWARD -i "$TUN_INTERFACE" -j ACCEPT 2>/dev/null || true
    ip6tables -A FORWARD -o "$TUN_INTERFACE" -j ACCEPT 2>/dev/null || true

    # NAT IPv6 traffic from TUN interface
    ip6tables -t nat -A POSTROUTING -s "$TUN_SUBNET6" -o "$TUN_BYPASS_INTERFACE" -j MASQUERADE 2>/dev/null || true

    # # Redirect IPv6 DNS traffic
    # local DNS_SERVER_IP6
    # DNS_SERVER_IP6=$(echo "$TUN_DNS_SERVERS6" | cut -d',' -f1)
    # ip6tables -t nat -A OUTPUT -p udp --dport 53 -m owner ! --uid-owner "$PSIPHON_USER" -j DNAT --to-destination "$DNS_SERVER_IP6"
    # ip6tables -t nat -A OUTPUT -p tcp --dport 53 -m owner ! --uid-owner "$PSIPHON_USER" -j DNAT --to-destination "$DNS_SERVER_IP6"

    success "IPv6 routing configured"
}

# Waits for IPv4 routing to stabilize
function wait_for_ipv4_routing() {
    log "Waiting for IPv4 routing to stabilize..."
    local timeout=10
    local count=0

    while [ $count -lt $timeout ]; do
        # Check if default route exists through TUN interface with peer gateway
        if ip route show default | grep -q "via $TUN_PEER_IP dev $TUN_INTERFACE"; then
            log "IPv4 routing stabilized"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done

    warning "IPv4 routing didn't stabilize within $timeout seconds"
    log "Current IPv4 routes:"
    ip route show | head -5
    return 1
}

# Comprehensive network readiness check
function check_network_readiness() {
    log "Performing comprehensive network readiness check..."
    local issues=0

    # Check TUN interface exists and is UP
    if ! ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        error "TUN interface $TUN_INTERFACE does not exist"
        issues=$((issues + 1))
    elif ! ip link show "$TUN_INTERFACE" | grep -q "UP"; then
        error "TUN interface $TUN_INTERFACE is not UP"
        issues=$((issues + 1))
    else
        log "✓ TUN interface $TUN_INTERFACE is UP"
    fi

    # Check TUN interface has IPv4 address
    if ! ip addr show "$TUN_INTERFACE" | grep -q "inet.*$TUN_IP"; then
        error "TUN interface missing IPv4 address $TUN_IP"
        issues=$((issues + 1))
    else
        log "✓ TUN interface has IPv4 address"
    fi

    # Check TUN interface has IPv6 address
    if ! ip addr show "$TUN_INTERFACE" | grep -q "inet6.*$TUN_IP6"; then
        warning "TUN interface missing IPv6 address $TUN_IP6"
    else
        log "✓ TUN interface has IPv6 address"
    fi

    # Check bypass interface exists and is UP
    if ! ip link show "$TUN_BYPASS_INTERFACE" >/dev/null 2>&1; then
        error "Bypass interface $TUN_BYPASS_INTERFACE does not exist"
        issues=$((issues + 1))
    elif ! ip link show "$TUN_BYPASS_INTERFACE" | grep -q "UP"; then
        error "Bypass interface $TUN_BYPASS_INTERFACE is not UP"
        issues=$((issues + 1))
    else
        log "✓ Bypass interface $TUN_BYPASS_INTERFACE is UP"
    fi

    # Check IPv4 default route through TUN
    if ! ip route show default | grep -q "$TUN_INTERFACE"; then
        warning "No IPv4 default route through $TUN_INTERFACE"
    else
        log "✓ IPv4 default route configured"
    fi

    # Check IPv6 default route through TUN
    if ! ip -6 route show default | grep -q "$TUN_INTERFACE"; then
        warning "No IPv6 default route through $TUN_INTERFACE"
    else
        log "✓ IPv6 default route configured"
    fi

    # Check iptables kill switch is active
    local ipv4_policy
    ipv4_policy=$(iptables -S | grep "^-P OUTPUT" | awk '{print $3}')
    if [[ "$ipv4_policy" != "DROP" ]]; then
        error "IPv4 kill switch (OUTPUT DROP policy) not active (current: ${ipv4_policy:-ACCEPT})"
        issues=$((issues + 1))
    else
        log "✓ IPv4 kill switch active"
    fi

    # Check ip6tables kill switch is active
    local ipv6_policy
    ipv6_policy=$(ip6tables -S | grep "^-P OUTPUT" | awk '{print $3}')
    if [[ "$ipv6_policy" != "DROP" ]]; then
        error "IPv6 kill switch (OUTPUT DROP policy) not active (current: ${ipv6_policy:-ACCEPT})"
        issues=$((issues + 1))
    else
        log "✓ IPv6 kill switch active"
    fi

    # Note: Connectivity tests are skipped here since Psiphon hasn't started yet
    log "✓ Network configuration complete (connectivity will be tested after Psiphon starts)"

    if [ $issues -eq 0 ]; then
        success "Network readiness check passed"
        return 0
    else
        error "Network readiness check failed with $issues critical issues"
        cleanup_routing
        return 1
    fi
}

# Network diagnostic function for troubleshooting
function diagnose_network_issues() {
    log "=== Network Diagnostic Report ==="
    log "Gathering comprehensive network state information..."

    # Basic interface information
    log ""
    log "1. Interface Status:"
    log "TUN Interface ($TUN_INTERFACE):"
    if ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        ip link show "$TUN_INTERFACE" | sed 's/^/   /'
        ip addr show "$TUN_INTERFACE" | grep -E "(inet|inet6)" | sed 's/^/   /'
    else
        log "   ERROR: TUN interface does not exist"
    fi

    log ""
    log "Bypass Interface ($TUN_BYPASS_INTERFACE):"
    if ip link show "$TUN_BYPASS_INTERFACE" >/dev/null 2>&1; then
        ip link show "$TUN_BYPASS_INTERFACE" | head -1 | sed 's/^/   /'
        ip addr show "$TUN_BYPASS_INTERFACE" | grep -E "(inet|inet6)" | head -2 | sed 's/^/   /'
    else
        log "   ERROR: Bypass interface does not exist"
    fi

    # Routing information
    log ""
    log "2. Routing Tables:"
    log "IPv4 Default Routes:"
    ip route show default | head -5 | sed 's/^/   /' || log "   No IPv4 default routes"

    log "IPv6 Default Routes:"
    ip -6 route show default | head -5 | sed 's/^/   /' || log "   No IPv6 default routes"

    log "TUN Interface Routes:"
    ip route show dev "$TUN_INTERFACE" | head -3 | sed 's/^/   /' || log "   No routes via TUN interface"

    # Firewall status
    log ""
    log "3. Firewall Status:"
    log "IPv4 iptables OUTPUT policy:"
    iptables-save

    log "IPv6 ip6tables OUTPUT policy:"
    ip6tables-save

    # Process status
    log ""
    log "4. Process Status:"
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        local pids
        pids=$(pgrep -f "psiphon-tunnel-core")
        log "Psiphon processes: $pids"
        for pid in $pids; do
            if ps -p "$pid" -o pid,ppid,user,args --no-headers 2>/dev/null; then
                ps -p "$pid" -o pid,ppid,user,args --no-headers | sed 's/^/   /'
            fi
        done
    else
        log "   No Psiphon processes found"
    fi

    # DNS configuration
    log ""
    log "5. DNS Configuration:"
    if [[ -f /etc/resolv.conf ]]; then
        log "Current resolv.conf:"
        head -5 /etc/resolv.conf | sed 's/^/   /'
    fi

    # Connectivity tests
    log ""
    log "6. Connectivity Tests:"

    # Test IPv4 connectivity through TUN (only if Psiphon is running)
    log "IPv4 connectivity test through TUN (HTTP):"
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        if timeout 8 curl -4 -s --interface "$TUN_INTERFACE" --connect-timeout 5 -o /dev/null http://www.google.com/generate_204 2>/dev/null; then
            log "   ✓ IPv4 HTTP through TUN successful"
        else
            log "   ✗ IPv4 HTTP through TUN failed"
        fi
    else
        log "   - Psiphon not running, skipping connectivity test"
    fi

    # Test IPv6 connectivity through TUN (only if Psiphon is running)
    log "IPv6 connectivity test through TUN (HTTP):"
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        if timeout 8 curl -6 -s --interface "$TUN_INTERFACE" --connect-timeout 5 -o /dev/null http://www.google.com/generate_204 2>/dev/null; then
            log "   ✓ IPv6 HTTP through TUN successful"
        else
            log "   ✗ IPv6 HTTP through TUN failed"
        fi
    else
        log "   - Psiphon not running, skipping connectivity test"
    fi

    # System information
    log ""
    log "7. System Information:"
    log "Kernel version: $(uname -r)"
    log "Available network namespaces: $(ip netns list 2>/dev/null | wc -l)"

    # Check for conflicting services
    log ""
    log "8. Potential Conflicts:"
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        log "   WARNING: NetworkManager is active (may interfere)"
    fi

    if systemctl is-active systemd-networkd >/dev/null 2>&1; then
        log "   INFO: systemd-networkd is active"
    fi

    if pgrep -f "warp-svc" >/dev/null 2>&1; then
        log "   INFO: WARP service detected"
    fi

    log ""
    log "=== End Diagnostic Report ==="
    success "Network diagnostic complete - review output above for issues"
}

function wait_for_ra_processing() {
    log "Waiting for Router Advertisement processing..."

    local timeout=30
    local count=0

    # Wait for any IPv6 changes to settle
    # This includes both native network RA and tunnel RA
    while [ $count -lt $timeout ]; do
        local current_routes
        current_routes=$(ip -6 route show 2>/dev/null | md5sum)

        # Wait a bit
        sleep 2
        count=$((count + 2))

        # Check if routes have stabilized
        local new_routes
        new_routes=$(ip -6 route show 2>/dev/null | md5sum)

        if [ "$current_routes" = "$new_routes" ]; then
            # Routes stable for 2 seconds
            log "IPv6 routes stabilized"
            break
        else
            log "IPv6 routes still changing, waiting... ($count/$timeout)"
        fi
    done

    if [ $count -ge $timeout ]; then
        warning "IPv6 route changes didn't stabilize within $timeout seconds, proceeding"
    fi

    # Log final IPv6 state
    log "Final IPv6 route state:"
    ip -6 route show

    success "RA processing wait completed"
}

function setup_tun_routes_after_ra() {
    log "Setting up TUN routes after RA processing..."

    # Delete any existing default routes for TUN interface first
    ip route del default dev "$TUN_INTERFACE" 2>/dev/null || true
    ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true

    # Add explicit route for TUN subnet if needed
    if ! ip route show | grep -q "$TUN_SUBNET.*$TUN_INTERFACE"; then
        log "Adding TUN subnet route..."
        ip route add "$TUN_SUBNET" dev "$TUN_INTERFACE" 2>/dev/null || true
    fi

    # Set up IPv4 routing with retry logic
    log "Setting up IPv4 default route..."
    local retry_count=0
    local ipv4_success=false

    while [ $retry_count -lt 3 ]; do
        if ip route add default via "$TUN_PEER_IP" dev "$TUN_INTERFACE" metric 50 2>/dev/null; then
            log "IPv4 default route added successfully via $TUN_PEER_IP"
            ipv4_success=true
            break
        else
            warning "Failed to add IPv4 default route, attempt $((retry_count + 1))/3"
            # Clean up any partial routes
            ip route del default via "$TUN_PEER_IP" dev "$TUN_INTERFACE" 2>/dev/null || true
            sleep 2
            retry_count=$((retry_count + 1))
        fi
    done

    if [ "$ipv4_success" = false ]; then
        error "Failed to establish IPv4 default route after 3 attempts"
        log "Current IPv4 routes:"
        ip route show
        cleanup_routing
        return 1
    fi

    # Wait for IPv4 routing to stabilize
    if ! wait_for_ipv4_routing; then
        warning "IPv4 routing stabilization check failed, but continuing"
    fi

    # Set up IPv6 routing with retry logic
    log "Setting up IPv6 default route..."
    retry_count=0
    local ipv6_success=false

    while [ $retry_count -lt 3 ]; do
        if ip -6 route add default dev "$TUN_INTERFACE" metric 50 pref high 2>/dev/null; then
            log "IPv6 default route added successfully"
            ipv6_success=true
            break
        else
            warning "Failed to add IPv6 default route, attempt $((retry_count + 1))/3"
            # Clean up any partial routes
            ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true
            sleep 2
            retry_count=$((retry_count + 1))
        fi
    done

    if [ "$ipv6_success" = false ]; then
        warning "Failed to establish IPv6 default route after 3 attempts"
        log "Current IPv6 routes:"
        ip -6 route show | head -10
    fi

    # Verify both routing tables are working
    local final_check_count=0
    while [ $final_check_count -lt 5 ]; do
        local ipv4_route_ok=false
        local ipv6_route_ok=false

        if ip route show default | grep -q "via $TUN_PEER_IP dev $TUN_INTERFACE"; then
            ipv4_route_ok=true
        fi

        if ip -6 route show default | grep -q "$TUN_INTERFACE"; then
            ipv6_route_ok=true
        fi

        if [ "$ipv4_route_ok" = true ] || [ "$ipv6_route_ok" = true ]; then
            if [ "$ipv4_route_ok" = true ]; then
                log "IPv4 routing verified"
            fi
            if [ "$ipv6_route_ok" = true ]; then
                log "IPv6 routing verified"
            fi
            break
        fi

        sleep 1
        final_check_count=$((final_check_count + 1))
    done

    # Show routing table for debugging
    log "Final IPv4 routes:"
    ip route show | head -5
    log "Final IPv6 routes:"
    ip -6 route show | head -5

    success "TUN routes configured after RA processing"
}

# systemd service psiphon binary restart helper
function systemd_psiphon_reload() {
    log "Reloading Psiphon binary service..."
    systemctl --no-block restart "$SERVICE_BINARY_NAME.service"
    success "Psiphon binary service reload command issued."
}


# Secure Service Initialization
# Starts Psiphon with security-first approach:
# 1. Validates binary integrity
# 2. Ensures proper permissions
# 3. Implements process isolation
# 4. Establishes secure tunnel configuration
function start_psiphon() {
    log "Initializing secure Psiphon service with TUN support..."

    # Verify binary exists and is executable
    if [[ ! -f "$PSIPHON_BINARY" ]]; then
        error "Psiphon binary not found at $PSIPHON_BINARY"
        return 1
    fi

    # if [[ ! -x "$PSIPHON_BINARY" ]]; then
    #     error "Psiphon binary is not executable"
    #     return 1
    # fi

    # Verify config exists
    if [[ ! -f "$PSIPHON_CONFIG_FILE" ]]; then
        error "Psiphon config not found at $PSIPHON_CONFIG_FILE"
        return 1
    fi

    # Kill any existing Psiphon processes
    pkill -f "psiphon-tunnel-core.*$TUN_INTERFACE" 2>/dev/null || true
    # Wait for processes to actually terminate
    local wait_count=0
    while pgrep -f "psiphon-tunnel-core.*$TUN_INTERFACE" >/dev/null 2>&1 && [ $wait_count -lt 10 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    # In service mode, run as a systemd service
    if [[ "$SERVICE_MODE" == "true" ]]; then
        log "start the homepage monitor service..."
        systemctl start $SERVICE_HOMEPAGE_MONITOR.path
        # Wait for service to be active
        local wait_count=0
        while [ "$(systemctl is-active $SERVICE_HOMEPAGE_MONITOR.path 2>/dev/null)" != "active" ] && [ $wait_count -lt 10 ]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done
        log "start the psiphon binary service..."
        systemctl start $SERVICE_BINARY_NAME.service
        log "Run: systemctl status $SERVICE_BINARY_NAME.service"
        log "   to check the status of the Psiphon binary service."
    else
        # For manual mode, keep the background process

        # Start Psiphon with native TUN support
        sudo -u "$PSIPHON_USER" "$PSIPHON_BINARY" \
            -config "$PSIPHON_CONFIG_FILE" \
            -dataRootDirectory "$INSTALL_DIR/data" \
            -tunDevice "$TUN_INTERFACE" \
            -tunBindInterface "$TUN_BYPASS_INTERFACE" \
            -tunDNSServers "$TUN_DNS_SERVERS,$TUN_DNS_SERVERS6" \
            -formatNotices \
            -useNoticeFiles 2>&1 | sudo -u "$PSIPHON_USER" tee -a "$PSIPHON_LOG_FILE" &

        local psiphon_pid=$!

        # Wait for process to initialize
        local wait_count=0
        while ! kill -0 "$psiphon_pid" 2>/dev/null && [ $wait_count -lt 10 ]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done

        # Wait until connected
        log "waiting psiphon to connect..."
        until tail -n 5 "$PSIPHON_LOG_FILE" | grep -q "ConnectedServerRegion"
        do
            echo -n "."
            sleep 1
        done

        echo ""

        # Open sponsor URL securely
        # We ignore errors here to avoid blocking startup
        if open_sponsor_url; then
            log "Sponsor URL opened successfully"
        else
            warning "Failed to open sponsor URL"
        fi

        # Verify process started successfully
        if [[ -z "$psiphon_pid" ]] || ! kill -0 "$psiphon_pid" 2>/dev/null; then
            error "Failed to start Psiphon or process died immediately"
            return 1
        fi

        echo "$psiphon_pid" | tee $PID_FILE >/dev/null
        chown root:root $PID_FILE
        chmod 644 $PID_FILE

        # Test if connection is actually working
        log "Verifying tunnel connectivity..."
        sleep 2
        local is_connected=0
        if timeout 10 curl -4s --interface "$TUN_INTERFACE" -m 7 https://youtube.com/generate_204 >/dev/null 2>&1; then
            log "IPv4 Connection verified through tunnel"
            is_connected++
        else
            warning "Could not verify tunnel IPv4 connectivity, but proceeding"
        fi
        sleep 1
        if timeout 10 curl -6s --interface "$TUN_INTERFACE" -m 7 https://youtube.com/generate_204 >/dev/null 2>&1; then
            log "IPv6 Connection verified through tunnel"
            is_connected++
        else
            warning "Could not verify tunnel IPv6 connectivity, but proceeding"
        fi

        if [[ $is_connected -lt 2 ]]; then
            warning "Consider the script manually!"
        fi

        # Final verification
        if ! kill -0 "$psiphon_pid" 2>/dev/null; then
            error "Psiphon process died after startup"
            return 1
        fi

        success "Psiphon started successfully with native TUN support (PID: $psiphon_pid)"
    fi
}

function open_sponsor_url() {
    # Open sponsor URL with enhanced security
    if [[ -z "$PSIPHON_SPONSOR_HOMEPAGE_PATH" || ! -f "$PSIPHON_SPONSOR_HOMEPAGE_PATH" ]]; then
        warning "Invalid or missing homepage file"
        return 1
    fi

    # Verify file permissions and ownership
    local file_perms
    file_perms=$(stat -c "%a" "$PSIPHON_SPONSOR_HOMEPAGE_PATH" 2>/dev/null)
    if [[ "$file_perms" != "600" && "$file_perms" != "644" ]]; then
        warning "Invalid homepage file permissions: $file_perms (expected 600 or 644)"
        return 1
    fi

    # Extract and validate URL using jq with explicit error checking
    local SPONSOR_URL
    if ! SPONSOR_URL=$(jq -r '.data.url // empty' "$PSIPHON_SPONSOR_HOMEPAGE_PATH" 2>/dev/null); then
        warning "Failed to parse homepage JSON file"
        return 1
    fi

    # Enhanced URL validation
    if [[ -z "$SPONSOR_URL" || "$SPONSOR_URL" == "null" ]]; then
        warning "Empty or null sponsor URL"
        return 1
    fi

    # Primary security check: URL pattern validation
    local url_regex='^https://ipfounder\.net/\?sponsor_id=[A-Za-z0-9]+[^[:space:]]*$'
    if [[ ! "$SPONSOR_URL" =~ $url_regex ]]; then
        warning "Invalid sponsor URL format detected"
        log "Security: Blocked attempt to open non-conforming URL"
        return 1
    fi

    # Secondary security check: Additional URL validation
    if [[ ${#SPONSOR_URL} -gt 500 ]]; then
        warning "URL exceeds maximum allowed length"
        return 1
    fi

    # Additional security: Check for suspicious characters
    if echo "$SPONSOR_URL" | grep -q '[;<>`|]'; then
        warning "URL contains suspicious characters"
        log "Security: Blocked URL with potentially dangerous characters"
        return 1
    fi

    # Get the active logged-in user with validation
    local ACTIVE_USER
    ACTIVE_USER="$(logname)"
    if [[ -z "$ACTIVE_USER" || "$ACTIVE_USER" == "root" ]]; then
        warning "No suitable non-root user found to open URL"
        return 1
    fi

    # Verify the user exists and is valid
    if ! id "$ACTIVE_USER" >/dev/null 2>&1; then
        warning "Invalid user account"
        return 1
    fi

    if ! command -v gio >/dev/null 2>&1; then
        warning "gio command not found"
        return 1
    fi

    log "Opening verified sponsor URL for user: $ACTIVE_USER"
    log "Sponsor URL: $SPONSOR_URL"

    # Execute with restricted environment
    (
        exec runuser -u "$ACTIVE_USER" \
        --whitelist-environment=DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR \
        -- gio open "$SPONSOR_URL" >/dev/null 2>&1 &
    )

    log "URL_OPEN: user=$ACTIVE_USER url_hash=$(echo -n "$SPONSOR_URL" | sha256sum | cut -d' ' -f1)"
    return 0
}

# Start all services
function start_services() {
    log "Starting services..."

    if start_psiphon; then
        success "Psiphon TUN service started successfully"
    else
        error "Failed to start services"
        stop_services
        return 1
    fi
}

function cleanup_routing() {
    log "Cleaning up routing and firewall rules..."

    # Disable kill switch: Reset default policies to ACCEPT and flush all firewall rules
    log "Disabling firewall kill switch..."
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true

    ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true

    # The default routes are removed when the TUN interface is deleted, but we can be explicit.
    ip route del default via "$TUN_PEER_IP" dev "$TUN_INTERFACE" 2>/dev/null || true
    ip route del default dev "$TUN_INTERFACE" 2>/dev/null || true
    ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true

    success "Routing and firewall rules cleaned up."
}

# Stop all services
function stop_services() {
    log "Stopping services..."

    local stopped_something=false

    if [[ "$SERVICE_MODE" == "true" ]]; then
        systemctl stop $SERVICE_HOMEPAGE_MONITOR.path
        if systemctl is-active --quiet $SERVICE_HOMEPAGE_MONITOR.path 2>/dev/null; then
            warning "Psiphon homepage monitor service did not stop cleanly, attempting to kill process..."
        else
            log "Psiphon homepage monitor service stopped."
            stopped_something=true
        fi

        systemctl stop $SERVICE_BINARY_NAME.service
        # Check if still running
        if systemctl is-active --quiet $SERVICE_BINARY_NAME.service 2>/dev/null; then
            warning "Psiphon binary service did not stop cleanly, attempting to kill process..."
        else
            log "Psiphon binary service stopped."
            stopped_something=true
        fi

        systemctl stop $SERVICE_HOMEPAGE_TRIGGER.service
        if systemctl is-active --quiet $SERVICE_HOMEPAGE_TRIGGER.service 2>/dev/null; then
            warning "Psiphon homepage trigger service did not stop cleanly."
        else
            log "Psiphon homepage trigger service stopped."
            stopped_something=true
        fi
    fi

    # Stop Psiphon
    if [[ -f $PID_FILE ]]; then
        local psiphon_pid
        psiphon_pid=$(cat $PID_FILE 2>/dev/null || echo "")
        if [[ -n "$psiphon_pid" ]] && kill -0 "$psiphon_pid" 2>/dev/null; then
            # Try graceful shutdown first
            kill -TERM "$psiphon_pid" 2>/dev/null || true
            # Wait for graceful termination
            local wait_count=0
            while kill -0 "$psiphon_pid" 2>/dev/null && [ $wait_count -lt 7 ]; do
                sleep 1
                wait_count=$((wait_count + 1))
            done
            # Force kill if still running
            if kill -0 "$psiphon_pid" 2>/dev/null; then
                kill -KILL "$psiphon_pid" 2>/dev/null || true
                sleep 1
            fi
            stopped_something=true
        fi
        rm -f $PID_FILE
    fi

    # Kill any remaining Psiphon processes
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        pkill -f "psiphon-tunnel-core" 2>/dev/null || true
        stopped_something=true
    fi

    # Clean up routing and firewall rules before taking down the interface
    cleanup_routing

    # Reset systemd-resolved configuration
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        log "Resetting systemd-resolved configuration..."
        rm -f /etc/systemd/resolved.conf.d/psiphon-tun.conf
        systemctl restart systemd-resolved
    else
        # Restore original DNS configuration
        if [ -f /etc/resolv.conf.original ]; then
            cp -fP /etc/resolv.conf.original /etc/resolv.conf
        fi
    fi

    # Bring down TUN interface
    if ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        ip link set "$TUN_INTERFACE" down 2>/dev/null || true
        ip link delete "$TUN_INTERFACE" 2>/dev/null || true
        stopped_something=true
    fi

    # Wait for services to actually stop
    local wait_count=0
    while (systemctl is-active $SERVICE_BINARY_NAME.service >/dev/null 2>&1 || systemctl is-active $SERVICE_HOMEPAGE_MONITOR.path >/dev/null 2>&1) && [ $wait_count -lt 7 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if $stopped_something; then
        success "Services stopped successfully"
    else
        log "No running services found"
    fi
}

# Install everything
function install_shell() {
    log "Installing Psiphon TUN setup..."

    check_dependencies
    create_user
    create_directories
    check_and_update_psiphon
    create_psiphon_config

    create_systemd_services

    success "Psiphon TUN setup installed successfully"
    log "Use '$0 start' to start the service"
    log "Use 'sudo systemctl enable $SERVICE_CONFIGURE_NAME' to start automatically at boot"
    log "Use 'sudo systemctl start $SERVICE_CONFIGURE_NAME' to start via systemd"
}

# Uninstall everything
function uninstall() {
    log "Uninstalling Psiphon TUN setup..."

    # Stop services first
    stop_services
    # Disable and remove systemd configuration services
    if systemctl is-enabled --quiet "$SERVICE_CONFIGURE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_CONFIGURE_NAME" 2>/dev/null || true
    fi
    # Disable and remove systemd binary services
    if systemctl is-enabled --quiet "$SERVICE_BINARY_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_BINARY_NAME" 2>/dev/null || true
    fi
    # Disable and remove homepage monitor service
    if systemctl is-enabled --quiet "$SERVICE_HOMEPAGE_MONITOR" 2>/dev/null; then
        systemctl disable "$SERVICE_HOMEPAGE_MONITOR" 2>/dev/null || true
    fi
    # Disable and remove homepage trigger service
    if systemctl is-enabled --quiet "$SERVICE_HOMEPAGE_TRIGGER" 2>/dev/null; then
        systemctl disable "$SERVICE_HOMEPAGE_TRIGGER" 2>/dev/null || true
    fi

    systemctl stop $SERVICE_CONFIGURE_NAME.service
    if systemctl is-active --quiet $SERVICE_CONFIGURE_NAME.service 2>/dev/null; then
        warning "Psiphon configuration service did not stop cleanly."
    else
        log "Psiphon configuration service stopped."
        stopped_something=true
    fi

    rm -f /etc/systemd/system/$SERVICE_CONFIGURE_NAME.service
    rm -f /etc/systemd/system/$SERVICE_BINARY_NAME.service
    rm -f /etc/systemd/system/$SERVICE_HOMEPAGE_MONITOR.path
    rm -f /etc/systemd/system/$SERVICE_HOMEPAGE_TRIGGER.service

    systemctl daemon-reload 2>/dev/null || true


    # Remove installation directory
    if [[ -d "$INSTALL_DIR" ]]; then
        read -p "Remove installation directory $INSTALL_DIR? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            log "Installation directory removed"
        fi
    fi

    # Remove user and group
    read -p "Remove user and group ($PSIPHON_USER, $PSIPHON_GROUP)? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        userdel "$PSIPHON_USER" 2>/dev/null || true
        groupdel "$PSIPHON_GROUP" 2>/dev/null || true
        log "User and group removed"
    fi

    success "Psiphon TUN setup uninstalled"
}

# Get WARP status
function get_warp_status() {
    ACTIVE_USER=$(logname)
    local status_output
    if [[ -x "$WARP_CLI_PATH" ]]; then
        status_output=$(exec runuser -u "$ACTIVE_USER" -- "$WARP_CLI_PATH" status 2>/dev/null || echo "ERROR")
        echo "$status_output"
    else
        echo "ERROR"
    fi
}

# Check if WARP is available and connected
function is_warp_connected() {
    [[ "$(get_warp_status)" == *"$WARP_STATUS_CONNECTED"* ]]
}

function get_warp_svc_pid() {
    # Get the PID of the warp-svc process - try multiple methods for reliability
    local warp_pid

    # Method 1: pgrep exact match
    warp_pid=$(pgrep -x "$WARP_SVC_PROCESS" 2>/dev/null | head -n1)

    # Method 2: fallback to pgrep with partial match
    if [[ -z "$warp_pid" ]]; then
        warp_pid=$(pgrep -f "$WARP_SVC_PROCESS" 2>/dev/null | head -n1)
    fi

    if [[ -n "$warp_pid" ]]; then
        echo "$warp_pid"
        return 0
    else
        return 1
    fi
}

function warp_status() {
    echo "=== WARP Integration Status ==="

    local psiphontunv4
    # Check WARP CLI availability
    if [[ -x "$WARP_CLI_PATH" ]]; then
        echo -e "WARP CLI: ${GREEN}Available${NC} ($WARP_CLI_PATH)"

        # Get WARP status
        local warp_status_output
        warp_status_output=$(get_warp_status)
        echo "WARP CLI Output: $warp_status_output"

        # Check connection status
        if is_warp_connected; then
            echo -e "WARP Status: ${GREEN}Connected${NC}"
            echo -e "WARP Interface: $WARP_INTERFACE"
            # Check WARP service process
            local warp_pid
            if warp_pid=$(get_warp_svc_pid); then
                echo -e "WARP Service: ${GREEN}Running${NC} (PID: $warp_pid)"
                echo -e "WARP Process: $WARP_SVC_PROCESS"
                echo -e "WARP User: root (warp-svc always runs as root)"

                # Check firewall rules for WARP
                echo ""
                echo "=== Firewall Configuration ==="
                echo "IPv4 rules for WARP process (PID: $warp_pid):"
                iptables -L OUTPUT -v -n | grep "$warp_pid" || echo "No PID-specific rules found"

                echo ""
                echo "IPv6 rules for WARP process (PID: $warp_pid):"
                ip6tables -L OUTPUT -v -n | grep "$warp_pid" || echo "No PID-specific rules found"

            else
                echo -e "WARP Service: ${RED}Process Not Found${NC}"
            fi

            # Test WARP connectivity
            echo ""
            echo "=== WARP Connectivity Test ==="
            # Try to detect if traffic is going through WARP
            local cdncgitracev4
            if cdncgitracev4=$(timeout 10 curl -4sSm 7 --interface $WARP_INTERFACE https://cloudflare.com/cdn-cgi/trace 2>/dev/null); then
                echo -e "WARP IPv4 Result: $(echo "$cdncgitracev4" | grep 'warp=')"
            else
                echo -e "WARP IPv4 Test: ${RED}FAILED${NC}"
            fi
            local cdncgitracev6
            if cdncgitracev6=$(timeout 10 curl -6sSm 7 --interface $WARP_INTERFACE https://cloudflare.com/cdn-cgi/trace 2>/dev/null); then
                echo -e "WARP IPv6 Result: $(echo "$cdncgitracev6" | grep 'warp=')"
            else
                echo -e "WARP IPv6 Test: ${RED}FAILED${NC}"
            fi

            # Check if psiphon process is active and has a connection to the internet
            local psiphonipv4
            psiphonipv4=$(timeout 10 curl -4sSm 7 -x socks5://127.0.0.1:$SOCKS_PORT https://cloudflare.com/cdn-cgi/trace)

            # Check for active psiphon TUN interface
            if psiphontunv4=$(ip addr show dev $TUN_INTERFACE | grep -o 'inet [0-9.]*' | cut -d' ' -f2); then
                echo -e "Psiphon TUN IPv4: ${GREEN}$psiphontunv4${NC}"
                echo -e "• Traffic Flow: ${GREEN}All applications → PsiphonTUN → Psiphon Process → WARP → Internet${NC}"
                echo "• Kill Switch: All traffic blocked by default (OUTPUT DROP)"
                echo -e "• Whitelisted: $PSIPHON_USER (for tunnel establishment)"
                # echo "• Whitelisted: $WARP_SVC_PROCESS PID (for WARP connectivity)"
            else
                if [[ $(echo "$cdncgitracev4" | grep 'warp=') == "warp=on" && $(echo "$psiphonipv4" | grep 'warp=') == "warp=off" ]]; then
                    echo -e "Psiphon running only as a proxy over WARP: ${GREEN}OK${NC}"
                    echo -e "• Traffic Flow 1: ${GREEN}Applications with proxy → Psiphon Process → WARP → Internet${NC}"
                    echo -e "• Traffic Flow 2: ${YELLOW}All other applications without proxy → WARP → Internet${NC}"
                elif  [[ $(echo "$cdncgitracev4" | grep 'warp=') == "warp=on" ]]; then
                    echo -e "• Traffic Flow: ${GREEN}Applications → WARP → Internet${NC}"
                fi
            fi
        else
            echo ""
            echo -e "=== WARP Status: ${RED}Not Connected${NC} ==="
        fi

    else
        echo -e "WARP CLI: ${RED}Not Available${NC} ($WARP_CLI_PATH)"
    fi
}

function status() {
    echo "=== Psiphon TUN Status ==="

    # Check if Psiphon process is running
    local psiphon_pid

    if [[ -f $PID_FILE ]]; then
        psiphon_pid=$(cat $PID_FILE 2>/dev/null || echo "")
        if [[ -n "$psiphon_pid" ]] && kill -0 "$psiphon_pid" 2>/dev/null; then
            echo -e "Psiphon: ${GREEN}RUNNING${NC} (PID: $psiphon_pid)"
        else
            echo -e "Psiphon: ${RED}STOPPED${NC} (stale PID file)"
        fi
    elif pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        psiphon_pid=$(pgrep -f "psiphon-tunnel-core")
        echo -e "Psiphon: ${YELLOW}RUNNING${NC} (PID: $psiphon_pid, no PID file)"
    else
        echo -e "Psiphon: ${RED}STOPPED${NC}"
    fi

    # Check TUN interface
    echo ""
    echo "=== Network Interface Status ==="
    if ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        local tun_ip
        tun_ip=$(ip addr show "$TUN_INTERFACE" | grep -o 'inet [0-9.]*' | cut -d' ' -f2 || echo "No IP")
        echo -e "TUN Interface: ${GREEN}UP${NC} ($TUN_INTERFACE, IP: $tun_ip)"
    else
        echo -e "TUN Interface: ${RED}DOWN${NC} ($TUN_INTERFACE)"
    fi

    # Check Routing
    echo ""
    echo "=== Routing Status ==="
    if ip route | grep -q "$TUN_INTERFACE"; then
        echo -e "TUN Routing: ${GREEN}CONFIGURED${NC}"
    else
        echo -e "TUN Routing: ${RED}NOT CONFIGURED${NC}"
    fi

    # Test connection if everything is running
    if [[ -n "${psiphon_pid:-}" ]] && kill -0 "$psiphon_pid" 2>/dev/null && ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        echo ""
        echo "=== Connection Test ==="
        local test_ip
        if test_ip=$(timeout 10 curl -s --interface "$TUN_INTERFACE" --connect-timeout 5 ifconfig.me 2>/dev/null); then
            # check for both IPv4 and IPv6 format
            if [[ -n "$test_ip" && ( "$test_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$test_ip" =~ ^[0-9a-f:]+$ ) ]]; then
                echo -e "External IP via TUN: ${GREEN}$test_ip${NC}"
            else
                echo -e "Connection Test: ${YELLOW}UNEXPECTED RESULT${NC} ($test_ip)"
            fi
        else
            echo -e "Connection Test: ${RED}FAILED${NC}"
            echo ""
            echo -e "${YELLOW}Connection test failed. Run 'sudo $0 diagnose' for detailed network diagnostics.${NC}"
        fi
    fi

    # IPv6 status test
    echo ""
    echo "=== IPv6 Status ==="
    if ip -6 addr show dev "$TUN_INTERFACE" >/dev/null 2>&1; then
        local ipv6_addr
        ipv6_addr=$(ip -6 addr show dev "$TUN_INTERFACE" | grep -o 'inet6 [0-9a-f:]*' | cut -d' ' -f2 || echo "No IPv6")
        echo -e "IPv6 Support: ${GREEN}ENABLED${NC}"
        echo -e "TUN IPv6: ${GREEN}$ipv6_addr${NC}"

        # # Test IPv6 connectivity
        # if timeout 10 ping6 -c 1 2606:4700:4700::1001 >/dev/null 2>&1; then
        #     echo -e "IPv6 Connectivity: ${GREEN}OK${NC}"
        # else
        #     echo -e "IPv6 Connectivity: ${RED}FAILED${NC}"
        # fi
    else
        echo -e "IPv6 Support: ${RED}NOT CONFIGURED${NC}"
        echo -e "${YELLOW}IPv6 not configured. Run 'sudo $0 diagnose' for detailed analysis.${NC}"
    fi

    echo ""
    echo "=== DNS Resolution Test ==="
    echo -e "DNS v4 Query Result: $(dig -4 +timeout=2 +retry=0 +short youtube.com @8.8.8.8 | head -n1)"
    echo -e "DNS v6 Query Result: $(dig -6 +timeout=2 +retry=0 +short youtube.com @2001:4860:4860::8888 | head -n1)"

    # WARP Status
    echo ""
    echo "=== WARP Integration Status ==="
    if [[ -x "$WARP_CLI_PATH" ]]; then
        if is_warp_connected; then
            echo -e "WARP Status: ${GREEN}Connected${NC}"
            if warp_pid=$(get_warp_svc_pid); then
                echo -e "WARP Service: ${GREEN}Running${NC} (PID: $warp_pid)"
            fi
        else
            echo -e "WARP Status: Not Connected"
            echo -e "VPN Mode: Psiphon Only"
        fi
    else
        echo -e "WARP CLI: ${RED}Not Installed${NC} ($WARP_CLI_PATH)"
        echo -e "VPN Mode: Psiphon Only"
    fi

    echo ""
    echo "=== curl test ==="
    echo -e "External IPv4 direct:\n$(timeout 10 curl -4sSm 7 https://cloudflare.com/cdn-cgi/trace)"
    echo ""
    sleep 1
    echo -e "External IPv6 direct:\n$(timeout 10 curl -6sSm 7 https://cloudflare.com/cdn-cgi/trace)"
    echo ""
    sleep 1
    echo -e "External IPv4 SOCKS port:\n$(timeout 10 curl -4sSm 7 -x socks5://127.0.0.1:$SOCKS_PORT https://cloudflare.com/cdn-cgi/trace)"
    echo ""
    sleep 1
    echo -e "External IPv6 SOCKS port:\n$(timeout 10 curl -6sSm 7 -x "socks5://[::ffff:127.0.0.1]:$SOCKS_PORT" https://cloudflare.com/cdn-cgi/trace)"
    echo ""
}

# Update Psiphon
function update() {
    log "Checking for Psiphon updates..."

    local was_running=false
    if [[ -f $PID_FILE ]]; then
        local psiphon_pid
        psiphon_pid=$(cat $PID_FILE 2>/dev/null || echo "")
        if [[ -n "$psiphon_pid" ]] && kill -0 "$psiphon_pid" 2>/dev/null; then
            was_running=true
        fi
    fi

    if $was_running; then
        log "Stopping services for update..."
        stop_services
    fi

    check_and_update_psiphon

    if $was_running; then
        log "Restarting services..."
        setup_tun_interface
        setup_routing
        start_services
    fi
}

# Show usage
function usage() {
    cat << EOF
      Freedom is the freedom to say that
          __o            o           __o                o     o
        o/  v\\          <|>        o/  v\\              <|>   <|>
       /|    <\\         < >       /|    <\\             / >   < \\
       //    o/         / \\       //    o/    _\\__o__  \\o__ __o/
            /v     _\\__o   o__/_       /v          \\   \\|__ __|
           />           \\ /           />      _\\__o__         |
         o/             <o>         o/             \\         <o>
        /v               |         /v                         |
       /> __o__/_       < >       /> __o__/_                 / \\
                            if that is granted, all else follows...
                                              ― George Orwell, 1984


Psiphon TUN Setup Script - Secure Tunneling Solution v$INSTALLER_VERSION

Usage: $0 [COMMAND]

COMMANDS:
    install     Install and configure Psiphon TUN setup
    uninstall   Remove Psiphon TUN setup completely
    start       Start Psiphon service with native TUN support
    stop        Stop Psiphon service and cleanup
    restart     Stop and restart Psiphon service
    status      Show status of all components
    diagnose    Run comprehensive network diagnostics for troubleshooting
    warp-status Check WARP integration status and configuration
    update      Check for and install Psiphon updates
    help        Show this help message

FEATURES:
    - Uses Psiphon's native TUN support (no external dependencies)
    - Automatic updates
    - Robust error handling and logging
    - Full traffic routing through Psiphon network
    - Support for both HTTP and SOCKS proxies

SECURITY FEATURES:
    • Runs Psiphon as dedicated non-root user ($PSIPHON_USER)
    • Binary integrity verification during download
    • Secure file permissions and ownership
    • Process isolation and capability restrictions
    • Input validation and error handling

NETWORK CONFIGURATION:
    • TUN Interface: $TUN_INTERFACE ($TUN_IP)
    • SOCKS Proxy: 127.0.0.1:$SOCKS_PORT
    • HTTP Proxy: 127.0.0.1:$HTTP_PORT
    • Traffic routing excludes Psiphon user to prevent loops

WARP INTEGRATION:
    • Auto-detects if WARP is connected (warp-cli status = Connected)
    • Creates VPN chain: Psiphon → WARP → Internet (may not work very well for now)
    • Use 'warp-status' command for detailed WARP integration info

FILES:
    • Install Directory: $INSTALL_DIR
    • Binary: $PSIPHON_BINARY
    • Psiphon Config: $PSIPHON_CONFIG_FILE
    • Logs: $LOG_FILE $(du -h "$LOG_FILE" | cut -f1)
    • Service: /etc/systemd/system/$SERVICE_CONFIGURE_NAME.service
    • Psiphon notices: $INSTALL_DIR/data/notices

EXAMPLES:
    $0 install          # Install and configure everything
    $0 start            # Start the TUN service
    $0 status           # Check service status

    # Systemd management:
    sudo systemctl enable $SERVICE_CONFIGURE_NAME    # Auto-start at boot
    sudo systemctl start $SERVICE_CONFIGURE_NAME     # Start via systemd
    sudo systemctl status $SERVICE_CONFIGURE_NAME    # Check systemd status

For more information, visit: https://github.com/boilingoden/psiphon-client-linux-service
And: https://github.com/Psiphon-Labs/psiphon-tunnel-core

EOF
}

# Main script logic
function main() {
    case "${1:-}" in
        install)
            check_root
            acquire_lock
            install_shell
            ;;
        uninstall)
            check_root
            acquire_lock
            uninstall
            ;;
        start)
            check_root
            acquire_lock
            check_and_update_psiphon
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            setup_tun_routes_after_ra
            check_network_readiness
            start_services
            ;;
        systemd_start)
            SERVICE_MODE="true"
            check_root
            acquire_lock
            check_and_update_psiphon
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            setup_tun_routes_after_ra
            check_network_readiness
            start_services
            ;;
        reload)
            check_root
            start_psiphon # it will first kill then start psiphon
            ;;
        systemd_reload)
            SERVICE_MODE="true"
            check_root
            systemd_psiphon_reload
            ;;
        stop)
            check_root
            acquire_lock
            stop_services
            ;;
        systemd_stop)
            SERVICE_MODE="true"
            check_root
            stop_services
            ;;
        restart)
            check_root
            acquire_lock
            stop_services
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            setup_tun_routes_after_ra
            check_network_readiness
            start_services
            ;;
        systemd_restart)
            SERVICE_MODE="true"
            check_root
            stop_services
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            setup_tun_routes_after_ra
            check_network_readiness
            start_services
            ;;
        status)
            status
            ;;
        diagnose)
            check_root
            diagnose_network_issues
            ;;
        warp-status)
            warp_status
            ;;
        update)
            check_root
            acquire_lock
            update
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            echo "Unknown command: ${1:-}"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
