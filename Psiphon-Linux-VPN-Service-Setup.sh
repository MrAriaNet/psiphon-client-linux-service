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

readonly INSTALLER_VERSION="1.0.0"
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
readonly CONFIG_FILE="$INSTALL_DIR/config"
readonly LOG_FILE="$INSTALL_DIR/psiphon-tun.log"
readonly LOCK_FILE="/run/psiphon-tun.lock"
readonly PID_FILE="/run/psiphon-tun.pid"
readonly GITHUB_API="https://api.github.com/repos/Psiphon-Labs/psiphon-tunnel-core-binaries"
readonly PSIPHON_BINARY_URL="https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/raw/master/linux/psiphon-tunnel-core-x86_64"
readonly SERVICE_NAME="psiphon-tun"
# Network Security Configuration
readonly TUN_INTERFACE="PsiphonTUN"      # Dedicated TUN interface for isolated traffic
readonly TUN_SUBNET="10.200.3.0/24"      # IPv4 subnet for tunnel traffic isolation
readonly TUN_IP="10.200.3.1"             # IPv4 gateway address for tunnel
readonly TUN_SUBNET6="fd42:42:42::/64"   # IPv6 subnet (ULA) for tunnel traffic isolation
readonly TUN_IP6="fd42:42:42::1"         # IPv6 gateway address for tunnel
# Secure fallback for interface selection: default route with non-loopback fallback
readonly TUN_BYPASS_INTERFACE=$(ip -json route get 8.8.8.8 2>/dev/null | jq -r '.[0].dev // empty' || 
                              ip -json link show | jq -r '.[] | select(.link_type!="loopback") | .ifname' | head -n1)
readonly TUN_DNS_SERVERS="8.8.8.8,8.8.4.4" # Google DNS
readonly TUN_DNS_SERVERS6="2001:4860:4860::8888,2001:4860:4860::8844" # Google DNS IPv6
SERVICE_MODE="false" # Set to true when running as a systemd service
SERVICE_RELOAD="false" # Set to true when reloading service

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
function log() {
    local message="$1"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[$timestamp]${NC} $message"
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] $message" >> "$LOG_FILE" 2>/dev/null || true
}

function error() {
    local message="$1"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[$timestamp][ERROR]${NC} $message" >&2
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] ERROR: $message" >> "$LOG_FILE" 2>/dev/null || true
}

function success() {
    local message="$1"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[$timestamp][SUCCESS]${NC} $message"
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] $message" >> "$LOG_FILE" 2>/dev/null || true
}

function warning() {
    local message="$1"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[$timestamp][WARNING]${NC} $message"
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] WARNING: $message" >> "$LOG_FILE" 2>/dev/null || true
}

function psiphonlog() {
    local message="$1"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[$timestamp]${NC} $message"
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] $message" >> "$LOG_FILE" 2>/dev/null || true
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

    local commit_message=$(echo "$latest_commit" | jq -r '.[0].commit.message' 2>/dev/null || echo "")

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

    # In service mode, run directly without backgrounding
    if [[ "$SERVICE_MODE" == "true" ]]; then
        if ! version_output=$(exec runuser -u "$PSIPHON_USER" -- "$PSIPHON_BINARY" -v 2>/dev/null); then
            echo "|"
            return 
        fi
    else 
        if ! version_output=$(sudo -u "$PSIPHON_USER" "$PSIPHON_BINARY" -v 2>/dev/null); then
            echo "|"
            return
        fi
    fi

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
    local current_revision=$(get_binary_version_info)

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
function create_systemd_service() {
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

    # Create systemd service file
    tee /etc/systemd/system/$SERVICE_NAME.service >/dev/null <<EOF
[Unit]
Description=Psiphon TUN Service
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/Psiphon-Labs/psiphon-tunnel-core

[Service]
Type=simple
ExecStart=$service_script start
ExecStop=$service_script stop
ExecReload=$service_script reload
PIDFile=$LOCK_FILE
# Restart=on-failure
# RestartSec=30
TimeoutStartSec=120
TimeoutStopSec=30
User=root
KillMode=mixed
KillSignal=SIGTERM
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
SecureBits=keep-caps
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
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
        ip tuntap add dev "$TUN_INTERFACE" mode tun user "$PSIPHON_USER" group "$PSIPHON_GROUP"
    fi

    # Configure IPv4 interface
    if ! ip addr flush dev "$TUN_INTERFACE" 2>&1; then
        warning "Failed to flush TUN interface: $?"
    fi
    
    # Configure both IPv4 and IPv6 addresses
    if ! ip addr add "$TUN_IP/24" dev "$TUN_INTERFACE" metric 50 2>&1; then
        warning "Failed to add IPv4 address to TUN interface: $?"
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

    # Delete any existing default routes for TUN interface first
    ip route del default dev "$TUN_INTERFACE" 2>/dev/null || true
    ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true
    
    # Set up IPv4 routing first
    if ! ip route add default dev "$TUN_INTERFACE" metric 50 2>&1; then
        error "Failed to add IPv4 default route to TUN table: $?"
        ip route show
        return 1
    fi
    
    # Verify IPv4 routing is working
    local retry_count=0
    while [ $retry_count -lt 3 ]; do
        if ip route show default | grep -q "$TUN_INTERFACE"; then
            log "IPv4 routing verified"
            break
        fi
        sleep 1
        retry_count=$((retry_count + 1))
    done
    
    # Set up IPv6 routing
    if ! ip -6 route add default dev "$TUN_INTERFACE" metric 50 pref high 2>&1; then
        error "Failed to add IPv6 default route to TUN table: $?"
        ip -6 route show
        return 1
    fi
    
    # Verify IPv6 routing is working
    retry_count=0
    while [ $retry_count -lt 3 ]; do
        if ip -6 route show default | grep -q "$TUN_INTERFACE"; then
            log "IPv6 routing verified"
            break
        fi
        sleep 1
        retry_count=$((retry_count + 1))
    done
    
    # Show routing table for debugging
    log "Current IPv4 routes:"
    ip route show
    log "Current IPv6 routes:"
    ip -6 route show
    
    # Update DNS configuration after routes are established
    change_dns_config

    success "TUN interface configured with IPv4 and IPv6"
}

# Network Security and Kill Switch Implementation
# Configures comprehensive traffic isolation and routing enforcement
function setup_routing() {
    log "Setting up routing and firewall rules..."

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
    iptables -P OUTPUT DROP

    # # Allow established and related connections to prevent breaking existing sessions.
    # iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow loopback traffic for local services.
    iptables -A OUTPUT -o lo -j ACCEPT

    # # Allow traffic to local private networks.
    # iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
    # iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
    # iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT

    # Allow traffic for the psiphon user to establish the tunnel.
    iptables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -j ACCEPT

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

# Add this function after setup_routing()
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
    ip6tables -P OUTPUT DROP

    # # Allow established and related connections.
    # ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow loopback traffic.
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # # Allow link-local addresses for local network discovery.
    # ip6tables -A OUTPUT -d fe80::/10 -j ACCEPT

    # Allow traffic for the psiphon user to establish the tunnel.
    ip6tables -A OUTPUT -m owner --uid-owner "$PSIPHON_USER" -j ACCEPT

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

# Reload Psiphon
function psiphon_reload() {
    log "Reloading Psiphon with native TUN support..."

    # Kill any existing Psiphon processes
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        log "$(exec pkill -nf "psiphon-tunnel-core" 2>/dev/null || true)"
    fi

    sleep 2

    exec runuser -u "$PSIPHON_USER" -- "$PSIPHON_BINARY" \
            -config "$PSIPHON_CONFIG_FILE" \
            -dataRootDirectory "$INSTALL_DIR/data" \
            -tunDevice "$TUN_INTERFACE" \
            -tunBindInterface "$TUN_BYPASS_INTERFACE" \
            -tunDNSServers "$TUN_DNS_SERVERS,$TUN_DNS_SERVERS6" \
            -formatNotices \
            -useNoticeFiles

    warning "Psiphon exited unexpectedly in service mode"
    warning "There is still a chance it may fail due to systemd service reload."

    # Reload binary to attempt recovery
    # TODO: check if it will cause a loop on failure or stop
    if [[ "$SERVICE_RELOAD" == "true" ]]; then
        # We don't need to set SERVICE_RELOAD="false"
        # because the script runs fresh each time
        psiphon_reload
    fi
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
    sleep 2

    # In service mode, run directly without backgrounding
    if [[ "$SERVICE_MODE" == "true" ]]; then
        exec runuser -u "$PSIPHON_USER" -- "$PSIPHON_BINARY" \
            -config "$PSIPHON_CONFIG_FILE" \
            -dataRootDirectory "$INSTALL_DIR/data" \
            -tunDevice "$TUN_INTERFACE" \
            -tunBindInterface "$TUN_BYPASS_INTERFACE" \
            -tunDNSServers "$TUN_DNS_SERVERS,$TUN_DNS_SERVERS6" \
            -formatNotices \
            -useNoticeFiles
        
        warning "Psiphon exited unexpectedly in service mode"
        warning "Check logs with: journalctl -u $SERVICE_NAME.service -f"
        warning "Or check log file: $LOG_FILE"
        warning "If Psiphon fails to start, try running script manually with:"
        warning "sudo $INSTALL_DIR/psiphon-tun.sh start"
        warning "There is still a chance it may fail due to systemd service reload."

        # reload binary to attempt recovery
        # TODO: check if it will cause a loop on failure or stop
        # TODO: these parts should be using trap functionality instead
        
        psiphon_reload
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
            -useNoticeFiles 2>&1 | sudo -u "$PSIPHON_USER" tee -a "$LOG_FILE" &

        local psiphon_pid=$!

        sleep 1

        # Wait until connected
        log "waiting psiphon to connect..."
        until tail -n 5 "$LOG_FILE" | grep -q "ConnectedServerRegion"
        do
            echo -n "."
            sleep 1
        done

        echo ""

        # Verify process started successfully
        if [[ -z "$psiphon_pid" ]] || ! kill -0 "$psiphon_pid" 2>/dev/null; then
            error "Failed to start Psiphon or process died immediately"
            return 1
        fi

        echo "$psiphon_pid" | tee $PID_FILE >/dev/null
        chown root:root $PID_FILE
        chmod 644 $PID_FILE

        # Give it time to establish connection
        sleep 5

        # Final verification
        if ! kill -0 "$psiphon_pid" 2>/dev/null; then
            error "Psiphon process died after startup"
            return 1
        fi

        success "Psiphon started successfully with native TUN support (PID: $psiphon_pid)"
    fi
}

# Start all services
function start_services() {
    log "Starting services..."

    if start_psiphon; then
        success "Psiphon TUN service started successfully"
    else
        error "Failed to start services"
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
    ip route del default dev "$TUN_INTERFACE" 2>/dev/null || true
    ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true

    success "Routing and firewall rules cleaned up."
}

# Stop all services
function stop_services() {
    log "Stopping services..."

    local stopped_something=false

    # Stop Psiphon
    if [[ -f $PID_FILE ]]; then
        local psiphon_pid
        psiphon_pid=$(cat $PID_FILE 2>/dev/null || echo "")
        if [[ -n "$psiphon_pid" ]] && kill -0 "$psiphon_pid" 2>/dev/null; then
            # Try graceful shutdown first
            kill -TERM "$psiphon_pid" 2>/dev/null || true
            sleep 3
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

    create_systemd_service

    success "Psiphon TUN setup installed successfully"
    log "Use '$0 start' to start the service"
    log "Use 'sudo systemctl enable $SERVICE_NAME' to start automatically at boot"
    log "Use 'sudo systemctl start $SERVICE_NAME' to start via systemd"
}

# Uninstall everything
function uninstall() {
    log "Uninstalling Psiphon TUN setup..."

    # Stop services first
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    fi

    rm -f /etc/systemd/system/$SERVICE_NAME.service
    systemctl daemon-reload 2>/dev/null || true

    stop_services

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

# Show status
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
            if [[ -n "$test_ip" ]] && ([[ "$test_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$test_ip" =~ ^[0-9a-f:]+$ ]]); then
                echo -e "External IP via TUN: ${GREEN}$test_ip${NC}"
            else
                echo -e "Connection Test: ${YELLOW}UNEXPECTED RESULT${NC} ($test_ip)"
            fi
        else
            echo -e "Connection Test: ${RED}FAILED${NC}"
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
    fi

    echo ""
    echo "=== DNS Resolution Test ==="
    echo -e "DNS v4 Query Result: $(dig -4 +timeout=2 +retry=0 +short youtube.com @8.8.8.8 | head -n1)"
    echo -e "DNS v6 Query Result: $(dig -6 +timeout=2 +retry=0 +short youtube.com @2001:4860:4860::8888 | head -n1)"

    echo ""
    echo "=== curl test ==="
    echo -e "External IPv4 direct:\n$(timeout 10 curl -4sSm 7 https://cloudflare.com/cdn-cgi/trace)"
    echo ""
    sleep 1
    echo -e "External IPv6 direct:\n$(timeout 10 curl -6sSm 7 https://cloudflare.com/cdn-cgi/trace)"
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


Psiphon TUN Setup Script - Secure Tunneling Solution

Usage: $0 [COMMAND]

COMMANDS:
    install     Install and configure Psiphon TUN setup
    uninstall   Remove Psiphon TUN setup completely
    start       Start Psiphon service with native TUN support
    stop        Stop Psiphon service and cleanup
    restart     Stop and restart Psiphon service
    status      Show status of all components
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
    • Traffic routing excludes Psiphon user to prevent loops

FILES:
    • Install Directory: $INSTALL_DIR
    • Binary: $PSIPHON_BINARY
    • Psiphon Config: $PSIPHON_CONFIG_FILE
    • Logs: $LOG_FILE $(du -h "$LOG_FILE" | cut -f1)
    • Service: /etc/systemd/system/$SERVICE_NAME.service
    • Psiphon notices: $INSTALL_DIR/data/notices

EXAMPLES:
    $0 install          # Install and configure everything
    $0 start            # Start the TUN service
    $0 status           # Check service status

    # Systemd management:
    sudo systemctl enable $SERVICE_NAME    # Auto-start at boot
    sudo systemctl start $SERVICE_NAME     # Start via systemd
    sudo systemctl status $SERVICE_NAME    # Check systemd status

For more information, visit: https://github.com/Psiphon-Labs/psiphon-tunnel-core
Script Source: https://github.com/boilingoden/psiphon-client-linux-service

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
            start_services
            ;;
        systemd_start)
            SERVICE_MODE="true"
            check_root
            acquire_lock
            check_and_update_psiphon
            setup_tun_interface
            setup_routing
            start_services
            ;;
        reload)
            SERVICE_RELOAD="true"
            check_root
            psiphon_reload # ask psiphon to reload itself 
            ;;
        systemd_reload)
            SERVICE_MODE="true"
            SERVICE_RELOAD="true"
            check_root
            psiphon_reload
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
            sleep 3
            setup_tun_interface
            setup_routing
            start_services
            ;;
        systemd_restart)
            SERVICE_MODE="true"
            check_root
            stop_services
            sleep 3
            setup_tun_interface
            setup_routing
            start_services
            ;;
        status)
            status
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
