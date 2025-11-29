# Psiphon Linux VPN Service - AI Development Guide

This repository implements a security-focused VPN service using Psiphon's TUN interface capabilities. The core architecture enforces a zero-trust networking model where all traffic must go through the VPN tunnel or be blocked - no exceptions.

Security > Functionality: The code always chooses security over convenience or features. Example: even DNS requests are blocked if not going through the tunnel, and any network transition immediately defaults to blocking all traffic.
1. **No Exceptions to Kill Switch**
   - Kill switch must remain active during all operations
   - Only explicit Stop/Restart commands can temporarily disable protection
   - All changes must maintain the "fail closed" security model
   
2. **Zero Trust Networking**
   - All traffic blocked by default (OUTPUT DROP policy)
   - Only psiphon-user can establish external connections
   - No exceptions for local networks or specific services
   
3. **Fail-Safe Operation**
   - Any error or uncertainty must result in complete traffic blocking
   - Recovery procedures must re-establish full security before functionality
   - No "temporary" bypasses or security relaxation allowed

Here's what you need to know to work effectively with this codebase:

## Architecture Overview

The script implements a secure VPN tunnel service with these key components:

1. **Core Service Components**
   - TUN interface management for network tunneling
   - Systemd service integration (3 related services: psiphon-tun, psiphon-binary, psiphon-homepage-monitor)
   - Secure user isolation via `psiphon-user` non-root account
   - IPv4/IPv6 routing and firewall configuration using **nftables** (NOT iptables)
   - DNS management to prevent DNS leaks via systemd-resolved

2. **Security Model**
   - Network kill switch with comprehensive protection via **nftables** (replaced iptables for broader protocol support):
     * Strict `nft chain inet psiphon_filter output { policy drop }` - all traffic blocked by default
     * All traffic forced through TUN interface except psiphon-user
     * Exclusive network access for `psiphon-user` via `meta skuid` rule exemption
     * No leaks on service failure (fail-closed, always drops unknown traffic)
     * Only `stop` and `restart` commands temporarily disable the kill switch
   - Dedicated non-root user (`psiphon-user`) for process isolation with CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE
   - Strict file permissions: 755 for binaries, 600 for configs, ownership psiphon-user:psiphon-group
   - Process capability restrictions via systemd service `CapabilityBoundingSet` and `AmbientCapabilities`
   - Binary integrity verification via SHA256 checksums from GitHub API

3. **Critical System Integration**
   - **Firewall**: Uses nftables with 3 tables: `inet psiphon_filter` (nat/filter), `ip psiphon_nat`, `ip6 psiphon_nat6`
   - **DNS**: Configures systemd-resolved via `/etc/systemd/resolved.conf.d/psiphon-tun.conf`
   - **Routing**: Uses RA (Router Advertisement) processing and custom routing tables
   - **WARP**: Optional Cloudflare WARP integration for VPN chaining (Psiphon → WARP → Internet)

## Key Workflows

### Installation Flow
```bash
1. Dependencies check (wget, curl, unzip, ip, nft)
2. User/group creation (psiphon-user:psiphon-group)
3. Directory structure setup (/opt/psiphon-tun/ with 0755 permissions)
4. Binary download and SHA256 verification from GitHub API
5. Psiphon configuration creation (SOCKS/HTTP proxy setup)
6. Systemd service creation (3 services: psiphon-tun, psiphon-binary, psiphon-homepage-monitor)
7. Network configuration (TUN interface, routing, firewall rules)
```

### Service Start Flow (script vs systemd modes)
The script has two operational modes controlled by `SERVICE_MODE` variable:
- **Script Mode** (`./script.sh start`): Direct execution with full control
- **Systemd Mode** (systemctl start): `SERVICE_MODE=true`, uses systemd service supervision

Both modes follow this sequence:
```bash
check_and_update_psiphon    # Auto-update from GitHub API
setup_tun_interface         # Create TUN device, IP addressing, IPv6 RA handling
setup_routing              # Configure nftables firewall (kill switch), enable forwarding
wait_for_ra_processing     # Wait for IPv6 Router Advertisement completion (~30 seconds)
start_services             # Launch psiphon-tunnel-core as psiphon-user
setup_tun_routes_after_ra  # Set default routes after RA processing
check_network_readiness    # Verify all components (TUN UP, routes exist, kill switch active)
```

### Service Reload Flow (preserves kill switch)
```bash
systemctl reload psiphon-tun  # Keeps kill switch active, restarts only Psiphon binary
→ calls systemd_psiphon_reload
→ starts Psiphon process (existing firewall rules remain intact)
```

### Service Stop Flow (activates kill switch)
```bash
1. Stop systemd services (psiphon-binary, psiphon-homepage-monitor)
2. Terminate Psiphon process (SIGTERM, then SIGKILL if needed)
3. cleanup_routing() - CRITICAL: Removes nftables rules but keeps TUN interface UP
4. Reset DNS (restore /etc/resolv.conf or systemd-resolved config)
5. Bring down TUN interface
→ Result: Zero traffic possible, full fail-closed state
```

### Update/Restart Flow (full cycle)
```bash
1. stop_services          # Teardown kill switch enforcement
2. setup_tun_interface    # Recreate TUN with fresh routing
3. setup_routing          # Rebuild firewall rules from scratch
4. start_services         # Launch updated/restarted Psiphon
```

- Network changes enforce security first (interface → routing → DNS → firewall)
- Auto-updates via GitHub API bypass censorship (`check_and_update_psiphon`)
- Lock files prevent race conditions during state changes via `acquire_lock()`

## Critical Files and Paths

```
/opt/psiphon-tun/          # Main installation directory
├── psiphon/               # Core psiphon files
│   ├── psiphon-tunnel-core    # Binary
│   └── psiphon.config         # Configuration
├── data/                  # Runtime data
└── psiphon-tun.log       # Service logs
```

## Project-Specific Conventions

1. **Error Handling**
   - All functions use the `log`, `error`, `success`, `warning` functions
   - Critical operations are wrapped in verification checks
   - Network operations have fallback mechanisms

2. **Security Practices**
   - All file operations set explicit permissions
   - Network configuration preserves existing routes
   - Service runs with minimal required capabilities
   - Kill switch ensures:
     * No traffic leaks during start or reload
     * Aslways block non-Psiphon traffic even on service failure
     * Protection across both IPv4 and IPv6 stacks
     * Only Psiphon process can establish external connections

3. **Configuration Management**
   - Default settings in readonly variables at script start
   - Runtime state tracked via PID and lock files
   - DNS servers configurable via variables

## Integration Points

1. **Network Stack**
   - TUN interface: `PsiphonTUN` (created via `ip link add` with `type tun`)
   - Default subnets: `10.200.3.0/24` (IPv4), `fd42:42:42::/64` (IPv6)
   - DNS: Google/Cloudflare DNS with both IPv4/IPv6 support
   - Automatic bypass interface detection for startup via `TUN_BYPASS_INTERFACE` (default route or first non-loopback)
   - IPv6 RA (Router Advertisement) processing requires ~30 second wait via `wait_for_ra_processing()`

2. **System Services**
   - Systemd service integration with 3 related units:
     * `psiphon-tun.service` - Configuration and orchestration (After=network-online.target)
     * `psiphon-binary.service` - Psiphon process (Requires=psiphon-tun.service, runs as psiphon-user)
     * `psiphon-homepage-monitor.path` - Watches sponsor homepage for UI notifications
   - DNS resolution through systemd-resolved when available (preferred over /etc/resolv.conf)
   - nftables for routing and firewalls (service-based: `systemctl restart nftables`)
   - Root/sudo required for all commands
   - Environment variables for easy configuration:
     ```bash
     PSIPHON_USER="psiphon-user"     # Dedicated non-root user
     SOCKS_PORT=1081                 # Local SOCKS proxy port
     HTTP_PORT=8081                  # Local HTTP proxy port
     INSTALL_DIR="/opt/psiphon-tun"  # Base installation directory
     TUN_INTERFACE="PsiphonTUN"      # TUN device name
     TUN_SUBNET="10.200.3.0/24"      # IPv4 allocation
     TUN_SUBNET6="fd42:42:42::/64"   # IPv6 allocation (ULA)
     ```

3. **Process Isolation Pattern**
   - Psiphon runs as non-root `psiphon-user` with minimal capabilities:
     * `CAP_NET_ADMIN` - TUN interface management
     * `CAP_NET_RAW` - Raw socket operations for tunneling
     * `CAP_NET_BIND_SERVICE` - Bind to ports 1081/8081
   - Locked via systemd `CapabilityBoundingSet` (all others dropped)
   - nftables exemption via `meta skuid <psiphon_user_id>` in OUTPUT chain (skips DROP policy)

4. **Logging Patterns**
   - All output through typed functions: `log()`, `error()`, `success()`, `warning()`
   - Timestamp format: `YYYY-MM-DD HH:MM:SS` with color codes (RED/GREEN/YELLOW/BLUE)
   - Dual output: console (with colors) + `/opt/psiphon-tun/psiphon-tun.log` (without colors)
   - Psiphon process logs: `/opt/psiphon-tun/psiphon-core.log`
   - Systemd integration: `journalctl -u psiphon-binary`, `journalctl -u psiphon-tun`

5. **Error Handling Pattern**
   ```bash
   function example_task() {
       log "Starting task..."
       
       # Check prerequisite with error handling
       if ! command_that_might_fail; then
           error "Task failed at step X"
           cleanup_partial_state  # Revert partial changes
           return 1
       fi
       
       success "Task completed"
   }
   ```
   - Critical operations wrapped in `if !` checks
   - Network changes always wrap in `cleanup_routing()` fallback
   - All external commands use `2>/dev/null || true` for safe failures

## Common Tasks

1. **Adding New Features**
   - Add function implementations before `main()` function
   - Update `usage()` function with new commands
   - Maintain the lock file pattern (`acquire_lock()`) for concurrency control
   - Example flow: declare function → call from `main()` → add to usage
   - Always call `stop_services` before network changes to maintain kill switch

2. **Modifying Network Rules**
   - All rules go through `configure_nftables()` function (handles IPv4 + IPv6)
   - Never directly modify iptables - use nftables instead (`/etc/nftables/psiphon-tun.nft`)
   - Always set both IPv4 (`ip`) and IPv6 (`ip6`) tables for consistency
   - Verify rules with: `nft list chain inet psiphon_filter output`
   - Critical: psiphon-user exemption via `meta skuid` rule must always exist

3. **Debugging**
   - Service logs: `tail -f /opt/psiphon-tun/psiphon-tun.log`
   - Verify network stack: `ip addr show PsiphonTUN` and `ip addr show fd42:42:42::/64`
   - Test IPv4/IPv6 connectivity: `curl --interface PsiphonTUN ifconfig.me`
   - Check kill switch: `sudo nft list chain inet psiphon_filter output` (must show policy drop)
   - Common issues:
     * DNS leaks: Check `/etc/resolv.conf` and `systemctl status systemd-resolved`
     * Connection drops: Verify `ps aux | grep psiphon-tunnel-core` and check interfaces
     * Route conflicts: Check `ip route show` for unexpected defaults or bypasses

4. **Testing Changes**
   - Always use full flow: `stop_services` → `setup_tun_interface` → `setup_routing` → `start_services`
   - Verify both IPv4 (`10.200.3.0/24`) and IPv6 (`fd42:42:42::/64`) functionality
   - Test DNS: `dig google.com @8.8.8.8` through tunnel
   - Binary updates use GitHub API: `check_and_update_psiphon()` bypasses censorship
   - Full status check:
     ```bash
     sudo ./Psiphon-Linux-VPN-Service-Setup.sh diagnose  # Comprehensive network audit
     sudo ./Psiphon-Linux-VPN-Service-Setup.sh status    # Quick status with connection test
     ```

## Critical Security Guidelines

1. **Modification Rules**
   - Never add bypass routes or exceptions to the kill switch
   - All new features must maintain full traffic isolation
   - Security checks cannot be skipped or deferred
   - No temporary workarounds that weaken security

2. **Testing Requirements**
   - Verify kill switch blocks all traffic when:
     * Service crashes or fails
     * Network changes or transitions
     * System suspends/resumes
     * Updates are being applied
   - Test both IPv4 and IPv6 leak prevention in all protocols and even DNS
   - Verify only psiphon-user can access network

3. **Recovery Procedures**
   - Always reset to full blocking state first
   - Verify security before restoring connectivity
   - Never attempt to preserve connections at security's expense

Remember: Security is absolute - it cannot be traded for convenience, performance, or functionality. When faced with a choice between security and any other consideration, security must always prevail.
