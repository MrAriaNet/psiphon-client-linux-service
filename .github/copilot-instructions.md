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
   - Systemd service integration
   - Secure user isolation
   - IPv4/IPv6 routing and firewall configuration
   - DNS management to avoid DNS Leaks

2. **Security Model**
   - Network kill switch with comprehensive protection:
     * Strict iptables/ip6tables OUTPUT DROP policies
     * All traffic forced through TUN interface
     * Exclusive access for psiphon-user to external network
     * No leaks on service failure
     * Only Stop and Restart can temporarily disable the kill switch
   - Dedicated non-root user (`psiphon-user`) for process isolation
   - Strict file permissions and ownership
   - Process capability restrictions
   - Binary integrity verification

## Key Workflows

### Installation Flow
```bash
1. Dependencies check
2. User/group creation
3. Directory structure setup
4. Binary download and verification
5. Configuration creation
6. Systemd service setup
7. Network configuration
```

### Service Management
Example flow from `main()`:
```bash
stop_services       # Reset to secure state
setup_tun_interface # Configure network isolation
setup_routing      # Enforce kill switch
start_services     # Start with latest binary
```
- Network changes enforce security first (interface → routing → DNS → firewall)
- Auto-updates via GitHub API bypass censorship (`check_and_update_psiphon`)
- Lock files prevent race conditions during state changes

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
   - TUN interface: `PsiphonTUN`
   - Default subnets: `10.200.3.0/24` (IPv4), `fd42:42:42::/64` (IPv6)
   - DNS: Google/Cloudflare DNS with both IPv4/IPv6 support

2. **System Services**
   - Systemd service integration
   - DNS resolution through systemd-resolved when available
   - iptables/ip6tables for routing and firewalls

## Common Tasks

1. **Adding New Features**
   - Add function implementations before the main() function
   - Update usage() function with new commands
   - Maintain the lock file pattern for concurrency control

2. **Debugging**
   - Check service logs: `tail -f /opt/psiphon-tun/psiphon-tun.log`
   - Verify network stack: `ip addr show PsiphonTUN`
   - Test connectivity: `curl --interface PsiphonTUN ifconfig.me`

3. **Testing Changes**
   - Use `stop_services` before major network changes
   - Verify both IPv4 and IPv6 functionality
   - Test DNS resolution through the tunnel
   - Check binary updates: `check_and_update_psiphon` function
   - Verify version info with `get_binary_version_info`

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
