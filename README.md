# Psiphon Linux VPN Service

System-wide VPN service for Linux with absolute kill-switch protection. Zero-trust networking model: all traffic must go through VPN or is blocked.

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)

## 🛡️ Key Features

- **Absolute Kill Switch**
  - Fail-closed security model
  - No bypass routes or exceptions
  - Full IPv4/IPv6 protection

- **Zero Trust Security**
  - Default deny-all policy
  - DNS leak prevention
  - Dedicated non-root user isolation

## 📋 Requirements

- Linux with systemd
- Root access
- iptables/ip6tables

## 🚀 Installation

```bash
git clone https://github.com/boilingoden/psiphon-client-linux-service.git
cd psiphon-client-linux-service
sudo ./Psiphon-Linux-VPN-Service-Setup.sh install
```

## 🔧 Usage

```bash
# Show all available commands
sudo ./Psiphon-Linux-VPN-Service-Setup.sh help

# Start VPN
sudo systemctl start psiphon-tun

# Stop VPN
sudo systemctl stop psiphon-tun

# Check status
sudo systemctl status psiphon-tun
```

Configuration: `/opt/psiphon-tun/psiphon/psiphon.config`

## 🔍 Network Info

- Interface: `PsiphonTUN`
- IPv4: `10.200.3.0/24`
- IPv6: `fd42:42:42::/64`

## 🐛 Troubleshooting

```bash
# View logs
sudo tail -f /opt/psiphon-tun/psiphon-tun.log

# Test connection
sudo ./Psiphon-Linux-VPN-Service-Setup.sh status
```

## 📄 License

This is free and unencumbered software released into the public domain - See [LICENSE](LICENSE) file
