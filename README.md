<div align="center">

# 🌐 netop

**A lightweight network manager for Linux**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Unlicense-blue.svg)](UNLICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.linux.org/)

Manage WiFi connections, VPNs (WireGuard/OpenVPN), DNS, MAC addresses, and more through a simple CLI and YAML configuration.

[Features](#-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[Documentation](#-documentation)

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 📡 Network Management
- **WiFi Management** - Connect to networks, scan for available networks
- **BSSID Pinning** - Lock to specific access points
- **Interface Control** - Automatic interface detection

</td>
<td width="50%">

### 🔒 Security & Privacy
- **VPN Support** - WireGuard and OpenVPN with automatic connection
- **MAC Randomization** - Randomize or set custom MAC addresses
- **Hostname Spoofing** - Configurable hostname per network
- **DNS Configuration** - Custom DNS servers or DHCP

</td>
</tr>
</table>

### 🎯 Additional Features
- **Configuration Inheritance** - Common settings applied to all networks
- **YAML Configuration** - Simple, readable configuration format
- **Network Profiles** - Save and manage multiple network configurations

[↑ Back to Top](#-netop)

---

## 📦 Installation

### From GitHub Releases (Recommended)

Download the latest binary from [Releases](https://github.com/angelfreak/netop/releases):

```bash
# Linux AMD64
curl -L https://github.com/angelfreak/netop/releases/latest/download/netop-linux-amd64 -o netop
chmod +x netop
sudo mv netop /usr/local/bin/
```

<details>
<summary><b>Using Install Script</b></summary>

Clone the repository and run the install script (requires Go 1.21+):

```bash
git clone https://github.com/angelfreak/netop.git
cd netop
./install.sh
```

</details>

<details>
<summary><b>From Source</b></summary>

Requires Go 1.21+:

```bash
git clone https://github.com/angelfreak/netop.git
cd netop
go build -o netop ./cmd/net
sudo mv netop /usr/local/bin/
```

</details>

### 📚 Dependencies

The following system utilities are required:

| Utility | Package | Purpose |
|---------|---------|---------|
| `ip` | `iproute2` | Interface/routing management |
| `iw` | `iw` | WiFi operations |
| `wpa_supplicant` | `wpasupplicant` | WiFi authentication |
| `dhclient` or `udhcpc` | `isc-dhcp-client` / `busybox` | DHCP client |
| `openvpn` | `openvpn` | OpenVPN support (optional) |
| `wg` | `wireguard-tools` | WireGuard support (optional) |

**Install on Debian/Ubuntu:**
```bash
sudo apt install iproute2 iw wpasupplicant isc-dhcp-client wireguard-tools
```

[↑ Back to Top](#-netop)

---

## 🚀 Quick Start

### 1. Create Configuration

Create `~/.net/config.yaml`:

```yaml
common:
  mac: 00:??:??:??:??:??  # Randomize last 5 bytes
  dns: 1.1.1.1, 1.0.0.1
  hostname: <name>s-MacBook-Pro  # Random first name
  vpn: myvpn  # Default VPN for all networks

vpn:
  myvpn:
    type: wireguard
    address: 10.0.0.2/32
    interface: wg0
    gateway: true
    config: |
      [Interface]
      PrivateKey = YOUR_PRIVATE_KEY

      [Peer]
      PublicKey = SERVER_PUBLIC_KEY
      AllowedIPs = 0.0.0.0/0
      Endpoint = vpn.example.com:51820

home:
  ssid: MyHomeNetwork
  psk: MyPassword123
  vpn:  # Empty = no VPN at home
  dns: dhcp

work:
  ssid: CorpWiFi
  psk: WorkPassword
  # Uses common VPN and DNS

coffee-shop:
  ssid: CoffeeShopFree
  psk:  # Open network
  # Uses common VPN for security
```

### 2. Connect to a Network

```bash
# Connect to configured network
sudo netop connect home

# Connect to any network (prompted for password)
sudo netop connect

# Connect without VPN
sudo netop connect work --no-vpn
```

### 3. Scan for Networks

```bash
sudo netop scan
```

[↑ Back to Top](#-netop)

---

## 📖 Documentation

<details>
<summary><b>📡 WiFi Commands</b></summary>

```bash
# Connect to configured network
sudo netop connect home

# Connect to any network (prompted for password)
sudo netop connect

# Connect without VPN
sudo netop connect work --no-vpn

# Scan for networks
sudo netop scan

# Show connection status
sudo netop list

# Disconnect everything
sudo netop stop
```

</details>

<details>
<summary><b>🔒 VPN Commands</b></summary>

```bash
# Connect to VPN
sudo netop vpn myvpn

# Disconnect all VPNs
sudo netop vpn stop

# List VPN status
sudo netop list
```

</details>

<details>
<summary><b>🌐 DNS Commands</b></summary>

```bash
# Set custom DNS
sudo netop dns 8.8.8.8 1.1.1.1

# Restore DHCP DNS
sudo netop dns dhcp
```

</details>

<details>
<summary><b>🎭 MAC Address Commands</b></summary>

```bash
# Set random MAC
sudo netop mac random

# Set specific MAC
sudo netop mac 00:11:22:33:44:55

# Restore original MAC
sudo netop mac default
```

</details>

<details>
<summary><b>🔧 Utility Commands</b></summary>

```bash
# Generate WireGuard keys
sudo netop genkey

# Show network config (with inherited settings)
sudo netop show home

# Show current connection status
sudo netop list

# Stop all connections
sudo netop stop
```

</details>

[↑ Back to Top](#-netop)

---

## 📋 Command Reference

| Command | Description |
|---------|-------------|
| `connect [name]` | Connect to a network |
| `scan` | Scan for WiFi networks |
| `list` | Show connection status |
| `stop` | Disconnect everything |
| `vpn <name>` | Connect to VPN |
| `vpn stop` | Disconnect all VPNs |
| `dns <servers...>` | Set DNS servers |
| `dns dhcp` | Use DHCP DNS |
| `mac <address>` | Set MAC address |
| `mac random` | Randomize MAC |
| `mac default` | Restore original MAC |
| `genkey` | Generate WireGuard keypair |
| `show <name>` | Show network config |

### 🚩 Global Flags

| Flag | Description |
|------|-------------|
| `--config, -c` | Config file path (default: `~/.net/config.yaml`) |
| `--debug` | Enable debug logging |
| `--no-vpn` | Skip VPN connection |

[↑ Back to Top](#-netop)

---

## ⚙️ Configuration Reference

<details>
<summary><b>Common Settings</b></summary>

```yaml
common:
  mac: "00:??:??:??:??:??"  # ? = random hex digit
  dns: 1.1.1.1, 8.8.8.8    # Comma-separated DNS servers
  hostname: MyLaptop       # Hostname for DHCP
  vpn: myvpn               # Default VPN name
```

</details>

<details>
<summary><b>Network Settings</b></summary>

```yaml
network-name:
  ssid: NetworkSSID        # WiFi SSID
  psk: password            # WPA password (empty for open)
  wpa: |                   # Custom wpa_supplicant config
    network={...}
  ap-addr: 00:11:22:33:44:55  # Pin to specific BSSID
  interface: wlan0         # Force specific interface
  addr: 192.168.1.100/24   # Static IP
  gateway: 192.168.1.1     # Static gateway
  routes:                  # Additional routes
    - 10.0.0.0/8 -> 192.168.1.1
  dns: 8.8.8.8             # Override DNS
  mac: random              # Override MAC
  hostname: MyDevice       # Override hostname
  vpn: myvpn               # Override VPN (empty to disable)
```

</details>

<details>
<summary><b>VPN Settings</b></summary>

```yaml
vpn:
  vpn-name:
    type: wireguard        # or "openvpn"
    interface: wg0         # WireGuard interface name
    address: 10.0.0.2/32   # WireGuard IP address
    gateway: true          # Route all traffic through VPN
    config: |              # WireGuard/OpenVPN config
      [Interface]
      PrivateKey = ...
```

</details>

<details>
<summary><b>Ignored Interfaces</b></summary>

```yaml
ignored:
  interfaces:
    - docker[0-9]+
    - veth.*
    - br[0-9]+
```

</details>

[↑ Back to Top](#-netop)

---

## 🛠️ Development

<details>
<summary><b>Project Structure</b></summary>

```
netop/
├── cmd/net/           # Main application
├── pkg/
│   ├── config/        # Configuration handling
│   ├── dhcp/          # DHCP client management
│   ├── hotspot/       # Hotspot functionality
│   ├── network/       # Network operations
│   ├── system/        # System utilities
│   ├── types/         # Type definitions
│   ├── vpn/           # VPN management
│   └── wifi/          # WiFi operations
├── config.example     # Example configuration
└── install.sh         # Installation script
```

</details>

<details>
<summary><b>Building</b></summary>

```bash
# Build for current platform
go build -o netop ./cmd/net

# Run tests
go test ./...

# Build for all platforms
GOOS=linux GOARCH=amd64 go build -o netop-linux-amd64 ./cmd/net
GOOS=linux GOARCH=arm64 go build -o netop-linux-arm64 ./cmd/net
GOOS=darwin GOARCH=arm64 go build -o netop-darwin-arm64 ./cmd/net
```

</details>

[↑ Back to Top](#-netop)

---

## 📄 License

This project is released into the public domain. See [UNLICENSE](UNLICENSE) for details.

---

<div align="center">

**Made with ❤️ for the Linux community**

[Report Bug](https://github.com/angelfreak/netop/issues) •
[Request Feature](https://github.com/angelfreak/netop/issues)

</div>
