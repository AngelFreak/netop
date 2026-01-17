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

[↑ Back to Top](#-net)

---

## 📦 Installation

### From GitHub Releases (Recommended)

Download the latest binary from [Releases](https://github.com/angelfreak/netop/releases):

```bash
# Linux AMD64
curl -L https://github.com/angelfreak/netop/releases/latest/download/net-linux-amd64 -o net
chmod +x net
sudo mv net /usr/local/bin/
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
go build -o net ./cmd/net
sudo mv net /usr/local/bin/
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

### 🔓 Running Without Sudo

Network operations require elevated privileges. Instead of typing `sudo` every time:

<details>
<summary><b>Option 1: Set Capabilities (Recommended)</b></summary>

Grant only the specific capabilities needed:

```bash
sudo setcap 'cap_net_admin+ep' /usr/local/bin/net
```

Now you can run `net` directly without sudo.

**⚠️ Limitations:** The current implementation internally uses `sudo` for certain operations and spawns subprocesses (`wpa_supplicant`, `dhclient`, etc.) that may require additional permissions. While capabilities eliminate the need for `sudo net` in many cases, some operations may still prompt for elevated privileges.

</details>

<details>
<summary><b>Option 2: Sudoers Rule</b></summary>

Create a passwordless sudo rule:

```bash
echo "$USER ALL=(ALL) NOPASSWD: /usr/local/bin/net" | sudo tee /etc/sudoers.d/net
```

Then add an alias to your shell rc file (`~/.bashrc` or `~/.zshrc`):

```bash
alias net='sudo /usr/local/bin/net'
```

**🔒 Security Note:** When using passwordless sudo, protect the binary from unauthorized modification:

```bash
sudo chown root:root /usr/local/bin/net
sudo chmod 755 /usr/local/bin/net
```

</details>

[↑ Back to Top](#-net)

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
sudo net connect home

# Connect to any network (prompted for password)
sudo net connect

# Connect without VPN
sudo net connect work --no-vpn
```

### 3. Scan for Networks

```bash
sudo net scan
```

[↑ Back to Top](#-net)

---

## 📖 Documentation

<details>
<summary><b>📡 WiFi Commands</b></summary>

```bash
# Connect to configured network
sudo net connect home

# Connect to any network (prompted for password)
sudo net connect

# Connect without VPN
sudo net connect work --no-vpn

# Scan for networks
sudo net scan

# Show connection status
sudo net list

# Disconnect everything
sudo net stop
```

</details>

<details>
<summary><b>🔒 VPN Commands</b></summary>

```bash
# Connect to VPN
sudo net vpn myvpn

# Disconnect all VPNs
sudo net vpn stop

# List VPN status
sudo net list
```

</details>

<details>
<summary><b>🌐 DNS Commands</b></summary>

```bash
# Set custom DNS
sudo net dns 8.8.8.8 1.1.1.1

# Restore DHCP DNS
sudo net dns dhcp
```

</details>

<details>
<summary><b>🎭 MAC Address Commands</b></summary>

```bash
# Set random MAC
sudo net mac random

# Set specific MAC
sudo net mac 00:11:22:33:44:55

# Restore original MAC
sudo net mac default
```

</details>

<details>
<summary><b>🔧 Utility Commands</b></summary>

```bash
# Generate WireGuard keys
sudo net genkey

# Show network config (with inherited settings)
sudo net show home

# Show current connection status
sudo net list

# Stop all connections
sudo net stop
```

</details>

[↑ Back to Top](#-net)

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

[↑ Back to Top](#-net)

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

<details>
<summary><b>Security Considerations</b></summary>

**Plain Text Credentials Warning**

When loading configuration, `net` will warn if it detects plain text credentials:
- WiFi passwords stored in `psk` fields
- VPN private keys embedded in inline `config` blocks

**Recommended Security Practices:**

1. **Restrict config file permissions:**
   ```bash
   chmod 600 ~/.net/config.yaml
   ```

2. **Use separate key files for VPNs** instead of inline configs:
   ```yaml
   vpn:
     myvpn:
       type: wireguard
       config: /path/to/wg0.conf  # Reference file instead of inline
   ```

3. **Store VPN key files with restricted permissions:**
   ```bash
   chmod 600 /etc/wireguard/wg0.conf
   ```

4. **For OpenVPN**, use separate key/cert files:
   ```yaml
   vpn:
     work:
       type: openvpn
       config: /etc/openvpn/client/work.ovpn
   ```

**Why this matters:** Config files may be backed up, synced, or accidentally committed to version control. Storing credentials in plain text increases the risk of exposure.

</details>

[↑ Back to Top](#-net)

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
go build -o net ./cmd/net

# Run tests
go test ./...

# Build for all platforms
GOOS=linux GOARCH=amd64 go build -o net-linux-amd64 ./cmd/net
GOOS=linux GOARCH=arm64 go build -o net-linux-arm64 ./cmd/net
GOOS=darwin GOARCH=arm64 go build -o net-darwin-arm64 ./cmd/net
```

</details>

[↑ Back to Top](#-net)

---

## 📄 License

This project is released into the public domain. See [UNLICENSE](UNLICENSE) for details.

---

<div align="center">

**Made with ❤️ for the Linux community**

[Report Bug](https://github.com/angelfreak/netop/issues) •
[Request Feature](https://github.com/angelfreak/netop/issues)

</div>
