# netop

A lightweight network manager for Linux. Manage WiFi connections, VPNs (WireGuard/OpenVPN), DNS, MAC addresses, and more through a simple CLI and YAML configuration.

## Features

- **WiFi Management** - Connect to networks, scan for available networks
- **VPN Support** - WireGuard and OpenVPN with automatic connection
- **MAC Randomization** - Randomize or set custom MAC addresses
- **DNS Configuration** - Custom DNS servers or DHCP
- **Hostname Spoofing** - Configurable hostname per network
- **BSSID Pinning** - Lock to specific access points
- **Configuration Inheritance** - Common settings applied to all networks

## Installation

### From GitHub Releases (Recommended)

Download the latest binary from [Releases](https://github.com/angelfreak/netop/releases):

```bash
# Linux AMD64
curl -L https://github.com/angelfreak/netop/releases/latest/download/netop-linux-amd64 -o netop
chmod +x netop
sudo mv netop /usr/local/bin/
```

### Using Install Script

First clone the repository, then run the install script:

```bash
git clone https://github.com/angelfreak/netop.git
cd netop
./install.sh
```

### From Source

Requires Go 1.21+:

```bash
git clone https://github.com/angelfreak/netop.git
cd netop
go build -o netop ./cmd/net
sudo mv netop /usr/local/bin/
```

## Dependencies

The following system utilities are required:

| Utility | Package | Purpose |
|---------|---------|---------|
| `ip` | iproute2 | Interface/routing management |
| `iw` | iw | WiFi operations |
| `wpa_supplicant` | wpasupplicant | WiFi authentication |
| `dhclient` or `udhcpc` | isc-dhcp-client / busybox | DHCP client |
| `openvpn` | openvpn | OpenVPN support (optional) |
| `wg` | wireguard-tools | WireGuard support (optional) |

Install on Debian/Ubuntu:
```bash
sudo apt install iproute2 iw wpasupplicant isc-dhcp-client wireguard-tools
```

## Configuration

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

## Usage

### Connect to a Network

```bash
# Connect to configured network
sudo netop connect home

# Connect to any network (prompted for password)
sudo netop connect

# Connect without VPN
sudo netop connect work --no-vpn
```

### Scan for Networks

```bash
sudo netop scan
```

### VPN Management

```bash
# Connect to VPN
sudo netop vpn myvpn

# Disconnect all VPNs
sudo netop vpn stop

# List VPN status
sudo netop list
```

### DNS Management

```bash
# Set custom DNS
sudo netop dns 8.8.8.8 1.1.1.1

# Restore DHCP DNS
sudo netop dns dhcp
```

### MAC Address

```bash
# Set random MAC
sudo netop mac random

# Set specific MAC
sudo netop mac 00:11:22:33:44:55

# Restore original MAC
sudo netop mac default
```

### Generate WireGuard Keys

```bash
sudo netop genkey
```

### Show Configuration

```bash
# Show network config (with inherited settings)
sudo netop show home

# Show current connection status
sudo netop list
```

### Stop All Connections

```bash
sudo netop stop
```

## Command Reference

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

### Global Flags

| Flag | Description |
|------|-------------|
| `--config, -c` | Config file path (default: ~/.net/config.yaml) |
| `--debug` | Enable debug logging |
| `--no-vpn` | Skip VPN connection |

## Configuration Reference

### Common Settings

```yaml
common:
  mac: "00:??:??:??:??:??"  # ? = random hex digit
  dns: 1.1.1.1, 8.8.8.8    # Comma-separated DNS servers
  hostname: MyLaptop       # Hostname for DHCP
  vpn: myvpn               # Default VPN name
```

### Network Settings

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

### VPN Settings

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

### Ignored Interfaces

```yaml
ignored:
  interfaces:
    - docker[0-9]+
    - veth.*
    - br[0-9]+
```

## Building

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

## License

This project is released into the public domain. See [UNLICENSE](UNLICENSE) for details.
