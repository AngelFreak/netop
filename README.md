<div align="center">

# 🌐 netop

**A lightweight network manager for Linux**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Unlicense-blue.svg)](UNLICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.linux.org/)

Manage WiFi connections, VPNs (WireGuard/OpenVPN/Tailscale/NetBird), DNS, MAC addresses, and more through a simple CLI and YAML configuration.

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
- **VPN Support** - WireGuard, OpenVPN, Tailscale, and NetBird
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
| `tailscale` | [tailscale.com/download](https://tailscale.com/download/linux) | Tailscale support (optional) |
| `netbird` | [docs.netbird.io](https://docs.netbird.io/how-to/installation) | NetBird support (optional) |

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

# Check for a captive portal on the current connection
net portal

# Disconnect everything
sudo net stop
```

</details>

<details>
<summary><b>🔒 VPN Commands</b></summary>

```bash
# Connect to VPN (WireGuard/OpenVPN)
sudo net vpn myvpn

# Connect to Tailscale
sudo net vpn my-tailscale

# Connect to NetBird
sudo net vpn my-netbird

# Disconnect all VPNs
sudo net vpn stop

# List VPN status
sudo net vpn
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
| `status` | Show full status (connection, internet/captive portal, VPN, hotspot, DHCP) |
| `portal` | Check for a captive portal on the current connection |
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

### 🛜 Captive Portal Detection

Networks such as hotel/airline/coffee-shop WiFi sit behind a **captive portal**:
the connection comes up (IP, gateway, DNS) but all traffic is blackholed until
you log in through a browser. netop probes a plain-HTTP connectivity-check URL to
tell these apart from a working connection:

- **`net portal`** — check on demand. Prints `Internet: ok`, or
  `Captive portal detected!` followed by the login URL (when the portal supplies
  one via redirect) or the probe URL to open in a browser (which the portal will
  intercept). This command does **not** require root, and always probes even when
  `common.portal.check: off` is set.
- **`net connect`** — after connecting, a non-fatal stderr warning is printed if a
  captive portal or no internet is detected. The VPN attempt proceeds unchanged.
- **`net status`** — shows one `Internet:` line reflecting the same probe.

**Exit codes** (for scripting `net portal`):

| Code | Meaning |
|------|---------|
| `0` | Online — internet reachable |
| `2` | Captive portal detected |
| `1` | Offline — no working internet, no portal identified |
| `3` | Configuration or internal error |

**Default-route limitation.** The probe follows the process's normal routing (the
lowest-metric default route), **not** the interface you just connected to. netop
treats dual-homing as first-class (a wired link with metric 100 beats WiFi at
600), so if Ethernet has internet while you connect to a captive WiFi, the probe
egresses over Ethernet and reports `ok`. To make this honest rather than silent,
every Internet outcome is labelled with the preferred IPv4 default route when
known — `Internet:  ok (default IPv4 route: eth0)` — and `net connect` prints a
stderr note when the default-route interface differs from the just-connected one,
naming the remediation (disable/unplug the preferred link, or open a browser on
the captive network). This is an IPv4 main-table metric heuristic, not a
guarantee of probe egress; on a dual-stack host the probe may egress over IPv6.

**Connect-time latency.** The connect-time check makes at most one settle-retry to
avoid a false offline warning right after association, so the worst case on a
truly offline network is roughly `settle (500ms) + 2 × portal timeout`. The retry
is deliberately unconditional; refused or no-route probes fail in milliseconds, so
the full cost is only paid on a blackholed network.

> **Note on `timeouts.*`.** Unlike `common.portal`, the `timeouts` subfields are
> historically **not** validated: a typo like `timeouts.portl` silently falls back
> to the 3s default rather than erroring. Tightening that is out of scope here
> (changing it could break configs that load today).

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
  portal:
    check: auto   # "auto" (default) or "off"; anything else is rejected at load
    url: http://detectportal.firefox.com/success.txt
      # must be plain http with a host; a custom endpoint must answer
      # HTTP 204 or a 200 body of exactly "success" when internet works.
      # It should normally be an externally reachable public endpoint —
      # a LAN-local probe answers even when the internet is down.
      # (Self-hosted probes are allowed deliberately, for privacy.)
  timeouts:
    portal: 3     # captive-portal probe timeout in seconds
```

`portal.check: off` disables only the automatic checks in `net connect` and
`net status` (including the multi-home note); `net portal` always probes on
demand. A non-`auto`/`off` `check` value or an invalid `url` is rejected at
config load.

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

**WireGuard / OpenVPN:**
```yaml
vpn:
  myvpn:
    type: wireguard        # or "openvpn"
    interface: wg0         # WireGuard interface name
    address: 10.0.0.2/32   # WireGuard IP address
    gateway: true          # Route all traffic through VPN
    config: |              # WireGuard/OpenVPN config
      [Interface]
      PrivateKey = ...
```

**Tailscale:**
```yaml
vpn:
  work-tailscale:
    type: tailscale
    profile: work@company.com   # Optional: switch profile (multi-account)
    auth_key: tskey-auth-xxxxx  # Optional: omit if logged in via browser
    exit_node: us-east-1        # Optional: route traffic through exit node
    accept_routes: true         # Optional: accept subnet routes from admin
  personal-tailscale:
    type: tailscale
    profile: me@gmail.com       # Switch to personal account
```

**NetBird:**
```yaml
vpn:
  work-netbird:
    type: netbird
    profile: work                          # Optional: NetBird profile (multi-account)
    setup_key: XXXXXXXX                    # Optional: omit if already logged in
    management_url: https://api.netbird.io  # Optional: defaults to NetBird cloud
  home-netbird:
    type: netbird
    profile: home                          # Switch to home account
```

> **Note:** Tailscale and NetBird require their daemon/service to be running (`tailscaled` / `netbird service`). `net` calls their CLI to connect/disconnect — it does not manage the daemon. DNS is always controlled by `net` (MagicDNS is disabled). Multi-account support uses `tailscale switch` and `netbird profile select` under the hood. Profiles are per-OS-user and `net` runs as root, so create them for root (e.g. `sudo netbird profile add`) — a profile that can't be selected fails the connection rather than silently using the wrong account.

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
