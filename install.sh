#!/bin/bash

# Net Manager Installation Script
# This script builds the Go binary and installs it to /usr/local/bin

set -e

echo "Net Manager Installer"
echo "===================="

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed or not in PATH."
    echo "Please install Go 1.21 or later from https://golang.org/dl/"
    exit 1
fi

# Check Go version (basic check)
GO_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
if [[ "$(printf '%s\n' "$GO_VERSION" "1.21" | sort -V | head -n1)" != "1.21" ]]; then
    echo "Warning: Go version $GO_VERSION detected. This project requires Go 1.21 or later."
fi

echo "Building net binary..."
go build -o net ./cmd/net

if [ ! -f net ]; then
    echo "Error: Build failed - binary not created."
    exit 1
fi

echo "Installing to /usr/local/bin/net..."
if command -v sudo &> /dev/null; then
    sudo cp net /usr/local/bin/net
else
    cp net /usr/local/bin/net
fi

# Clean up
rm net

# Install default config file
echo "Setting up configuration..."
CONFIG_DIR="$HOME/.net"
CONFIG_FILE="$CONFIG_DIR/config.yaml"

# Create config directory if it doesn't exist
if [ ! -d "$CONFIG_DIR" ]; then
    echo "Creating config directory: $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
fi

# Install default config if it doesn't already exist
if [ ! -f "$CONFIG_FILE" ]; then
    if [ -f "config.example" ]; then
        echo "Installing example config to: $CONFIG_FILE"
        # Owner-only: the config holds WiFi passwords and VPN keys.
        install -m 600 "config.example" "$CONFIG_FILE"
        echo "Example configuration installed. Edit $CONFIG_FILE and replace the placeholders"
        echo "(networks, passwords, VPN keys) with your own settings."
    else
        echo "Warning: config.example not found (run this script from the repository root). Skipping config installation."
    fi
else
    echo "Existing config found at $CONFIG_FILE - not overwriting."
fi

# Check for a DHCP client: net uses udhcpc (BusyBox) or dhclient, whichever
# is installed, preferring udhcpc on WiFi and dhclient on wired. Both live in
# sbin, which is on root's PATH (net runs as root) but often not on a user's,
# so look there too.
has_root_cmd() {
    PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin" command -v "$1" &> /dev/null
}
echo "Checking for a DHCP client..."
if has_root_cmd udhcpc || has_root_cmd dhclient; then
    for client in udhcpc dhclient; do
        if has_root_cmd "$client"; then
            echo "$client is available."
        fi
    done
else
    echo "Warning: no DHCP client found. net needs udhcpc or dhclient:"
    echo "  Debian/Ubuntu: sudo apt install udhcpc        (or isc-dhcp-client)"
    echo "  Alpine:        included in busybox"
    echo "  Fedora/RHEL:   sudo dnf install dhcp-client"
    echo "  Arch:          sudo pacman -S dhclient"
fi

echo ""
echo "Installation successful!"
echo "You can now use the 'net' command from anywhere."
echo "(The command will automatically request root privileges when needed)"
echo ""
echo "Configuration:"
echo "  Config file: $CONFIG_FILE"
echo "  Edit the config file to customize network settings, VPN, and DNS preferences."
echo ""
echo "Usage examples:"
echo "  net connect home  # Connect to a network"
echo "  net scan          # Scan for WiFi networks"
echo "  net list          # Show connection status"
echo "  net --help        # Show all available commands"
