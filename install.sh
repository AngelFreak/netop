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
    if [ -f ".net/config.yaml" ]; then
        echo "Installing default config to: $CONFIG_FILE"
        cp ".net/config.yaml" "$CONFIG_FILE"
        echo "Default configuration installed. Edit $CONFIG_FILE to customize your settings."
    else
        echo "Warning: Default config file (.net/config.yaml) not found. Skipping config installation."
    fi
else
    echo "Existing config found at $CONFIG_FILE - not overwriting."
fi

# Check for dhclient (DHCP client)
echo "Checking for dhclient..."
if ! command -v dhclient &> /dev/null; then
    echo "Warning: dhclient not found."
    echo "Please install isc-dhcp-client:"
    echo "  Debian/Ubuntu: sudo apt install isc-dhcp-client"
    echo "  Fedora/RHEL:   sudo dnf install dhcp-client"
    echo "  Arch:          sudo pacman -S dhclient"
else
    echo "dhclient is available."
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
