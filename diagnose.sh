#!/bin/bash
# Network diagnostics script for net (netop project)

echo "=== net Network Diagnostics ==="
echo

# Check hostname
echo "1. Hostname Configuration"
echo "   Current hostname: $(hostname)"
echo

# Check /etc/hosts
echo "2. /etc/hosts file"
if grep -q "$(hostname)" /etc/hosts; then
    echo "   ✓ Hostname found in /etc/hosts"
    grep "$(hostname)" /etc/hosts | sed 's/^/     /'
else
    echo "   ✗ Hostname NOT found in /etc/hosts"
    echo "   This causes: 'sudo: unable to resolve host' warnings"
    echo
    echo "   To fix, add this line to /etc/hosts:"
    echo "   127.0.1.1       $(hostname)"
fi
echo

# Check dhclient version and flags
echo "3. DHCP Client (dhclient)"
if command -v dhclient &> /dev/null; then
    echo "   ✓ dhclient is installed"
    DHCLIENT_VERSION=$(dhclient --version 2>&1 | head -n1)
    echo "   Version: $DHCLIENT_VERSION"

    # Test if -cf flag is supported (config file for hostname)
    if dhclient --help 2>&1 | grep -q "\-cf"; then
        echo "   ✓ Supports -cf flag for config file (hostname via config)"
    else
        echo "   ⚠ May not support -cf flag for config file"
    fi
else
    echo "   ✗ dhclient is NOT installed"
    echo "   Install with: sudo apt install isc-dhcp-client"
fi
echo

# Check wireless interface
echo "4. Wireless Interfaces"
WIRELESS=$(ip link show | grep -E "^[0-9]+: (wlan|wlp)" | awk -F: '{print $2}' | tr -d ' ')
if [ -n "$WIRELESS" ]; then
    for iface in $WIRELESS; do
        echo "   Found: $iface"
        STATE=$(ip link show $iface | grep -oP "state \K\w+")
        echo "     State: $STATE"

        # Check if interface is busy
        if iw dev $iface scan 2>&1 | grep -q "busy"; then
            echo "     ⚠ Interface is busy (may be connected or managed by another process)"
        fi
    done
else
    echo "   No wireless interfaces found"
fi
echo

# Check wired interface
echo "5. Wired Interfaces"
WIRED=$(ip link show | grep -E "^[0-9]+: (eth|enp|enx)" | awk -F: '{print $2}' | tr -d ' ')
if [ -n "$WIRED" ]; then
    for iface in $WIRED; do
        echo "   Found: $iface"
        STATE=$(ip link show $iface | grep -oP "state \K\w+")
        echo "     State: $STATE"
    done
else
    echo "   No wired interfaces found"
fi
echo

# Check required tools
echo "6. Required System Tools"
TOOLS="ip iw wpa_supplicant dhclient pkill timeout"
for tool in $TOOLS; do
    if command -v $tool &> /dev/null; then
        echo "   ✓ $tool"
    else
        echo "   ✗ $tool (MISSING)"
    fi
done
echo

# Check net configuration
echo "7. net Configuration"
CONFIG_FILE="$HOME/.net/config.yaml"
if [ -f "$CONFIG_FILE" ]; then
    echo "   ✓ Config file exists: $CONFIG_FILE"
    NETWORKS=$(grep -E "^[a-zA-Z]" "$CONFIG_FILE" | grep -v "^common:" | grep -v "^ignored:" | grep -v "^vpn:" | wc -l)
    echo "   Networks configured: $NETWORKS"
else
    echo "   ✗ Config file not found: $CONFIG_FILE"
    echo "   Run: net list --help"
fi
echo

echo "=== Diagnostics Complete ==="
echo
echo "To fix the hostname resolution warning, run:"
echo "  echo '127.0.1.1       $(hostname)' | sudo tee -a /etc/hosts"
