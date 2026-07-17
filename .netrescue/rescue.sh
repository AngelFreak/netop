#!/bin/bash
# EMERGENCY: restore internet if net testing breaks connectivity.
# Run with: sudo bash /home/user/dev/netop/.netrescue/rescue.sh
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
set -x
# 1. Unlock resolv.conf and restore working DNS
chattr -i /etc/resolv.conf 2>/dev/null
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
# 2. Bring the physical WiFi interface up and clear any VPN default route
ip link set wlp1s0 up
ip route del default 2>/dev/null
# 3. Try DHCP first (dhclient is installed in /sbin); this is the real fix
timeout 25 dhclient -1 wlp1s0
# 4. If DHCP didn't set a default route, fall back to the known static gateway
ip route show default | grep -q . || ip route replace default via 192.168.3.2 dev wlp1s0
set +x
echo "=== Rescue done. Verifying ==="
ping -c2 -W2 1.1.1.1 && echo "IP OK" || echo "IP STILL DOWN"
ping -c2 -W2 google.com && echo "DNS OK" || echo "DNS STILL DOWN"
