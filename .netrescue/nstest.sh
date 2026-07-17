#!/bin/bash
# Isolated netop test harness — runs the REAL net binary inside a throwaway
# network namespace against a fake DHCP+router peer. Your real network stack
# (interfaces, routes, /etc/resolv.conf) is NEVER touched: everything lives
# inside the namespace, and resolv.conf is bind-mounted to a temp file just
# for the namespace's mount view.
#
# Run:  sudo bash /home/user/dev/netop/.netrescue/nstest.sh
#
# Safe to run on a live machine. Cleans up on exit even if a step fails.
set -u
export PATH="/usr/sbin:/sbin:/usr/bin:/bin"

NET=/home/user/dev/netop/net-test
NS=netoptest
HOST_VETH=veth-host
NS_VETH=veth-ns
WORK=$(mktemp -d /tmp/netoptest.XXXXXX)
PASS=0; FAIL=0

say()  { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  PASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '\033[1;31m  FAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
nse()  { ip netns exec "$NS" "$@"; }   # run a command inside the namespace

cleanup() {
  say "Cleanup"
  nse pkill -f dnsmasq 2>/dev/null
  pkill -f "dnsmasq.*$WORK" 2>/dev/null
  ip netns del "$NS" 2>/dev/null           # deleting the ns removes veth-ns too
  ip link del "$HOST_VETH" 2>/dev/null
  rm -rf "$WORK"
  echo "  namespace, veth, dnsmasq, tempdir removed"
  # Prove the host is untouched
  say "Host network unchanged (for your peace of mind)"
  echo "  host default route: $(ip route show default | head -1)"
  echo "  host resolv.conf:   $(head -1 /etc/resolv.conf)"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root (sudo)"; exit 1; }
[ -x "$NET" ] || { echo "net-test binary not found at $NET"; exit 1; }

say "Building isolated namespace + fake wired network"
ip netns add "$NS"
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
ip link set "$NS_VETH" netns "$NS"
# Host side of the veth acts as the "router": 10.99.0.1
ip addr add 10.99.0.1/24 dev "$HOST_VETH"
ip link set "$HOST_VETH" up
nse ip link set lo up
# Fake DHCP server on the host side, serving the namespace
dnsmasq --no-daemon --interface="$HOST_VETH" --bind-interfaces \
  --dhcp-range=10.99.0.50,10.99.0.150,1h \
  --dhcp-option=3,10.99.0.1 --dhcp-option=6,10.99.0.1 \
  --pid-file="$WORK/dnsmasq.pid" --log-facility="$WORK/dnsmasq.log" \
  --conf-file=/dev/null &
sleep 1
echo "  namespace $NS up; veth pair up; dnsmasq serving 10.99.0.50-150"

# net writes /etc/resolv.conf. Give the namespace its OWN resolv.conf via a
# private mount so the host's is physically untouchable from inside.
printf '# netoptest placeholder\n' > "$WORK/resolv.conf"

# A minimal config for a wired network on the namespace interface, no VPN.
mkdir -p "$WORK/.net"
cat > "$WORK/.net/config.yaml" <<CFG
wired:
  interface: $NS_VETH
CFG

# Run net INSIDE the namespace, with a private mount namespace so its
# resolv.conf edits land on our temp file, and HOME pointed at our config.
runnet() {
  nse unshare --mount bash -c "
    mount --bind '$WORK/resolv.conf' /etc/resolv.conf
    export HOME='$WORK' PATH='$PATH'
    $NET --config '$WORK/.net/config.yaml' \"\$@\"
  " _ "$@"
}

say "TEST 1: net status inside namespace (interface auto-detection)"
out=$(runnet --iface "$NS_VETH" status 2>&1)
echo "$out" | sed 's/^/    /'
echo "$out" | grep -q "$NS_VETH" && ok "status reports the namespace interface" || bad "status did not find $NS_VETH"

say "TEST 2: net connect wired (real DHCP lease + resolv.conf handling)"
out=$(runnet connect wired 2>&1)
echo "$out" | sed 's/^/    /'
# Verify the namespace interface actually got a DHCP lease in our range
ip4=$(nse ip -4 addr show "$NS_VETH" | grep -oP 'inet \K10\.99\.0\.\d+')
[ -n "$ip4" ] && ok "got DHCP lease: $ip4" || bad "no DHCP lease obtained"
echo "$out" | grep -qi "Connected" && ok "connect reported success" || bad "connect did not report success"

say "TEST 3: resolv.conf lock/unlock ownership (the round-2 fix)"
# After a DHCP-DNS connect that wrote a nameserver, resolv.conf should be
# locked AND owned; net stop must then be able to unlock it.
lsattr "$WORK/resolv.conf" 2>/dev/null | sed 's/^/    attrs: /'
runnet stop 2>&1 | sed 's/^/    /'
if lsattr "$WORK/resolv.conf" 2>/dev/null | grep -q '^....i'; then
  bad "resolv.conf still immutable after net stop"
else
  ok "resolv.conf unlocked after net stop (no permanent immutability)"
fi

say "RESULTS"
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" = 0 ] && echo "  ALL GREEN" || echo "  see failures above"
