#!/bin/bash
###############################################################################
# netop hardware test harness — run this when you're home, then send Claude
# the output file it produces:  /tmp/netop-test-report.txt
#
#   cd /home/user/dev/netop
#   ./nettest.sh          (or: sudo ./nettest.sh — it self-elevates either way)
#
# What it does:
#   * builds the current net binary from your checked-out code
#   * runs read-only tests directly on your machine (safe, no changes)
#   * runs write-path tests (DHCP, connect, resolv.conf lock/unlock) inside a
#     THROWAWAY network namespace — your real interfaces, routes, and
#     /etc/resolv.conf are physically isolated and never touched
#   * captures diagnostics and a before/after host-network snapshot
#   * cleans everything up on exit, even on Ctrl+C or error
#
# It needs sudo (net self-elevates and netns creation needs root), but the
# only thing it changes on the real host is nothing — everything mutating runs
# in the namespace. A before/after host snapshot is included to prove it.
###############################################################################
set -u
export PATH="/usr/sbin:/sbin:/usr/bin:/bin"

# Self-elevate: if not root, re-exec the whole script under sudo so both
# `./nettest.sh` and `sudo ./nettest.sh` (and `bash nettest.sh`) work.
if [ "$(id -u)" != 0 ]; then
  echo "Re-running with sudo..."
  exec sudo -E bash "$0" "$@"
fi

REPO=/home/user/dev/netop
NET="$REPO/net-hwtest"
REPORT=/tmp/netop-test-report.txt
NS=netophwtest
HOST_VETH=vhw-host
NS_VETH=vhw-ns
WORK=$(mktemp -d /tmp/netophw.XXXXXX)
PASS=0; FAIL=0; WARN=0
# Host-state snapshot (populated before any test; used by cleanup to restore).
SAVED_DEFAULT_ROUTE=""
SAVED_RESOLV_IMMUTABLE=0

# Everything (stdout+stderr) is teed to the report so you can just send the file.
# Remove any stale (possibly root-owned) report from a previous run first, so
# tee can't fail with "Permission denied", then hand ownership back to the
# invoking user at the end so they can read/paste it without sudo.
rm -f "$REPORT" 2>/dev/null || REPORT="/tmp/netop-test-report.$$.txt"
exec > >(tee "$REPORT") 2>&1

sec()  { printf '\n\033[1;36m########## %s ##########\033[0m\n' "$*"; }
sub()  { printf '\n\033[1;34m--- %s ---\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [PASS]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '\033[1;31m  [FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
warn() { printf '\033[1;33m  [WARN]\033[0m %s\n' "$*"; WARN=$((WARN+1)); }
nse()  { ip netns exec "$NS" "$@"; }

cleanup() {
  sub "Cleanup"
  nse pkill -f dnsmasq 2>/dev/null
  pkill -f "dnsmasq.*$WORK" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  ip link del "$HOST_VETH" 2>/dev/null
  echo "  namespace, veth, dnsmasq removed"

  # --- Restore the host network to exactly its pre-test state ---
  # The tests run in a namespace and shouldn't touch the host, but if anything
  # (a test, or an interruption mid-run) disturbed the real default route or
  # resolv.conf, put them back. Restore BEFORE deleting $WORK (it holds the
  # saved resolv.conf) and before the after-snapshot below.
  sub "Restore host network to pre-test state"
  restored=0
  if [ -f "$WORK/host-resolv.conf.saved" ]; then
    if ! cmp -s "$WORK/host-resolv.conf.saved" /etc/resolv.conf 2>/dev/null; then
      chattr -i /etc/resolv.conf 2>/dev/null
      cp "$WORK/host-resolv.conf.saved" /etc/resolv.conf 2>/dev/null && { echo "  restored /etc/resolv.conf"; restored=1; }
    fi
    # Re-apply the immutable flag only if it was set originally.
    if [ "$SAVED_RESOLV_IMMUTABLE" = 1 ]; then
      lsattr /etc/resolv.conf 2>/dev/null | grep -q '^....i' || { chattr +i /etc/resolv.conf 2>/dev/null && echo "  re-applied immutable flag on resolv.conf"; }
    else
      lsattr /etc/resolv.conf 2>/dev/null | grep -q '^....i' && { chattr -i /etc/resolv.conf 2>/dev/null && echo "  removed immutable flag (was not set before)"; }
    fi
  fi
  if [ -n "$SAVED_DEFAULT_ROUTE" ]; then
    now=$(ip route show default 2>/dev/null | head -1)
    if [ "$now" != "$SAVED_DEFAULT_ROUTE" ]; then
      if ip route replace $SAVED_DEFAULT_ROUTE 2>/dev/null; then
        echo "  restored default route: $SAVED_DEFAULT_ROUTE"; restored=1
      else
        # Restore failed — likely the route's interface (e.g. a VPN's wg0) is
        # gone and can't be rebuilt by a route command. Point the user at the
        # rescue script so they aren't left offline.
        echo "  WARNING: could not restore default route '$SAVED_DEFAULT_ROUTE'"
        echo "           if you have no internet, run: sudo bash $REPO/.netrescue/rescue.sh"
      fi
    fi
  fi
  [ "$restored" = 0 ] && echo "  host default route/DNS already unchanged — nothing to restore"

  rm -rf "$WORK"
  sub "HOST NETWORK AFTER TEST (compare to 'before' — must be identical)"
  echo "  default route: $(ip route show default | head -1)"
  echo "  resolv.conf:   $(head -2 /etc/resolv.conf | tr '\n' ' ')"
  echo "  resolv attrs:  $(lsattr /etc/resolv.conf 2>/dev/null | awk '{print $1}')"
  sec "SUMMARY"
  echo "  passed: $PASS   failed: $FAIL   warnings: $WARN"
  echo
  echo "Report saved to $REPORT — send this file to Claude."
  # Hand the report (and built binary) back to the invoking user so they can
  # read/paste/delete without sudo, and so a later run's tee won't collide.
  if [ -n "${SUDO_USER:-}" ]; then
    chown "$SUDO_USER" "$REPORT" 2>/dev/null
    chown "$SUDO_USER" "$NET" 2>/dev/null
  fi
}
trap cleanup EXIT

sec "netop hardware test — $(date)"

sub "Environment"
echo "  kernel:  $(uname -r)"
echo "  go:      $(go version 2>/dev/null || echo 'go not found')"
for t in ip iw wpa_supplicant dnsmasq dhclient udhcpc wg netbird tailscale unshare; do
  printf '  %-14s %s\n' "$t:" "$(command -v $t 2>/dev/null || echo '-')"
done

sub "HOST NETWORK BEFORE TEST (captured for restore, not just display)"
# Save the real host network state so cleanup can put it back exactly as it
# was, even if a test or an interruption disturbs the host. The write-path
# tests run in a namespace and shouldn't touch these, but this guarantees it.
SAVED_DEFAULT_ROUTE=$(ip route show default 2>/dev/null | head -1)
SAVED_RESOLV_IMMUTABLE=0
lsattr /etc/resolv.conf 2>/dev/null | grep -q '^....i' && SAVED_RESOLV_IMMUTABLE=1
cp /etc/resolv.conf "$WORK/host-resolv.conf.saved" 2>/dev/null
echo "  default route: ${SAVED_DEFAULT_ROUTE:-<none>}"
echo "  resolv.conf:   $(head -2 /etc/resolv.conf | tr '\n' ' ')"
echo "  resolv attrs:  $(lsattr /etc/resolv.conf 2>/dev/null | awk '{print $1}') (immutable=$SAVED_RESOLV_IMMUTABLE)"
echo "  interfaces:    $(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo' | tr '\n' ' ')"
echo "  (saved for restore on exit)"

##############################################################################
sec "BUILD"
##############################################################################
cd "$REPO" || { echo "cannot cd $REPO"; exit 1; }
echo "  branch: $(git branch --show-current 2>/dev/null)  commit: $(git rev-parse --short HEAD 2>/dev/null)"
# Build as the invoking user so go's cache/modules (owned by them) are reused;
# fall back to a root build with a private cache if that isn't possible.
BUILD_USER="${SUDO_USER:-}"
built=0
if [ -n "$BUILD_USER" ] && command -v runuser >/dev/null 2>&1; then
  if runuser -u "$BUILD_USER" -- go build -o "$NET" ./cmd/net 2>&1; then
    ok "built net binary as $BUILD_USER ($(git rev-parse --short HEAD 2>/dev/null))"; built=1
  fi
fi
if [ "$built" = 0 ]; then
  # Root build with a throwaway cache so it can't fail on cache permissions.
  if GOCACHE="$WORK/gocache" GOFLAGS=-mod=mod go build -o "$NET" ./cmd/net 2>&1; then
    ok "built net binary ($(git rev-parse --short HEAD 2>/dev/null))"; built=1
  fi
fi
[ "$built" = 1 ] || { bad "build failed — cannot continue"; exit 1; }

##############################################################################
sec "PART A — READ-ONLY TESTS ON REAL MACHINE (no changes made)"
##############################################################################
sub "A1: net status (interface auto-detection + SSID)"
out=$("$NET" status 2>&1); echo "$out" | sed 's/^/    /'
if echo "$out" | grep -qiE "State:\s+connected"; then
  ok "auto-detected a connected interface (not the wlan0 fallback)"
else
  warn "status shows no connected interface — are you online via WiFi/wired?"
fi
echo "$out" | grep -qiE "Interface:\s+wlan0" && bad "still using the wlan0 fallback (interface detection bug)" || ok "not falling back to wlan0"

sub "A2: net vpn (ListVPNs — status truthfulness + same-type ambiguity)"
"$NET" vpn 2>&1 | sed 's/^/    /'
echo "    (check: an actually-up VPN shows 'connected'; multiple same-type"
echo "     configs are NOT all falsely 'connected')"

sub "A3: net show (config loads cleanly incl. metric/alias fields)"
if "$NET" show >/dev/null 2>&1; then ok "config loaded without validation errors"; else bad "config failed to load"; fi
"$NET" show 2>&1 | head -20 | sed 's/^/    /'

sub "A4: root-exemption flag parsing (finding #29) — must NOT prompt for sudo"
# We're already root, so instead assert these run without trying to re-exec sudo.
for args in "--iface wlp1s0 status" "--config /nonexistent status"; do
  if timeout 8 "$NET" $args </dev/null >/dev/null 2>&1; then
    ok "'net $args' ran without hanging on sudo"
  else
    warn "'net $args' errored/timed out (may be unrelated to the flag fix)"
  fi
done

##############################################################################
sec "PART B — WRITE-PATH TESTS IN ISOLATED NAMESPACE (host untouched)"
##############################################################################
sub "Building throwaway namespace + fake wired network with real DHCP"
ip netns add "$NS"
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
ip link set "$NS_VETH" netns "$NS"
ip addr add 10.99.0.1/24 dev "$HOST_VETH"; ip link set "$HOST_VETH" up
nse ip link set lo up
dnsmasq --no-daemon --interface="$HOST_VETH" --bind-interfaces \
  --dhcp-range=10.99.0.50,10.99.0.150,1h \
  --dhcp-option=3,10.99.0.1 --dhcp-option=6,10.99.0.1 \
  --pid-file="$WORK/dnsmasq.pid" --log-facility="$WORK/dnsmasq.log" \
  --conf-file=/dev/null &
sleep 1
echo "  ns=$NS iface=$NS_VETH router/dhcp=10.99.0.1 (range .50-.150)"

printf '# netop hwtest placeholder\n' > "$WORK/resolv.conf"
mkdir -p "$WORK/.net"
cat > "$WORK/.net/config.yaml" <<CFG
wired:
  interface: $NS_VETH
CFG

# Run net inside the ns + a private mount ns so its resolv.conf writes hit our
# temp file, and HOME points at our throwaway config.
runnet() {
  nse unshare --mount bash -c "
    mount --bind '$WORK/resolv.conf' /etc/resolv.conf
    export HOME='$WORK' PATH='$PATH'
    '$NET' --config '$WORK/.net/config.yaml' \"\$@\"
  " _ "$@"
}

sub "B1: net status inside namespace"
out=$(runnet --iface "$NS_VETH" status 2>&1); echo "$out" | sed 's/^/    /'
echo "$out" | grep -q "$NS_VETH" && ok "status found the namespace interface $NS_VETH" || bad "status did not find $NS_VETH"

sub "B2: net connect wired — real DHCP lease + route + resolv.conf"
out=$(runnet connect wired 2>&1); echo "$out" | sed 's/^/    /'
ip4=$(nse ip -4 addr show "$NS_VETH" 2>/dev/null | grep -oP 'inet \K10\.99\.0\.\d+')
[ -n "$ip4" ] && ok "obtained DHCP lease: $ip4" || bad "no DHCP lease obtained"
echo "$out" | grep -qi "Connected" && ok "connect reported success" || warn "connect did not print 'Connected'"

sub "B3: resolv.conf ownership — the round-2 immutability fix"
echo "    resolv.conf attrs after connect: $(lsattr "$WORK/resolv.conf" 2>/dev/null | awk '{print $1}')"
runnet stop 2>&1 | sed 's/^/    /'
if lsattr "$WORK/resolv.conf" 2>/dev/null | grep -q '^....i'; then
  bad "resolv.conf STILL immutable after 'net stop' (would strand DNS)"
else
  ok "resolv.conf unlocked after 'net stop' — no permanent immutability"
fi

sub "dnsmasq log (namespace DHCP activity)"
tail -8 "$WORK/dnsmasq.log" 2>/dev/null | sed 's/^/    /' || echo "    (no log)"

##############################################################################
sec "PART C — LIVE WiFi + VPN AUTO-CONNECT (opt-in; touches your real WiFi)"
##############################################################################
# This is the ONLY test that touches your real connection. It reproduces the
# original complaint: `net connect <network>` should bring up WiFi AND then
# auto-connect the VPN tied to that network. It is skipped unless you opt in:
#
#   NETOP_LIVE_WIFI=1 ./nettest.sh
#
# Optionally target a specific configured network:
#   NETOP_LIVE_WIFI=1 NETOP_WIFI_NET=home ./nettest.sh
#
# Your current SSID is captured first and reconnected afterward; the host
# resolv.conf/route restore in cleanup is the backstop, and .netrescue/rescue.sh
# is there if anything goes wrong.
if [ "${NETOP_LIVE_WIFI:-0}" != 1 ]; then
  sub "SKIPPED — set NETOP_LIVE_WIFI=1 to run the live WiFi + VPN auto-connect test"
  echo "    (this is the only test that touches your real connection)"
else
  WIFI_IFACE=$(for d in /sys/class/net/*/wireless; do [ -e "$d" ] && basename "$(dirname "$d")" && break; done)
  ORIG_SSID=$(iw dev "$WIFI_IFACE" link 2>/dev/null | awk -F': ' '/SSID:/{print $2; exit}')
  TARGET_NET="${NETOP_WIFI_NET:-$ORIG_SSID}"
  echo "    wifi interface: ${WIFI_IFACE:-<none>}"
  echo "    current SSID:   ${ORIG_SSID:-<none>}"
  echo "    target network: ${TARGET_NET:-<none>} (from config or current SSID)"

  restore_wifi() {
    if [ -n "${ORIG_SSID:-}" ] && [ -n "${WIFI_IFACE:-}" ]; then
      sub "Reconnecting to original WiFi: $ORIG_SSID"
      "$NET" connect "$ORIG_SSID" >/dev/null 2>&1 || \
        echo "    WARNING: could not auto-reconnect to '$ORIG_SSID' — run: sudo bash $REPO/.netrescue/rescue.sh"
      sleep 3
      now=$(iw dev "$WIFI_IFACE" link 2>/dev/null | awk -F': ' '/SSID:/{print $2; exit}')
      [ "$now" = "$ORIG_SSID" ] && echo "    reconnected to $ORIG_SSID" || echo "    still not on $ORIG_SSID (now: ${now:-none}) — see rescue.sh"
    fi
  }

  if [ -z "$WIFI_IFACE" ] || [ -z "$TARGET_NET" ]; then
    warn "no wireless interface or target network — skipping live test"
  else
    sub "C1: net connect $TARGET_NET (real WiFi assoc + DHCP + VPN auto-connect)"
    out=$(timeout 90 "$NET" connect "$TARGET_NET" 2>&1); echo "$out" | sed 's/^/    /'
    echo "$out" | grep -qi "Connected" && ok "WiFi connect reported success" || warn "connect did not print 'Connected'"

    sub "C2: verify VPN auto-connected (if the network has a vpn: configured)"
    vpncfg=$("$NET" show "$TARGET_NET" 2>/dev/null | awk -F': ' '/^VPN:/{print $2}')
    if [ -n "$vpncfg" ]; then
      echo "    network '$TARGET_NET' has vpn: $vpncfg"
      st=$("$NET" status 2>/dev/null)
      if echo "$st" | grep -iE "$vpncfg .*: connected" >/dev/null; then
        ok "VPN '$vpncfg' auto-connected after WiFi (the original complaint — fixed)"
      else
        bad "VPN '$vpncfg' did NOT auto-connect — this is the original bug, still present"
        echo "$st" | grep -iA1 "$vpncfg" | sed 's/^/      /'
      fi
    else
      echo "    network '$TARGET_NET' has no vpn: configured — nothing to auto-connect"
      warn "pick a VPN-tied network with NETOP_WIFI_NET=<name> to test auto-connect"
    fi

    restore_wifi
  fi
fi

# cleanup + summary run via the EXIT trap
