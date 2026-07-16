# Migration Plan: Replace shell-outs with native Go libraries

## Motivation

netop is ~9k lines of Go that mostly **wraps external tools** (73 `ip` calls, plus
`iptables`, `iw`, `wpa_cli`, `wg`, `chattr`, `cat`, `rm`, etc.). This session found
that a large share of real bugs came from **parsing the text output of `ip`** (e.g.
device-only default routes like `default dev wg0 scope link` that have no `via`, and
the `iw`/`ip` binaries not being on PATH for root-exempt commands).

Replacing the fragile text-parsing shell-outs with native Go libraries would:
- Remove a whole class of output-format-parsing bugs (structured data, not strings).
- Remove PATH dependencies (netlink talks to the kernel via socket — no binary lookup).
- Let read-only commands (`net status`) query routes/addresses **without root**.
- Keep the single-static-binary goal (all candidates below are pure-Go, no cgo).

**Guiding principle (unchanged from CLAUDE.md):** don't reinvent complex daemons.
We migrate the *mechanical, text-scraping* shell-outs — not `wpa_supplicant`,
`openvpn`, `dnsmasq`, `hostapd`, or the DHCP protocol itself.

## Approach

**Incremental, one function per PR, behind the existing test suite.** The
`SystemExecutor` interface is already the seam. Introduce small typed managers
(`RouteManager`, `LinkManager`, `FirewallManager`) in `pkg/types` with native
implementations; migrate the buggiest functions first; each PR is individually
reviewable and revertible. No rewrite.

---

## Shell-out inventory → library mapping

### TIER 1 — High value, low risk. Do these first.

| Current shell-out | Count | Native Go replacement | Notes |
|---|---|---|---|
| `ip route show [default]`, `ip route add/replace/del` | ~44 | **github.com/vishvananda/netlink** — `RouteList`, `RouteAdd`, `RouteReplace`, `RouteDel` | Structured `Route{Dst, Gw, LinkIndex, Scope}`. `Dst==nil` = default route; `Gw==nil` = device-only route (our wg0 case). Kills the text-parsing bugs directly. |
| `ip addr show/add/replace/flush` | ~9 | **vishvananda/netlink** — `AddrList`, `AddrAdd`, `AddrReplace`, `AddrDel` | Read ops work **without root**. Replaces `ParseIPFromOutput`. |
| `ip link show/set up/down/add/delete` | ~10 | **vishvananda/netlink** — `LinkByName`, `LinkSetUp`, `LinkSetDown`, `LinkAdd`, `LinkDel` | Also gives link type detection (wireless vs wired) without `iw`/sysfs scraping. |
| `ip -o link show` (interface detection) | — | **vishvananda/netlink** `LinkList` + `net.Interfaces()` | Complements the sysfs approach already used in `findDefaultInterface`. |

Single dependency: `github.com/vishvananda/netlink` (pure Go, MIT). This alone
covers the ~73 `ip` calls — the largest and most bug-prone category.

### TIER 2 — Clear wins, moderate scope.

| Current shell-out | Count | Native Go replacement | Notes |
|---|---|---|---|
| `iptables -t nat ... MASQUERADE`, FORWARD rules | ~18 | **github.com/coreos/go-iptables/iptables** | Pure Go wrapper over libiptc semantics; `AppendUnique`, `Delete`, `Exists`. Removes duplicate-rule and cleanup-ordering bugs in hotspot/dhcp. |
| `wg show/setconf` (WireGuard) | ~2 | **golang.zx2c4.com/wireguard/wgctrl** | Official WireGuard control lib. `Device()`, `ConfigureDevice()`. Replaces text parsing of `wg show` (peer detection in ListVPNs). Interface create/up still via netlink. |
| `cat <pidfile>` / `rm -f` / `mv` / `cp` / `install` / `mkdir` / `tee` | ~30 combined | **Go stdlib** `os`, `io`, `os/exec` gone | These are trivially replaceable with `os.ReadFile`, `os.Remove`, `os.Rename`, `os.WriteFile`, `os.MkdirAll`. Many already partly done. Low-hanging fruit, removes shell overhead + quoting risk. |
| `sh -c "echo N > /proc/sys/net/ipv4/ip_forward"` | ~6 | **Go stdlib** `os.WriteFile("/proc/sys/net/ipv4/ip_forward", ...)` | Direct sysctl write; no shell. |
| `kill`/`pkill`/`pgrep` | ~16 | **Go stdlib** `os.FindProcess`+`Signal`, or **github.com/mitchellh/go-ps** for name matching | Replaces the pidfile+pkill dance; more precise process targeting (addresses the unscoped-pkill-wpa_supplicant finding). |
| `chattr +i/-i /etc/resolv.conf` | ~5 | **golang.org/x/sys/unix** `FS_IOC_SETFLAGS` ioctl (FS_IMMUTABLE_FL) | Direct ioctl, no `chattr` binary. Keeps the resolv.conf immutability logic but native. |
| `ethtool` (carrier/link) | 1 | sysfs `/sys/class/net/<if>/carrier` (already used) or netlink link flags | Already mostly sysfs; drop ethtool. |
| `hostname` | ~2 | **Go stdlib** `os.Hostname()` | Trivial. |

### TIER 3 — Do NOT migrate (keep shelling out). Correct per CLAUDE.md.

| Tool | Why keep it |
|---|---|
| `wpa_supplicant` / `wpa_cli` (WiFi assoc) | This is `nl80211` — a large, separate netlink family. A native WiFi supplicant is a project unto itself (`github.com/mdlayher/wifi` can *read* status but not associate/authenticate). Keep shelling out. |
| `dhclient` / `udhcpc` (DHCP client) | DHCP is a userspace protocol. Options exist (`github.com/insomniacslk/dhcp`) but reimplementing lease acquisition + renewal is risky. Keep. |
| `dnsmasq` / `hostapd` (hotspot server side) | Full daemons. Not worth reimplementing. Keep. |
| `tailscale` / `netbird` (VPN CLIs) | Third-party control planes; the CLI *is* the API. Keep. |
| `openvpn` | Daemon. Keep. |
| `nmcli` (tell NetworkManager to release iface) | Talking to another daemon; CLI is the interface. Keep. |

---

## Recommended sequence (each = one small PR)

1. **Add `vishvananda/netlink`**; introduce `RouteManager` interface + netlink impl.
   Migrate `getCurrentGateway`, `ParseGatewayFromOutput`, `restoreDefaultRoute*`
   (the device-only-route bug lives here). Verify with existing integration tests.
2. Migrate address ops (`SetIP`, `ParseIPFromOutput`, addr flush) to netlink.
   Enables `net status` route/addr reads **without root**.
3. Migrate link ops (up/down/add/delete, WireGuard iface create) to netlink.
4. Replace `cat`/`rm`/`mv`/`cp`/`mkdir`/`tee`/`hostname` shell-outs with stdlib.
5. Replace `chattr` with the `FS_IOC_SETFLAGS` ioctl via `x/sys/unix`.
6. Replace `sh -c echo > /proc/...ip_forward` with `os.WriteFile`.
7. `iptables` → `coreos/go-iptables` (hotspot + dhcp NAT).
8. `wg show/setconf` → `wgctrl`.
9. `kill/pkill/pgrep` → stdlib process handling + `go-ps`.

Stop after any step — each stands alone and improves correctness.

## Dependencies added (all pure-Go, no cgo, single static binary preserved)

- `github.com/vishvananda/netlink` (Tier 1)
- `github.com/coreos/go-iptables` (Tier 2)
- `golang.zx2c4.com/wireguard/wgctrl` (Tier 2)
- `github.com/mitchellh/go-ps` (Tier 2, optional)
- `golang.org/x/sys/unix` (Tier 2 — likely already indirect)

Contrast with CLAUDE.md's "minimal dependencies (cobra, viper, logrus, testify)":
these are all small, widely-used, single-purpose libs — but the tradeoff (more deps
vs. fewer shell-outs) is a deliberate decision to make per tier, not a blanket yes.

## What this does NOT do

- Not a rewrite. Architecture, tests, and CLI are unchanged.
- Does not touch WiFi association, DHCP, VPN control planes, or hotspot daemons.
- Does not change behavior — same operations, native calls instead of text parsing.

## Open question for the maintainer

Tier 1 (netlink for routes/addrs/links) is the clear win: biggest bug category,
single dep, unlocks root-free `status`. Tiers 2–3 are optional and can be decided
later. Recommend starting with a Tier-1 proof-of-concept PR (`getCurrentGateway` +
gateway parsing) and evaluating before committing to the rest.
