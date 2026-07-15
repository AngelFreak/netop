# netop Migration Execution Plan (all tiers)

Companion to MIGRATION.md. This is the concrete, ordered execution plan. Each
numbered item = one PR, behind the existing test suite, individually revertible.
Principle: replace fragile *text-parsing* shell-outs with native Go; keep
daemons/control-planes (wpa_supplicant, dhclient, dnsmasq, hostapd, openvpn,
tailscale, netbird, nmcli) as shell-outs.

## Architecture seam

Add typed interfaces in `pkg/types/types.go`, netlink/native impls in new
subpackages, wired via dependency injection (matching existing managers). The
`SystemExecutor` stays for the tools we keep shelling out to.

New interfaces:
- `RouteManager`  — GetDefaultRoute, ReplaceDefault, AddRoute, DelRoute, ListRoutes
- `LinkManager`   — ByName, SetUp, SetDown, Add, Delete, List, IsWireless
- `AddrManager`   — List, Add, Replace, Flush
- `FirewallManager` — EnsureMasquerade, EnsureForward, RemoveRules (Tier 2)

Each netlink call needs a graceful fallback path documented (return error, let
caller decide) since some environments (containers) restrict netlink.

---

## TIER 1 — netlink for routes / addresses / links (github.com/vishvananda/netlink)

**T1.1 — Add dependency + RouteManager skeleton + netlink impl**
- `go get github.com/vishvananda/netlink`
- Add `RouteManager` interface, `pkg/netlink/route.go` impl.
- Unit tests with a fake RouteManager; integration test (tagged) exercises real netlink in a netns.

**T1.2 — Migrate gateway detection (highest-bug area)**
- Replace `getCurrentGateway` (pkg/vpn/vpn.go) and `ParseGatewayFromOutput`
  (pkg/system/utils.go). Handle BOTH `Gw != nil` (via gateway) AND `Gw == nil`
  (device-only default, e.g. wg0) — the current text parser mishandles the latter.
- `restoreDefaultRoute` / `restoreDefaultRouteFromState` (pkg/vpn) use RouteManager.

**T1.3 — Migrate route add/replace/del**
- `AddRoute`, default-route set, endpoint /32 protective route (pkg/vpn, pkg/network).
- `applyDefaultRouteMetric` (pkg/network) — set metric via netlink Route.Priority.

**T1.4 — Migrate address ops (AddrManager)**
- `SetIP`, addr flush, `ParseIPFromOutput`, `GetConnectionInfo` IP read (pkg/network).
- Read path enables `net status` addr/route reads WITHOUT root — update
  commandNeedsRoot accordingly (status already exempt; verify it truly works unprivileged).

**T1.5 — Migrate link ops (LinkManager)**
- link up/down/add/delete/flush; WireGuard interface create/delete (pkg/vpn),
  hotspot/dhcp interface up-down (pkg/hotspot, pkg/dhcp).
- `IsWireless` via netlink link type — complements sysfs in findDefaultInterface.

Exit criteria for Tier 1: all ~73 `ip` shell-outs gone; integration tests green;
`net status` works unprivileged; `go test -race ./...` clean; binary still
CGO_ENABLED=0.

---

## TIER 2 — targeted native replacements

**T2.1 — iptables → github.com/coreos/go-iptables**
- FirewallManager interface; migrate hotspot + dhcp NAT (MASQUERADE, FORWARD).
- Use AppendUnique/Exists/Delete — removes duplicate-rule and cleanup bugs.

**T2.2 — chattr → FS_IOC_SETFLAGS ioctl (golang.org/x/sys/unix)**
- Native immutable flag set/clear for resolv.conf (pkg/network). Keep exact
  ownership semantics from the round-2 fix; add tests via a temp file.

**T2.3 — sysctl ip_forward → os.WriteFile**
- Replace `sh -c "echo N > /proc/sys/net/ipv4/ip_forward"` (hotspot, dhcp).
  Keep the save/restore-prior-value logic.

**T2.4 — wg show/setconf → golang.zx2c4.com/wireguard/wgctrl**
- Peer/status read (ListVPNs peer detection) and config apply (pkg/vpn).
  Interface create/up stays netlink (from T1.5).

**T2.5 — file/proc stdlib cleanup**
- `cat`→os.ReadFile, `rm`→os.Remove, `mv`→os.Rename, `cp`→io.Copy,
  `mkdir`→os.MkdirAll, `tee`/`install`→os.WriteFile(0600), `hostname`→os.Hostname.
- `kill`/`pkill`/`pgrep` → os.FindProcess+Signal / github.com/mitchellh/go-ps.
  This also lets us scope the wpa_supplicant kill precisely (prior finding).

Exit criteria Tier 2: iptables/chattr/sysctl/wg/file shell-outs gone; NAT
correctness tests; static binary preserved.

---

## TIER 3 — explicitly NOT migrated (documented decisions)

Keep shelling out: wpa_supplicant/wpa_cli (nl80211 supplicant = separate project),
dhclient/udhcpc (DHCP protocol), dnsmasq/hostapd (daemons), openvpn (daemon),
tailscale/netbird (control-plane CLIs), nmcli (another daemon). No work here;
this tier exists to record the boundary so future contributors don't re-litigate it.

---

## Cross-cutting requirements (every PR)

- Behind existing unit + integration tests; add tests for each migrated function.
- `go test -race ./...`, `go vet`, `gofmt -l` clean (CI gates these).
- Binary must still build with `CGO_ENABLED=0` (release.yml requirement).
- Preserve exact behavior (same ops, native calls) — no behavior changes bundled in.
- Graceful degradation: if a netlink op fails (restricted env), return a clear
  error; never panic.
- Update CLAUDE.md's "minimal dependencies" note as deps are added, with rationale.

## Risks / mitigations

- **Netlink permission in some envs**: read ops are unprivileged; write ops need
  CAP_NET_ADMIN which net already has. Document + fallback error.
- **Behavior drift**: migrate one function per PR; integration tests in netns are
  the safety net (already exist in tests/integration/testutil).
- **Dep footprint**: all Tier-1/2 libs are pure-Go, single-purpose, widely used.
  Decide per tier; Tier 1 is the committed win, Tiers 2-3 optional.

## Sequencing

Tier 1 fully first (it's the bug-removal win and unblocks root-free status), then
Tier 2 items in any order. Tier 3 is never executed. Recommend a Tier-1 T1.2 PoC
(gateway detection) reviewed before proceeding to the rest of Tier 1.

---

## Review corrections (Codex + Grok)

Incorporate before execution:

1. **iptables is NOT native.** `coreos/go-iptables` execs the `iptables` binary
   (with `-w` locking, `AppendUnique`/`Exists`/`Delete`). It reduces duplicate-rule
   and list-parsing bugs but keeps the binary dependency. Relabel T2.1 as "safer
   iptables wrapper (still exec)", not native. Still worth doing for correctness.

2. **The "status without root" win is partial.** netlink read ops (RouteList,
   AddrList) are unprivileged, BUT `net status` also calls `currentSSID` →
   `iw dev <if> link`, which is still a binary + may need perms. Don't claim fully
   root-free status until the SSID read is addressed (mdlayher/wifi can READ status
   via nl80211, or accept a narrow iw shell for SSID). Adjust T1.4 accordingly.

3. **Missing Tier-1 migration sites** (add as explicit items):
   - MAC get/set: `ip link ... address` (SetMAC), `GetMAC` parsing of `link/ether`,
     and permanent-MAC via `ethtool -P` (driver-dependent — may keep a narrow
     ethtool shell for the permanent case; netlink handles set/get).
   - `applyDefaultRouteMetric` (network.go) — set via `Route.Priority`, and its
     current del+re-add text parsing.
   - `ip link show type wireguard` enumeration + `wg show` scraping in
     `ListVPNs`/`disconnectLegacy` (vpn.go) — netlink LinkList by type + wgctrl.
   - `detectOutInterface` (hotspot.go) default-route parsing.
   - `dhcpclient.parseIPAddress` / `ip addr show` usage.
   - Remove now-dead `Parse*FromOutput` helpers + their tests as sites migrate.

4. **DI/refactor surface is larger than stated.** Decide explicitly: do existing
   managers grow `RouteManager`/`LinkManager` fields, or a hybrid? Every mock
   executor in tests needs a corresponding fake for the new managers. Budget for
   this wiring in T1.1.

5. **Preserve atomic/secure file semantics.** `WriteSecureFile` uses
   `install -m 0600 /dev/stdin` specifically for atomic 0600 creation (TOCTOU
   avoidance). A stdlib replacement must be tempfile+chmod+rename, not a naive
   `os.WriteFile`. Same care for the chattr→ioctl change: GETFLAGS + bit-twiddle +
   SETFLAGS (don't clobber other flags), preserving the round-2 ownership/restore
   semantics exactly.

6. **go-ps changes pkill semantics.** `pkill -f` matches full argv; `go-ps` matches
   comm/argv differently. This directly affects the scoped-wpa_supplicant-kill logic
   — test that the new matching targets the same processes. Higher risk than the
   plan implied.

7. **Netlink parity must be explicitly tested**, not assumed:
   - Device-only default route (`default dev wg0`, `Gw==nil`, Scope LINK) must
     return the exact same `(gw="", iface="wg0")` tuple as today — a dedicated test.
   - Set Family (FAMILY_V4), Table (main), Scope, Priority correctly or you get
     "file exists" / wrong scope / IPv6 leakage.
   - Implement the graceful EPERM path (restricted envs), don't just document it.
   - WireGuard LinkAdd attrs (MTU, txqlen) must match `ip link add ... type wireguard`.
   - Error messages become syscall-style, not "ip: ... (stderr: ...)" — update any
     tests/log assertions that match on the old text.

8. **Start file/proc cleanups (T2.3, T2.5) earlier** — they're low-risk and can
   land in parallel with Tier 1, front-loading easy wins.
