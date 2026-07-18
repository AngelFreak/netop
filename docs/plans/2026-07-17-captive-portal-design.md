# Captive Portal Detection — Design

**Date:** 2026-07-17
**Status:** Validated with user (brainstorming session)

> **Revised after consensus review (see the implementation plan's Review Log for
> the round count).** This design has been synced to the final, reviewed
> contracts in `2026-07-17-captive-portal-implementation.md`; where the two
> differ the implementation plan is authoritative.

## Problem

Networks like `Amtrak_WiFi` sit behind a captive portal. After `net connect`, the
connection looks up (IP, gateway, DNS) but all traffic is blackholed until the
user logs in via a browser. Today the user must *remember* a probe URL (e.g.
`http://detectportal.brave-http-only.com/`) and visit it manually. netop once had
a DNS-based heuristic check (`getent`/`dig google.com`) but it was unreliable and
removed in `08c679d`; `Connect()` now skips detection entirely
(`pkg/wifi/wifi.go:248`).

## Decisions (validated with user)

1. **Handling:** Detect and print the portal's login URL when the portal supplies
   one via redirect, otherwise the probe URL to open in a browser (which the
   portal will intercept) — no browser auto-open, no auto-login. Fits netop's
   transparency and headless targets.
2. **Triggers:** Automatically at the end of `net connect` (non-fatal, short
   timeout, one settle-retry) **and** a standalone `net portal` command for
   re-checks (portals re-lock periodically).
3. **Probe endpoint:** `http://detectportal.firefox.com/success.txt` by default
   (plain HTTP, body `success`, widely allowlisted, Mozilla-run). Configurable
   via YAML.
4. **`net status`:** runs the same quick probe and shows an `Internet:` line.
5. **VPN interplay:** on portal detection during connect, warn + print URL, then
   proceed with the configured VPN attempt unchanged (WireGuard completes its
   handshake once the portal is cleared; user re-runs `net portal` after login).

## Architecture

New package `pkg/portal` implementing a new interface in `pkg/types`:

```go
// pkg/types

// PortalStatus classifies internet reachability as seen by the portal probe.
type PortalStatus int

const (
    // PortalStatusUnknown is the zero value — deliberately NOT online, so a
    // forgotten status field or future enum value can never fail open into
    // "internet works". CLI code treats it like offline.
    PortalStatusUnknown PortalStatus = iota
    PortalStatusOnline  // the probe returned the expected response — internet works
    PortalStatusPortal  // a captive portal intercepted the probe
    PortalStatusOffline // probe failed or returned a non-portal error status
)

// PortalResult is the outcome of a captive-portal probe.
//
// Display-safety contract: implementations MUST only populate PortalURL and
// ProbeURL with validated absolute http/https URLs that contain no control or
// format characters — CLI code prints these fields verbatim to the terminal.
type PortalResult struct {
    Status PortalStatus
    // PortalURL is the portal's login URL taken from the redirect Location
    // header, when the portal provided a usable one. Empty when the portal
    // didn't redirect (DNS-hijack style) or sent an unusable/unsafe Location —
    // open ProbeURL in a browser instead.
    PortalURL string
    // ProbeURL is the probe endpoint that was used. When PortalURL is empty,
    // opening ProbeURL in a browser will trigger the portal's redirect.
    ProbeURL string
}

// PortalDetector probes for internet connectivity and captive portals.
// Transport failures and unexpected error statuses are reported as
// PortalStatusOffline, not as errors; Check returns a non-nil error only for
// misconfiguration (e.g. an https probe URL, which portals cannot intercept).
// The probe uses the process's normal routing (default route); it is not bound
// to a specific interface.
type PortalDetector interface {
    Check() (PortalResult, error)
}
```

`pkg/portal.Detector` is constructed with probe URL, timeout, and logger
(dependency injection; the HTTP transport is a proxy-free
`http.DefaultTransport` clone built once in `New`, and is an injectable field for
tests). `New` substitutes a package-private no-op logger when passed nil, and a
non-positive timeout normalizes to the 3s default.

### Detection logic

Plain `net/http` GET (native Go, no shell-outs), with:

- Redirect following **disabled** (`CheckRedirect` returns
  `http.ErrUseLastResponse`) so we can read the portal's `Location`.
- Timeout from config (default **3s**).
- **No proxy** (explicit `Proxy: nil` on the cloned transport) — we are probing
  the local network path, not an environment proxy. This is deliberate: a proxy
  would answer on the portal's behalf and mask it. Documented in `net portal
  --help`.
- Cache-bypass request headers (`Cache-Control: no-cache, no-store` +
  `Pragma: no-cache`) so a stale cached `200 success` cannot fake Online.
- The default Go User-Agent is kept deliberately (revisit only if a real probe
  endpoint is found to require a browser UA).
- Response classified by **status first**; the body is read (with a size cap,
  `maxBodyBytes+1`) **only for a 200**, so a hanging redirect/error body cannot
  stall the probe until timeout.

Classification (matches the implementation plan's Architecture blurb exactly):

| Response | Result | Login/Probe URL |
|---|---|---|
| `204 No Content` | **Online** | — |
| `200` and body (ASCII-trimmed) == `success`, not oversized | **Online** | — |
| `301` / `302` / `303` / `307` / `308` | **Portal** | `PortalURL` from `Location` when it sanitizes, else `ProbeURL` fallback |
| `511 Network Authentication Required` | **Portal** | `Location` if present & sanitizes, else `ProbeURL` fallback |
| `401` / `403` **with a Location header present** | **Portal** (enterprise/hotel interception) | `PortalURL` when the Location sanitizes, else `ProbeURL` fallback |
| `200` with an unexpected body (DNS-hijack style) | **Portal** | `Location` used for `PortalURL` when sanitizable (Location never decides Online); else `ProbeURL` |
| `200` oversized body ("success" + KBs of junk) | **Portal** (never Online) | — |
| everything else — transport error, timeout, DNS failure, `304`, other non-redirect 3xx (`300`/`305`), bare `401`/`403`, `404`, `5xx` | **Offline** | — |

Key invariants driven by review:

- **Location-header PRESENCE is the interception evidence** for 401/403; the
  Location header's quality only decides `PortalURL` vs the `ProbeURL` fallback. A
  bare 401/403 (no Location) is **Offline** — a corporate 403 block page must not
  false-positive.
- **304 and non-redirect 3xx are Offline even WITH a `Location`** — a caching or
  reserved/deprecated 3xx is not interception, so a probe-endpoint outage or a
  caching intermediary is never misreported as a portal.
- The body is read only on 200; a body that dies mid-read on a 200 is a flaky
  link (**Offline**), **but** a `Location` captured before the read beats the
  broken-body heuristic (**Portal**).

**Location sanitization (`loginURL`).** The redirect target is only accepted as a
`PortalURL` when it is an **absolute http/https URL with a non-empty host**, or a
scheme-relative `//host/…` form with a non-empty parsed host (portal interception
necessarily restarts over http). Rejected → empty `PortalURL`, caller uses the
`ProbeURL` fallback:

- **path-relative** (`/login`), **bare-name** (`login`), and **query-only**
  (`?next=x`) references — resolving them against the probe host would mislabel
  "probe host + path" as the login URL, which is wrong under transparent
  interception.
- **degenerate scheme-relative** forms (`//`, `///`, `///evil/…`) with no
  non-empty host.
- non-http(s) schemes (`javascript:`, `file:`), **userinfo** (`user:pass@…`),
  unparseable input, percent-encoded C0/DEL control bytes, and anything over a
  2048-byte length cap.

When `PortalURL` is empty the CLI prints the `ProbeURL` as the address to open
manually (the portal will intercept it).

## CLI / UX

**`net portal`** (new command, root-exempt — added to the `commandNeedsRootArgs`
exemption list so it never re-execs under sudo; `Args: cobra.NoArgs`):

```
$ net portal
Captive portal detected!
  Log in at: http://amtrakconnect.com/login?... (default IPv4 route: wlan0)
$ echo $?
2
```

- **Always probes**, even with `common.portal.check: off` (which only disables the
  automatic checks in connect and status).
- **Exit codes: `0` online, `2` portal detected, `1` offline, `3` config/internal
  error.** `PortalStatusUnknown` (and any future/unmapped status) maps to `1`,
  never `0` — the exit switch fails closed.
- Online prints `Internet: ok`; offline prints the neutral `Internet:
  unreachable` (the HTTP-status detail stays in debug logs — no "no response from
  probe" copy that lies for a 4xx/5xx).
- Every `net portal` outcome carries `(default IPv4 route: <iface>)` when the
  preferred default route is known (mirrors `net status`).
- The testable logic lives in `App.RunPortal`; the cobra `Run` is a thin
  `os.Exit` switch (repo convention). `RunPortal`'s error path returns
  `PortalStatusOffline, err` (status is meaningful only when err is nil). Nil
  config with a live `ConfigMgr` → error + exit 3, no probe.

**`net connect`** — after `printConnectionInfo`, before the VPN attempt:

- One **settle-retry**: probe, and if the first result is Offline, wait a settle
  delay (default 500ms, `App.PortalRetryDelay` for tests) and probe once more;
  the offline warning is only emitted after the retry. `net portal`/`net status`
  stay single-shot.
- **Online** → nothing extra (keep connect output clean).
- **Portal** → `Warning: captive portal detected — log in at: <url>` (stderr,
  non-fatal), then the VPN attempt proceeds as configured.
- **Offline** → `Warning: no internet connectivity detected` (stderr,
  non-fatal). **Demoted to a debug log when a VPN resolves for the network** (a
  VPN-required network is expected to look offline until the tunnel is up); portal
  warnings are unaffected.
- **Unknown** → warns "internet connectivity could not be determined" (no retry —
  Unknown is not Offline), never silently no-ops.
- The VPN hint fires **only when a VPN actually resolves** for the network
  (`resolveVPNName`, extracted from the deleted `connectVPN`; single resolution
  reused by both the hint and the connect attempt).
- **Multi-home note** (see below) prints on **any** outcome, before the probe.

**`net status`** — adds one line using the same probe. Every outcome names the
preferred IPv4 default route when known, with unlabeled fallbacks when unknown:

```
Internet:  ok (default IPv4 route: eth0)
Internet:  captive portal (http://portal.example/login) (default IPv4 route: eth0)
Internet:  unreachable (default IPv4 route: eth0)
Internet:  probe error (…)          # misconfigured probe URL; labeled when route known
```

- **Honors `check: off`** — the Internet line is omitted entirely (the user
  explicitly disabled the check; `net portal` remains available on demand).
- **Skips probing on config load failure** (`portalCheckEnabled` returns false
  when `GetConfig() == nil` — policy is unknown, and the loader already surfaced
  the error).
- `PortalStatusUnknown` (and any unmapped status) prints `unreachable`, never
  `ok`.
- The line is **host-wide**, not scoped to the shown `Interface:` — it prints even
  when the selected interface is disconnected, because the probe uses the default
  route.

`App` gets a `PortalDet types.PortalDetector` field (wired in `createApp()` /
`createPortalDetector()` from the configured URL + timeout) and a `RouteMgr
types.RouteManager` field (wired to `netlink.NewRouteManager()`, nil-safe) used
by `preferredDefaultIface`.

## Multi-home: known product gap with honest signaling

The probe uses the process's normal routing (default route), **not** the
just-connected interface. netop models dual-homing as first-class (wired metric
100 beats WiFi 600), so connecting to a captive WiFi while Ethernet has internet
would probe via Ethernet and see "ok".

A connect-time **bound** probe IS technically feasible — `net connect` runs as
root (sudo re-exec), which has the caps for `SO_BINDTODEVICE` — but correct
binding also requires binding DNS resolution (a custom `net.Resolver` with a
`Dialer.Control` hook; Go's default resolver ignores the transport dialer), and
it would make `net connect` classify differently from the root-exempt `net
portal`/`net status` on the same network. That complexity/consistency trade-off
is **REJECTED as a product decision** for this feature, not an impossibility; a
follow-up issue for an opt-in bound connect-time probe is reasonable future work.

Instead the gap is **signaled**:

- `net connect` compares the preferred IPv4 default route's interface (via
  `preferredDefaultIface` — `ListRoutes()` → lowest-metric default, first-wins on
  ties; **not** `GetDefaultRoute`, which returns the first default in the netlink
  dump) with the just-connected interface and prints an **outcome-neutral** stderr
  note when they differ, naming the **remediation** (disable/unplug the preferred
  link, or open a browser on the captive SSID). A note the user cannot act on
  trains them to ignore it.
- `net status` and `net portal` label every Internet outcome with the preferred
  IPv4 default route when known.

This is an **IPv4 main-table metric heuristic, not a probe-egress guarantee**: on
a dual-stack host the probe may egress over IPv6. The `(default IPv4 route: …)`
label and the godoc/README both state this scope. `check: off` disables the
automatic checks and therefore this note along with them.

## Configuration

```yaml
common:
  portal:
    check: auto   # "auto" (default) or "off"; anything else is rejected at load
    url: http://detectportal.firefox.com/success.txt
      # must be plain http with a host; a custom endpoint must answer
      # HTTP 204 or a 200 body of exactly "success" when internet works.
  timeouts:
    portal: 3     # captive-portal probe timeout in seconds, default 3
```

- New `PortalConfig` struct on `CommonConfig` (`portal` added to
  `validCommonFields`, with its own `validPortalFields` valid-field validation
  like `timeouts`). `PortalConfig.CheckDisabled()` normalizes case/whitespace so
  `"Off"` / `" OFF "` behave as `off`.
- `Portal int` added to `TimeoutConfig` with `GetPortalTimeout()` defaulting to
  3s (non-positive → default).
- **`common.portal` must be absent, null, or a map.** A scalar or list
  (`portal: off`, `portal: true`, `portal: [auto]`) is rejected with an explicit
  "must be a mapping" error — otherwise viper/mapstructure produces a cryptic
  decode error or a silent zero struct. Bare `portal:` / `portal: null` are valid
  stubs (defaults apply).
- **`check` is validated on the raw map before unmarshal.** Viper weak-typing
  silently coerces YAML bools/ints to `"0"`/`"1"` with no decode error, which
  would invert the user's intent; the raw-map check requires a Go string whose
  trimmed/lowercased value is `""`, `"auto"`, or `"off"` — anything else fails
  with `common.portal.check must be "auto" or "off"`.
- **`url` is validated at load** (the CLI prints ProbeURL verbatim under the
  display-safety contract): absent / null / empty string → the built-in default
  (no error); a non-empty string must pass `types.ValidatePortalProbeURL`
  (visible-ASCII-only `0x21..0x7e` — no spaces, controls, or non-ASCII / IDN
  confusables — then parseable, scheme `http`, non-empty host, no userinfo, no
  fragment, no percent-encoded control bytes); a non-string (YAML bool/int/list)
  fails with `common.portal.url must be a string`.
- `check: off` disables the automatic connect-time and status checks (and the
  multi-home note) only; `net portal` always probes on demand.
- Value errors use the `ValidationError.Message` field (its `Error()` returns
  `Message` verbatim when set, else the existing unknown-field wording) — the
  validation pass returns `ValidationErrors`, never a bare `fmt.Errorf`.

Self-hosted / LAN-local probe URLs are **allowed deliberately** (privacy), but a
LAN-local probe answers even when the internet is down — documented in
`config.example`. Localhost/private/loopback probe URLs are **not** rejected.

> Note: unlike `common.portal`, the `timeouts.*` subfields remain historically
> **unvalidated** — a `timeouts.portl` typo silently falls back to the 3s
> default. Tightening that is out of scope (changing it could break configs that
> load today).

## Error handling

- Detection is **never fatal** to connect — worst case is a warning line.
- All transport failures collapse to `Offline`; `Check()` returns a non-nil error
  only for misconfiguration (invalid/HTTPS probe URL).
- `net status` prints `Internet: probe error (…)` (or skips the line on config
  load failure / `check: off`) rather than failing the whole status output.
- `net portal` maps a config/internal error to **exit 3**, distinct from offline
  (**exit 1**).

## Testing

- `pkg/portal` unit tests with `httptest.Server` covering every classification
  row (204, 200+success, the redirect-status table 301/302/303/307/308 → portal
  and 300/304/305 → offline, 511, 401/403 ± Location, 200+garbage body, oversized
  body, U+00A0-padded success, body read failure, cache-bypass headers,
  connection refused, timeout) — deterministic, no real network. Hostile
  `Location`/probe-URL paths that Go's transport rejects on the wire are covered
  by pure `loginURL` / `ValidatePortalProbeURL` unit tests instead.
- HTTPS-URL and no-host probe misconfiguration returns error.
- `cmd/net` app tests with a mock `PortalDetector`: connect prints portal warning
  and still attempts VPN; VPN offline-warning demotion; settle-retry both
  outcomes; Unknown warns; `net portal` exit codes and route labels;
  `RunPortal` ignores `check: off`; config-load-failure exit 3; status line
  rendering for all states incl. Unknown-never-ok, disconnected-iface, and
  default-route labels; `createPortalDetector` wiring through a live httptest
  server.
- Config tests: `portal` map/null/scalar shapes, unknown subfields rejected,
  `check`/`url` value + non-string validation, empty/null/absent `url` → default,
  `GetPortalTimeout` default incl. negative and the aggregate suites.

## Out of scope (YAGNI)

- Auto-opening browsers, auto-submitting portal forms.
- Multiple fallback probe endpoints.
- Periodic background re-checking (netop has no daemon).
- IPv6-specific probing; per-destination routing lookup for the multi-home note.
- Interface-bound connect-time probing (feasible but rejected — see Multi-home).
