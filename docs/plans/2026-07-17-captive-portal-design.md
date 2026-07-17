# Captive Portal Detection — Design

**Date:** 2026-07-17
**Status:** Validated with user (brainstorming session)

## Problem

Networks like `Amtrak_WiFi` sit behind a captive portal. After `net connect`, the
connection looks up (IP, gateway, DNS) but all traffic is blackholed until the
user logs in via a browser. Today the user must *remember* a probe URL (e.g.
`http://detectportal.brave-http-only.com/`) and visit it manually. netop once had
a DNS-based heuristic check (`getent`/`dig google.com`) but it was unreliable and
removed in `08c679d`; `Connect()` now skips detection entirely
(`pkg/wifi/wifi.go:248`).

## Decisions (validated with user)

1. **Handling:** Detect and print the actual portal login URL — no browser
   auto-open, no auto-login. Fits netop's transparency and headless targets.
2. **Triggers:** Automatically at the end of `net connect` (non-fatal, short
   timeout) **and** a standalone `net portal` command for re-checks (portals
   re-lock periodically).
3. **Probe endpoint:** `http://detectportal.firefox.com/success.txt` by default
   (plain HTTP, body `success`, widely allowlisted, Mozilla-run). Configurable
   via YAML.
4. **`net status`:** runs the same quick probe and shows an `Internet:` line.
5. **VPN interplay:** on portal detection during connect, warn + print URL, then
   proceed with the configured VPN attempt unchanged (WireGuard will complete
   once the portal is cleared; user re-runs `net portal` after login).

## Architecture

New package `pkg/portal` implementing a new interface in `pkg/types`:

```go
// pkg/types
type PortalStatus int

const (
    PortalStatusOnline  PortalStatus = iota // internet reachable
    PortalStatusPortal                      // captive portal intercepting
    PortalStatusOffline                     // no connectivity at all
)

type PortalResult struct {
    Status    PortalStatus
    PortalURL string // login URL from redirect Location; may be "" if unknown
}

type PortalDetector interface {
    Check() (PortalResult, error) // error only for internal misuse (bad config URL)
}
```

`pkg/portal.Detector` is constructed with probe URL, timeout, and logger
(dependency injection; HTTP client built internally but base transport is
injectable for tests via an optional field).

### Detection logic

Plain `net/http` GET (native Go, no shell-outs), with:

- Redirect following **disabled** (`CheckRedirect` returns
  `http.ErrUseLastResponse`) so we can read the portal's `Location`.
- Timeout from config (default **3s**).
- **No proxy** (explicit `Proxy: nil` on the transport) — we are probing the
  local network path, not an environment proxy.
- Response body read with a 4 KB limit.
- HTTP only; if the configured probe URL is HTTPS, return an error telling the
  user portals cannot intercept HTTPS (defeats detection).

Classification:

| Response | Result |
|---|---|
| `204 No Content` | Online (supports generate_204-style endpoints) |
| `200` and body (trimmed) == `success` | Online |
| `30x` with `Location` | Portal; URL = `Location` resolved against probe URL (handles relative redirects) |
| `511 Network Authentication Required` | Portal; URL from `Location` if present, else "" |
| `200` with unexpected body (DNS-hijack portals) | Portal; URL = "" |
| transport error / timeout / DNS failure | Offline |

When `PortalURL` is empty the CLI prints the probe URL as the address to open
manually (the portal will intercept it).

## CLI / UX

**`net portal`** (new command):

```
$ net portal
Captive portal detected!
  Log in at: http://amtrakconnect.com/login?...
$ echo $?   # exit codes for scripting
2
```

Exit codes: `0` online, `2` portal detected, `1` offline or error.
Output for online: `Internet: ok`. Offline: `Internet: unreachable (no
response from probe)`.

**`net connect`** — after `printConnectionInfo`, before the VPN attempt:

- Online → nothing extra (keep connect output clean).
- Portal → `Warning: captive portal detected — log in at: <url>` (stderr,
  non-fatal), then VPN proceeds as configured plus a hint that VPN will
  complete after portal login.
- Offline → `Warning: no internet connectivity detected` (could be slow DHCP
  upstream; non-fatal).

**`net status`** — adds one line using the same probe:

```
Internet:  ok | captive portal (http://...) | unreachable
```

`App` gets a `PortalDet types.PortalDetector` field, wired in `createApp()`.

## Configuration

```yaml
common:
  portal:
    check: auto            # "auto" (default) or "off" — auto-check on connect
    url: http://detectportal.firefox.com/success.txt
  timeouts:
    portal: 3              # seconds, default 3
```

- New `PortalConfig` struct on `CommonConfig` (`portal` added to
  `validCommonFields`, with its own valid-field validation like `timeouts`).
- `Portal int` added to `TimeoutConfig` with `GetPortalTimeout()` defaulting
  to 3s.
- `check: off` disables the automatic connect-time check only; `net portal`
  and `net status` always probe on demand.

## Error handling

- Detection is **never fatal** to connect — worst case is a warning line.
- All transport failures collapse to `Offline`; `Check()` returns a non-nil
  error only for misconfiguration (invalid/HTTPS probe URL).
- `net status` prints `Internet: unreachable` rather than failing the whole
  status output if the probe errors.

## Testing

- `pkg/portal` unit tests with `httptest.Server` covering every classification
  row (204, 200+success, 302+absolute Location, 302+relative Location, 511,
  200+garbage body, connection refused, timeout) — deterministic, no real
  network.
- HTTPS-URL misconfiguration returns error.
- `cmd/net` app tests with a mock `PortalDetector`: connect prints portal
  warning and still attempts VPN; `net portal` exit codes; status line
  rendering for all three states.
- Config tests: `portal` fields parse, unknown subfields rejected,
  `GetPortalTimeout` default.

## Out of scope (YAGNI)

- Auto-opening browsers, auto-submitting portal forms.
- Multiple fallback probe endpoints.
- Periodic background re-checking (netop has no daemon).
- IPv6-specific probing.
