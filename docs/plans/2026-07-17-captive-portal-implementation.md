# Captive Portal Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect captive portals (e.g. Amtrak_WiFi) after connect, on demand via `net portal`, and in `net status` — printing the actual portal login URL.

**Architecture:** New `pkg/portal.Detector` does a plain-HTTP GET to a probe URL (default `http://detectportal.firefox.com/success.txt`) with redirects disabled. Classification: 204 or `success` body → online; 3xx or 511 → portal (login URL from `Location`); 200 with unexpected body → portal (DNS-hijack style); transport errors **and all other HTTP statuses (4xx/5xx)** → offline, so a probe-endpoint outage is never misreported as a portal. Exposed via a new `types.PortalDetector` interface injected into `App`. Non-fatal warning in `net connect`, standalone root-exempt `net portal` command with scripting exit codes, one `Internet:` line in `net status`.

**Tech Stack:** Go stdlib `net/http` + `httptest` (no new dependencies), cobra, testify.

**Design doc:** `docs/plans/2026-07-17-captive-portal-design.md`

**Verified facts this plan relies on** (checked against the tree at `3923607`+):

- Config is loaded in `rootCmd.PersistentPreRun` → `initializeManagers()` (`cmd/net/main.go:75-77`, LoadConfig at `main.go:238`), which cobra runs **before** any command's `Run` — so `createApp()`/`createPortalDetector()` always see a loaded config in real runs. The nil-config fallback only covers load failures.
- `os.Exit` inside cobra `Run` is the repo-wide convention (`status.go:14`, `connect.go:37`, every command file). `net portal` follows it; testable logic lives in `App.RunPortal`.
- Root elevation: `commandNeedsRootArgs` (`cmd/net/main.go:~130`) exempts only `help, completion, status, show, list` — `portal` MUST be added there or it re-execs under sudo.
- `gopkg.in/yaml.v3` (used by viper v1.18.2 here) parses unquoted `check: off` as the **string** `"off"`, not a boolean (verified empirically). The config test below locks this.
- `newTestApp()` (`cmd/net/app_test.go:321`) leaves `testConfigManager.config` **nil**; connect tests must inject their own `testConfigManager` (mirror `TestApp_RunConnect_DirectSSID:436`).
- `trackingVPNManager` (`app_test.go:1240`) embeds `testVPNManager` and only tracks `Disconnect`; Task 5 extends it.

---

### Task 1: types — PortalStatus, PortalResult, PortalDetector, portal timeout

**Files:**
- Modify: `pkg/types/types.go`
- Test: `pkg/types/validation_test.go` (timeout getter tests live here)

**Step 1: Write the failing test** (append to `pkg/types/validation_test.go`)

```go
func TestTimeoutConfigGetPortalTimeout(t *testing.T) {
	config := &TimeoutConfig{}
	assert.Equal(t, 3*time.Second, config.GetPortalTimeout())

	config = &TimeoutConfig{Portal: 10}
	assert.Equal(t, 10*time.Second, config.GetPortalTimeout())
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/types/ -run TestTimeoutConfigGetPortalTimeout -v`
Expected: compile error `config.GetPortalTimeout undefined`

**Step 3: Write minimal implementation**

In `pkg/types/types.go`:

Add `Portal int` field to `TimeoutConfig`:

```go
	Portal      int `yaml:"portal" mapstructure:"portal"`           // Captive portal probe (default: 3s)
```

Add getter after `GetCarrierTimeout`:

```go
// GetPortalTimeout returns the captive-portal probe timeout with default fallback
func (t *TimeoutConfig) GetPortalTimeout() time.Duration {
	if t.Portal > 0 {
		return time.Duration(t.Portal) * time.Second
	}
	return 3 * time.Second
}
```

Add types + interface (near the manager interfaces):

```go
// PortalStatus classifies internet reachability as seen by the portal probe.
type PortalStatus int

const (
	// PortalStatusOnline means the probe returned the expected response — internet works.
	PortalStatusOnline PortalStatus = iota
	// PortalStatusPortal means a captive portal intercepted the probe.
	PortalStatusPortal
	// PortalStatusOffline means the probe failed or returned a non-portal error
	// status — no working internet, but no portal positively identified either.
	PortalStatusOffline
)

// PortalResult is the outcome of a captive-portal probe.
type PortalResult struct {
	Status PortalStatus
	// PortalURL is the portal's login URL taken from the redirect Location
	// header, when the portal provided one. Empty when the portal didn't
	// redirect (DNS-hijack style) — open ProbeURL in a browser instead.
	PortalURL string
	// ProbeURL is the probe endpoint that was used. When PortalURL is empty,
	// opening ProbeURL in a browser will trigger the portal's redirect.
	ProbeURL string
}

// PortalDetector probes for internet connectivity and captive portals.
// Transport failures and unexpected error statuses are reported as
// PortalStatusOffline, not as errors; Check returns a non-nil error only for
// misconfiguration (e.g. an https probe URL, which portals cannot intercept).
type PortalDetector interface {
	Check() (PortalResult, error)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/types/ -v -run Portal`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/types/types.go pkg/types/validation_test.go
git commit -m "feat(types): portal detector interface and portal probe timeout"
```

---

### Task 2: config — `common.portal` section with nested validation

**Files:**
- Modify: `pkg/types/types.go` (CommonConfig + PortalConfig struct)
- Modify: `pkg/config/config.go` (validCommonFields, validPortalFields, nested validation)
- Test: `pkg/config/config_test.go`

**Step 1: Write the failing tests** (append to `pkg/config/config_test.go`; check the file for the existing temp-config helper / constructor names and mirror them exactly)

```go
func TestPortalConfigParsing(t *testing.T) {
	// NB: `check: off` is deliberately unquoted — yaml.v3 must keep it a string.
	configContent := `
common:
  portal:
    check: off
    url: http://example.com/probe
  timeouts:
    portal: 7
`
	// ...temp-file + LoadConfig boilerplate per existing tests...
	assert.NoError(t, err)
	assert.Equal(t, "off", cfg.Common.Portal.Check)
	assert.Equal(t, "http://example.com/probe", cfg.Common.Portal.URL)
	assert.Equal(t, 7*time.Second, cfg.Common.Timeouts.GetPortalTimeout())
}

func TestPortalConfigUnknownFieldRejected(t *testing.T) {
	configContent := `
common:
  portal:
    chek: off
`
	// ...LoadConfig...
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chek")
}

func TestPortalConfigBadCheckValueRejected(t *testing.T) {
	configContent := `
common:
  portal:
    check: sometimes
`
	// ...LoadConfig...
	assert.Error(t, err)
}
```

**Step 2: Run to verify failure**

Run: `go test ./pkg/config/ -run TestPortalConfig -v`
Expected: FAIL — `cfg.Common.Portal` undefined / `portal` rejected as unknown common field

**Step 3: Implement**

`pkg/types/types.go` — add to `CommonConfig`:

```go
	Portal   PortalConfig  `yaml:"portal" mapstructure:"portal"`
```

New struct after `TimeoutConfig`:

```go
// PortalConfig controls captive-portal detection.
type PortalConfig struct {
	// Check is "auto" (default: probe after connect and in status) or "off"
	// (skip those automatic checks; `net portal` always probes on demand).
	Check string `yaml:"check" mapstructure:"check"`
	// URL is the plain-http probe endpoint. Empty means the built-in default.
	URL string `yaml:"url" mapstructure:"url"`
}

// CheckDisabled reports whether automatic portal checks are turned off.
func (p *PortalConfig) CheckDisabled() bool {
	return p.Check == "off"
}
```

`pkg/config/config.go`:

```go
	// Valid fields for PortalConfig
	validPortalFields = map[string]bool{
		"check": true,
		"url":   true,
	}
```

Add `"portal": true` to `validCommonFields`. In the validation pass where `common` is validated (around `config.go:195`), when the common map contains a `portal` key that is itself a map, validate its subfields against `validPortalFields` (same `validateFields` helper, section name `common.portal`), and reject a `check` value that is a string other than `""`, `"auto"`, or `"off"`. (Nested `timeouts` subfields are historically unvalidated — `portal` is stricter on purpose: a typo in `check`/`url` silently re-enables probing or probes the wrong host, per review.)

**Step 4: Run to verify pass**

Run: `go test ./pkg/config/ ./pkg/types/`
Expected: PASS (all — watch for existing validation tests that enumerate common fields)

**Step 5: Commit**

```bash
git add pkg/types/types.go pkg/config/config.go pkg/config/config_test.go
git commit -m "feat(config): common.portal section with validated fields"
```

---

### Task 3: pkg/portal — the Detector

**Files:**
- Create: `pkg/portal/portal.go`
- Create: `pkg/portal/portal_test.go`

**Step 1: Write the failing tests**

```go
package portal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

var _ types.PortalDetector = (*Detector)(nil)

type testLogger struct{}

func (l *testLogger) Debug(msg string, fields ...interface{}) {}
func (l *testLogger) Info(msg string, fields ...interface{})  {}
func (l *testLogger) Warn(msg string, fields ...interface{})  {}
func (l *testLogger) Error(msg string, fields ...interface{}) {}

func newTestDetector(url string) *Detector {
	return New(url, 2*time.Second, &testLogger{})
}

func TestCheck_Online_204(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOnline, result.Status)
	assert.Empty(t, result.PortalURL)
}

func TestCheck_Online_SuccessBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("success\n"))
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOnline, result.Status)
}

func TestCheck_Portal_RedirectAbsolute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://portal.example.com/login?res=notyet")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Equal(t, "http://portal.example.com/login?res=notyet", result.PortalURL)
	assert.Equal(t, srv.URL, result.ProbeURL)
}

func TestCheck_Portal_RedirectRelative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Equal(t, srv.URL+"/login", result.PortalURL)
}

func TestCheck_Portal_511(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNetworkAuthenticationRequired)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Empty(t, result.PortalURL) // no Location — caller falls back to ProbeURL
	assert.Equal(t, srv.URL, result.ProbeURL)
}

func TestCheck_Portal_HijackedOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>Welcome to Amtrak WiFi</html>"))
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Empty(t, result.PortalURL)
	assert.Equal(t, srv.URL, result.ProbeURL)
}

func TestCheck_Offline_ServerError(t *testing.T) {
	// A broken probe endpoint (CDN outage, corporate block page with 5xx)
	// must NOT be reported as a captive portal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, result.Status)
}

func TestCheck_Offline_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, result.Status)
}

func TestCheck_Offline_ConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(nil)
	url := srv.URL
	srv.Close() // now refused

	result, err := newTestDetector(url).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, result.Status)
}

func TestCheck_Offline_Timeout(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked // hold the request open past the detector timeout
	}))
	defer func() { close(blocked); srv.Close() }()

	d := New(srv.URL, 200*time.Millisecond, &testLogger{})
	start := time.Now()
	result, err := d.Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, result.Status)
	assert.Less(t, time.Since(start), 2*time.Second) // honored the timeout
}

func TestCheck_Portal_MalformedLocationNotEchoed(t *testing.T) {
	// A hostile AP could stuff terminal escape sequences into Location.
	// Unparseable Locations must never be passed through raw.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://bad.example.com/\x1b]0;pwned\x07")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.NotContains(t, result.PortalURL, "\x1b")
}

func TestCheck_HTTPSRejected(t *testing.T) {
	_, err := newTestDetector("https://example.com/probe").Check()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http")
}

func TestNew_DefaultURL(t *testing.T) {
	d := New("", time.Second, &testLogger{})
	assert.Equal(t, DefaultProbeURL, d.probeURL)
}
```

**Step 2: Run to verify failure**

Run: `go test ./pkg/portal/ -v`
Expected: FAIL — package doesn't compile (no portal.go)

**Step 3: Write implementation** — `pkg/portal/portal.go`:

```go
// Package portal detects captive portals by probing a known plain-HTTP
// endpoint and classifying the response, the same technique Firefox
// (detectportal.firefox.com) and Android (generate_204) use. Plain Go
// net/http — no shell-outs, no external binaries.
package portal

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/types"
)

// DefaultProbeURL is Mozilla's connectivity-check endpoint. It is plain HTTP
// (interceptable by portals) and widely allowlisted because every Firefox
// install probes it.
const DefaultProbeURL = "http://detectportal.firefox.com/success.txt"

// maxBodyBytes caps how much of the probe response we read; the expected
// bodies are tiny ("success" or empty).
const maxBodyBytes = 4096

// Detector probes for captive portals. Implements types.PortalDetector.
type Detector struct {
	probeURL string
	timeout  time.Duration
	logger   types.Logger
	// transport overrides the HTTP transport in tests; nil uses a
	// proxy-free default so we probe the local network path.
	transport http.RoundTripper
}

// New creates a Detector. An empty probeURL selects DefaultProbeURL.
func New(probeURL string, timeout time.Duration, logger types.Logger) *Detector {
	if probeURL == "" {
		probeURL = DefaultProbeURL
	}
	return &Detector{probeURL: probeURL, timeout: timeout, logger: logger}
}

// Check probes the endpoint and classifies the response. Transport failures
// and unexpected error statuses mean PortalStatusOffline (nil error); an
// error is returned only for a misconfigured probe URL.
func (d *Detector) Check() (types.PortalResult, error) {
	u, err := url.Parse(d.probeURL)
	if err != nil {
		return types.PortalResult{}, fmt.Errorf("invalid portal probe URL %q: %w", d.probeURL, err)
	}
	if u.Scheme != "http" {
		return types.PortalResult{}, fmt.Errorf("portal probe URL must be plain http, got %q — portals cannot intercept %s", d.probeURL, u.Scheme)
	}

	transport := d.transport
	if transport == nil {
		// No proxy: the point is to test the local network path directly.
		transport = &http.Transport{Proxy: nil}
	}
	client := &http.Client{
		Timeout:   d.timeout,
		Transport: transport,
		// Don't follow redirects — the portal's Location header IS the answer.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(d.probeURL)
	if err != nil {
		d.logger.Debug("Portal probe got no response", "url", d.probeURL, "error", err)
		return types.PortalResult{Status: types.PortalStatusOffline, ProbeURL: d.probeURL}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	d.logger.Debug("Portal probe response", "status", resp.StatusCode)

	switch {
	case resp.StatusCode == http.StatusNoContent,
		resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == "success":
		return types.PortalResult{Status: types.PortalStatusOnline, ProbeURL: d.probeURL}, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400,
		resp.StatusCode == http.StatusNetworkAuthenticationRequired:
		return types.PortalResult{
			Status:    types.PortalStatusPortal,
			PortalURL: d.locationURL(resp),
			ProbeURL:  d.probeURL,
		}, nil
	case resp.StatusCode == http.StatusOK:
		// 200 with an unexpected body: something rewrote the response
		// (DNS-hijack style portals do this). No login URL known.
		return types.PortalResult{Status: types.PortalStatusPortal, ProbeURL: d.probeURL}, nil
	default:
		// 4xx/5xx (except 511): the probe endpoint itself is broken or
		// blocked. Don't cry "portal" over a CDN outage.
		d.logger.Debug("Portal probe returned unexpected status, treating as offline", "status", resp.StatusCode)
		return types.PortalResult{Status: types.PortalStatusOffline, ProbeURL: d.probeURL}, nil
	}
}

// locationURL returns the redirect target, resolved against the probe URL for
// relative Locations. Returns "" for missing or unparseable Locations — raw
// header bytes from a hostile AP must never reach the user's terminal.
func (d *Detector) locationURL(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	ref, err := url.Parse(loc)
	if err != nil {
		d.logger.Debug("Portal sent unparseable Location, ignoring", "error", err)
		return ""
	}
	return resp.Request.URL.ResolveReference(ref).String()
}
```

Note on the escape-injection test: `url.Parse` accepts some control characters
by percent-encoding them via `String()` re-serialization, and rejects others.
Either path keeps raw ESC bytes out of the output — the assertion is
`NotContains "\x1b"`, not a specific encoding.

**Step 4: Run to verify pass**

Run: `go test ./pkg/portal/ -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add pkg/portal/
git commit -m "feat(portal): native HTTP captive-portal detector"
```

---

### Task 4: `net portal` command (root-exempt)

**Files:**
- Modify: `cmd/net/app.go:16-35` (App struct)
- Modify: `cmd/net/app.go` (RunPortal method)
- Create: `cmd/net/portal.go`
- Modify: `cmd/net/main.go` (`commandNeedsRootArgs` exempt list, ~line 130)
- Test: `cmd/net/app_test.go`, `cmd/net/main_test.go`

**Step 1: Write the failing tests**

Append to `cmd/net/app_test.go` (mock next to the other test managers):

```go
type testPortalDetector struct {
	result types.PortalResult
	err    error
	called bool
}

func (d *testPortalDetector) Check() (types.PortalResult, error) {
	d.called = true
	return d.result, d.err
}

func TestApp_RunPortal_Online(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{Status: types.PortalStatusOnline}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOnline, status)
	assert.Contains(t, stdout.String(), "Internet: ok")
}

func TestApp_RunPortal_PortalWithLoginURL(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Contains(t, stdout.String(), "Captive portal detected")
	assert.Contains(t, stdout.String(), "Log in at: http://portal.example.com/login")
}

func TestApp_RunPortal_PortalWithoutLoginURL(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status:   types.PortalStatusPortal,
		ProbeURL: "http://probe.example.com/",
	}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Contains(t, stdout.String(), "Open http://probe.example.com/ in a browser")
}

func TestApp_RunPortal_Offline(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{Status: types.PortalStatusOffline}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, status)
	assert.Contains(t, stdout.String(), "Internet: unreachable")
}

func TestApp_RunPortal_NoDetector(t *testing.T) {
	app, _, _ := newTestApp() // PortalDet nil
	_, err := app.RunPortal()
	assert.Error(t, err)
}
```

Append cases to the `TestCommandNeedsRootArgs` table in `cmd/net/main_test.go` (match the existing table shape):

```go
	{"portal is exempt", []string{"portal"}, false},
	{"portal with iface flag is exempt", []string{"--iface", "wlan0", "portal"}, false},
```

**Step 2: Run to verify failure**

Run: `go test ./cmd/net/ -run 'TestApp_RunPortal|TestCommandNeedsRootArgs' -v`
Expected: compile error (`app.PortalDet`, `app.RunPortal` undefined); after stubbing, root-exemption cases FAIL

**Step 3: Implement**

`cmd/net/app.go` App struct — after `DHCPMgr`:

```go
	PortalDet  types.PortalDetector // Captive portal / connectivity probing
```

RunPortal method (near RunStatus):

```go
// RunPortal probes for internet connectivity and captive portals, printing
// the portal login URL when one is detected. Returns the detected status so
// the CLI can map it to scripting-friendly exit codes.
func (a *App) RunPortal() (types.PortalStatus, error) {
	if a.PortalDet == nil {
		return 0, fmt.Errorf("portal detection not available")
	}
	result, err := a.PortalDet.Check()
	if err != nil {
		a.errorf("Error: %v\n", err)
		return 0, err
	}
	switch result.Status {
	case types.PortalStatusPortal:
		a.println("Captive portal detected!")
		if result.PortalURL != "" {
			a.printf("  Log in at: %s\n", result.PortalURL)
		} else {
			a.printf("  Open %s in a browser to trigger the portal login page\n", result.ProbeURL)
		}
	case types.PortalStatusOffline:
		a.println("Internet: unreachable (no response from probe)")
	default:
		a.println("Internet: ok")
	}
	return result.Status, nil
}
```

`cmd/net/main.go` — add `"portal"` to the root-exempt switch (the probe is
plain HTTP; no CAP_NET_ADMIN needed):

```go
		case "help", "completion", "status", "show", "list", "portal":
```

`cmd/net/portal.go` (new file; `Run` + `os.Exit` is this repo's command
convention — see status.go):

```go
package main

import (
	"os"

	"github.com/angelfreak/net/pkg/types"
	"github.com/spf13/cobra"
)

var portalCmd = &cobra.Command{
	Use:   "portal",
	Short: "Check for a captive portal on the current connection",
	Long: `Probe a connectivity-check URL to determine whether the current network
has working internet or a captive portal intercepting traffic.

A captive portal is reported only on positive evidence (redirect, HTTP 511,
or a rewritten response body). Probe failures and server errors are reported
as "unreachable" — if the probe endpoint itself is down, that is not a portal.

Exit codes: 0 = online, 2 = captive portal detected, 1 = offline or error.`,
	Run: func(cmd *cobra.Command, args []string) {
		status, err := createApp().RunPortal()
		if err != nil {
			os.Exit(1)
		}
		switch status {
		case types.PortalStatusPortal:
			os.Exit(2)
		case types.PortalStatusOffline:
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(portalCmd)
}
```

**Step 4: Run to verify pass**

Run: `go test ./cmd/net/ -run 'TestApp_RunPortal|TestCommandNeedsRootArgs' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/net/app.go cmd/net/portal.go cmd/net/main.go cmd/net/app_test.go cmd/net/main_test.go
git commit -m "feat(cli): root-exempt net portal command with scripting exit codes"
```

---

### Task 5: connect + status integration

**Files:**
- Modify: `cmd/net/app.go` (`RunConnect` tail ~line 281-288, `RunStatus`, new helper)
- Test: `cmd/net/app_test.go`

**Step 1: Write the failing tests** (complete and compile-ready; setups mirror `TestApp_RunConnect_DirectSSID` and `TestApp_RunConnect_WithVPNIntegration`)

First extend `trackingVPNManager` (`app_test.go:1240`) to also track connects:

```go
// trackingVPNManager tracks Disconnect and Connect calls
type trackingVPNManager struct {
	testVPNManager
	disconnectCalled bool
	connectCalled    bool
	lastConnectName  string
}

func (v *trackingVPNManager) Disconnect(name string) error {
	v.disconnectCalled = true
	return nil
}

func (v *trackingVPNManager) Connect(name string) error {
	v.connectCalled = true
	v.lastConnectName = name
	return nil
}
```

(Check whether existing tests assert on `trackingVPNManager` behavior that a
`Connect` override would change — `testVPNManager.Connect` is a no-op success,
so overriding with another no-op success is behavior-preserving.)

New tests:

```go
func TestApp_RunConnect_PortalWarning(t *testing.T) {
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stderr.String(), "captive portal detected")
	assert.Contains(t, stderr.String(), "http://portal.example.com/login")
}

func TestApp_RunConnect_PortalCheckOff(t *testing.T) {
	app, _, stderr := newTestApp()
	det := &testPortalDetector{result: types.PortalResult{Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p"}}
	app.PortalDet = det
	app.ConfigMgr = &testConfigManager{
		config:     &types.Config{Common: types.CommonConfig{Portal: types.PortalConfig{Check: "off"}}},
		networkErr: errors.New("not found"),
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.False(t, det.called, "portal check must be skipped when check: off")
	assert.NotContains(t, stderr.String(), "captive portal")
}

func TestApp_RunConnect_NilDetectorNoCrash(t *testing.T) {
	app, stdout, _ := newTestApp() // PortalDet nil — must not panic
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connected!")
}

func TestApp_RunConnect_PortalStillConnectsVPN(t *testing.T) {
	app, _, stderr := newTestApp()
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{"home": {SSID: "Home", VPN: "myvpn"}},
			VPN:      map[string]types.VPNConfig{"myvpn": {Type: "wireguard"}},
		},
		networkConfig: &types.NetworkConfig{SSID: "Home", VPN: "myvpn"},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p",
	}}

	err := app.RunConnect("home", "")
	assert.NoError(t, err)
	assert.True(t, tracker.connectCalled, "VPN attempt must still happen after portal warning")
	assert.Equal(t, "myvpn", tracker.lastConnectName)
	assert.Contains(t, stderr.String(), "may not come up until")
}

func TestApp_RunStatus_ShowsInternetLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  captive portal (http://portal.example.com/login)")
}

func TestApp_RunStatus_PortalCheckOffSkipsProbe(t *testing.T) {
	app, stdout, _ := newTestApp()
	det := &testPortalDetector{result: types.PortalResult{Status: types.PortalStatusOnline}}
	app.PortalDet = det
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{Common: types.CommonConfig{Portal: types.PortalConfig{Check: "off"}}},
	}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.False(t, det.called)
	assert.NotContains(t, stdout.String(), "Internet:")
}
```

**Step 2: Run to verify failure**

Run: `go test ./cmd/net/ -run 'TestApp_RunConnect_Portal|TestApp_RunConnect_NilDetector|TestApp_RunStatus_ShowsInternet|TestApp_RunStatus_PortalCheckOff' -v`
Expected: FAIL (no warning printed / no Internet line); the NilDetector test may already pass — keep it as a regression guard

**Step 3: Implement**

`cmd/net/app.go` — helpers near `connectVPN`:

```go
// portalCheckEnabled reports whether automatic portal probing is enabled
// (a detector is wired and config doesn't say check: off).
func (a *App) portalCheckEnabled() bool {
	if a.PortalDet == nil {
		return false
	}
	if cfg := a.ConfigMgr.GetConfig(); cfg != nil && cfg.Common.Portal.CheckDisabled() {
		return false
	}
	return true
}

// checkPortalAfterConnect probes for a captive portal right after a
// connection comes up. Never fatal — prints warnings to stderr only.
// Reports whether a portal was detected so RunConnect can add a VPN hint.
func (a *App) checkPortalAfterConnect() bool {
	if !a.portalCheckEnabled() {
		return false
	}
	result, err := a.PortalDet.Check()
	if err != nil {
		a.Logger.Debug("Portal check failed", "error", err)
		return false
	}
	switch result.Status {
	case types.PortalStatusPortal:
		if result.PortalURL != "" {
			a.errorf("Warning: captive portal detected — log in at: %s\n", result.PortalURL)
		} else {
			a.errorf("Warning: captive portal detected — open %s in a browser to log in\n", result.ProbeURL)
		}
		return true
	case types.PortalStatusOffline:
		a.errorf("Warning: no internet connectivity detected\n")
	}
	return false
}
```

In `RunConnect`, replace the tail (after `a.printConnectionInfo(connectedIface)`):

```go
	portalDetected := a.checkPortalAfterConnect()

	// Connect VPN if configured and not disabled
	if !a.NoVPN {
		if portalDetected {
			a.errorf("Note: the VPN may not come up until the portal login is complete.\n")
		}
		a.connectVPN(configName)
	}
	return nil
```

In `RunStatus`, after the connection-info block (the `if connErr == nil && conn != nil { ... }` block), add:

```go
	// Internet reachability / captive portal (skipped when portal.check: off)
	if a.portalCheckEnabled() {
		if result, err := a.PortalDet.Check(); err == nil {
			switch result.Status {
			case types.PortalStatusPortal:
				url := result.PortalURL
				if url == "" {
					url = result.ProbeURL
				}
				a.printf("Internet:  captive portal (%s)\n", url)
			case types.PortalStatusOffline:
				a.printf("Internet:  unreachable\n")
			default:
				a.printf("Internet:  ok\n")
			}
		}
	}
```

**Step 4: Run to verify pass**

Run: `go test ./cmd/net/`
Expected: PASS (all — existing connect/status tests must stay green; nil PortalDet keeps old behavior)

**Step 5: Commit**

```bash
git add cmd/net/app.go cmd/net/app_test.go
git commit -m "feat(cli): portal check after connect and Internet line in status"
```

---

### Task 6: wiring + docs

**Files:**
- Modify: `cmd/net/main.go:270-287` (`createApp` + new `createPortalDetector`)
- Modify: `README.md` (command list + config reference; grep for existing `timeouts` docs)
- Modify: `config.example` (portal + timeouts.portal entries)
- Modify: `docs/plans/2026-07-17-captive-portal-design.md` (sync review-driven changes)

**Step 1: Wire detector in `createApp`**

```go
func createApp() *App {
	return &App{
		// ... existing fields ...
		PortalDet:  createPortalDetector(),
		// ...
	}
}

// createPortalDetector builds the portal detector from config. Config is
// loaded by PersistentPreRun (initializeManagers) before any command Run
// calls createApp, so the nil-config fallback only covers load failures.
func createPortalDetector() types.PortalDetector {
	probeURL := ""
	timeout := (&types.TimeoutConfig{}).GetPortalTimeout()
	if cfg := cfgManager.GetConfig(); cfg != nil {
		probeURL = cfg.Common.Portal.URL
		timeout = cfg.Common.Timeouts.GetPortalTimeout()
	}
	return portal.New(probeURL, timeout, logger)
}
```

Add `"github.com/angelfreak/net/pkg/portal"` to main.go imports.

**Step 2: Build**

Run: `go build ./... && go test ./...`
Expected: clean build, all tests pass

**Step 3: Docs** — add `net portal` to README's command section, and to BOTH the README config reference and `config.example` (users copy the example):

```yaml
common:
  portal:
    check: auto   # probe for captive portals after connect and in status ("off" to disable)
    url: http://detectportal.firefox.com/success.txt
  timeouts:
    portal: 3     # captive-portal probe timeout in seconds
```

**Step 4: Sync the design doc** — update `2026-07-17-captive-portal-design.md`: classification table (4xx/5xx ⇒ offline), PortalResult shape (PortalURL vs ProbeURL), `net status` honors `check: off`, root-exemption note, VPN hint wording. Add a "Revised after consensus review" note.

**Step 5: Commit**

```bash
git add cmd/net/main.go README.md config.example docs/plans/2026-07-17-captive-portal-design.md
git commit -m "feat(cli): wire portal detector; document net portal"
```

---

### Task 7: full verification

**Step 1:** `gofmt -l . | grep -v vendor` → no output; `go vet ./...` → clean
**Step 2:** `go test ./...` → all packages PASS (this is the required, deterministic verification: unit + httptest coverage of every classification row)
**Step 3:** Build a real binary: `go build -o /tmp/net-portal-test ./cmd/net`
**Step 4 (manual QA — this session only, not CI):** the requesting user is literally sitting behind Amtrak_WiFi's portal; run `/tmp/net-portal-test portal` on the live network. Expect `Internet: ok` (already logged in) or `Captive portal detected!` + URL; verify exit code with `echo $?`; confirm no sudo prompt appears (root exemption). Also run `/tmp/net-portal-test status` and confirm the `Internet:` line.
**Step 5:** Push branch, open PR per repo workflow (`gh pr create` with explicit `--repo`/`--base`/`--head` — origin redirects), then PR self-review per CLAUDE.md.

---

## Review Log

### Round 1 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 1 | Grok (blocker) | `net portal` missing from root-exempt list → forced sudo | **Accepted.** Task 4 adds `"portal"` to `commandNeedsRootArgs` + `TestCommandNeedsRootArgs` cases. |
| 2 | Codex (blocker) | `createPortalDetector` may run before config load | **Rejected with evidence:** config loads in `PersistentPreRun` (main.go:75-77) before any `Run` → `createApp()`. Lifecycle now documented in Task 6. |
| 3 | Codex (blocker) | `os.Exit` in cobra `Run` untestable / may violate convention | **Rejected with evidence:** `Run` + `os.Exit` is the repo convention (status.go, connect.go, …). Exit mapping is a trivial switch; tested logic lives in `RunPortal`. |
| 4 | Codex + Grok + self (major) | Any unexpected status (404/500/502) misclassified as Portal | **Accepted.** 4xx/5xx (except 511) now classify as Offline; tests added for 500, 404; `net portal` help text documents positive-evidence rule. |
| 5 | Codex (major) | Probe-URL fallback printed as "Log in at:" is misleading | **Accepted.** `PortalResult` now has `PortalURL` (Location only) + `ProbeURL`; CLI says "Open <probe> in a browser to trigger the portal login page" when no Location. |
| 6 | Codex (major) + self (minor) | `net status` network probe latency / no opt-out | **Accepted (partial).** `net status` honors `portal.check: off`; timeout bounded at 3s default. Always-on probing for status rejected as default per user's design decision. |
| 7 | Codex (major) | "VPN will complete once portal login is done" possibly false for non-WireGuard | **Accepted.** Reworded to "the VPN may not come up until the portal login is complete"; behavior (still attempt VPN) unchanged per user decision. |
| 8 | Grok (major) | Task 5 tests panic on real harness (nil config), tracking mock lacks Connect | **Accepted.** Tests rewritten compile-ready with proper `testConfigManager` setups; `trackingVPNManager` extended with `connectCalled`/`lastConnectName`. |
| 9 | Grok (major) | Nested `common.portal` validation dropped vs design contract | **Accepted.** Added `validPortalFields`, nested validation, `check`-value validation, and rejection tests. |
| 10 | Grok (minor) | No timeout test | **Accepted.** `TestCheck_Offline_Timeout` added with blocking handler. |
| 11 | Grok (minor) | `config.example` not updated | **Accepted.** Task 6 updates `config.example`. |
| 12 | Codex (minor) | Amtrak real-life step not reproducible | **Accepted (partial).** Marked manual QA (session-specific, explicitly requested by user); deterministic verification is the test suite. |
| 13 | Self (major) | YAML `off` boolean ambiguity | **Resolved empirically:** yaml.v3 keeps unquoted `off` a string; config test locks it. `check`-value validation rejects other strings. |
| 14 | Self (major) | Terminal escape injection via raw `Location` fallback | **Accepted.** Unparseable Locations return ""; test `TestCheck_Portal_MalformedLocationNotEchoed` added. |
