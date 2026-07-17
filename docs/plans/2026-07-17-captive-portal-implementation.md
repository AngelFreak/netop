# Captive Portal Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect captive portals (e.g. Amtrak_WiFi) after connect, on demand via `net portal`, and in `net status` — printing the actual portal login URL.

**Architecture:** New `pkg/portal.Detector` does a plain-HTTP GET to a probe URL (default `http://detectportal.firefox.com/success.txt`) with redirects disabled; classification of the response (204/`success` body → online, 30x/511 → portal with `Location` URL, garbage 200 → portal, transport error → offline). Exposed via a new `types.PortalDetector` interface injected into `App`. Non-fatal warning in `net connect`, standalone `net portal` command with scripting exit codes, one `Internet:` line in `net status`.

**Tech Stack:** Go stdlib `net/http` + `httptest` (no new dependencies), cobra, testify.

**Design doc:** `docs/plans/2026-07-17-captive-portal-design.md`

**Design deviation note:** the design says "when PortalURL is empty the CLI prints the probe URL". Instead, the Detector itself falls back to the probe URL in `PortalURL` when no `Location` is available — keeps the interface minimal and every caller correct.

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

Add types + interface (near `WiFiNetwork`/manager interfaces):

```go
// PortalStatus classifies internet reachability as seen by the portal probe.
type PortalStatus int

const (
	// PortalStatusOnline means the probe returned the expected response — internet works.
	PortalStatusOnline PortalStatus = iota
	// PortalStatusPortal means a captive portal intercepted the probe.
	PortalStatusPortal
	// PortalStatusOffline means the probe got no HTTP response at all.
	PortalStatusOffline
)

// PortalResult is the outcome of a captive-portal probe.
type PortalResult struct {
	Status PortalStatus
	// PortalURL is the address to open in a browser to reach the portal login.
	// It is the redirect Location when the portal provided one, otherwise the
	// probe URL itself (which the portal will intercept). Empty when online.
	PortalURL string
}

// PortalDetector probes for internet connectivity and captive portals.
// Transport failures are reported as PortalStatusOffline, not as errors;
// Check returns a non-nil error only for misconfiguration (e.g. an https
// probe URL, which portals cannot intercept).
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

### Task 2: config — `common.portal` section

**Files:**
- Modify: `pkg/types/types.go` (CommonConfig + PortalConfig struct)
- Modify: `pkg/config/config.go:26-32` (validCommonFields)
- Test: `pkg/config/config_test.go`

**Step 1: Write the failing test** (append to `pkg/config/config_test.go`, follow the existing temp-file test pattern in that file)

```go
func TestPortalConfigParsing(t *testing.T) {
	configContent := `
common:
  portal:
    check: off
    url: http://example.com/probe
  timeouts:
    portal: 7
`
	tmpFile := createTempConfig(t, configContent) // use the file's existing helper; if named differently, match it
	defer os.Remove(tmpFile)

	cm := NewManager(&testLogger{})
	cfg, err := cm.LoadConfig(tmpFile)
	assert.NoError(t, err)
	assert.Equal(t, "off", cfg.Common.Portal.Check)
	assert.Equal(t, "http://example.com/probe", cfg.Common.Portal.URL)
	assert.Equal(t, 7*time.Second, cfg.Common.Timeouts.GetPortalTimeout())
}
```

Note: check `config_test.go` for the actual helper/constructor names (`NewManager`, logger stub, temp-config helper) and mirror them exactly.

**Step 2: Run test to verify it fails**

Run: `go test ./pkg/config/ -run TestPortalConfigParsing -v`
Expected: FAIL — `cfg.Common.Portal` undefined, and/or validation rejects unknown field `portal`

**Step 3: Write minimal implementation**

`pkg/types/types.go` — add to `CommonConfig`:

```go
	Portal   PortalConfig  `yaml:"portal" mapstructure:"portal"`
```

New struct after `TimeoutConfig`:

```go
// PortalConfig controls captive-portal detection.
type PortalConfig struct {
	// Check is "auto" (default: probe after connect) or "off" (skip the
	// automatic connect-time check; `net portal` and `net status` still probe).
	Check string `yaml:"check" mapstructure:"check"`
	// URL is the plain-http probe endpoint. Empty means the built-in default.
	URL string `yaml:"url" mapstructure:"url"`
}
```

`pkg/config/config.go` — add to `validCommonFields`:

```go
		"portal":   true,
```

(Nested subfields are not validated for `timeouts` today; keep `portal` consistent with that.)

**Step 4: Run test to verify it passes**

Run: `go test ./pkg/config/ ./pkg/types/`
Expected: PASS (all — watch for existing validation tests that enumerate common fields)

**Step 5: Commit**

```bash
git add pkg/types/types.go pkg/config/config.go pkg/config/config_test.go
git commit -m "feat(config): common.portal section and portal timeout"
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

	d := newTestDetector(srv.URL)
	result, err := d.Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Equal(t, srv.URL, result.PortalURL) // no Location → probe URL fallback
}

func TestCheck_Portal_HijackedOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>Welcome to Amtrak WiFi</html>"))
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Equal(t, srv.URL, result.PortalURL)
}

func TestCheck_Offline_ConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(nil)
	url := srv.URL
	srv.Close() // now refused

	result, err := newTestDetector(url).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, result.Status)
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
// mean PortalStatusOffline (nil error); an error is returned only for a
// misconfigured probe URL.
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
		return types.PortalResult{Status: types.PortalStatusOffline}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	d.logger.Debug("Portal probe response", "status", resp.StatusCode)

	switch {
	case resp.StatusCode == http.StatusNoContent:
		return types.PortalResult{Status: types.PortalStatusOnline}, nil
	case resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == "success":
		return types.PortalResult{Status: types.PortalStatusOnline}, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400,
		resp.StatusCode == http.StatusNetworkAuthenticationRequired:
		return types.PortalResult{Status: types.PortalStatusPortal, PortalURL: d.portalURL(resp)}, nil
	default:
		// Unexpected 200 body or any other status: something rewrote the
		// response (DNS-hijack style portals do this).
		return types.PortalResult{Status: types.PortalStatusPortal, PortalURL: d.probeURL}, nil
	}
}

// portalURL returns the redirect target (resolved against the probe URL for
// relative Locations), or the probe URL itself when the portal sent none.
func (d *Detector) portalURL(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return d.probeURL
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return resp.Request.URL.ResolveReference(ref).String()
}
```

**Step 4: Run to verify pass**

Run: `go test ./pkg/portal/ -v`
Expected: all PASS

**Step 5: Compile-time interface assertion** — add to `portal_test.go`:

```go
var _ types.PortalDetector = (*Detector)(nil)
```

**Step 6: Commit**

```bash
git add pkg/portal/
git commit -m "feat(portal): native HTTP captive-portal detector"
```

---

### Task 4: `net portal` command

**Files:**
- Modify: `cmd/net/app.go:16-35` (App struct)
- Create: `cmd/net/portal.go`
- Modify: `cmd/net/app.go` (RunPortal method)
- Test: `cmd/net/app_test.go`

**Step 1: Write the failing tests** (append to `cmd/net/app_test.go`; add the mock next to the other test managers)

```go
type testPortalDetector struct {
	result types.PortalResult
	err    error
}

func (d *testPortalDetector) Check() (types.PortalResult, error) {
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

func TestApp_RunPortal_PortalDetected(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
	}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Contains(t, stdout.String(), "Captive portal detected")
	assert.Contains(t, stdout.String(), "http://portal.example.com/login")
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

**Step 2: Run to verify failure**

Run: `go test ./cmd/net/ -run TestApp_RunPortal -v`
Expected: compile error — `app.PortalDet`, `app.RunPortal` undefined

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
		a.printf("  Log in at: %s\n", result.PortalURL)
	case types.PortalStatusOffline:
		a.println("Internet: unreachable (no response from probe)")
	default:
		a.println("Internet: ok")
	}
	return result.Status, nil
}
```

`cmd/net/portal.go` (new file, mirror `status.go` structure):

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

Run: `go test ./cmd/net/ -run TestApp_RunPortal -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/net/app.go cmd/net/portal.go cmd/net/app_test.go
git commit -m "feat(cli): net portal command with scripting exit codes"
```

---

### Task 5: connect + status integration

**Files:**
- Modify: `cmd/net/app.go` (`RunConnect` around line 281-288, `RunStatus`)
- Test: `cmd/net/app_test.go`

**Step 1: Write the failing tests**

```go
func TestApp_RunConnect_PortalWarning(t *testing.T) {
	app, _, stderr := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
	}}

	err := app.RunConnect("TestNetwork", "password")
	assert.NoError(t, err)
	assert.Contains(t, stderr.String(), "captive portal detected")
	assert.Contains(t, stderr.String(), "http://portal.example.com/login")
}

func TestApp_RunConnect_PortalCheckOff(t *testing.T) {
	app, _, stderr := newTestApp()
	// configure check: off via the test config manager's config
	cfg := app.ConfigMgr.GetConfig()
	cfg.Common.Portal.Check = "off"
	app.PortalDet = &testPortalDetector{result: types.PortalResult{Status: types.PortalStatusPortal, PortalURL: "http://x"}}

	err := app.RunConnect("TestNetwork", "password")
	assert.NoError(t, err)
	assert.NotContains(t, stderr.String(), "captive portal")
}

func TestApp_RunConnect_NilDetectorNoCrash(t *testing.T) {
	app, _, _ := newTestApp() // PortalDet nil — must not panic
	err := app.RunConnect("TestNetwork", "password")
	assert.NoError(t, err)
}

func TestApp_RunConnect_PortalStillConnectsVPN(t *testing.T) {
	// use the existing trackingVPNManager pattern to assert VPN attempt still happens
	app, _, stderr := newTestApp()
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	// give the test config manager a network with a VPN configured (mirror existing VPN test setup in this file)
	app.PortalDet = &testPortalDetector{result: types.PortalResult{Status: types.PortalStatusPortal, PortalURL: "http://x"}}

	err := app.RunConnect("TestNetwork", "password")
	assert.NoError(t, err)
	assert.Contains(t, stderr.String(), "VPN will")
	// assert tracker recorded a Connect call — mirror field names from trackingVPNManager
}

func TestApp_RunStatus_ShowsInternetLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{result: types.PortalResult{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
	}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:")
	assert.Contains(t, stdout.String(), "captive portal (http://portal.example.com/login)")
}
```

Note: `TestApp_RunConnect_PortalCheckOff` requires the test config manager to return a non-nil config — check `testConfigManager` in `app_test.go` and set its config field the way other tests do. Adjust test-network names to whatever `testWiFiManager`/`testConfigManager` already support (look at existing `TestApp_RunConnect_*` tests and copy their setup).

**Step 2: Run to verify failure**

Run: `go test ./cmd/net/ -run 'TestApp_RunConnect_Portal|TestApp_RunStatus_ShowsInternet|TestApp_RunConnect_NilDetector' -v`
Expected: FAIL (no warning printed / no Internet line)

**Step 3: Implement**

`cmd/net/app.go` — private helper near `connectVPN`:

```go
// checkPortalAfterConnect probes for a captive portal right after a
// connection comes up, unless disabled via common.portal.check: off.
// Never fatal — prints warnings to stderr only. Reports whether a portal
// was detected so RunConnect can add a VPN hint.
func (a *App) checkPortalAfterConnect() bool {
	if a.PortalDet == nil {
		return false
	}
	if cfg := a.ConfigMgr.GetConfig(); cfg != nil && cfg.Common.Portal.Check == "off" {
		return false
	}
	result, err := a.PortalDet.Check()
	if err != nil {
		a.Logger.Debug("Portal check failed", "error", err)
		return false
	}
	switch result.Status {
	case types.PortalStatusPortal:
		a.errorf("Warning: captive portal detected — log in at: %s\n", result.PortalURL)
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
			a.errorf("Note: VPN will complete once the portal login is done.\n")
		}
		a.connectVPN(configName)
	}
	return nil
```

In `RunStatus`, after the connection-info block (the `if connErr == nil && conn != nil { ... }` block), add:

```go
	// Internet reachability / captive portal
	if a.PortalDet != nil {
		if result, err := a.PortalDet.Check(); err == nil {
			switch result.Status {
			case types.PortalStatusPortal:
				a.printf("Internet:  captive portal (%s)\n", result.PortalURL)
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
- Modify: `cmd/net/main.go:270-287` (`createApp`)
- Modify: `README.md` (command list + config reference; grep for existing `timeouts` docs)

**Step 1: Wire detector in `createApp`**

```go
func createApp() *App {
	return &App{
		// ... existing fields ...
		PortalDet:  createPortalDetector(),
		// ...
	}
}

// createPortalDetector builds the portal detector from config when loaded,
// falling back to defaults (Firefox probe URL, 3s) otherwise.
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

Add `"github.com/angelfreak/net/pkg/portal"` to main.go imports. Verify where `cfgManager` gets its config loaded (PersistentPreRun?) so `createPortalDetector` runs after load; if createApp can run before config load, the nil-config fallback covers it.

**Step 2: Build**

Run: `go build ./... && go test ./...`
Expected: clean build, all tests pass

**Step 3: README** — add `net portal` to the commands section and this to the config example near `timeouts`:

```yaml
common:
  portal:
    check: auto   # probe for captive portals after connect ("off" to disable)
    url: http://detectportal.firefox.com/success.txt
  timeouts:
    portal: 3     # probe timeout in seconds
```

**Step 4: Commit**

```bash
git add cmd/net/main.go README.md
git commit -m "feat(cli): wire portal detector; document net portal"
```

---

### Task 7: full verification

**Step 1:** `gofmt -l . | grep -v vendor` → no output; `go vet ./...` → clean
**Step 2:** `go test ./...` → all packages PASS
**Step 3:** Build a real binary: `go build -o /tmp/net-portal-test ./cmd/net`
**Step 4:** Real-life check on the live network (Amtrak_WiFi): run `/tmp/net-portal-test portal`; expect `Internet: ok` (already logged in) or `Captive portal detected!` + URL; verify exit code with `echo $?`. Also run `/tmp/net-portal-test status` and confirm the `Internet:` line. Neither needs root (pure HTTP probe + status reads).
**Step 5:** Push branch, open PR per repo workflow (`gh pr create` with explicit `--repo`/`--base`/`--head` — origin redirects), then PR self-review per CLAUDE.md.
