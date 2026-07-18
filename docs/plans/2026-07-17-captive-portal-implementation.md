# Captive Portal Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect captive portals (e.g. Amtrak_WiFi) after connect, on demand via `net portal`, and in `net status` — printing the actual portal login URL.

**Architecture:** New `pkg/portal.Detector` does a plain-HTTP GET to a probe URL (default `http://detectportal.firefox.com/success.txt`) with redirects disabled. Classification: 204 or `success` body → online; 3xx or 511 → portal (login URL from `Location`); 401/403 **with a sanitized `Location`** → portal (enterprise/hotel interception); 200 with unexpected body → portal (DNS-hijack style); transport errors **and all other HTTP statuses** → offline, so a probe-endpoint outage is never misreported as a portal. Exposed via a new `types.PortalDetector` interface injected into `App`. Non-fatal warning in `net connect` (with one settle-retry to avoid false offline warnings), standalone root-exempt `net portal` command with scripting exit codes, one `Internet:` line in `net status`.

**Known product gap (with honest signaling, not silent):** the probe uses the process's normal routing (default route), not the just-connected interface. netop models dual-homing as first-class (wired metric 100 beats WiFi 600), so connecting to a captive WiFi while Ethernet has internet would probe via Ethernet and see "ok". Binding the probe to the connected interface needs `SO_BINDTODEVICE` (CAP_NET_RAW — would break the root-exempt `net portal`) or fragile source-IP games; out of scope. Instead the gap is **signaled**: the connect-time check compares the default route's interface (via `types.RouteManager`) with the just-connected interface and prints a stderr note when they differ; `net status` labels its line host-wide (`Internet:  ok (default route)`); README, design doc, and `net portal --help` document the semantics.

**Tech Stack:** Go stdlib `net/http` + `httptest` (no new dependencies), cobra, testify.

**Design doc:** `docs/plans/2026-07-17-captive-portal-design.md`

**Verified facts this plan relies on** (checked against the tree at `3923607`+):

- Config is loaded in `rootCmd.PersistentPreRun` → `initializeManagers()` (`cmd/net/main.go:75-77`, LoadConfig at `main.go:238`), which cobra runs **before** any command's `Run` — so `createApp()`/`createPortalDetector()` always see a loaded config in real runs. The nil-config fallback only covers load failures.
- `os.Exit` inside cobra `Run` is the repo-wide convention (`status.go:14`, `connect.go:37`, every command file). `net portal` follows it; testable logic lives in `App.RunPortal`.
- Root elevation: `commandNeedsRootArgs` (`cmd/net/main.go:~130`) exempts only `help, completion, status, show, list` — `portal` MUST be added there or it re-execs under sudo.
- `gopkg.in/yaml.v3` (used by viper v1.18.2 here) parses unquoted `check: off` as the **string** `"off"`, not a boolean (verified empirically). The config test below locks this. **However**, viper's `Unmarshal` uses mapstructure with weak typing: `check: false` silently coerces to the string `"0"` and `check: true`/`check: 1` to `"1"` — **no decode error** (verified empirically against viper v1.18.2). `"0"` is not `"off"`, so without raw pre-unmarshal validation the user's intent silently inverts. Raw-map type+value validation of `check` is therefore mandatory, not defensive.
- Go's `net/http` client rejects raw control bytes in response headers at the transport layer ("malformed MIME header"), so hostile `Location` bytes cannot be exercised through `httptest` — URL sanitization is tested via a **pure helper** instead.
- `newTestApp()` (`cmd/net/app_test.go:321`) leaves `testConfigManager.config` **nil**; connect tests must inject their own `testConfigManager` (mirror `TestApp_RunConnect_DirectSSID:436`).
- `trackingVPNManager` (`app_test.go:1240`) embeds `testVPNManager` and only tracks `Disconnect`; Task 5 extends it.
- `connectVPN` (`app.go:90-109`) is a no-op when no VPN resolves for the network — the connect-time VPN hint must use the same resolution so it never fires without a VPN.

---

### Task 1: types — PortalStatus, PortalResult, PortalDetector, portal timeout

**Files:**
- Modify: `pkg/types/types.go`
- Test: `pkg/types/validation_test.go` (timeout getter tests live here)

**Step 1: Write the failing test** (append to `pkg/types/validation_test.go`)

```go
func TestTimeoutConfigGetPortalTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   TimeoutConfig
		expected time.Duration
	}{
		{"default when zero", TimeoutConfig{Portal: 0}, 3 * time.Second},
		{"default when negative", TimeoutConfig{Portal: -1}, 3 * time.Second},
		{"custom 10 seconds", TimeoutConfig{Portal: 10}, 10 * time.Second},
		{"custom 1 second", TimeoutConfig{Portal: 1}, 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetPortalTimeout()
			assert.Equal(t, tt.expected, result)
		})
	}
}
```

(Table shape matches `TestTimeoutConfigGetCarrierTimeout` at `validation_test.go:300`, including the negative case.)

Also — REQUIRED, not optional — add these exact lines to the existing aggregate suites in the same file:

- `TestTimeoutConfigAllDefaults` (`validation_test.go:321`): `assert.Equal(t, 3*time.Second, config.GetPortalTimeout())`
- `TestTimeoutConfigAllCustom` (`validation_test.go:331`): add `Portal: 7` to the struct literal and `assert.Equal(t, 7*time.Second, config.GetPortalTimeout())`

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
	// PortalStatusUnknown is the zero value — deliberately NOT online, so a
	// forgotten status field or future enum value can never fail open into
	// "internet works". CLI code treats it like offline.
	PortalStatusUnknown PortalStatus = iota
	// PortalStatusOnline means the probe returned the expected response — internet works.
	PortalStatusOnline
	// PortalStatusPortal means a captive portal intercepted the probe.
	PortalStatusPortal
	// PortalStatusOffline means the probe failed or returned a non-portal error
	// status — no working internet, but no portal positively identified either.
	PortalStatusOffline
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
// The probe uses the process's normal routing (default route); it is not
// bound to a specific interface.
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

**Step 1: Write the failing tests** (append to `pkg/config/config_test.go` — complete bodies, no ellipsis; `mockLogger` already exists in that file at line ~30)

One shared helper, then every case goes through the REAL `LoadConfig`:

```go
// loadPortalConfig writes content to a temp config file and loads it through
// the real Manager, so every portal test exercises actual load+validation.
func loadPortalConfig(t *testing.T, content string) (*types.Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return NewManager(&mockLogger{}).LoadConfig(path)
}

func TestPortalConfigParsing(t *testing.T) {
	// NB: `check: off` is deliberately unquoted — yaml.v3 must keep it a string.
	cfg, err := loadPortalConfig(t, `
common:
  portal:
    check: off
    url: http://example.com/probe
  timeouts:
    portal: 7
`)
	assert.NoError(t, err)
	assert.Equal(t, "off", cfg.Common.Portal.Check)
	assert.True(t, cfg.Common.Portal.CheckDisabled())
	assert.Equal(t, "http://example.com/probe", cfg.Common.Portal.URL)
	assert.Equal(t, 7*time.Second, cfg.Common.Timeouts.GetPortalTimeout())
}

func TestPortalConfigUnknownFieldRejected(t *testing.T) {
	_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    chek: off\n")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chek")
}

func TestPortalConfigBadCheckValueRejected(t *testing.T) {
	_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    check: sometimes\n")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `must be "auto" or "off"`)
}

func TestPortalConfigNonStringCheckRejected(t *testing.T) {
	// Viper weak-typing coerces YAML bools/ints to "0"/"1" with NO decode
	// error (verified empirically), which would silently invert the user's
	// intent. Raw-map validation must reject non-strings before unmarshal.
	for _, val := range []string{"false", "true", "1"} {
		_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    check: "+val+"\n")
		assert.Error(t, err, "check: %s must be rejected", val)
		assert.Contains(t, err.Error(), `must be "auto" or "off"`)
	}
}

func TestPortalConfigBadURLRejected(t *testing.T) {
	// ProbeURL is printed verbatim by the CLI (display-safety contract), so
	// the configured URL is validated at load.
	for _, u := range []string{"https://example.com/p", "http:foo", "ftp://x/", "not a url"} {
		_, err := loadPortalConfig(t, "\ncommon:\n  portal:\n    url: \""+u+"\"\n")
		assert.Error(t, err, "url %q must be rejected", u)
	}
}

func TestPortalConfigScalarPortalRejected(t *testing.T) {
	// A scalar or list portal: value must fail with the explicit mapping
	// message, not a cryptic mapstructure decode error or a silent zero.
	for _, portalLine := range []string{"portal: off", "portal: true", "portal: [auto]"} {
		_, err := loadPortalConfig(t, "\ncommon:\n  "+portalLine+"\n")
		assert.Error(t, err, "%q must be rejected", portalLine)
		assert.Contains(t, err.Error(), "must be a mapping")
	}
}
```

(Add `"path/filepath"` to the test file's imports if absent.)

The shared validator's table test, in `pkg/types/validation_test.go`:

```go
func TestValidatePortalProbeURL(t *testing.T) {
	assert.NoError(t, ValidatePortalProbeURL("http://x.example.com/p"))
	for name, bad := range map[string]string{
		"https undetectable":  "https://x.example.com/",
		"no host":             "http:foo",
		"userinfo":            "http://u:p@x.example.com/",
		"non-ascii host":      "http://exämple.com/",
		"format rune":         "http://evil‮.com/x",
		"raw control byte":    "http://x.example.com/\x1b",
		"unparseable":         "not a url",
	} {
		assert.Error(t, ValidatePortalProbeURL(bad), "%s: %q must be rejected", name, bad)
	}
}
```

Also a types-level test (in `pkg/types/validation_test.go`):

```go
func TestPortalConfigCheckDisabled(t *testing.T) {
	assert.False(t, (&PortalConfig{}).CheckDisabled())
	assert.False(t, (&PortalConfig{Check: "auto"}).CheckDisabled())
	assert.True(t, (&PortalConfig{Check: "off"}).CheckDisabled())
	assert.True(t, (&PortalConfig{Check: " OFF "}).CheckDisabled()) // normalized
}
```

**Step 2: Run to verify failure**

Run: `go test ./pkg/config/ -run TestPortalConfig -v && go test ./pkg/types/ -run TestPortalConfigCheckDisabled -v`
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
	// A custom endpoint must respond with HTTP 204 or a 200 whose body is
	// exactly "success" (surrounding whitespace ignored) when internet works —
	// anything else is classified as portal/offline.
	URL string `yaml:"url" mapstructure:"url"`
}

// CheckDisabled reports whether automatic portal checks are turned off.
// Case- and whitespace-insensitive so "Off"/" OFF " behave as expected.
func (p *PortalConfig) CheckDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(p.Check), "off")
}
```

(`pkg/types` already imports nothing beyond context/net/time — add `strings`.)

`pkg/config/config.go`:

```go
	// Valid fields for PortalConfig
	validPortalFields = map[string]bool{
		"check": true,
		"url":   true,
	}
```

Add `"portal": true` to `validCommonFields`. In the validation pass where `common` is validated (around `config.go:195`), when the common map contains a `portal` key that is itself a map:

1. Require `common.portal` to be **absent, null, or a map**. A scalar or list (`portal: off`, `portal: true`, `portal: [auto]`) appends `ValidationError{Section: "common.portal", Field: "portal", Message: "common.portal must be a mapping with optional \"check\" and \"url\" fields"}` — otherwise mapstructure produces a cryptic decode error or a silent zero struct. Test `TestPortalConfigScalarPortalRejected` covers all three shapes.
2. Validate its subfields against `validPortalFields` (same `validateFields` helper, section name `common.portal`).
3. Validate the `check` value **on the raw map, before unmarshal** (viper weak-typing coerces bools/ints to strings with no error): if present it must be a Go **string** whose trimmed, lowercased value is `""`, `"auto"`, or `"off"`; anything else (including YAML booleans/ints) fails with an error containing `common.portal.check must be "auto" or "off"` — via the `ValidationError.Message` mechanism specified below (no other error path).
4. Validate the `url` value at load with these exact semantics (Grok r4: `url: ""` must not be rejected as "no host"):
   - **absent key, YAML null (`url:`), or empty string (`url: ""`)** → default probe URL, no error;
   - **non-empty string** → must pass the shared `types.ValidatePortalProbeURL` helper (raw Cc/Cf rune scan, parse OK, scheme `http`, non-empty host, no userinfo — the CLI prints ProbeURL verbatim under the display-safety contract);
   - **non-string** → clear error.

Error plumbing (exact, no implementer's choice): extend `ValidationError` with an optional `Message string` field; `Error()` returns `Message` when set, else the existing unknown-field format. Inside the `common` branch of the raw-validation pass, append value errors like:

```go
errors = append(errors, ValidationError{
	Section: "common.portal",
	Field:   "check",
	Message: `common.portal.check must be "auto" or "off"`,
})
```

Do NOT return a bare `fmt.Errorf` from the validation pass — its return type is `ValidationErrors` (`[]ValidationError`). Tests assert the message substring on the aggregated `err.Error()`.

Additional tests:

```go
func TestPortalConfigEmptyURLAllowed(t *testing.T) {
	// Three explicit, complete YAML shapes: empty string, null, absent key.
	for name, configContent := range map[string]string{
		"empty string": "\ncommon:\n  portal:\n    url: \"\"\n",
		"null":         "\ncommon:\n  portal:\n    url:\n",
		"absent":       "\ncommon:\n  portal: {}\n",
	} {
		_, err := loadPortalConfig(t, configContent)
		assert.NoError(t, err, "portal url form %s must be accepted", name)
	}
}
```

This is deliberately stricter than the historically-unvalidated `timeouts` because a typo here silently re-enables probing or probes the wrong host.

**Placement note:** the URL rule uses `types.ValidatePortalProbeURL`. **Add it to the EXISTING** `pkg/types/validation.go` next to the other validators (`ValidateMAC`, `ValidateSSID`, …) — the file already exists; do not create a new one. `pkg/types` is the dependency-free bottom layer both `pkg/config` and `pkg/portal` already import, so config never depends on the runtime detector package. Its test goes in the existing `pkg/types/validation_test.go`; Task 3's Detector calls the same helper.

**Step 4: Run to verify pass**

Run: `go test ./pkg/config/ ./pkg/types/`
Expected: PASS (all — watch for existing validation tests that enumerate common fields)

**Step 5: Commit**

```bash
git add pkg/types/types.go pkg/types/validation.go pkg/types/validation_test.go pkg/config/config.go pkg/config/config_test.go
git commit -m "feat(config): common.portal section with validated fields"
```

---

### Task 3: pkg/portal — the Detector

**Files:**
- Create: `pkg/portal/portal.go`
- Create: `pkg/portal/portal_test.go`

**Step 1: Write the failing tests**

Two groups: httptest-driven classification tests (realistic wire paths only), and pure unit tests for `loginURL` (hostile input paths that `net/http` would reject on the wire).

```go
package portal

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// --- classification via httptest (realistic wire paths) ---

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

func TestCheck_Portal_AuthStatusWithLocation(t *testing.T) {
	// Enterprise/hotel portals sometimes intercept with 401/403 + Location.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://portal.example.com/login")
			w.WriteHeader(status)
		}))

		result, err := newTestDetector(srv.URL).Check()
		srv.Close()
		assert.NoError(t, err)
		assert.Equal(t, types.PortalStatusPortal, result.Status, "status %d", status)
		assert.Equal(t, "http://portal.example.com/login", result.PortalURL, "status %d", status)
	}
}

func TestCheck_Offline_403WithoutLocation(t *testing.T) {
	// A bare 403 (corporate block page) is NOT portal evidence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, result.Status)
}

func TestCheck_Offline_304NotModified(t *testing.T) {
	// A caching intermediary's 304 is NOT interception evidence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
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

// brokenBodyTransport returns a 200 whose body errors mid-read — injected
// via the Detector's test transport because httptest paths for mid-body
// failures are not reliably deterministic.
type brokenBodyTransport struct{}

type brokenBody struct{ sent bool }

func (b *brokenBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "part"), nil
	}
	return 0, errors.New("connection reset mid-body")
}
func (b *brokenBody) Close() error { return nil }

func (brokenBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       &brokenBody{},
		Header:     http.Header{},
		Request:    req,
	}, nil
}

func TestCheck_Offline_BodyReadFailure(t *testing.T) {
	// 200 with a body that dies mid-read is a flaky link, not a portal.
	d := New("http://probe.example.com/", time.Second, &testLogger{})
	d.transport = brokenBodyTransport{}

	result, err := d.Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, result.Status)
}

func TestCheck_Portal_UnicodeWhitespacePaddedSuccess(t *testing.T) {
	// Only ASCII whitespace may surround "success" — a legitimate endpoint
	// never pads with U+00A0 etc., so treat it as a rewritten response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("success\u00a0")) // non-breaking space, explicit escape
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
}

func TestCheck_Portal_OversizedSuccessBody(t *testing.T) {
	// "success" + KBs of whitespace + junk must never classify Online: an
	// oversized body means something rewrote the response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("success"))
		w.Write([]byte(strings.Repeat(" ", 5000)))
		w.Write([]byte("<html>portal junk</html>"))
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
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

// --- probe URL misconfiguration ---

func TestCheck_HTTPSRejected(t *testing.T) {
	_, err := newTestDetector("https://example.com/probe").Check()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http")
}

func TestCheck_ProbeURLWithoutHostRejected(t *testing.T) {
	for _, bad := range []string{"http:foo", "http:///path-only", "not a url", "http://user:pw@x.example.com/"} {
		_, err := newTestDetector(bad).Check()
		assert.Error(t, err, "probe URL %q must be rejected", bad)
	}
}

(The validator's own table test `TestValidatePortalProbeURL` lives in
`pkg/types/validation_test.go` — created in Task 2: accepts
`http://x.example.com/p`; rejects https, `http:foo` (no host),
`http://u:p@x.example.com/` (userinfo), `http://evil‮.com/x` and
`http://exämple.com/` (non-ASCII — printable-ASCII-only rule), and
`"http://x.example.com/\x1b"` (raw control).)

func TestNew_DefaultURL(t *testing.T) {
	d := New("", time.Second, &testLogger{})
	assert.Equal(t, DefaultProbeURL, d.probeURL)
}

// --- loginURL pure-helper tests (hostile inputs net/http would reject on the wire) ---

func mustParse(t *testing.T, raw string) *url.URL {
	u, err := url.Parse(raw)
	assert.NoError(t, err)
	return u
}

func TestLoginURL(t *testing.T) {
	base := mustParse(t, "http://probe.example.com/success.txt")
	tests := []struct {
		name string
		loc  string
		want string
	}{
		{"absolute http", "http://portal.example.com/login", "http://portal.example.com/login"},
		{"absolute https", "https://portal.example.com/login", "https://portal.example.com/login"},
		{"relative resolves against base", "/login", "http://probe.example.com/login"},
		{"empty", "", ""},
		{"unparseable", "http://bad host/", ""},
		{"javascript scheme rejected", "javascript:alert(1)", ""},
		{"file scheme rejected", "file:///etc/passwd", ""},
		{"userinfo rejected", "http://user:pass@evil.example.com/login", ""},
		{"schemeless userinfo rejected", "//user:pass@evil.example.com/login", ""},
		{"schemeless host-relative allowed", "//portal.example.com/login", "http://portal.example.com/login"},
		{"no host after resolve rejected", "http:opaque", ""},
		// url.Parse rejects ASCII CTL bytes outright (stringContainsCTLByte),
		// so these return "" via the parse-error path:
		{"raw control char rejected", "http://x.example.com/\x1b]0;pwn\x07", ""},
		{"newline rejected", "http://x.example.com/a\nb", ""},
		// URL.String() percent-encodes non-ASCII in BOTH path and host
		// (verified on Go 1.26) — serialized output is display-safe ASCII,
		// so these are ACCEPTED in encoded form. The Cc/Cf rune scan on the
		// serialized string stays as defense-in-depth only:
		{"bidi in path is percent-encoded", "http://x.example.com/‮gnp.exe", "http://x.example.com/%E2%80%AEgnp.exe"},
		{"bidi in host is percent-encoded", "http://evil‮.com/x", "http://evil%E2%80%AE.com/x"},
		{"percent-encoded controls stay encoded", "http://x.example.com/%1b%0d%0a", "http://x.example.com/%1b%0d%0a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := loginURL(base, tt.loc, &testLogger{})
			assert.Equal(t, tt.want, got)
			for _, r := range got {
				assert.False(t, r < 0x20 || r == 0x7f, "control byte in output")
			}
		})
	}
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
//
// The probe uses the process's normal routing (default route). It is NOT
// bound to a specific interface: on a multi-homed machine the result
// reflects the preferred route, which may not be the interface that was
// just connected. Binding would require SO_BINDTODEVICE (CAP_NET_RAW) and
// break the root-exempt `net portal` command.
package portal

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

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

// nopLogger backs a nil logger argument so every d.logger call site is safe.
type nopLogger struct{}

func (nopLogger) Debug(string, ...interface{}) {}
func (nopLogger) Info(string, ...interface{})  {}
func (nopLogger) Warn(string, ...interface{})  {}
func (nopLogger) Error(string, ...interface{}) {}

// New creates a Detector. An empty probeURL selects DefaultProbeURL; a nil
// logger is replaced with a no-op logger.
func New(probeURL string, timeout time.Duration, logger types.Logger) *Detector {
	if probeURL == "" {
		probeURL = DefaultProbeURL
	}
	if logger == nil {
		logger = nopLogger{}
	}
	return &Detector{probeURL: probeURL, timeout: timeout, logger: logger}
}

In `pkg/types/validation.go` (created during Task 2, shown here for context —
the Detector calls it):

```go
// ValidatePortalProbeURL reports whether raw is acceptable as a captive-portal
// probe endpoint: printable ASCII only in the RAW string (the CLI prints the
// configured URL verbatim — this rules out control bytes, bidi/format runes,
// and IDN-confusable hostnames in one check), parseable, plain http (portals
// cannot intercept https), non-empty host, no userinfo. Shared by config
// load-time validation and the detector's runtime guard.
func ValidatePortalProbeURL(raw string) error {
	for _, r := range raw {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("portal probe URL must be printable ASCII")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid portal probe URL %q: %w", raw, err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("portal probe URL must be plain http, got %q — portals cannot intercept %s", raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("portal probe URL %q has no host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("portal probe URL %q must not contain userinfo", raw)
	}
	return nil
}
```

Back in `pkg/portal/portal.go`:

```go
// Check probes the endpoint and classifies the response. Transport failures
// and unexpected error statuses mean PortalStatusOffline (nil error); an
// error is returned only for a misconfigured probe URL.
func (d *Detector) Check() (types.PortalResult, error) {
	if err := types.ValidatePortalProbeURL(d.probeURL); err != nil {
		return types.PortalResult{}, err
	}

	transport := d.transport
	if transport == nil {
		// Clone the default transport to keep Go's tuned defaults (dialer
		// timeouts, connection pooling), then disable proxies: the point is
		// to test the local network path directly.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		transport = t
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

	d.logger.Debug("Portal probe response", "status", resp.StatusCode)

	// Classify on status alone wherever possible — only a 200 needs the body
	// (to tell "success" from a hijacked page). Reading the body of a
	// redirect/error response would let a hostile or broken endpoint hold
	// the check hostage until the timeout.
	switch {
	case resp.StatusCode == http.StatusNoContent:
		return types.PortalResult{Status: types.PortalStatusOnline, ProbeURL: d.probeURL}, nil
	case isRedirectStatus(resp.StatusCode),
		resp.StatusCode == http.StatusNetworkAuthenticationRequired:
		return types.PortalResult{
			Status:    types.PortalStatusPortal,
			PortalURL: loginURL(resp.Request.URL, resp.Header.Get("Location"), d.logger),
			ProbeURL:  d.probeURL,
		}, nil
	case resp.StatusCode != http.StatusOK:
		// Some enterprise/hotel portals answer 401/403 WITH a Location — a
		// redirect header on an error status is interception evidence, so
		// honor it. (Body sniffing is deliberately not done here: a
		// corporate 403 block page would false-positive as a portal.
		// Non-redirect 3xx like 304 land here too and classify offline —
		// a caching intermediary is not interception evidence.)
		if login := loginURL(resp.Request.URL, resp.Header.Get("Location"), d.logger); login != "" &&
			(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return types.PortalResult{Status: types.PortalStatusPortal, PortalURL: login, ProbeURL: d.probeURL}, nil
		}
		// Other 4xx/5xx (except 511): the probe endpoint itself is broken or
		// blocked. Don't cry "portal" over a CDN outage.
		d.logger.Debug("Portal probe returned unexpected status, treating as offline", "status", resp.StatusCode)
		return types.PortalResult{Status: types.PortalStatusOffline, ProbeURL: d.probeURL}, nil
	}

	// 200: read one byte past the cap so an oversized body can never be
	// trimmed into a fake "success" (e.g. "success" + KBs of whitespace).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		// A truncated/broken body on an otherwise-OK response is a flaky
		// link, not evidence of a portal.
		d.logger.Debug("Portal probe body read failed", "error", err)
		return types.PortalResult{Status: types.PortalStatusOffline, ProbeURL: d.probeURL}, nil
	}
	// ASCII-whitespace trim only: Unicode-whitespace padding around "success"
	// is not something a legitimate probe endpoint produces.
	if len(body) <= maxBodyBytes && strings.Trim(string(body), " \t\r\n") == "success" {
		return types.PortalResult{Status: types.PortalStatusOnline, ProbeURL: d.probeURL}, nil
	}
	// 200 with an unexpected body: something rewrote the response
	// (DNS-hijack style portals do this). No login URL known.
	return types.PortalResult{Status: types.PortalStatusPortal, ProbeURL: d.probeURL}, nil
}

// isRedirectStatus reports whether status is a redirect that carries
// interception semantics. Deliberately NOT all of 3xx: 304 Not Modified is a
// caching intermediary, and 300/305/306 carry no portal meaning — treating
// them as portals would violate the positive-evidence rule.
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// loginURL turns a portal's Location header into a display-safe login URL:
// resolved against base for relative references, restricted to absolute
// http/https URLs with a host, and rejected outright ("") if the serialized
// URL contains any control or format characters. The Location value comes
// from an untrusted network — it must never reach the terminal unvalidated.
// Plain-http login URLs are accepted by design: captive-portal interception
// necessarily starts over http, and schemeless redirects (//host/path)
// inherit the probe's http scheme.
func loginURL(base *url.URL, location string, logger types.Logger) string {
	if location == "" {
		return ""
	}
	ref, err := url.Parse(location)
	if err != nil {
		logger.Debug("Portal sent unparseable Location, ignoring", "error", err)
		return ""
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		logger.Debug("Portal Location has non-http scheme, ignoring", "scheme", resolved.Scheme)
		return ""
	}
	if resolved.Host == "" {
		return ""
	}
	if resolved.User != nil {
		// http://user:pass@evil/… is a spoofing trick — same rule as the
		// probe-URL validator.
		logger.Debug("Portal Location contains userinfo, ignoring")
		return ""
	}
	s := resolved.String()
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			logger.Debug("Portal Location contains control/format characters, ignoring")
			return ""
		}
	}
	return s
}
```

**Step 4: Run to verify pass**

Run: `go test ./pkg/portal/ -v`
Expected: all PASS

**Step 5: Commit**

```bash
git add pkg/portal/
git commit -m "feat(portal): native HTTP captive-portal detector"
```

---

### Task 4: `net portal` command, fully wired

**Files:**
- Modify: `cmd/net/app.go:16-35` (App struct)
- Modify: `cmd/net/app.go` (RunPortal method)
- Create: `cmd/net/portal.go`
- Modify: `cmd/net/main.go` (`commandNeedsRootArgs` exempt list ~line 130; `createApp` + new `createPortalDetector` ~line 270; import `pkg/portal`)
- Test: `cmd/net/app_test.go`, `cmd/net/main_test.go`

(Wiring lives here, not in a later task, so every intermediate commit ships a working `net portal` — no broken bisect points.)

**Step 1: Write the failing tests**

Append to `cmd/net/app_test.go` (mock next to the other test managers). The mock supports a result **sequence** because Task 5's connect flow probes more than once (settle-retry):

```go
// testPortalDetector returns results in sequence, repeating the last one.
// err applies to every call; errs (when set) is a per-call error sequence
// (indexed like results, repeating the last entry) and overrides err.
type testPortalDetector struct {
	results []types.PortalResult
	err     error
	errs    []error
	calls   int
}

func (d *testPortalDetector) Check() (types.PortalResult, error) {
	d.calls++
	i := d.calls - 1
	if len(d.errs) > 0 {
		j := i
		if j >= len(d.errs) {
			j = len(d.errs) - 1
		}
		if d.errs[j] != nil {
			return types.PortalResult{}, d.errs[j]
		}
	} else if d.err != nil {
		return types.PortalResult{}, d.err
	}
	if len(d.results) == 0 {
		return types.PortalResult{}, nil
	}
	if i >= len(d.results) {
		i = len(d.results) - 1
	}
	return d.results[i], nil
}

func TestApp_RunPortal_Online(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOnline, status)
	assert.Contains(t, stdout.String(), "Internet: ok")
}

func TestApp_RunPortal_PortalWithLoginURL(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Contains(t, stdout.String(), "Captive portal detected")
	assert.Contains(t, stdout.String(), "Log in at: http://portal.example.com/login")
}

func TestApp_RunPortal_PortalWithoutLoginURL(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:   types.PortalStatusPortal,
		ProbeURL: "http://probe.example.com/",
	}}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Contains(t, stdout.String(), "Open http://probe.example.com/ in a browser")
}

func TestApp_RunPortal_Offline(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}

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

func TestApp_RunPortal_DetectorError(t *testing.T) {
	app, _, stderr := newTestApp()
	app.PortalDet = &testPortalDetector{err: errors.New("probe URL must be plain http")}

	_, err := app.RunPortal()
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "probe URL must be plain http")
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
	RouteMgr   types.RouteManager   // Route inspection for multi-home signaling (nil-safe)
```

RunPortal method (near RunStatus):

```go
// RunPortal probes for internet connectivity and captive portals, printing
// the portal login URL when one is detected. Returns the detected status so
// the CLI can map it to scripting-friendly exit codes; the status is only
// meaningful when err is nil.
func (a *App) RunPortal() (types.PortalStatus, error) {
	if a.PortalDet == nil {
		return types.PortalStatusOffline, fmt.Errorf("portal detection not available")
	}
	result, err := a.PortalDet.Check()
	if err != nil {
		a.errorf("Error: %v\n", err)
		return types.PortalStatusOffline, err
	}
	switch result.Status {
	case types.PortalStatusPortal:
		a.println("Captive portal detected!")
		if result.PortalURL != "" {
			a.printf("  Log in at: %s\n", result.PortalURL)
		} else {
			a.printf("  Open %s in a browser to trigger the portal login page\n", result.ProbeURL)
		}
	case types.PortalStatusOnline:
		a.println("Internet: ok")
	default:
		// Offline, Unknown, and any future status: never fail open into
		// "ok". Neutral copy — Offline covers both no-response and HTTP
		// error statuses from the probe endpoint.
		a.println("Internet: unreachable")
	}
	return result.Status, nil
}
```

`cmd/net/main.go` — add `"portal"` to the root-exempt switch (the probe is
plain HTTP; no CAP_NET_ADMIN needed):

```go
		case "help", "completion", "status", "show", "list", "portal":
```

`cmd/net/main.go` — wire the detector (and the route manager used by Task 5's
multi-home signaling) in `createApp` and add the factory:

```go
func createApp() *App {
	return &App{
		// ... existing fields ...
		PortalDet:  createPortalDetector(),
		RouteMgr:   netlink.NewRouteManager(),
		// ...
	}
}
```

(`App` gains `RouteMgr types.RouteManager` next to `PortalDet`; add the
`pkg/netlink` import. Nil `RouteMgr` must be tolerated by all users — tests
mostly leave it nil. Verified: `netlink.NewRouteManager()` is a pure
zero-field constructor — no sockets or netlink state at construction; calls
open per-operation and route READS are unprivileged (types.go RouteManager
doc), so root-exempt `net portal`/`net status` are unaffected.)

```go

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
	Args:  cobra.NoArgs, // scripting command with exit-code semantics — reject stray args
	Short: "Check for a captive portal on the current connection",
	Long: `Probe a connectivity-check URL to determine whether the current network
has working internet or a captive portal intercepting traffic.

A captive portal is reported only on positive evidence (redirect, HTTP 511,
or a rewritten response body). Probe failures and server errors are reported
as "unreachable" — if the probe endpoint itself is down, that is not a portal.

The probe follows normal process routing; on a multi-homed machine it
reflects the preferred interface, not necessarily the one just connected
(the multi-home note is an IPv4-main-table metric heuristic, not a guarantee
of probe egress). HTTP proxy environment variables are intentionally ignored
— a proxy would answer on the portal's behalf and mask it.

Exit codes: 0 = online, 2 = captive portal detected, 1 = offline,
3 = configuration or internal error.`,
	Run: func(cmd *cobra.Command, args []string) {
		status, err := createApp().RunPortal()
		if err != nil {
			os.Exit(3)
		}
		switch status {
		case types.PortalStatusOnline:
			// exit 0
		case types.PortalStatusPortal:
			os.Exit(2)
		default:
			// Offline, Unknown, future statuses: never exit 0 by accident.
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(portalCmd)
}
```

**Step 4: Run to verify pass**

Run: `go test ./cmd/net/ -run 'TestApp_RunPortal|TestCommandNeedsRootArgs' -v && go build ./...`
Expected: PASS, clean build — `net portal` works end-to-end from this commit on

**Step 5: Commit**

```bash
git add cmd/net/app.go cmd/net/portal.go cmd/net/main.go cmd/net/app_test.go cmd/net/main_test.go
git commit -m "feat(cli): root-exempt net portal command with scripting exit codes"
```

---

### Task 5: connect + status integration

**Files:**
- Modify: `cmd/net/app.go` (`RunConnect` tail ~line 281-288, `RunStatus`, `connectVPN` refactor, new helpers; add `"time"` and `types.RouteManager` field usage — `RouteMgr` field itself was added in Task 4)
- Test: `cmd/net/app_test.go` (also converts the seven `TestApp_connectVPN_*` tests, see Step 3 note)

**Step 1: Write the failing tests** (complete and compile-ready; setups mirror `TestApp_RunConnect_DirectSSID` and `TestApp_RunConnect_WithVPNIntegration`)

First extend `trackingVPNManager` (`app_test.go:1240`) to also track connects
(`testVPNManager.Connect` is a no-op success, so this override is
behavior-preserving for existing tests):

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

New tests:

```go
func TestApp_RunConnect_PortalWarning(t *testing.T) {
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stderr.String(), "captive portal detected")
	assert.Contains(t, stderr.String(), "http://portal.example.com/login")
	// No VPN configured → no VPN hint
	assert.NotContains(t, stderr.String(), "VPN")
}

func TestApp_RunConnect_PortalCheckOff(t *testing.T) {
	app, _, stderr := newTestApp()
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p"}}}
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
	assert.Equal(t, 0, det.calls, "portal check must be skipped when check: off")
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
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p",
	}}}

	err := app.RunConnect("home", "")
	assert.NoError(t, err)
	assert.True(t, tracker.connectCalled, "VPN attempt must still happen after portal warning")
	assert.Equal(t, "myvpn", tracker.lastConnectName)
	assert.Contains(t, stderr.String(), "may not come up until")
}

func TestApp_RunConnect_OfflineRetriesOnce(t *testing.T) {
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	// First probe races DHCP/DNS settling and reports Offline; retry sees the portal.
	det := &testPortalDetector{results: []types.PortalResult{
		{Status: types.PortalStatusOffline},
		{Status: types.PortalStatusPortal, PortalURL: "http://portal.example.com/login", ProbeURL: "http://p"},
	}}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.Contains(t, stderr.String(), "captive portal detected")
	assert.NotContains(t, stderr.String(), "no internet connectivity")
}

func TestApp_RunConnect_OnlineAfterSettleRetry(t *testing.T) {
	// Offline then Online: the settle-retry succeeded — no warning at all.
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	det := &testPortalDetector{results: []types.PortalResult{
		{Status: types.PortalStatusOffline},
		{Status: types.PortalStatusOnline},
	}}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.NotContains(t, stderr.String(), "Warning:")
}

func TestApp_RunConnect_OfflineAfterRetryWarns(t *testing.T) {
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.Contains(t, stderr.String(), "no internet connectivity")
}

// stubRouteManager implements types.RouteManager with a fixed route table;
// only ListRoutes matters here (preferredDefaultIface uses it), the rest are
// inert no-ops.
type stubRouteManager struct{ routes []types.Route }

func (s *stubRouteManager) ListRoutes() ([]types.Route, error) { return s.routes, nil }
func (s *stubRouteManager) GetDefaultRoute() (*types.Route, error) {
	return nil, errors.New("not implemented")
}
func (s *stubRouteManager) GetDefaultRouteForIface(string) (*types.Route, error) {
	return nil, errors.New("not implemented")
}
func (s *stubRouteManager) ReplaceDefault(string, string, int) error     { return nil }
func (s *stubRouteManager) SetDefaultForIface(string, string, int) error { return nil }
func (s *stubRouteManager) AddRoute(string, string, string) error        { return nil }
func (s *stubRouteManager) ReplaceRoute(string, string, string) error    { return nil }
func (s *stubRouteManager) DelRoute(string) error    { return nil }
func (s *stubRouteManager) FlushRoutes(string) error { return nil }

func TestApp_RunConnect_MultiHomedNotePicksLowestMetric(t *testing.T) {
	// TWO defaults, dump order deliberately wlan0-first: the note must
	// compare against the lowest-metric (preferred) default, eth0@100 —
	// not whatever the netlink dump lists first.
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &stubRouteManager{routes: []types.Route{
		{Dst: "default", Gw: "192.168.1.1", Iface: "wlan0", Metric: 600},
		{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
	}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stderr.String(), "default route (IPv4: eth0)")
	assert.Contains(t, stderr.String(), "wlan0")
}

func TestApp_RunConnect_MultiHomedNoteOnAnyOutcome(t *testing.T) {
	// A portal/offline verdict via the wrong link misleads just like a false
	// "ok" — the note must print regardless of the probe outcome.
	for _, result := range []types.PortalResult{
		{Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p"},
		{Status: types.PortalStatusOffline},
	} {
		app, _, stderr := newTestApp()
		app.PortalRetryDelay = time.Millisecond
		app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
		app.WiFiMgr = &testWiFiManager{
			connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
		}
		app.PortalDet = &testPortalDetector{results: []types.PortalResult{result}}
		app.RouteMgr = &stubRouteManager{routes: []types.Route{
			{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
		}}

		err := app.RunConnect("TestSSID", "password123")
		assert.NoError(t, err)
		assert.Contains(t, stderr.String(), "default route (IPv4: eth0)", "outcome %v", result.Status)
	}
}

func TestApp_RunConnect_NoMultiHomedNoteWhenRoutesMatch(t *testing.T) {
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &stubRouteManager{routes: []types.Route{
		{Dst: "default", Gw: "192.168.1.1", Iface: "wlan0", Metric: 600},
	}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.NotContains(t, stderr.String(), "default route (")
}

func TestApp_RunConnect_MisconfiguredProbeWarns(t *testing.T) {
	// A Check() error means misconfiguration — must be visible on stderr,
	// not silently swallowed (a silent skip looks like "no portal").
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{err: errors.New("probe URL must be plain http")}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err) // still non-fatal
	assert.Contains(t, stderr.String(), "portal probe misconfigured")
}

func TestApp_RunConnect_RetryErrorNoOfflineWarning(t *testing.T) {
	// First probe offline, retry errors out: don't warn "offline" off a
	// half-completed check.
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	det := &testPortalDetector{
		results: []types.PortalResult{{Status: types.PortalStatusOffline}},
		errs:    []error{nil, errors.New("transient")},
	}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.NotContains(t, stderr.String(), "no internet connectivity")
}

func TestApp_RunStatus_ProbeErrorLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{err: errors.New("probe URL must be plain http")}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  probe error")
}

func TestApp_RunStatus_ShowsInternetLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  captive portal (http://portal.example.com/login)")
	assert.Equal(t, 1, app.PortalDet.(*testPortalDetector).calls, "status probes exactly once (no retry)")
}

func TestApp_RunStatus_OnlineLabeledHostWide(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  ok (default route)")
}

func TestApp_RunStatus_OnlineNamesDefaultRouteIface(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &stubRouteManager{routes: []types.Route{
		{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
	}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  ok (default route: eth0)")
}

func TestApp_RunStatus_UnknownStatusNeverOk(t *testing.T) {
	// Zero-value PortalResult (PortalStatusUnknown) must never print "ok".
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{} // empty results → zero-value result

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  unreachable")
	assert.NotContains(t, stdout.String(), "Internet:  ok")
}

func TestApp_RunConnect_VPNConfiguredSuppressesOfflineWarning(t *testing.T) {
	// VPN-required networks legitimately look offline pre-VPN: no scary
	// warning, but the VPN attempt must still proceed.
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{Common: types.CommonConfig{VPN: "default-vpn"}},
		networkErr: errors.New("not found"),
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.NotContains(t, stderr.String(), "no internet connectivity")
	assert.True(t, tracker.connectCalled)
}

func TestApp_RunStatus_OfflineLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  unreachable")
}

func TestApp_RunStatus_PortalCheckOffSkipsProbe(t *testing.T) {
	app, stdout, _ := newTestApp()
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.PortalDet = det
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{Common: types.CommonConfig{Portal: types.PortalConfig{Check: "off"}}},
	}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Equal(t, 0, det.calls)
	assert.NotContains(t, stdout.String(), "Internet:")
}
```

**Step 2: Run to verify failure**

Run: `go test ./cmd/net/ -run 'TestApp_RunConnect_Portal|TestApp_RunConnect_NilDetector|TestApp_RunConnect_Offline|TestApp_RunConnect_MultiHomed|TestApp_RunConnect_NoMultiHomed|TestApp_RunConnect_Misconfigured|TestApp_RunConnect_RetryError|TestApp_RunStatus_' -v`
Expected: FAIL (no warning printed / no Internet line); the NilDetector test may already pass — keep it as a regression guard

**Step 3: Implement**

`cmd/net/app.go` — App struct gains:

```go
	// PortalRetryDelay is the settle delay before the one connect-time retry
	// when the first portal probe reports offline. Zero means the 500ms
	// default; tests set 1ms.
	PortalRetryDelay time.Duration
```

Refactor `connectVPN` so name resolution is reusable (behavior unchanged):

```go
// resolveVPNName replaces connectVPN (which is deleted — RunConnect was its
// only production caller and now calls attemptVPNConnect itself so the portal
// hint and the VPN attempt resolve the name exactly once). Carries over
// connectVPN's doc comment about inheritance semantics (vpn: name / vpn:
// empty / no key).
```

Seven existing tests (`TestApp_connectVPN_*`, app_test.go:1026-1139) call
`connectVPN` directly and MUST be replaced with these complete conversions
(setups copied verbatim from the originals; inheritance cases assert
`resolveVPNName`, the error case exercises `attemptVPNConnect`):

```go
// Tests for resolveVPNName and attemptVPNConnect (converted from the former
// TestApp_connectVPN_* suite when connectVPN was inlined into RunConnect)

func TestApp_resolveVPNName_NetworkSpecificVPN(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi", VPN: "work-vpn"},
			},
		},
	}
	assert.Equal(t, "work-vpn", app.resolveVPNName("work"))
}

func TestApp_resolveVPNName_CommonVPN(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"}, // No VPN configured
			},
		},
	}
	assert.Equal(t, "default-vpn", app.resolveVPNName("home"))
}

func TestApp_resolveVPNName_NetworkVPNOverridesCommon(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi", VPN: "work-vpn"},
			},
		},
	}
	assert.Equal(t, "work-vpn", app.resolveVPNName("work"))
}

func TestApp_resolveVPNName_NoConfig(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: nil}
	assert.Equal(t, "", app.resolveVPNName("any"))
}

func TestApp_resolveVPNName_NoVPNConfigured(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"},
			},
		},
	}
	assert.Equal(t, "", app.resolveVPNName("home"))
}

func TestApp_resolveVPNName_VPNExplicitlyDisabled(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"}, // Common VPN is set
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"}, // VPN field empty, but explicitly disabled
			},
		},
		vpnExplicitlyDisabled: map[string]bool{
			"home": true, // Simulate vpn: (empty) in YAML
		},
	}
	// Must NOT inherit common VPN because vpn: was explicitly set to empty
	assert.Equal(t, "", app.resolveVPNName("home"))
}

func TestApp_resolveVPNName_UnconfiguredNameFallsBackToCommon(t *testing.T) {
	// The plain-SSID path: RunConnect passes the SSID as configName when the
	// name isn't a configured network — common.vpn must still apply
	// (the second success path of the old connectVPN).
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{Common: types.CommonConfig{VPN: "default-vpn"}},
	}
	assert.Equal(t, "default-vpn", app.resolveVPNName("any"))
}

func TestApp_resolveVPNName_NilConfigMgr(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = nil
	assert.Equal(t, "", app.resolveVPNName("any"))
}

func TestApp_attemptVPNConnect_ConnectionError(t *testing.T) {
	app, stdout, stderr := newTestApp()
	app.VPNMgr = &testVPNManager{connectErr: errors.New("connection refused")}

	app.attemptVPNConnect("broken-vpn")
	// VPN connection failure should show warning to user but not fail WiFi connection
	assert.NotContains(t, stdout.String(), "VPN connected")
	assert.Contains(t, stderr.String(), "VPN connection failed")
}

// End-to-end characterizations through RunConnect: unit tests on
// resolveVPNName can stay green while the RunConnect wiring is broken
// (hint without connect, wrong configName), so the two inheritance edges
// that motivated the refactor are asserted through the full command.

func TestApp_RunConnect_NetworkVPNOverridesCommonEndToEnd(t *testing.T) {
	app, _, _ := newTestApp()
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi", VPN: "work-vpn"},
			},
		},
		networkConfig: &types.NetworkConfig{SSID: "WorkWiFi", VPN: "work-vpn"},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("work", "")
	assert.NoError(t, err)
	assert.True(t, tracker.connectCalled)
	assert.Equal(t, "work-vpn", tracker.lastConnectName)
}

func TestApp_RunConnect_VPNExplicitlyDisabledEndToEnd(t *testing.T) {
	app, _, _ := newTestApp()
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"},
			},
		},
		networkConfig:         &types.NetworkConfig{SSID: "HomeWiFi"},
		vpnExplicitlyDisabled: map[string]bool{"home": true},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("home", "")
	assert.NoError(t, err)
	assert.False(t, tracker.connectCalled, "vpn: (explicitly empty) must not inherit common.vpn")
}
```

Continuing `cmd/net/app.go` implementation:

```go
func (a *App) resolveVPNName(networkName string) string {
	if a.ConfigMgr == nil {
		return ""
	}
	config := a.ConfigMgr.GetConfig()
	if config == nil {
		return ""
	}
	if netConfig, ok := config.Networks[networkName]; ok {
		return a.ConfigMgr.MergeWithCommon(networkName, &netConfig).VPN
	}
	return config.Common.VPN
}
```

Portal helpers near `connectVPN`:

```go
// portalCheckEnabled reports whether automatic portal probing is enabled
// (a detector is wired and config doesn't say check: off).
func (a *App) portalCheckEnabled() bool {
	if a.PortalDet == nil {
		return false
	}
	if a.ConfigMgr != nil {
		if cfg := a.ConfigMgr.GetConfig(); cfg != nil && cfg.Common.Portal.CheckDisabled() {
			return false
		}
	}
	return true
}

// checkPortalAfterConnect probes for a captive portal right after a
// connection comes up on connectedIface. An initial "offline" gets one retry
// after a short settle delay — right after DHCP, routes/DNS can lag by a few
// hundred ms and a premature warning trains users to ignore it. When the
// default route egresses a different interface than the one just connected
// (dual-homed: wired metric 100 beats WiFi 600), the probe result describes
// the wrong path — say so instead of reporting a silent false "ok". When a
// VPN is configured (vpnConfigured), an offline verdict is expected on
// VPN-required networks, so the offline warning is demoted to debug — the
// upcoming VPN attempt is the meaningful signal. Never fatal — prints
// warnings to stderr only. Reports whether a portal was detected so
// RunConnect can add a VPN hint.
func (a *App) checkPortalAfterConnect(connectedIface string, vpnConfigured bool) bool {
	if !a.portalCheckEnabled() {
		return false
	}
	// Honest multi-home signaling: the probe follows the kernel's preferred
	// default route (lowest metric — wired 100 beats WiFi 600), which may
	// not be the just-connected interface. Any outcome via the wrong link
	// misleads (false ok, false offline, or a portal URL for the wrong
	// network), so the note prints regardless of the probe result.
	// NB: RouteMgr.GetDefaultRoute() returns the FIRST default in the
	// netlink dump, not the preferred one — use preferredDefaultIface.
	// The comparison is IPv4-main-table only (ListRoutes' scope); the note
	// says "IPv4 default route" so a dual-stack IPv6 egress isn't overclaimed.
	if iface := a.preferredDefaultIface(); iface != "" && connectedIface != "" && iface != connectedIface {
		a.errorf("Note: the portal probe follows the system default route (IPv4: %s), not the just-connected %s — the result may not describe %s.\n", iface, connectedIface, connectedIface)
	}
	result, err := a.PortalDet.Check()
	if err != nil {
		// Check errors mean misconfiguration (e.g. https probe URL) — the
		// user asked for auto-checks, so a silent skip would look like "no
		// portal". Surface it, but never fail the connect.
		a.errorf("Warning: portal probe misconfigured: %v\n", err)
		return false
	}
	if result.Status == types.PortalStatusOffline {
		delay := a.PortalRetryDelay
		if delay == 0 {
			delay = 500 * time.Millisecond
		}
		time.Sleep(delay)
		retry, retryErr := a.PortalDet.Check()
		if retryErr != nil {
			// Transient detector failure on the retry: don't warn "offline"
			// based on a half-completed check.
			a.Logger.Debug("Portal re-check failed", "error", retryErr)
			return false
		}
		result = retry
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
		if vpnConfigured {
			// VPN-required networks legitimately look offline pre-VPN;
			// warning here would be noise before the meaningful attempt.
			a.Logger.Debug("No internet before VPN attempt — VPN may provide connectivity")
		} else {
			a.errorf("Warning: no internet connectivity detected\n")
		}
	}
	return false
}

// preferredDefaultIface returns the outgoing interface of the LOWEST-metric
// IPv4 default route — the kernel's preferred IPv4 path. Heuristic for the
// honesty note only: the probe may resolve AAAA and egress IPv6 on a
// dual-stack host, which this cannot see (ListRoutes is IPv4 main table). Returns "" when unknown (nil RouteMgr, netlink error, or
// no default route). GetDefaultRoute is NOT used: it returns the first
// default in the netlink dump, which on a dual-homed machine may be the
// higher-metric one.
func (a *App) preferredDefaultIface() string {
	if a.RouteMgr == nil {
		return ""
	}
	routes, err := a.RouteMgr.ListRoutes()
	if err != nil {
		return ""
	}
	// ListRoutes is already scoped to the IPv4 main table; types.Route
	// carries no family/table/scope fields, so metric is the only selector
	// available. Ties keep the first seen (kernel dump order) — deterministic
	// per dump, and good enough for an advisory note.
	best := ""
	bestMetric := -1
	for _, r := range routes {
		if !r.IsDefault() || r.Iface == "" {
			continue
		}
		if bestMetric == -1 || r.Metric < bestMetric {
			best, bestMetric = r.Iface, r.Metric
		}
	}
	return best
}
```

In `RunConnect`, replace the tail (after `a.printConnectionInfo(connectedIface)`):

```go
	// Resolve the VPN name once, before the portal check, so the hint, the
	// offline-warning suppression, and the attempt can never disagree.
	vpnName := ""
	if !a.NoVPN {
		vpnName = a.resolveVPNName(configName)
	}

	portalDetected := a.checkPortalAfterConnect(connectedIface, vpnName != "")

	if vpnName != "" {
		if portalDetected {
			a.errorf("Note: the VPN may not come up until the portal login is complete.\n")
		}
		a.attemptVPNConnect(vpnName)
	}
	return nil
```

In `RunStatus`, after the connection-info block (the `if connErr == nil && conn != nil { ... }` block), add (single-shot, no retry — status should stay snappy):

```go
	// Internet reachability / captive portal (skipped when portal.check: off)
	if a.portalCheckEnabled() {
		result, err := a.PortalDet.Check()
		switch {
		case err != nil:
			// Misconfigured probe must be visible, not indistinguishable
			// from check: off.
			a.printf("Internet:  probe error (%v)\n", err)
		case result.Status == types.PortalStatusPortal:
			url := result.PortalURL
			if url == "" {
				url = result.ProbeURL
			}
			a.printf("Internet:  captive portal (%s)\n", url)
		case result.Status == types.PortalStatusOnline:
			// Labeled host-wide: the probe follows the default route and is
			// not scoped to the Interface: shown above (which may even be
			// disconnected while another link provides internet). Name the
			// route's interface when it is known.
			if iface := a.preferredDefaultIface(); iface != "" {
				a.printf("Internet:  ok (default route: %s)\n", iface)
			} else {
				a.printf("Internet:  ok (default route)\n")
			}
		default:
			// Offline, Unknown, and any future status — never fail open.
			a.printf("Internet:  unreachable\n")
		}
	}
```

**Step 4: Run to verify pass**

Run: `go test ./cmd/net/`
Expected: PASS (all — existing connect/status/VPN tests must stay green; the `connectVPN` refactor is behavior-preserving)

**Step 5: Commit**

```bash
git add cmd/net/app.go cmd/net/app_test.go
git commit -m "feat(cli): portal check after connect and Internet line in status"
```

---

### Task 6: docs

**Files:**
- Modify: `README.md` (command list + config reference; grep for existing `timeouts` docs)
- Modify: `config.example` (portal + timeouts.portal entries)
- Modify: `docs/plans/2026-07-17-captive-portal-design.md` (sync review-driven changes)

**Step 1: README** — add `net portal` to the commands section (exit codes 0/2/1/3, the default-route limitation, and the connect-time latency bound: worst case ≈ settle 500ms + 2× portal timeout when the network is truly offline — the retry is deliberately unconditional; refused/no-route probes fail in milliseconds so the full cost only hits blackholed networks). Note that `timeouts.*` subfields remain historically unvalidated (a `timeouts.portl` typo silently falls back to the 3s default) — tightening that is out of scope for this feature (pre-existing behavior; changing it could break configs that load today). Add to BOTH the README config reference and `config.example` (users copy the example):

```yaml
common:
  portal:
    check: auto   # "auto" (default) or "off"; anything else is rejected at load
    url: http://detectportal.firefox.com/success.txt
      # must be plain http with a host; a custom endpoint must answer
      # HTTP 204 or a 200 body of exactly "success" when internet works.
      # It should normally be an externally reachable public endpoint —
      # a LAN-local probe answers even when the internet is down.
      # (Self-hosted probes are allowed deliberately, for privacy.)
  timeouts:
    portal: 3     # captive-portal probe timeout in seconds
```

**Step 2: Sync the design doc** — the design is already stale relative to seven review rounds; the sync must be EXHAUSTIVE, replacing these sections wholesale (grep the design afterwards to confirm each string landed):

1. Classification table → the Architecture blurb of this plan verbatim (204/success→online; 3xx/511→portal; 401/403+sanitized Location→portal; 200 unexpected body→portal; everything else incl. 4xx/5xx→offline; oversized body never online; body read only on 200).
2. `PortalResult` shape → `PortalURL` (Location only) + `ProbeURL` + display-safety contract; probe URL validation (printable ASCII, http, host, no userinfo).
3. CLI section → exit codes **0/2/1/3** (3 = config/internal error), neutral `Internet: unreachable` copy, `Args: cobra.NoArgs`, root exemption.
4. `net status` → honors `check: off`, host-wide `(default route)` label.
5. Connect flow → settle-retry (500ms + one retry, offline-warn only after retry), VPN hint only when a VPN resolves, `resolveVPNName` replacing `connectVPN`.
6. Multi-home → known product gap, IPv4-labeled honesty note via lowest-metric default, dual-stack caveat.
7. Config → `common.portal` map-only rule, `check` value validation (raw map, weak-typing trap), `url` empty/null/absent ⇒ default.

Add a "Revised after consensus review (8 rounds)" note at the top.

**Step 3: Commit**

```bash
git add README.md config.example docs/plans/2026-07-17-captive-portal-design.md
git commit -m "docs: document net portal command and portal config"
```

---

### Task 7: full verification

**Step 1:** `files=$(git ls-files '*.go' | xargs gofmt -l); test -z "$files"` → exit 0 (tracked Go files only — no vendor/build-output traversal, no pipefail fragility); `go vet ./...` → clean
**Step 2:** `go test ./...` → all packages PASS (this is the required, deterministic verification: unit + httptest coverage of every classification row)
**Step 3:** Build a real binary: `go build -o /tmp/net-portal-test ./cmd/net`
**Step 4 (opportunistic manual QA — optional, outside acceptance criteria; explicitly requested by the user for this session):** the requesting user is literally sitting behind Amtrak_WiFi's portal; run `/tmp/net-portal-test portal` on the live network. Expect `Internet: ok` (already logged in) or `Captive portal detected!` + URL; verify exit code with `echo $?`; confirm no sudo prompt appears (root exemption). Also run `/tmp/net-portal-test status` and confirm the `Internet:` line. Required verification is Steps 1–3 (deterministic).
**Step 5 (requires network + GitHub credentials; skip gracefully if unavailable):** Push branch, open PR per repo workflow (`gh pr create` with explicit `--repo`/`--base`/`--head` — origin redirects), then PR self-review per CLAUDE.md. A completed implementation with Steps 1–3 green is NOT a failure if publishing is impossible.

---

## Review Log

### Round 1 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 1 | Grok (blocker) | `net portal` missing from root-exempt list → forced sudo | **Accepted.** Task 4 adds `"portal"` to `commandNeedsRootArgs` + `TestCommandNeedsRootArgs` cases. |
| 2 | Codex (blocker) | `createPortalDetector` may run before config load | **Rejected with evidence:** config loads in `PersistentPreRun` (main.go:75-77) before any `Run` → `createApp()`. Lifecycle documented. |
| 3 | Codex (blocker) | `os.Exit` in cobra `Run` untestable / may violate convention | **Rejected with evidence:** `Run` + `os.Exit` is the repo convention (status.go, connect.go, …). Exit mapping is a trivial switch; tested logic lives in `RunPortal`. |
| 4 | Codex + Grok + self (major) | Any unexpected status (404/500/502) misclassified as Portal | **Accepted.** 4xx/5xx (except 511) classify as Offline; tests for 500, 404; help text documents positive-evidence rule. |
| 5 | Codex (major) | Probe-URL fallback printed as "Log in at:" is misleading | **Accepted.** `PortalResult` split into `PortalURL` (Location only) + `ProbeURL`; distinct CLI phrasing. |
| 6 | Codex (major) + self (minor) | `net status` network probe latency / no opt-out | **Accepted (partial).** `net status` honors `portal.check: off`; timeout bounded (3s default). |
| 7 | Codex (major) | "VPN will complete once portal login is done" possibly false for non-WireGuard | **Accepted.** Reworded to "may not come up until…"; behavior unchanged per user decision. |
| 8 | Grok (major) | Task 5 tests panic on real harness (nil config), tracking mock lacks Connect | **Accepted.** Tests rewritten compile-ready; `trackingVPNManager` extended. |
| 9 | Grok (major) | Nested `common.portal` validation dropped vs design contract | **Accepted.** `validPortalFields`, nested validation, `check`-value validation + tests. |
| 10 | Grok (minor) | No timeout test | **Accepted.** `TestCheck_Offline_Timeout` added. |
| 11 | Grok (minor) | `config.example` not updated | **Accepted.** Task 6 updates it. |
| 12 | Codex (minor) | Amtrak real-life step not reproducible | **Accepted (partial).** Marked manual QA (session-specific, explicitly user-requested). |
| 13 | Self (major) | YAML `off` boolean ambiguity | **Resolved empirically:** yaml.v3 keeps unquoted `off` a string; config test locks it. |
| 14 | Self (major) | Terminal escape injection via raw `Location` fallback | **Accepted.** Superseded by round-2 #17 (pure-helper validation). |

### Round 2 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review: APPROVE w/ 2 minors

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 15 | Grok (blocker) | Raw-ESC `Location` httptest case cannot pass — Go's transport rejects control bytes in headers before classification | **Accepted.** Sanitization moved to pure helper `loginURL(base, location, logger)` with direct unit tests (unparseable, javascript:/file:, control chars, bidi, percent-encoded); httptest keeps only realistic wire paths. |
| 16 | Codex (blocker) | Probe URL with no host (`http:foo`) escapes misconfiguration contract | **Accepted.** `u.Host != ""` validated; `TestCheck_ProbeURLWithoutHostRejected`. |
| 17 | Codex (major ×2) | `Location` scheme unrestricted (javascript:, file:); ESC-only sanitization too narrow | **Accepted.** `loginURL` allows only absolute http/https with host and rejects any control (Cc) or format (Cf) runes in the serialized URL. |
| 18 | Codex (major) | Sanitization assumption spread across CLI call sites | **Accepted (partial).** Display-safety contract documented on `types.PortalResult`; single enforcement point is the detector's `loginURL` + tests. CLI-side re-sanitizing rejected as duplication. |
| 19 | Codex (major) | `portalCheckEnabled` panics on nil `ConfigMgr` | **Accepted.** Nil guard added. |
| 20 | Grok (major) | VPN hint fires when no VPN is configured (plain-SSID Amtrak path) | **Accepted.** `resolveVPNName` extracted from `connectVPN`; hint gated on non-empty VPN; `TestApp_RunConnect_PortalWarning` asserts no VPN hint. |
| 21 | Grok (major) | Probe not bound to connected interface — multi-homed false "ok" | **Accepted (documented limitation).** `SO_BINDTODEVICE` needs CAP_NET_RAW (breaks root-exempt `net portal`); source-IP binding unreliable. Limitation documented in plan header, package doc, interface doc, `net portal --help`, README. Grok's "minimum acceptable" option. |
| 22 | Grok (major) | No post-connect settle → false offline warnings | **Accepted.** Connect-time only: one retry after settle delay (default 500ms, `App.PortalRetryDelay` for tests); offline warned only after retry. `net portal`/`net status` stay single-shot. Tests for both retry outcomes. |
| 23 | Grok + Codex + self (minor) | Non-string / case-variant `check` values | **Accepted.** Validation rejects non-strings with clear message; `CheckDisabled` normalizes case/whitespace; tests added. |
| 24 | Grok (minor) | Task-4 commit ships unwired `net portal` (broken bisect point) | **Accepted.** Wiring moved into Task 4; Task 6 is docs-only. |
| 25 | Codex (minor) | `gofmt -l \| grep` exits non-zero on success | **Accepted.** `test -z "$(...)"` form. |
| 26 | Self (nit) | `RunPortal` returns `0, err` where 0 aliases Online | **Accepted.** Error path returns `PortalStatusOffline, err`; doc comment notes status meaningful only when err is nil. |

### Round 3 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review: REVISE (1 major)

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 27 | Grok (major) | "check: false → cryptic decode error" fact is FALSE: viper weak-typing silently coerces bools to "0"/"1" | **Accepted, re-verified empirically** (bool→"0", no error). Fact corrected; raw-map value validation made mandatory; test asserts the explicit `must be "auto" or "off"` message (plain error, since `ValidationError` only formats unknown-field messages). |
| 28 | Grok (major) | Misconfigured probe silent on connect (Debug only) and status (line vanishes) | **Accepted.** Connect prints `Warning: portal probe misconfigured: …`; status prints `Internet:  probe error (…)`; tests added. |
| 29 | Grok (major) | Body read failure on a 200 classified as Portal | **Accepted.** ReadAll error → Offline; `TestCheck_Offline_BodyReadFailure` (short Content-Length). |
| 30 | Grok (minor) | `ProbeURL` display-safety unenforced for configured URLs | **Accepted.** `common.portal.url` validated at config load (http scheme, host); detector's runtime check stays as second layer. |
| 31 | Grok (minor) | Connect-time worst-case latency (≈6.5s offline) undocumented | **Accepted.** Bound documented in README/design; single retry kept. |
| 32 | Codex (blocker) | Bare `&http.Transport{}` loses Go's tuned defaults | **Accepted.** `http.DefaultTransport.(*http.Transport).Clone()` with `Proxy = nil`. |
| 33 | Codex (major) | Custom probe URL success contract unspecified | **Accepted.** Contract documented (204 or exact `success` body) in `PortalConfig.URL` doc, README, config.example. |
| 34 | Codex (major) | Retry error silently keeps first offline result → misleading warning | **Accepted.** Retry error → debug log, no warning; `TestApp_RunConnect_RetryErrorNoOfflineWarning`. |
| 35 | Codex (major) | VPN name resolved twice (hint + connectVPN) | **Accepted.** Resolved once in RunConnect; `connectVPN` deleted (single caller); `attemptVPNConnect` called directly. |
| 36 | Codex (minor) | Scripts can't distinguish offline from config error | **Accepted.** Exit code 3 for config/internal errors; help text updated. |
| 37 | Codex (minor) | Validation semantics not documented | **Accepted.** README/config.example note allowed values and URL constraints. |
| 38 | Self (major) | `TestLoginURL` bidi-in-PATH vector expects "" but `URL.String()` percent-encodes it (display-safe, accepted) | **Accepted.** Vector fixed to expect percent-encoded form; new host-bidi vector expects "" (hosts serialize raw, rune scan rejects). |

### Round 4 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review: 1 major (found & fixed pre-merge)

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 39 | Self + Grok (blocker) + Codex (major) | Deleting `connectVPN` breaks seven direct-call tests / behavior-preservation unproven | **Accepted (self-caught pre-merge).** The seven `TestApp_connectVPN_*` tests are the characterization suite; plan converts them (inheritance cases → `resolveVPNName` assertions, ConnectionError → `attemptVPNConnect` direct). |
| 40 | Grok (major) | `url: ""` rejected as "no host" contradicts "empty means default"; `url:` null mishandled | **Accepted.** Explicit semantics: absent/null/"" → default (no error); non-empty string → validated; non-string → error. `TestPortalConfigEmptyURLAllowed` added. |
| 41 | Grok (major) | Multi-home "YAGNI single-interface" rationale false — repo models dual-homing (metrics 100/600); silent false "ok" | **Accepted.** Reframed as known product gap with honest signaling: connect-time stderr note when default-route iface ≠ connected iface (via `types.RouteManager`, wired `netlink.NewRouteManager()`, nil-safe); tests with stub route manager. |
| 42 | Grok (major) | `net status` probes while selected iface disconnected; `ok` next to `State: disconnected` unspecified | **Accepted (option B).** Line labeled host-wide: `Internet:  ok (default route)`; README documents it is not scoped to `Interface:`. |
| 43 | Grok (minor) + Codex (major) | ProbeURL display-safety weaker than contract; no shared validator | **Accepted.** `portal.ValidateProbeURL` (parse, http, host, no userinfo, no Cc/Cf runes) shared by config load and `Check()`; created in Task 2 so commits stay green. |
| 44 | Codex (blocker→minor as assessed) | Oversized body can trim to fake "success" | **Accepted.** Read `maxBodyBytes+1`; oversized is never Online (Portal on 200); whitespace-padding test added. (An adversarial portal can spoof `success` outright — no detector beats that — so this is robustness, not security.) |
| 45 | Codex (major) | Short-Content-Length httptest for body failure may be nondeterministic | **Accepted.** Replaced with injected `RoundTripper` whose body errors mid-read. |
| 46 | Codex (major) | `net portal` accepts stray args | **Accepted.** `Args: cobra.NoArgs`. |
| 47 | Codex (minor) | Schemeless `//host` redirect yields http URL, tradeoff undocumented | **Accepted.** Documented on `loginURL`: portal interception necessarily starts over http. |
| 48 | Codex (minor) | Per-task commits pollute history if final verification fails | **Rejected:** incremental commits that compile and pass tests are this repo's explicit convention (CLAUDE.md); PR review happens on the branch. |
| 49 | Grok (secondary) | `fmt.Errorf` doesn't fit `ValidationErrors`; missing `time` import; `-run` filter gaps | **Accepted.** `ValidationError.Message` field specified; imports and filter updated. |

### Round 5 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review: APPROVE w/ 1 pre-merged minor

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 50 | Codex (blocker) + Grok (major) | `pkg/config` importing `pkg/portal` couples config to the runtime detector; helper also risked double definition and unstaged files | **Accepted.** Helper is `types.ValidatePortalProbeURL` in `pkg/types/validation.go` (dependency-free bottom layer, existing validator home); single definition (Task 3 shows it as context only); Task 2 commit stages `validation.go`. |
| 51 | Codex (major) | Body read before status classification lets a hanging redirect/error body stall until timeout | **Accepted.** Status-only classification first; body read only for 200. |
| 52 | Codex (major) | Rune scan on `u.String()` misses raw Cc/Cf in the configured string that is printed verbatim | **Accepted.** Scan the RAW input string before parsing. |
| 53 | Codex (major) | `RouteMgr` wiring side effects unverified | **Rejected-as-risk, verified instead:** `netlink.NewRouteManager()` is a pure zero-field constructor; netlink calls open per-operation; route reads unprivileged. Noted in plan. |
| 54 | Codex (minor) | Multi-home note printed regardless of probe outcome | **Accepted.** Note moved into the Online branch — the only outcome where false "ok" is the risk. |
| 55 | Codex (minor) | Amtrak QA inside required verification | **Accepted.** Marked opportunistic/optional; required verification = deterministic steps 1–3. |
| 56 | Grok (major) | `loginURL` accepts userinfo URLs from hostile portals | **Accepted.** `resolved.User != nil` → ""; two test vectors added. |
| 57 | Grok (major) | Value-error plumbing left "implementer's choice" contradicting `ValidationErrors` | **Accepted.** Exact `ValidationError{Section, Field, Message}` append specified; `fmt.Errorf` option deleted. |
| 58 | Grok (major) | `connectVPN` test conversion was prose, not compile-ready code | **Accepted.** All seven converted tests pasted in full (setups copied verbatim from app_test.go:1026-1139). |
| 59 | Grok (minor) | Task 3 test imports missing `errors`/`strings` | **Accepted.** Import block fixed. |
| 60 | Grok (minor) | Multi-home branch can nil-deref a `(nil, nil)` route | **Accepted.** `r != nil` guard added. |
| 61 | Self (minor) | Status host-wide label "(default route)" untested | **Accepted (pre-merged).** `TestApp_RunStatus_OnlineLabeledHostWide` added. |

### Round 6 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review: APPROVE

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 62 | Grok (major) | `GetDefaultRoute()` returns FIRST default in netlink dump, not lowest-metric — honesty note can compare the wrong iface on the exact motivating topology | **Accepted.** New `preferredDefaultIface()` helper: `ListRoutes()` → lowest-metric default. Two-defaults test with dump order reversed. |
| 63 | Grok (major) | Multi-home note only on Online — false portal/offline via wrong link also mislead | **Accepted (supersedes r5 #54).** Note prints on ANY outcome, before the probe, with outcome-neutral wording ("the result may not describe wlan0") — which also resolves Codex's r5 wording complaint. Any-outcome test added. |
| 64 | Grok (major) | Test conversion dropped the unknown-name → `common.vpn` fallback path (the plain-SSID/Amtrak path!) | **Accepted.** `TestApp_resolveVPNName_UnconfiguredNameFallsBackToCommon` added. |
| 65 | Grok (minor) | Stale "implementer's choice" sentence contradicts exact plumbing spec | **Accepted.** Bullet now points solely at `ValidationError.Message`. |
| 66 | Grok (minor) | `timeouts.portal` typos silently ignored while `common.portal` is strict | **Accepted (document-only).** Pre-existing `timeouts.*` behavior documented in README; tightening it could break configs that load today — out of scope. |
| 67 | Codex (blocker as filed) | Non-ASCII/IDN-confusable hostnames pass probe-URL validation | **Accepted.** Printable-ASCII-only rule for the raw configured URL (subsumes Cc/Cf); non-ASCII test vector. `loginURL` untouched — international portal hosts are legitimate network data there. |
| 68 | Codex (major) | Unicode TrimSpace widens the "success" match | **Accepted.** ASCII-only trim; U+00A0-padded test classifies Portal. |
| 69 | Codex (major) | Unconditional settle-retry on deterministic failures | **Rejected (documented instead):** categorizing offline reasons adds detector API surface for marginal gain; refused/no-route probes fail in ms so the retry cost is ~500ms there, and the full ≈6.5s bound only hits blackholed networks — bound now stated exactly in README. Single retry was a deliberate r2 decision. |
| 70 | Codex (major) | `resolveVPNName` panics on nil `ConfigMgr` | **Accepted.** Nil guard + `TestApp_resolveVPNName_NilConfigMgr`. (Old `connectVPN` had the same exposure, but the guard matches the plan's other nil-safe helpers.) |
| 71 | Codex (minor) | PR push unconditional in verification | **Accepted.** Step 5 marked network/credentials-dependent; local green ≠ failure. |

### Round 7 (2026-07-17) — Codex: REVISE, Grok: REVISE, Claude self-review: APPROVE

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 72 | Grok (blocker) | Host-bidi `TestLoginURL` vector fails: `URL.String()` percent-encodes non-ASCII HOSTS too (Go 1.26) — plan's "serialized raw" premise false | **Accepted, re-verified empirically.** Vector expects percent-encoded form; serialized output is always ASCII, Cc/Cf scan kept as defense-in-depth only. |
| 73 | Grok + Codex (major) | Non-map `common.portal` (`portal: off` / `true` / `[auto]`) unspecified → cryptic decode or silent zero | **Accepted.** Raw pass requires absent/null/map; scalar/list appends explicit `ValidationError`; `TestPortalConfigScalarPortalRejected`. |
| 74 | Grok (major) | 401/403 + `Location` portals classified Offline — real hotel/enterprise miss | **Accepted (Location-only rule).** 401/403 WITH sanitized Location → Portal; body-HTML sniffing rejected (corporate 403 block pages would false-positive — the r1 rule Codex established). Tests both ways. |
| 75 | Grok (major) + Codex (major) | Multi-home note is IPv4-main-table heuristic; dual-stack probe may egress IPv6 — note overclaims | **Accepted (label + docs).** Note reads "(IPv4: eth0)"; godoc states the heuristic scope; README/design mention dual-stack caveat. Routing-lookup-per-destination rejected as complexity for an advisory note. |
| 76 | Codex (major) | Reject localhost/private/loopback probe URLs | **Rejected (documented instead):** self-hosted LAN probes are deliberately legitimate for privacy-focused netop users; config.example documents that a LAN-local probe answers when the internet is down. |
| 77 | Codex (major) | Connect-time latency 6.5s worst case; wants async/shorter timeout/conditional retry | **Rejected (re-litigation of r2 decision, documented in r6 #69):** cost only hits blackholed networks; async would break VPN-hint ordering; documented bound stands. |
| 78 | Grok (minor) | "unreachable (no response from probe)" lies for HTTP 4xx/5xx | **Accepted.** Neutral "Internet: unreachable"; detail stays in debug logs. |
| 79 | Grok (minor) | Offline→Online settle path untested | **Accepted.** `TestApp_RunConnect_OnlineAfterSettleRetry` added. |
| 80 | Codex (minor) | `test -z "$(…| grep …)"` trips pipefail runners | **Accepted.** `files=$(… || true); test -z "$files"`. |

### Round 8 (2026-07-18) — Codex: REVISE, Grok: REVISE, Claude self-review: 1 minor (pre-merged)

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 81 | Grok (blocker) + Codex (major) | Architecture blurb contradicts Task 3 on 401/403+Location | **Accepted.** Architecture rewritten to match Task 3 exactly; 401 covered by looping `TestCheck_Portal_AuthStatusWithLocation` over both statuses. |
| 82 | Grok (major) | `TestPortalConfigScalarPortalRejected` and `TestValidatePortalProbeURL` were name-only | **Accepted.** Full compile-ready bodies pasted in Task 2. |
| 83 | Grok (major) + Codex (major) | Empty-URL "absent" fixture synthesized by string concat — flaky/wrong | **Accepted.** Three explicit YAML documents (`url: ""`, `url:`, `portal: {}`). |
| 84 | Grok (major) | Task 6 design sync partial while design is already stale (old exit codes, old copy, no ProbeURL…) | **Accepted.** Step 2 is now an exhaustive 7-point wholesale-replacement list with grep-back verification. |
| 85 | Grok (major) | VPN conversion loses end-to-end RunConnect coverage for override + explicit-disable edges | **Accepted.** `TestApp_RunConnect_NetworkVPNOverridesCommonEndToEnd` and `TestApp_RunConnect_VPNExplicitlyDisabledEndToEnd` added through the full command. |
| 86 | Grok (minor) | No status Offline-line test; aggregate timeout suites skip the new getter | **Accepted.** `TestApp_RunStatus_OfflineLine`; aggregate-suite extension noted in Task 1. |
| 87 | Grok (minor) | `loginURL`/`Check` panic on nil logger | **Accepted.** `New` substitutes a package-private `nopLogger`. |
| 88 | Codex (major) | `RouteMgr` field only mentioned parenthetically, not in the App struct snippet | **Accepted.** Field added to the Task 4 struct code block. |
| 89 | Codex (major) | `preferredDefaultIface` selector limits (family/table/ECMP ties) unstated | **Accepted (documented).** Comment states IPv4-main-table scope, metric-only selection, first-wins ties — `types.Route` carries no further fields. |
| 90 | Codex (minor) | `gofmt -l .` traverses non-tracked paths | **Accepted.** `git ls-files '*.go' \| xargs gofmt -l`. |
| 91 | Codex (minor) | `superpowers:executing-plans` allegedly unavailable | **Rejected with evidence:** the skill IS available in this environment's skill list; Codex cannot see it. |
| 92 | Self (minor) | U+00A0 test literal was a pasted invisible character | **Accepted (pre-merged).** Explicit U+00A0 escape sequence in the Go literal. |

### Round 9 (2026-07-18) — Codex: REVISE, Grok: REVISE, Claude self-review: APPROVE

| # | Source | Objection | Resolution |
|---|--------|-----------|------------|
| 93 | Grok (major) | Zero value `PortalStatusOnline = 0` + `default:` branches fail OPEN into "internet ok" | **Accepted.** `PortalStatusUnknown` is now the zero value; `RunPortal`/`RunStatus` defaults print "unreachable"; `net portal` exit mapping defaults to 1; `TestApp_RunStatus_UnknownStatusNeverOk`. |
| 94 | Grok (major) | Task 2 tests still had `// ...LoadConfig...` ellipses despite "compile-ready" claim | **Accepted.** `loadPortalConfig` helper (t.TempDir + os.WriteFile + real `NewManager().LoadConfig`) + every body completed, no ellipsis. |
| 95 | Grok (major) | `GetPortalTimeout` test lacks the suite's table shape/negative case; aggregate updates hedged | **Accepted.** Table matches `GetCarrierTimeout` incl. negative; exact `AllDefaults`/`AllCustom` lines required with file line refs. |
| 96 | Grok (major) | All 3xx → portal, including 304 Not Modified (caching, not interception) | **Accepted.** `isRedirectStatus` limits to 301/302/303/307/308 (+511); 304 → Offline with test. |
| 97 | Grok (minor) | "Create validation.go" — file already exists | **Accepted.** Wording: add to EXISTING file. |
| 98 | Grok (minor) | Multi-home heuristic wording overclaims | **Accepted.** Help/README describe an IPv4-main-table metric heuristic, not a probe-egress guarantee. |
| 99 | Codex (blocker as filed) | `superpowers:executing-plans` unavailable | **Rejected — repeat of #91,** already rejected with evidence (skill present in this environment). |
| 100 | Codex (major) | `check: off` silences the status line ambiguously | **Rejected:** the user explicitly disabled the check; printing a disabled-notice line on every status is noise, and `net portal` remains available on demand. Grok r4 #42 requested exactly this skip. |
| 101 | Codex (major) | Status/portal don't show which interface was probed | **Accepted (status).** `Internet:  ok (default route: eth0)` when the preferred default is known; `net portal --help` documents routing. |
| 102 | Codex (major) | Proxy disabled unconditionally breaks proxy-only enterprise networks | **Rejected (documented):** probing through a proxy defeats portal detection — the proxy answers on the portal's behalf; r1 design decision. Now documented in `net portal --help`. |
| 103 | Codex (major) | False "no internet" warning on VPN-required networks | **Accepted.** Offline warning demoted to debug when a VPN resolves for the network (portal warnings unaffected); `TestApp_RunConnect_VPNConfiguredSuppressesOfflineWarning`. |
