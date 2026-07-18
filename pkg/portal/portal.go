// Package portal detects captive portals by probing a known plain-HTTP
// endpoint and classifying the response, the same technique Firefox
// (detectportal.firefox.com) and Android (generate_204) use. Plain Go
// net/http — no shell-outs, no external binaries.
//
// The probe uses the process's normal routing (default route). It is NOT
// bound to a specific interface: on a multi-homed machine the result
// reflects the preferred route, which may not be the interface that was
// just connected. Binding (SO_BINDTODEVICE) is feasible where netop runs
// as root (net connect), but correct binding also needs a bound DNS
// resolver and would make root and root-exempt commands classify the same
// network differently — rejected as a product decision; an opt-in bound
// connect-time probe is possible future work.
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

// maxLoginURLBytes caps the sanitized login URL we will print — a hostile
// portal must not be able to flood the terminal/logs via Location.
const maxLoginURLBytes = 2048

// Detector probes for captive portals. Implements types.PortalDetector.
type Detector struct {
	probeURL string
	timeout  time.Duration
	logger   types.Logger
	// transport is set by New to a proxy-free DefaultTransport clone (we
	// probe the local network path, and reuse avoids stranding idle
	// connections across checks); tests may overwrite it after New.
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
	if timeout <= 0 {
		// http.Client{Timeout: 0} means NO deadline — a zero/negative value
		// must never disable the bound on a blackholed network.
		timeout = (&types.TimeoutConfig{}).GetPortalTimeout()
	}
	// Build the proxy-free transport ONCE: a fresh clone per Check would
	// strand idle connections/goroutines across the connect-time retry.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &Detector{probeURL: probeURL, timeout: timeout, logger: logger, transport: t}
}

// Check probes the endpoint and classifies the response. Transport failures
// and unexpected error statuses mean PortalStatusOffline (nil error); an
// error is returned only for a misconfigured probe URL.
func (d *Detector) Check() (types.PortalResult, error) {
	if err := types.ValidatePortalProbeURL(d.probeURL); err != nil {
		return types.PortalResult{}, err
	}

	client := &http.Client{
		Timeout:   d.timeout,
		Transport: d.transport, // set once in New (proxy-free clone) or injected by tests
		// Don't follow redirects — the portal's Location header IS the answer.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(http.MethodGet, d.probeURL, nil)
	if err != nil {
		return types.PortalResult{}, fmt.Errorf("building probe request: %w", err)
	}
	// A stale cached "success" from an intermediary would fake Online —
	// insist on a fresh answer (same headers Firefox/NetworkManager send).
	req.Header.Set("Cache-Control", "no-cache, no-store")
	req.Header.Set("Pragma", "no-cache")
	// User-Agent stays Go's default: dedicated probe hosts don't filter by
	// UA. Revisit (Firefox-like UA) only on field evidence of a portal that
	// ignores non-browser agents.

	resp, err := client.Do(req)
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
		// honor its PRESENCE even when the URL itself fails sanitization
		// (PortalURL stays empty and the caller falls back to ProbeURL,
		// same as the 3xx path). Bare 401/403 without Location remain
		// offline: a corporate block page is not a portal, and body
		// sniffing is deliberately not done. Non-redirect 3xx like 304
		// land here too and classify offline.
		if loc := resp.Header.Get("Location"); loc != "" &&
			(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return types.PortalResult{
				Status:    types.PortalStatusPortal,
				PortalURL: loginURL(resp.Request.URL, loc, d.logger),
				ProbeURL:  d.probeURL,
			}, nil
		}
		// Other 4xx/5xx (except 511): the probe endpoint itself is broken or
		// blocked. Don't cry "portal" over a CDN outage.
		d.logger.Debug("Portal probe returned unexpected status, treating as offline", "status", resp.StatusCode)
		return types.PortalResult{Status: types.PortalStatusOffline, ProbeURL: d.probeURL}, nil
	}

	// 200: capture Location FIRST — rewrite portals may send it, and it
	// remains valid evidence even if the body then stalls or breaks.
	loc := resp.Header.Get("Location")
	// Read one byte past the cap so an oversized body can never be
	// trimmed into a fake "success" (e.g. "success" + KBs of whitespace).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		if loc != "" {
			// Broken body but a Location present: interception evidence
			// wins over the flaky-link heuristic.
			return types.PortalResult{
				Status:    types.PortalStatusPortal,
				PortalURL: loginURL(resp.Request.URL, loc, d.logger),
				ProbeURL:  d.probeURL,
			}, nil
		}
		// A truncated/broken body on an otherwise-OK response with no
		// Location is a flaky link, not evidence of a portal.
		d.logger.Debug("Portal probe body read failed", "error", err)
		return types.PortalResult{Status: types.PortalStatusOffline, ProbeURL: d.probeURL}, nil
	}
	// ASCII-whitespace trim only: Unicode-whitespace padding around "success"
	// is not something a legitimate probe endpoint produces.
	if len(body) <= maxBodyBytes && strings.Trim(string(body), " \t\r\n") == "success" {
		return types.PortalResult{Status: types.PortalStatusOnline, ProbeURL: d.probeURL}, nil
	}
	// 200 with an unexpected body: something rewrote the response
	// (DNS-hijack style portals do this). Some such portals still send a
	// Location header — use it when it sanitizes; Location never decides
	// Online (body/204 stay authoritative).
	return types.PortalResult{
		Status:    types.PortalStatusPortal,
		PortalURL: loginURL(resp.Request.URL, loc, d.logger),
		ProbeURL:  d.probeURL,
	}, nil
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
// inherit the probe's http scheme. Path-relative references are rejected —
// they can only name "probe host + path", which is not the portal's login
// host under transparent interception.
func loginURL(base *url.URL, location string, logger types.Logger) string {
	if location == "" {
		return ""
	}
	ref, err := url.Parse(location)
	if err != nil {
		logger.Debug("Portal sent unparseable Location, ignoring", "error", err)
		return ""
	}
	if ref.Scheme == "" && !strings.HasPrefix(location, "//") {
		// Path-relative (or query/fragment-only) Location: resolving it
		// against the probe host would label "probe host + path" as the
		// portal's login URL — wrong under transparent interception, where
		// the probe hostname still points at the real probe server. The
		// ProbeURL fallback re-triggers interception either way.
		logger.Debug("Portal sent relative Location, using probe URL fallback")
		return ""
	}
	if strings.HasPrefix(location, "//") && ref.Host == "" {
		// Degenerate scheme-relative forms ("//", "///evil/…") parse with
		// an empty host and would resolve to the probe host — same
		// mislabeling as path-relative references.
		logger.Debug("Portal sent degenerate scheme-relative Location, using probe URL fallback")
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
	if types.HasPercentEncodedControl(s) {
		// Downstream tooling (browsers, log processors) may decode %00-%1f/
		// %7f later — encoded controls have no place in a login URL.
		logger.Debug("Portal Location contains percent-encoded control bytes, ignoring")
		return ""
	}
	if len(s) > maxLoginURLBytes {
		logger.Debug("Portal Location exceeds length cap, ignoring", "len", len(s))
		return ""
	}
	for _, r := range s {
		// Controls, format runes, and raw spaces (String() can preserve
		// spaces in the query component) — none belong in a printed URL.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' {
			logger.Debug("Portal Location contains unprintable characters, ignoring")
			return ""
		}
	}
	return s
}
