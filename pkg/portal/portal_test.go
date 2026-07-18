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

func TestCheck_SendsCacheBypassHeaders(t *testing.T) {
	var gotCacheControl, gotPragma string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCacheControl = r.Header.Get("Cache-Control")
		gotPragma = r.Header.Get("Pragma")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	_, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Contains(t, gotCacheControl, "no-cache")
	assert.Equal(t, "no-cache", gotPragma)
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

func TestCheck_Portal_AllRedirectStatuses(t *testing.T) {
	// Every status the classifier treats as interception evidence.
	for _, status := range []int{301, 302, 303, 307, 308} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://portal.example.com/login?res=notyet")
			w.WriteHeader(status)
		}))

		result, err := newTestDetector(srv.URL).Check()
		srv.Close()
		assert.NoError(t, err, "status %d", status)
		assert.Equal(t, types.PortalStatusPortal, result.Status, "status %d", status)
		assert.Equal(t, "http://portal.example.com/login?res=notyet", result.PortalURL, "status %d", status)
		assert.Equal(t, srv.URL, result.ProbeURL, "status %d", status)
	}
}

func TestCheck_Offline_NonRedirect3xx(t *testing.T) {
	// 3xx without interception semantics (caching / reserved / deprecated)
	// must classify offline even WITH a Location header present.
	for _, status := range []int{300, 304, 305} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://portal.example.com/login")
			w.WriteHeader(status)
		}))

		result, err := newTestDetector(srv.URL).Check()
		srv.Close()
		assert.NoError(t, err, "status %d", status)
		assert.Equal(t, types.PortalStatusOffline, result.Status, "status %d", status)
	}
}

func TestCheck_Portal_RedirectRelative(t *testing.T) {
	// A path-relative Location is still portal EVIDENCE, but resolving it
	// against the probe host would mislabel "probe host + path" as the
	// login URL (wrong under transparent interception) — so PortalURL
	// stays empty and callers use the ProbeURL fallback.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Empty(t, result.PortalURL)
	assert.Equal(t, srv.URL, result.ProbeURL)
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

func TestCheck_Portal_200LocationWithBrokenBody(t *testing.T) {
	// Location captured before the body read: interception evidence beats
	// the flaky-link heuristic when both apply.
	d := New("http://probe.example.com/", time.Second, &testLogger{})
	d.transport = brokenBodyWithLocationTransport{}

	result, err := d.Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Equal(t, "http://portal.example.com/login", result.PortalURL)
}

func TestCheck_Portal_200WithLocation(t *testing.T) {
	// Some rewrite-style portals send 200 + portal HTML + a Location.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://portal.example.com/login")
		w.Write([]byte("<html>login here</html>"))
	}))
	defer srv.Close()

	result, err := newTestDetector(srv.URL).Check()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, result.Status)
	assert.Equal(t, "http://portal.example.com/login", result.PortalURL)
}

func TestCheck_Portal_AuthStatusWithUnsanitizableLocation(t *testing.T) {
	// Location PRESENCE is the interception evidence; a URL that fails
	// sanitization (userinfo) still means portal — with ProbeURL fallback.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://user:pass@evil.example.com/login")
			w.WriteHeader(status)
		}))

		result, err := newTestDetector(srv.URL).Check()
		srv.Close()
		assert.NoError(t, err, "status %d", status)
		assert.Equal(t, types.PortalStatusPortal, result.Status, "status %d", status)
		assert.Empty(t, result.PortalURL, "status %d", status)
		assert.Equal(t, srv.URL, result.ProbeURL, "status %d", status)
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

type brokenBodyWithLocationTransport struct{}

func (brokenBodyWithLocationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       &brokenBody{},
		Header:     http.Header{"Location": []string{"http://portal.example.com/login"}},
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

func TestNew_DefaultURL(t *testing.T) {
	d := New("", time.Second, &testLogger{})
	assert.Equal(t, DefaultProbeURL, d.probeURL)
}

func TestNew_DefaultTimeoutWhenZeroOrNegative(t *testing.T) {
	for _, tmo := range []time.Duration{0, -time.Second} {
		d := New("", tmo, &testLogger{})
		assert.Equal(t, 3*time.Second, d.timeout)
	}
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
		{"path-relative rejected (probe-host mislabeling)", "/login", ""},
		{"bare-name relative rejected", "login", ""},
		{"query-only relative rejected", "?next=x", ""},
		{"degenerate double-slash rejected", "//", ""},
		{"degenerate triple-slash rejected", "///", ""},
		{"triple-slash host smuggle rejected", "///evil.com/login", ""},
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
		{"percent-encoded controls rejected", "http://x.example.com/%1b%0d%0a", ""},
		{"percent-encoded DEL rejected", "http://x.example.com/%7F", ""},
		{"benign percent-encoding allowed", "http://x.example.com/%20a?x=%2Fb", "http://x.example.com/%20a?x=%2Fb"},
		{"raw space in query rejected", "http://x.example.com/login?next=a b", ""},
		{"oversized URL rejected", "http://x.example.com/" + strings.Repeat("a", 3000), ""},
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
