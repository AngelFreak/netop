package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/angelfreak/net/pkg/types"
)

// envelope is the single JSON document every command writes to stdout under
// --json. Agents parse one shape: check ok, then read data or error.
type envelope struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *cmdError       `json:"error,omitempty"`
}

// cmdError is the structured error carried by a failed envelope.
type cmdError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes. They classify failures for agents; the exit code is coarser
// (see exitCode).
const (
	codeFailed    = "failed"    // generic operation failure
	codeNotFound  = "not_found" // config entry, network, or VPN does not exist
	codeUsage     = "usage"     // bad arguments or flags
	codePrivilege = "privilege" // needs CAP_NET_ADMIN and could not elevate
)

// Exit codes. 2 and 3 are deliberately not used here: `net portal` already
// owns them as its own scripting contract (2 = captive portal, 3 = internal
// error). Usage and privilege follow sysexits(3).
const (
	exitOK        = 0
	exitFailed    = 1
	exitUsage     = 64 // EX_USAGE
	exitPrivilege = 77 // EX_NOPERM
)

// codedError attaches an error code to an underlying error.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// withCode wraps err with an explicit error code.
func withCode(code string, err error) error {
	return &codedError{code: code, err: err}
}

// errorCode classifies err. An explicit code wins; otherwise sentinel errors
// from pkg/ are mapped; anything else is a generic failure.
func errorCode(err error) string {
	var ce *codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	if errors.Is(err, types.ErrNotFound) {
		return codeNotFound
	}
	return codeFailed
}

// exitCode maps an error to the process exit status.
func exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	switch errorCode(err) {
	case codeUsage:
		return exitUsage
	case codePrivilege:
		return exitPrivilege
	default:
		return exitFailed
	}
}

// writeEnvelope encodes env as one JSON document followed by a newline.
func writeEnvelope(w io.Writer, env envelope) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(env)
}

// emit writes a successful envelope for command with data to stdout.
func (a *App) emit(command string, data interface{}) error {
	// Encode via an Encoder rather than json.Marshal so "<", ">" and "&"
	// (common in config placeholders like "<name>s-MacBook-Pro") are not
	// turned into \u003c escapes; this is stdout for agents, not HTML.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encoding %s result: %w", command, err)
	}
	return writeEnvelope(a.Stdout, envelope{OK: true, Command: command, Data: bytes.TrimSpace(buf.Bytes())})
}

// emitError writes a failed envelope for command to stdout.
func (a *App) emitError(command string, err error) {
	_ = writeEnvelope(a.Stdout, envelope{
		Command: command,
		Error:   &cmdError{Code: errorCode(err), Message: err.Error()},
	})
}

// fail reports err for command: in JSON mode it writes the error envelope,
// in text mode it is a no-op. It always returns err so call sites can
// `return a.fail("list", err)`.
func (a *App) fail(command string, err error) error {
	if a.JSON {
		a.emitError(command, err)
	}
	return err
}

// errJSONUnsupported is returned by commands that do not implement --json
// yet, so an agent gets an explicit usage error instead of empty stdout and
// exit 0.
func errJSONUnsupported(command string) error {
	return withCode(codeUsage, fmt.Errorf("--json is not supported by 'net %s' yet", command))
}

// rejectJSON is the cobra-level guard for commands whose App method has no
// JSON path: it writes the usage envelope and exits when --json is set.
func rejectJSON(command string) {
	if !jsonOut {
		return
	}
	err := errJSONUnsupported(command)
	_ = writeEnvelope(os.Stdout, envelope{Command: command, Error: &cmdError{Code: errorCode(err), Message: err.Error()}})
	os.Exit(exitCode(err))
}
