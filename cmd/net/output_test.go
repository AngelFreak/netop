package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeEnvelope parses one JSON document from stdout and fails the test on
// anything that is not exactly one well-formed envelope.
func decodeEnvelope(t *testing.T, out string) envelope {
	t.Helper()
	var env envelope
	dec := json.NewDecoder(stringsReader(out))
	require.NoError(t, dec.Decode(&env), "stdout was not a JSON envelope: %q", out)
	assert.False(t, dec.More(), "stdout carried more than one JSON document: %q", out)
	return env
}

func TestEmit_WritesOKEnvelope(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true

	require.NoError(t, app.emit("list", map[string]int{"n": 1}))

	env := decodeEnvelope(t, stdout.String())
	assert.True(t, env.OK)
	assert.Equal(t, "list", env.Command)
	assert.Nil(t, env.Error)
	assert.JSONEq(t, `{"n":1}`, string(env.Data))
}

func TestEmit_DoesNotHTMLEscape(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true

	require.NoError(t, app.emit("show", map[string]string{"hostname": "<name>s-MacBook-Pro & co"}))

	assert.Contains(t, stdout.String(), `"<name>s-MacBook-Pro & co"`)
	assert.NotContains(t, stdout.String(), `\u003c`)
}

func TestEmitError_WritesErrorEnvelope(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true

	app.emitError("show", errors.New("boom"))

	env := decodeEnvelope(t, stdout.String())
	assert.False(t, env.OK)
	assert.Equal(t, "show", env.Command)
	require.NotNil(t, env.Error)
	assert.Equal(t, "failed", env.Error.Code)
	assert.Equal(t, "boom", env.Error.Message)
}

func TestEmitError_UsesCodeFromCodedError(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true

	app.emitError("show", withCode(codeNotFound, errors.New("network \"x\" not found")))

	env := decodeEnvelope(t, stdout.String())
	assert.Equal(t, "not_found", env.Error.Code)
}

func TestTextHelpers_SilentInJSONMode(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true

	app.printf("a")
	app.println("b")
	app.progress("c")

	assert.Empty(t, stdout.String(), "text helpers must not write to stdout in JSON mode")
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"plain", errors.New("x"), 1},
		{"not_found", withCode(codeNotFound, errors.New("x")), 1},
		{"usage", withCode(codeUsage, errors.New("x")), 64},
		{"privilege", withCode(codePrivilege, errors.New("x")), 77},
		{"wrapped", errors.Join(errors.New("ctx"), withCode(codePrivilege, errors.New("x"))), 77},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, exitCode(tc.err))
		})
	}
}
