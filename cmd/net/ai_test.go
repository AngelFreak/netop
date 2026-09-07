package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAI_IsARegisteredCommand is the regression test for `net ai` being
// swallowed by the root fallback, which treats a lone unknown argument as a
// network name and tries to connect to a WiFi called "ai".
func TestAI_IsARegisteredCommand(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"ai"})
	require.NoError(t, err)
	assert.Equal(t, "ai", cmd.Name(), "`net ai` must resolve to the ai command, not fall through to connect")
}

func TestAI_IsRootExempt(t *testing.T) {
	// Printing a guide needs neither privileges nor a config file. Escalating
	// would make an agent's first call prompt for a password.
	assert.False(t, commandNeedsRootArgs([]string{"ai"}))
	assert.False(t, commandNeedsRootArgs([]string{"--debug", "ai"}))
}

func TestAI_GuideCoversContract(t *testing.T) {
	guide := aiGuide()

	for _, want := range []string{
		"--json",
		`"ok"`,
		"exit code",
		"CAP_NET_ADMIN",
	} {
		assert.Contains(t, guide, want, "guide must document %q", want)
	}
}

// TestAI_GuideListsEveryCommand is the anti-drift check: the guide is built
// from the live cobra tree, so a new subcommand cannot be silently missing.
func TestAI_GuideListsEveryCommand(t *testing.T) {
	guide := aiGuide()
	for _, c := range rootCmd.Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		assert.Contains(t, guide, "net "+c.Name(), "guide must document the %q command", c.Name())
	}
}

// TestAI_GuideMarksJSONSupport tells an agent which commands it can use with
// --json today and which will refuse, so it does not have to discover the
// usage error by trying.
func TestAI_GuideMarksJSONSupport(t *testing.T) {
	guide := aiGuide()
	status := commandLine(t, guide, "net status")
	assert.NotContains(t, status, "no --json", "status supports --json")

	connect := commandLine(t, guide, "net connect")
	assert.Contains(t, connect, "no --json", "connect does not support --json yet and must say so")
}

// commandLine returns the entry from the guide's command list for the given
// command: the line that starts with it, not a mention inside prose or the
// workflow example.
func commandLine(t *testing.T, guide, name string) string {
	t.Helper()
	for _, line := range strings.Split(guide, "\n") {
		if strings.HasPrefix(line, name) {
			return line
		}
	}
	t.Fatalf("guide has no command-list entry for %q", name)
	return ""
}

func TestAI_RunsWithoutRootOrConfig(t *testing.T) {
	// The guide must not touch managers or config: an agent may call it
	// before anything is set up.
	app, stdout, _ := newTestApp()
	app.ConfigMgr = nil
	app.NetworkMgr = nil
	app.WiFiMgr = nil

	require.NoError(t, app.RunAI())
	assert.Contains(t, stdout.String(), "--json")
}

func TestAI_JSONModeEmitsGuide(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.JSON = true

	require.NoError(t, app.RunAI())
	env := decodeEnvelope(t, stdout.String())
	assert.True(t, env.OK)
	assert.Equal(t, "ai", env.Command)
	assert.Contains(t, string(env.Data), "--json")
}

// TestAI_DocFileMatchesGuide keeps docs/AI.md honest: it is generated from
// the same source, so a drifted checked-in copy fails here.
func TestAI_DocFileMatchesGuide(t *testing.T) {
	onDisk, err := readDocsAI()
	require.NoError(t, err, "docs/AI.md must exist; regenerate with: go generate ./cmd/net")
	assert.Equal(t, aiGuide(), onDisk, "docs/AI.md is stale; regenerate with: go generate ./cmd/net")
}

var _ = cobra.Command{}
