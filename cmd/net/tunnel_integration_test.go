//go:build integration

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `sudo net tunnel` must run as the sudo caller. The drop is process-wide
// and irreversible, so it runs in a child copy of the test binary.
func TestDropSudoPrivileges_Integration(t *testing.T) {
	if os.Getenv("NET_TEST_DROP_CHILD") == "1" {
		dropped, err := dropSudoPrivileges()
		fmt.Printf("dropped=%v err=%v euid=%d egid=%d home=%s\n", dropped, err, os.Geteuid(), os.Getegid(), os.Getenv("HOME"))
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no 'nobody' user")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDropSudoPrivileges_Integration$")
	cmd.Env = append(os.Environ(), "NET_TEST_DROP_CHILD=1", "SUDO_UID="+nobody.Uid)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	assert.Contains(t, string(out), fmt.Sprintf("dropped=true err=<nil> euid=%s egid=%s home=%s", nobody.Uid, nobody.Gid, nobody.HomeDir))
}
