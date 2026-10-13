//go:build integration

package dhcpclient

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/tests/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mountTmpfs mounts a fresh tmpfs with the given options under a temp dir.
func mountTmpfs(t *testing.T, opts string) string {
	t.Helper()
	dir := t.TempDir()
	out, err := exec.Command("mount", "-t", "tmpfs", "-o", opts, "tmpfs", dir).CombinedOutput()
	require.NoError(t, err, "mount: %s", out)
	t.Cleanup(func() { _ = exec.Command("umount", dir).Run() })
	return dir
}

// /run is noexec on many distros. A udhcpc script placed there is never run,
// so the lease is never applied and the interface gets no address. The probe
// must catch that and fall back to udhcpc's stock script.
func TestPrepareUdhcpcScript_NoexecMountFallsBack_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	manager := NewManager(system.NewExecutor(&mockLogger{}, false), &mockLogger{})
	manager.scriptDir = filepath.Join(mountTmpfs(t, "noexec,mode=0755"), "net")

	assert.Equal(t, "", manager.prepareUdhcpcScript(), "a script on a noexec mount must not be handed to udhcpc")
}

func TestPrepareUdhcpcScript_ExecMountUsesScript_Integration(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	manager := NewManager(system.NewExecutor(&mockLogger{}, false), &mockLogger{})
	manager.scriptDir = filepath.Join(mountTmpfs(t, "mode=0755"), "net")

	assert.Equal(t, filepath.Join(manager.scriptDir, "udhcpc.script"), manager.prepareUdhcpcScript())
}
