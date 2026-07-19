//go:build linux

package network

import "syscall"

// setHostname sets the system hostname via the sethostname(2) syscall,
// replacing a shell-out to the `hostname` command.
func setHostname(name string) error {
	return syscall.Sethostname([]byte(name))
}
