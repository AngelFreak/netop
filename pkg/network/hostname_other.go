//go:build !linux

package network

import "errors"

// setHostname is unsupported on non-Linux platforms; the netop binary only runs
// on Linux, but pkg/network is cross-compiled for darwin in CI.
func setHostname(name string) error {
	return errors.New("setHostname is only supported on Linux")
}
