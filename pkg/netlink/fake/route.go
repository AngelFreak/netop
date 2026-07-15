// Package fake provides in-memory test doubles for the netlink managers so
// other packages can unit-test route-dependent logic without touching the
// kernel. These are intended for use in tests only.
package fake

import (
	"errors"

	"github.com/angelfreak/net/pkg/types"
)

// RouteManager is an in-memory fake implementation of types.RouteManager.
//
// Configure Routes to control what GetDefaultRoute/ListRoutes return. Calls to
// ReplaceDefault are recorded in Replaced and also update the in-memory default
// route so a subsequent GetDefaultRoute reflects the change. Set the *Err
// fields to force a specific method to fail.
type RouteManager struct {
	// Routes is the full route table returned by ListRoutes and searched by
	// GetDefaultRoute (which returns the first route where IsDefault()).
	Routes []types.Route

	// Replaced records every ReplaceDefault call in order.
	Replaced []ReplaceCall

	// Force errors from specific methods when set.
	GetErr     error
	ListErr    error
	ReplaceErr error
}

// ReplaceCall records the arguments of a single ReplaceDefault invocation.
type ReplaceCall struct {
	Iface  string
	Gw     string
	Metric int
}

// GetDefaultRoute returns the first route in Routes for which IsDefault() is
// true, or an error if none exists (mirroring the netlink impl).
func (m *RouteManager) GetDefaultRoute() (*types.Route, error) {
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	for i := range m.Routes {
		if m.Routes[i].IsDefault() {
			r := m.Routes[i]
			return &r, nil
		}
	}
	return nil, errors.New("no default route found")
}

// ReplaceDefault records the call and updates the in-memory default route.
func (m *RouteManager) ReplaceDefault(iface, gw string, metric int) error {
	if m.ReplaceErr != nil {
		return m.ReplaceErr
	}
	m.Replaced = append(m.Replaced, ReplaceCall{Iface: iface, Gw: gw, Metric: metric})

	// Update the in-memory default route so GetDefaultRoute reflects it.
	newDefault := types.Route{Iface: iface, Gw: gw, Metric: metric}
	for i := range m.Routes {
		if m.Routes[i].IsDefault() {
			m.Routes[i] = newDefault
			return nil
		}
	}
	m.Routes = append(m.Routes, newDefault)
	return nil
}

// ListRoutes returns the configured routes.
func (m *RouteManager) ListRoutes() ([]types.Route, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	return m.Routes, nil
}
