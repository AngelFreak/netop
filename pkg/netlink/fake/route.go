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
	// SetForIface records every SetDefaultForIface call in order.
	SetForIface []ReplaceCall
	// Added records every AddRoute call in order.
	Added []AddCall
	// Flushed records the interface of every FlushRoutes call in order.
	Flushed []string

	// Force errors from specific methods when set.
	GetErr         error
	GetIfaceErr    error
	ListErr        error
	ReplaceErr     error
	SetForIfaceErr error
	AddErr         error
	FlushErr       error
}

// ReplaceCall records the arguments of a single ReplaceDefault invocation.
type ReplaceCall struct {
	Iface  string
	Gw     string
	Metric int
}

// AddCall records the arguments of a single AddRoute invocation.
type AddCall struct {
	Iface       string
	Destination string
	Gw          string
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

// SetDefaultForIface records the call and replaces only the in-memory default
// route on iface, leaving default routes on other interfaces intact.
func (m *RouteManager) SetDefaultForIface(iface, gw string, metric int) error {
	if m.SetForIfaceErr != nil {
		return m.SetForIfaceErr
	}
	m.SetForIface = append(m.SetForIface, ReplaceCall{Iface: iface, Gw: gw, Metric: metric})

	newDefault := types.Route{Iface: iface, Gw: gw, Metric: metric}
	for i := range m.Routes {
		if m.Routes[i].IsDefault() && m.Routes[i].Iface == iface {
			m.Routes[i] = newDefault
			return nil
		}
	}
	m.Routes = append(m.Routes, newDefault)
	return nil
}

// GetDefaultRouteForIface returns the first configured default route whose
// Iface matches, or an error if none exists on that interface.
func (m *RouteManager) GetDefaultRouteForIface(iface string) (*types.Route, error) {
	if m.GetIfaceErr != nil {
		return nil, m.GetIfaceErr
	}
	for i := range m.Routes {
		if m.Routes[i].IsDefault() && m.Routes[i].Iface == iface {
			r := m.Routes[i]
			return &r, nil
		}
	}
	return nil, errors.New("no default route on interface " + iface)
}

// AddRoute records the call and appends the route to the in-memory table.
func (m *RouteManager) AddRoute(iface, destination, gw string) error {
	if m.AddErr != nil {
		return m.AddErr
	}
	m.Added = append(m.Added, AddCall{Iface: iface, Destination: destination, Gw: gw})
	m.Routes = append(m.Routes, types.Route{Dst: destination, Gw: gw, Iface: iface})
	return nil
}

// FlushRoutes records the call and removes all in-memory routes on iface.
func (m *RouteManager) FlushRoutes(iface string) error {
	if m.FlushErr != nil {
		return m.FlushErr
	}
	m.Flushed = append(m.Flushed, iface)
	kept := m.Routes[:0]
	for _, r := range m.Routes {
		if r.Iface != iface {
			kept = append(kept, r)
		}
	}
	m.Routes = kept
	return nil
}

// ListRoutes returns the configured routes.
func (m *RouteManager) ListRoutes() ([]types.Route, error) {
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	return m.Routes, nil
}
