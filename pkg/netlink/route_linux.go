//go:build linux

// Package netlink provides native, structured access to the Linux routing
// table (and, over time, addresses and links) via rtnetlink, replacing the
// fragile text-parsing of the `ip` command.
//
// This file is the real Linux implementation. A stub in route_other.go keeps
// the package buildable on non-Linux platforms (the CI cross-compiles darwin
// binaries), where every operation returns ErrUnsupported.
package netlink

import (
	"errors"
	"fmt"
	"net"

	vnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/angelfreak/net/pkg/types"
)

// Compile-time assertions that the netlink implementations satisfy the typed
// manager interfaces.
var (
	_ types.RouteManager = (*RouteManager)(nil)
	_ types.AddrManager  = (*AddrManager)(nil)
	_ types.LinkManager  = (*LinkManager)(nil)
)

// RouteManager is the Linux/netlink implementation of types.RouteManager.
type RouteManager struct{}

// NewRouteManager returns a netlink-backed RouteManager.
func NewRouteManager() *RouteManager {
	return &RouteManager{}
}

// GetDefaultRoute returns the current IPv4 default route (destination 0/0), or
// an error if none exists. It correctly represents both gateway default routes
// (Gw set) and device-only default routes such as `default dev wg0` (Gw == "").
func (m *RouteManager) GetDefaultRoute() (*types.Route, error) {
	routes, err := vnl.RouteListFiltered(vnl.FAMILY_V4, &vnl.Route{Table: unix.RT_TABLE_MAIN}, vnl.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}
	for i := range routes {
		r := &routes[i]
		if !isDefaultDst(r.Dst) {
			continue
		}
		out, err := toRoute(r)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, fmt.Errorf("no default route found")
}

// ReplaceDefault installs (or replaces) the IPv4 default route. When gw is "",
// a device-only default route via iface is installed (scope link). A metric of
// 0 leaves the priority unset.
//
// Semantics match `ip route replace default ...`: after this call the main
// table has exactly one IPv4 default route — the one requested. We delete every
// existing default route first, then add the new one. Delete-then-add (rather
// than a single RouteReplace) is deliberate: NLM_F_REPLACE matches on the route
// key including priority, so switching metric or switching between a
// device-only and a gateway default can leave the old route in place on some
// kernels. Clearing first makes the outcome deterministic across kernels.
func (m *RouteManager) ReplaceDefault(iface, gw string, metric int) error {
	route, err := buildDefaultRoute(iface, gw, metric)
	if err != nil {
		return err
	}

	// Remove ALL existing IPv4 default routes so exactly one remains afterward.
	if err := m.deleteDefaultRoutes(0); err != nil {
		return fmt.Errorf("clearing existing default route: %w", err)
	}

	if err := vnl.RouteAdd(route); err != nil {
		return fmt.Errorf("adding default route via %q dev %q: %w", gw, iface, err)
	}
	return nil
}

// SetDefaultForIface installs the IPv4 default route via iface, replacing only
// the default route already on that interface and leaving default routes on
// other interfaces intact (multi-homing). When gw is "", a device-only default
// route via iface is installed (scope link). A metric of 0 leaves it unset.
func (m *RouteManager) SetDefaultForIface(iface, gw string, metric int) error {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	route, err := buildDefaultRouteForLink(link, gw, metric)
	if err != nil {
		return err
	}

	// Remove only the default route(s) on THIS interface.
	if err := m.deleteDefaultRoutes(link.Attrs().Index); err != nil {
		return fmt.Errorf("clearing existing default route on %q: %w", iface, err)
	}

	if err := vnl.RouteAdd(route); err != nil {
		return fmt.Errorf("adding default route via %q dev %q: %w", gw, iface, err)
	}
	return nil
}

// buildDefaultRoute resolves iface and returns the netlink default route to
// install. See buildDefaultRouteForLink.
func buildDefaultRoute(iface, gw string, metric int) (*vnl.Route, error) {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	return buildDefaultRouteForLink(link, gw, metric)
}

// buildDefaultRouteForLink builds a netlink IPv4 default route on link. Dst is
// set explicitly to 0.0.0.0/0 (required for device-only routes). A gateway
// yields scope UNIVERSE; an empty gateway yields a device-only route (scope
// LINK).
func buildDefaultRouteForLink(link vnl.Link, gw string, metric int) (*vnl.Route, error) {
	route := &vnl.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       defaultV4Net(),
		Family:    vnl.FAMILY_V4,
		Table:     unix.RT_TABLE_MAIN,
		Priority:  metric,
	}
	if gw != "" {
		gwIP := net.ParseIP(gw)
		if gwIP == nil {
			return nil, fmt.Errorf("invalid gateway address %q", gw)
		}
		if gwIP.To4() == nil {
			return nil, fmt.Errorf("gateway %q is not an IPv4 address", gw)
		}
		route.Gw = gwIP
		route.Scope = vnl.SCOPE_UNIVERSE
	} else {
		route.Scope = vnl.SCOPE_LINK
	}
	return route, nil
}

// deleteDefaultRoutes removes IPv4 default routes from the main table. When
// linkIndex is 0, every default route is removed; otherwise only default routes
// on that link. Missing-route deletions are not treated as errors.
func (m *RouteManager) deleteDefaultRoutes(linkIndex int) error {
	routes, err := vnl.RouteListFiltered(vnl.FAMILY_V4, &vnl.Route{Table: unix.RT_TABLE_MAIN}, vnl.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}
	for i := range routes {
		if !isDefaultDst(routes[i].Dst) {
			continue
		}
		if linkIndex != 0 && routes[i].LinkIndex != linkIndex {
			continue
		}
		if err := vnl.RouteDel(&routes[i]); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("deleting default route: %w", err)
		}
	}
	return nil
}

// GetDefaultRouteForIface returns the IPv4 default route whose outgoing
// interface is iface, or an error if none exists on that interface.
func (m *RouteManager) GetDefaultRouteForIface(iface string) (*types.Route, error) {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	routes, err := vnl.RouteListFiltered(vnl.FAMILY_V4, &vnl.Route{Table: unix.RT_TABLE_MAIN}, vnl.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}
	linkIdx := link.Attrs().Index
	for i := range routes {
		r := &routes[i]
		if !isDefaultDst(r.Dst) || r.LinkIndex != linkIdx {
			continue
		}
		out, err := toRoute(r)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, fmt.Errorf("no default route on interface %q", iface)
}

// buildRoute constructs a netlink route to destination (CIDR or bare host IP)
// via gw on iface. When gw is "", a device-scoped (link-scope) route is built.
func buildRoute(iface, destination, gw string) (*vnl.Route, error) {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	dst, err := parseDestination(destination)
	if err != nil {
		return nil, err
	}
	route := &vnl.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Family:    vnl.FAMILY_V4,
		Table:     unix.RT_TABLE_MAIN,
	}
	if gw != "" {
		gwIP := net.ParseIP(gw)
		if gwIP == nil {
			return nil, fmt.Errorf("invalid gateway address %q", gw)
		}
		if gwIP.To4() == nil {
			return nil, fmt.Errorf("gateway %q is not an IPv4 address", gw)
		}
		route.Gw = gwIP
		route.Scope = vnl.SCOPE_UNIVERSE
	} else {
		route.Scope = vnl.SCOPE_LINK
	}
	return route, nil
}

// AddRoute adds a route to destination (CIDR) via gw on iface. When gw is "",
// a device-scoped (onlink) route is added.
func (m *RouteManager) AddRoute(iface, destination, gw string) error {
	route, err := buildRoute(iface, destination, gw)
	if err != nil {
		return err
	}
	if err := vnl.RouteAdd(route); err != nil {
		return fmt.Errorf("adding route %s via %q dev %q: %w", destination, gw, iface, err)
	}
	return nil
}

// ReplaceRoute installs a route to destination via gw on iface, replacing any
// existing route to the same destination.
func (m *RouteManager) ReplaceRoute(iface, destination, gw string) error {
	route, err := buildRoute(iface, destination, gw)
	if err != nil {
		return err
	}
	if err := vnl.RouteReplace(route); err != nil {
		return fmt.Errorf("replacing route %s via %q dev %q: %w", destination, gw, iface, err)
	}
	return nil
}

// DelRoute removes the route to destination. Missing routes (ESRCH) are not
// treated as errors.
func (m *RouteManager) DelRoute(destination string) error {
	dst, err := parseDestination(destination)
	if err != nil {
		return err
	}
	route := &vnl.Route{
		Dst:    dst,
		Family: vnl.FAMILY_V4,
		Table:  unix.RT_TABLE_MAIN,
	}
	if err := vnl.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("deleting route %s: %w", destination, err)
	}
	return nil
}

// FlushRoutes removes all IPv4 routes associated with iface. Missing-route
// deletions are not treated as errors.
func (m *RouteManager) FlushRoutes(iface string) error {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}
	// RouteList filtered by link returns the routes whose oif is this link.
	routes, err := vnl.RouteList(link, vnl.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("listing routes for %q: %w", iface, err)
	}
	for i := range routes {
		if err := vnl.RouteDel(&routes[i]); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("deleting route on %q: %w", iface, err)
		}
	}
	return nil
}

// ListRoutes returns all IPv4 routes in the main table.
func (m *RouteManager) ListRoutes() ([]types.Route, error) {
	routes, err := vnl.RouteListFiltered(vnl.FAMILY_V4, &vnl.Route{Table: unix.RT_TABLE_MAIN}, vnl.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}
	out := make([]types.Route, 0, len(routes))
	for i := range routes {
		r, err := toRoute(&routes[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, nil
}

// parseDestination parses a route destination that may be either CIDR notation
// (e.g. "10.0.0.0/8") or a bare IPv4 host address (e.g. "10.0.0.5", treated as
// /32), matching the flexibility of `ip route add <dest>`.
func parseDestination(destination string) (*net.IPNet, error) {
	if _, dst, err := net.ParseCIDR(destination); err == nil {
		return dst, nil
	}
	if ip := net.ParseIP(destination); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
		}
		return nil, fmt.Errorf("destination %q is not an IPv4 address", destination)
	}
	return nil, fmt.Errorf("invalid destination %q: not a CIDR or IP address", destination)
}

// defaultV4Net returns the 0.0.0.0/0 network used as an explicit default-route
// destination. Needed for device-only default routes, where the kernel rejects
// a route with neither Dst nor Gw set.
func defaultV4Net() *net.IPNet {
	return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
}

// isDefaultDst reports whether a netlink route destination represents the
// default route. netlink represents the default route as a nil Dst or an
// all-zero /0 network.
func isDefaultDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0 && dst.IP.IsUnspecified()
}

// toRoute converts a netlink Route into the package-neutral types.Route,
// resolving the outgoing interface name from the link index.
func toRoute(r *vnl.Route) (*types.Route, error) {
	out := &types.Route{
		Metric: r.Priority,
	}
	if r.Dst != nil && !isDefaultDst(r.Dst) {
		out.Dst = r.Dst.String()
	}
	if r.Gw != nil {
		out.Gw = r.Gw.String()
	}
	if r.LinkIndex > 0 {
		link, err := vnl.LinkByIndex(r.LinkIndex)
		if err == nil {
			out.Iface = link.Attrs().Name
		}
		// If the link can't be resolved (rare, transient), leave Iface empty
		// rather than failing the whole listing.
	}
	return out, nil
}
