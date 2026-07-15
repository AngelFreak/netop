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
	"fmt"
	"net"

	vnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/angelfreak/net/pkg/types"
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
func (m *RouteManager) ReplaceDefault(iface, gw string, metric int) error {
	link, err := vnl.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("resolving interface %q: %w", iface, err)
	}

	route := &vnl.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       nil, // nil Dst = default route
		Family:    vnl.FAMILY_V4,
		Table:     unix.RT_TABLE_MAIN,
		Priority:  metric,
	}

	if gw != "" {
		gwIP := net.ParseIP(gw)
		if gwIP == nil {
			return fmt.Errorf("invalid gateway address %q", gw)
		}
		if gwIP.To4() == nil {
			return fmt.Errorf("gateway %q is not an IPv4 address", gw)
		}
		route.Gw = gwIP
		route.Scope = vnl.SCOPE_UNIVERSE
	} else {
		// Device-only default route (e.g. wg0): no gateway, link scope.
		route.Scope = vnl.SCOPE_LINK
	}

	if err := vnl.RouteReplace(route); err != nil {
		return fmt.Errorf("replacing default route via %q dev %q: %w", gw, iface, err)
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
