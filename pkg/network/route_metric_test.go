package network

import (
	"testing"

	"github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

func newMetricTestManager(rm *fake.RouteManager) *Manager {
	return &Manager{
		routeMgr: rm,
		executor: &mockSystemExecutor{},
		logger:   &mockLogger{},
	}
}

func TestApplyDefaultRouteMetric_SetsMetric(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{{Gw: "10.1.0.1", Iface: "eth0", Metric: 0}},
	}
	m := newMetricTestManager(rm)

	m.applyDefaultRouteMetric("eth0", 100)

	// The default route on eth0 is reinstalled with the metric via SetDefaultForIface.
	assert.Len(t, rm.SetForIface, 1)
	assert.Equal(t, fake.ReplaceCall{Iface: "eth0", Gw: "10.1.0.1", Metric: 100}, rm.SetForIface[0])
}

// Correction #14: skip if the metric already matches — avoid churn.
func TestApplyDefaultRouteMetric_SkipsWhenAlreadySet(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{{Gw: "10.1.0.1", Iface: "eth0", Metric: 100}},
	}
	m := newMetricTestManager(rm)

	m.applyDefaultRouteMetric("eth0", 100)

	assert.Empty(t, rm.SetForIface, "metric already set: no route change should occur")
}

func TestApplyDefaultRouteMetric_ZeroMetricIsNoOp(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{{Gw: "10.1.0.1", Iface: "eth0", Metric: 0}},
	}
	m := newMetricTestManager(rm)

	m.applyDefaultRouteMetric("eth0", 0)

	assert.Empty(t, rm.SetForIface, "metric <= 0 is a no-op")
}

// A device-only default route (no gateway) is skipped — there's no gateway to
// re-add with a metric.
func TestApplyDefaultRouteMetric_SkipsDeviceOnlyRoute(t *testing.T) {
	rm := &fake.RouteManager{
		Routes: []types.Route{{Gw: "", Iface: "eth0", Metric: 0}},
	}
	m := newMetricTestManager(rm)

	m.applyDefaultRouteMetric("eth0", 100)

	assert.Empty(t, rm.SetForIface, "device-only route has no gateway: skip")
}

func TestApplyDefaultRouteMetric_NoRouteOnIface(t *testing.T) {
	rm := &fake.RouteManager{} // GetDefaultRouteForIface returns an error
	m := newMetricTestManager(rm)

	m.applyDefaultRouteMetric("eth0", 100)

	assert.Empty(t, rm.SetForIface, "no default route on iface: nothing to re-tag")
}
