package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// eventLog records what happened, in order, across goroutines.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

// stuckWiFi is a WiFi manager whose connect is stuck (an access point that
// never answers) until its context is cancelled.
type stuckWiFi struct {
	testWiFiManager
	log     *eventLog
	entered chan struct{}
}

func (w *stuckWiFi) Connect(ctx context.Context, ssid, password, hostname string) error {
	close(w.entered)
	<-ctx.Done()
	w.log.add("connect returned")
	return ctx.Err()
}

func (w *stuckWiFi) Disconnect() error {
	w.log.add("wifi disconnect")
	return nil
}

// stuckNetwork is a network manager whose configured connect is stuck until
// its context is cancelled.
type stuckNetwork struct {
	testNetworkManager
	log     *eventLog
	entered chan struct{}
}

func (n *stuckNetwork) ConnectToConfiguredNetwork(ctx context.Context, config *types.NetworkConfig, password string, wifiMgr types.WiFiManager) error {
	config.Interface = "eth0"
	close(n.entered)
	<-ctx.Done()
	n.log.add("connect returned")
	return ctx.Err()
}

func (n *stuckNetwork) Disconnect(iface string) error {
	n.log.add("link disconnect " + iface)
	return nil
}

func (n *stuckNetwork) UnlockDNS() error {
	n.log.add("unlock dns")
	return nil
}

// interruptDuring runs connect in the background, fires the interrupt handler
// once the connect is stuck inside the manager, and returns when connect
// returns. It fails the test if either side hangs.
func interruptDuring(t *testing.T, reg *cleanupRegistry, entered <-chan struct{}, log *eventLog, connect func() error) {
	t.Helper()
	returned := make(chan struct{})
	go func() {
		_ = connect()
		log.add("RunConnect returned")
		close(returned)
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("connect never reached the manager")
	}
	handled := make(chan struct{})
	go func() {
		reg.handleInterrupt(5*time.Second, 5*time.Second)
		log.add("interrupt handled")
		close(handled)
	}()
	for _, ch := range []chan struct{}{handled, returned} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("hung; events so far: %v", log.list())
		}
	}
}

// before reports whether a occurs before b in events.
func before(events []string, a, b string) bool {
	ia, ib := -1, -1
	for i, e := range events {
		if e == a && ia < 0 {
			ia = i
		}
		if e == b && ib < 0 {
			ib = i
		}
	}
	return ia >= 0 && ib >= 0 && ia < ib
}

// An interrupt during a plain-SSID connect cancels the connect, waits for it
// to return, and only then undoes it. The command does not return to its own
// exit path before the cleanup ran (#89).
func TestRunConnect_InterruptCancelsTheConnectThenCleansUp_PlainSSID(t *testing.T) {
	log := &eventLog{}
	reg := &cleanupRegistry{}
	app, _, _ := newTestApp()
	app.cleanups = reg
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	wifi := &stuckWiFi{log: log, entered: make(chan struct{})}
	app.WiFiMgr = wifi

	interruptDuring(t, reg, wifi.entered, log, func() error { return app.RunConnect("Cafe", "") })

	events := log.list()
	assert.True(t, before(events, "connect returned", "wifi disconnect"),
		"cleanup must wait for the cancelled connect: %v", events)
	assert.True(t, before(events, "wifi disconnect", "RunConnect returned"),
		"the cancelled connect must not keep its cleanups from running: %v", events)
}

func TestRunConnect_InterruptCancelsTheConnectThenCleansUp_ConfiguredNetwork(t *testing.T) {
	log := &eventLog{}
	reg := &cleanupRegistry{}
	app, _, _ := newTestApp()
	app.cleanups = reg
	app.NoVPN = true
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkConfig: &types.NetworkConfig{}}
	network := &stuckNetwork{log: log, entered: make(chan struct{})}
	app.NetworkMgr = network

	interruptDuring(t, reg, network.entered, log, func() error { return app.RunConnect("office", "") })

	events := log.list()
	assert.True(t, before(events, "connect returned", "unlock dns"), "%v", events)
	assert.True(t, before(events, "connect returned", "link disconnect eth0"), "%v", events)
	assert.True(t, before(events, "link disconnect eth0", "RunConnect returned"), "%v", events)
}

// A connect that is not interrupted keeps today's behaviour: once the link is
// up its cleanups are dropped, and later work (portal check, VPN) runs under
// a live context.
func TestRunConnect_UninterruptedConnectDropsItsCleanups(t *testing.T) {
	reg := &cleanupRegistry{}
	app, _, _ := newTestApp()
	app.cleanups = reg
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}

	require.NoError(t, app.RunConnect("Cafe", ""))

	assert.Zero(t, reg.Len())
	assert.NoError(t, reg.context().Err())
}

// With nothing registered there is nothing to race, so an interrupt (say,
// during the VPN step) does not wait for the in-flight command.
func TestHandleInterrupt_DoesNotWaitWhenNothingIsRegistered(t *testing.T) {
	reg := &cleanupRegistry{}
	end := reg.begin() // a command is in flight, with no cleanups
	defer func() { go end() }()

	done := make(chan struct{})
	go func() {
		reg.handleInterrupt(time.Hour, time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleInterrupt waited for a command that has nothing to clean up")
	}
}

// A stuck command does not hold the cleanup back forever: after the wait
// budget the cleanups run anyway.
func TestHandleInterrupt_RunsCleanupsAfterTheWaitBudget(t *testing.T) {
	reg := &cleanupRegistry{}
	_ = reg.begin() // never ends
	ran := false
	reg.register("undo", func() { ran = true })

	reg.handleInterrupt(50*time.Millisecond, time.Second)

	assert.True(t, ran)
}

// The interrupt handler already says "interrupt received, cleaning up"; the
// cancelled connect must not add an error message for it.
func TestRunConnect_InterruptedConnectPrintsNoError(t *testing.T) {
	for _, configured := range []bool{false, true} {
		log := &eventLog{}
		reg := &cleanupRegistry{}
		app, _, stderr := newTestApp()
		app.cleanups = reg
		app.NoVPN = true
		entered := make(chan struct{})
		if configured {
			app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkConfig: &types.NetworkConfig{}}
			app.NetworkMgr = &stuckNetwork{log: log, entered: entered}
		} else {
			app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
			app.WiFiMgr = &stuckWiFi{log: log, entered: entered}
		}

		interruptDuring(t, reg, entered, log, func() error { return app.RunConnect("Cafe", "") })

		assert.NotContains(t, stderr.String(), "Error", "configured=%v", configured)
	}
}
