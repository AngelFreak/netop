package fake

import (
	"strconv"

	"github.com/angelfreak/net/pkg/types"
)

// Compile-time assertion that the fake satisfies the interface.
var _ types.RuleManager = (*RuleManager)(nil)

// RuleManager is an in-memory fake implementation of types.RuleManager.
//
// Calls are recorded in Calls, in order, as "add <dst> <priority>" or
// "del <priority>", so tests can assert both what was done and the sequence.
// Set AddErr or DelErr to force that method to fail. OnCall, when set, runs
// on every call (e.g. to note how many commands an executor had run).
type RuleManager struct {
	Calls  []string
	OnCall func()

	AddErr error
	DelErr error
}

// AddLookupMain records the call and returns AddErr.
func (f *RuleManager) AddLookupMain(dst string, priority int) error {
	f.record("add " + dst + " " + strconv.Itoa(priority))
	return f.AddErr
}

// DelRules records the call and returns DelErr.
func (f *RuleManager) DelRules(priority int) error {
	f.record("del " + strconv.Itoa(priority))
	return f.DelErr
}

func (f *RuleManager) record(call string) {
	f.Calls = append(f.Calls, call)
	if f.OnCall != nil {
		f.OnCall()
	}
}
