//go:build linux

package netlink

import (
	"net"
	"testing"
)

func TestIsDefaultDst(t *testing.T) {
	mustCIDR := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("bad CIDR %q: %v", s, err)
		}
		return n
	}

	tests := []struct {
		name string
		dst  *net.IPNet
		want bool
	}{
		{"nil dst is default", nil, true},
		{"0.0.0.0/0 is default", mustCIDR("0.0.0.0/0"), true},
		{"::/0 is default", mustCIDR("::/0"), true},
		{"specific /24 is not default", mustCIDR("192.168.1.0/24"), false},
		{"host /32 is not default", mustCIDR("10.0.0.1/32"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDefaultDst(tt.dst); got != tt.want {
				t.Errorf("isDefaultDst(%v) = %v, want %v", tt.dst, got, tt.want)
			}
		})
	}
}
