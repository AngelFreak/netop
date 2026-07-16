package types

import "testing"

func TestRouteIsDefault(t *testing.T) {
	tests := []struct {
		name string
		dst  string
		want bool
	}{
		{"empty dst is default", "", true},
		{"literal default", "default", true},
		{"ipv4 zero net", "0.0.0.0/0", true},
		{"ipv6 zero net", "::/0", true},
		{"specific network", "192.168.1.0/24", false},
		{"host route", "10.0.0.5/32", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Route{Dst: tt.dst}
			if got := r.IsDefault(); got != tt.want {
				t.Errorf("Route{Dst:%q}.IsDefault() = %v, want %v", tt.dst, got, tt.want)
			}
		})
	}
}
