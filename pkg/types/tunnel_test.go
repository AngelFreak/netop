package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseForward(t *testing.T) {
	tests := []struct {
		spec string
		want Forward
	}{
		{"3000", Forward{LocalPort: 3000, RemoteHost: "127.0.0.1", RemotePort: 3000}},
		{"13000:3000", Forward{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000, Pinned: true}},
		{"5432:db.internal:5432", Forward{LocalPort: 5432, RemoteHost: "db.internal", RemotePort: 5432, Pinned: true}},
		{"8080:10.0.0.5:80", Forward{LocalPort: 8080, RemoteHost: "10.0.0.5", RemotePort: 80, Pinned: true}},
		{"5432:[::1]:5432", Forward{LocalPort: 5432, RemoteHost: "::1", RemotePort: 5432, Pinned: true}},
		{" 3000 ", Forward{LocalPort: 3000, RemoteHost: "127.0.0.1", RemotePort: 3000}},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := ParseForward(tt.spec)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseForward_Rejects(t *testing.T) {
	for _, spec := range []string{
		"", "0", "65536", "-1", "abc", "3000:", ":3000", "3000:abc",
		"3000:host:", "3000:host:0", "3000:-oProxyCommand=x:22",
		"3000:ho st:22", "1:2:3:4", "3000:host:22:extra",
	} {
		t.Run(spec, func(t *testing.T) {
			_, err := ParseForward(spec)
			assert.Error(t, err)
		})
	}
}

func TestForward_SSHArg(t *testing.T) {
	f := Forward{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000}
	assert.Equal(t, "127.0.0.1:13000:127.0.0.1:3000", f.SSHArg())
}

func TestForward_SSHArgBracketsIPv6(t *testing.T) {
	f := Forward{LocalPort: 5432, RemoteHost: "::1", RemotePort: 5432}
	assert.Equal(t, "127.0.0.1:5432:[::1]:5432", f.SSHArg())
}

func TestForward_String(t *testing.T) {
	f := Forward{LocalPort: 13000, RemoteHost: "127.0.0.1", RemotePort: 3000}
	assert.Equal(t, "localhost:13000 → 127.0.0.1:3000", f.String())
}

func TestValidateSSHHost(t *testing.T) {
	for _, host := range []string{"user@100.72.140.241", "server", "box.tail1234.ts.net", "me@[::1]"} {
		assert.NoError(t, ValidateSSHHost(host), host)
	}
}

func TestValidateSSHHost_Rejects(t *testing.T) {
	for _, host := range []string{"", "-oProxyCommand=sh", "user@ho st", "host\nx", "a\tb"} {
		assert.Error(t, ValidateSSHHost(host), "%q", host)
	}
}

func TestForward_SpecRoundTrips(t *testing.T) {
	for _, spec := range []string{"3000", "13000:3000", "5432:db.internal:5432", "5432:[::1]:5432"} {
		f, err := ParseForward(spec)
		require.NoError(t, err)
		assert.Equal(t, spec, f.Spec())
	}
}
