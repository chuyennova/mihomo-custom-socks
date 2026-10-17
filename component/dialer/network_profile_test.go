package dialer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNormalizeAndResolveNetworkProfile(t *testing.T) {
	origGlobal := DefaultNetworkProfile.Load()
	defer DefaultNetworkProfile.Store(origGlobal)
	DefaultNetworkProfile.Store(NetworkProfileOff)

	// Opt-in disabled cases
	for _, offVal := range []string{"", " ", "off", "OFF", "none", "default", "disabled", "false"} {
		norm, err := NormalizeNetworkProfile(offVal)
		require.NoError(t, err, "expected %q to be valid off value", offVal)
		require.Equal(t, NetworkProfileOff, norm)
		spec, ok := ResolveNetworkProfile(offVal)
		require.False(t, ok)
		require.Empty(t, spec.Name)
	}

	// Valid Windows profile aliases
	for _, winVal := range []string{"windows", "Windows", "WINDOWS10", "win10", "win11", "windows10-v1"} {
		norm, err := NormalizeNetworkProfile(winVal)
		require.NoError(t, err, "expected %q to normalize to windows", winVal)
		require.Equal(t, NetworkProfileWindows, norm)
		spec, ok := ResolveNetworkProfile(winVal)
		require.True(t, ok)
		require.Equal(t, NetworkProfileWindows, spec.Name)
		require.Equal(t, 128, spec.IPv4TTL)
		require.Equal(t, 128, spec.IPv6HopLimit)
		require.True(t, spec.IPDontFragment)
		require.Equal(t, 64240, spec.TCPWindowSize)
		require.Equal(t, 8, spec.TCPWindowScale)
		require.Equal(t, 1460, spec.TCPMSS)
		require.Equal(t, "2-1-3-1-1-4", spec.TCPOptionsOrder)
		require.Equal(t, "64240_2-1-3-1-1-4_1460_8", spec.TargetJA4T)
	}

	// Invalid profile must return error
	_, err := NormalizeNetworkProfile("unknown-os-profile")
	require.Error(t, err)

	// Global fallback when override is empty
	DefaultNetworkProfile.Store(NetworkProfileWindows)
	spec, ok := ResolveNetworkProfile("")
	require.True(t, ok)
	require.Equal(t, NetworkProfileWindows, spec.Name)
}

func TestNetworkProfileSocketApplication(t *testing.T) {
	origGlobal := DefaultNetworkProfile.Load()
	defer DefaultNetworkProfile.Store(origGlobal)
	DefaultNetworkProfile.Store(NetworkProfileOff)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Baseline (opt-in OFF): must not trigger NetworkProfile intervention
	beforeCount := AppliedProfileConnCount.Load()
	c1, err := DialContext(ctx, "tcp4", ln.Addr().String())
	require.NoError(t, err)
	_ = c1.Close()
	require.Equal(t, beforeCount, AppliedProfileConnCount.Load(), "baseline dial must not apply network profile when opt-in is off")

	// 2. Per-connection opt-in (WithNetworkProfile("windows")): must apply socket options and record readback
	c2, err := DialContext(ctx, "tcp4", ln.Addr().String(), WithNetworkProfile(NetworkProfileWindows))
	require.NoError(t, err)
	_ = c2.Close()

	require.Greater(t, AppliedProfileConnCount.Load(), beforeCount, "windows profile dial must apply socket control")
	last := LastAppliedProfileResult.Load()
	require.Equal(t, NetworkProfileWindows, last.ProfileName)
	require.Equal(t, 128, last.ConfiguredTTL)
	require.Equal(t, 128, last.ActualTTL)
	require.Equal(t, 64240, last.ConfiguredWindow)
	require.GreaterOrEqual(t, last.ActualRcvBuf, 64240)
	require.Equal(t, 1460, last.ConfiguredMSS)
	require.Equal(t, 8, last.ConfiguredWS)
	require.Equal(t, "2-1-3-1-1-4", last.TCPOptionsOrder)
	require.Equal(t, "64240_2-1-3-1-1-4_1460_8", last.TargetJA4T)
	require.Contains(t, last.AppliedSocketOpts, "IP_TTL=128")
	require.Contains(t, last.AppliedSocketOpts, "SO_RCVBUF=64240")
	require.Contains(t, last.AppliedSocketOpts, "TCP_NODELAY=1")
}
