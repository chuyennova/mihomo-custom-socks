package dialer

import (
	"context"
	"encoding/hex"
	"net"
	"runtime"
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
	require.Greater(t, last.ActualRcvBuf, 0)
	require.Equal(t, 1460, last.ConfiguredMSS)
	require.Equal(t, 8, last.ConfiguredWS)
	require.Equal(t, "2-1-3-1-1-4", last.TCPOptionsOrder)
	require.Equal(t, "64240_2-1-3-1-1-4_1460_8", last.TargetJA4T)
	require.Contains(t, last.AppliedSocketOpts, "IP_TTL=128")
	if runtime.GOOS == "windows" {
		require.Contains(t, last.AppliedSocketOpts, "IP_DONTFRAGMENT=1")
		require.Contains(t, last.AppliedSocketOpts, "SO_RCVBUF=autotune(target=64240,WS=8)")
	} else {
		require.Contains(t, last.AppliedSocketOpts, "SO_RCVBUF=64240")
	}
	require.Contains(t, last.AppliedSocketOpts, "TCP_NODELAY=1")
}

func TestPacketJA4TAndWindowsPacketRewriter(t *testing.T) {
	// 1. Construct a raw IPv4 + TCP SYN packet matching the exact Android/Linux SOCKS5 exit fingerprint
	// measured at the target website: JA4T = 65535_2-4-8-1-3_1350_6 (TTL=64, DF=false, MSS=1350 (0x0546),
	// Options: MSS(2), SACK(4), TS(8), NOP(1), WS(3)=6).
	rawLinuxSYN, err := hex.DecodeString(
		"4500003c12340000400600000a00000201010101" + // IPv4 header (20B): len=60, id=0x1234, flags=0 (DF=0), ttl=64, proto=6
			"c35001bb1122334400000000a002ffff00000000" + // TCP header (20B): src=50000, dst=443, doff=10 (40B), flags=SYN(0x02), win=65535
			"02040546" + // Option 2: MSS = 1350 (0x0546)
			"0402" + // Option 4: SACK Permitted
			"080a0102030400000000" + // Option 8: Timestamp
			"01" + // Option 1: NOP
			"030306", // Option 3: Window Scale = 6
	)
	require.NoError(t, err)
	require.Len(t, rawLinuxSYN, 60)

	beforeFp, ok := InspectPacketJA4T(rawLinuxSYN)
	require.True(t, ok)
	require.Equal(t, 4, beforeFp.IPVersion)
	require.Equal(t, 64, beforeFp.TTL)
	require.False(t, beforeFp.DontFragment)
	require.True(t, beforeFp.IsSYN)
	require.Equal(t, uint16(65535), beforeFp.WindowSize)
	require.Equal(t, 1350, beforeFp.MSS)
	require.Equal(t, 6, beforeFp.WindowScale)
	require.True(t, beforeFp.HasTimestamp)
	require.True(t, beforeFp.HasSACKPermitted)
	require.Equal(t, "2-4-8-1-3", beforeFp.TCPOptionsOrder)
	require.Equal(t, "65535_2-4-8-1-3_1350_6", beforeFp.JA4T)

	// Rewrite in-place to Windows Network Profile (preserving path MSS=1350 since 1350 <= 1460)
	buf := make([]byte, 128)
	copy(buf, rawLinuxSYN)
	newLen, modified := RewritePacketToWindowsProfile(buf, len(rawLinuxSYN), WindowsNetworkProfileSpec)
	require.True(t, modified)
	require.Equal(t, 52, newLen, "stripping 10-byte Timestamp and aligning to 12-byte Windows options shrinks SYN from 60B to 52B")

	afterFp, ok := InspectPacketJA4T(buf[:newLen])
	require.True(t, ok)
	require.Equal(t, 128, afterFp.TTL)
	require.True(t, afterFp.DontFragment)
	require.True(t, afterFp.IsSYN)
	require.Equal(t, uint8(0x02), afterFp.TCPFlags)
	require.Equal(t, uint16(64240), afterFp.WindowSize)
	require.Equal(t, 1350, afterFp.MSS)
	require.Equal(t, 8, afterFp.WindowScale)
	require.False(t, afterFp.HasTimestamp, "Windows SYN must not include TCP Timestamp option")
	require.True(t, afterFp.HasSACKPermitted)
	require.Equal(t, "2-1-3-1-1-4", afterFp.TCPOptionsOrder)
	require.Equal(t, "64240_2-1-3-1-1-4_1350_8", afterFp.JA4T)
	require.True(t, afterFp.HeaderChecksumValid, "rewritten IPv4 header checksum must be valid")
	require.True(t, afterFp.TCPChecksumValid, "rewritten TCP checksum must be valid")

	// 2. Construct a raw IPv4 + TCP SYN packet with MTU=1500 (MSS=1460) and mipstack's default layout (2-4-1-3-1-1-8, ECE|CWR, 24B padded options)
	rawMipstackSYN, err := hex.DecodeString(
		"4500004043214000400600000a00000201010101" + // IPv4: len=64 (0x0040), DF=1, ttl=64
			"c35101bb1122334400000000b0c2ffff00000000" + // TCP: doff=11 (44B), flags=SYN|ECE|CWR(0xc2), win=65535
			"020405b4" + // Option 2: MSS = 1460 (0x05b4)
			"0402" + // Option 4: SACK Permitted
			"01" + // Option 1: NOP
			"030308" + // Option 3: Window Scale = 8
			"0101" + // Option 1, 1: NOP, NOP
			"080a0102030400000000" + // Option 8: Timestamp
			"0000", // 2-byte EOL padding to 24B option boundary
	)
	require.NoError(t, err)
	require.Len(t, rawMipstackSYN, 64)
	beforeMips, ok := InspectPacketJA4T(rawMipstackSYN)
	require.True(t, ok)
	require.Equal(t, "65535_2-4-1-3-1-1-8_1460_8", beforeMips.JA4T)

	copy(buf, rawMipstackSYN)
	newLen2, modified2 := RewritePacketToWindowsProfile(buf, len(rawMipstackSYN), WindowsNetworkProfileSpec)
	require.True(t, modified2)
	require.Equal(t, 52, newLen2)

	afterMips, ok := InspectPacketJA4T(buf[:newLen2])
	require.True(t, ok)
	require.Equal(t, 128, afterMips.TTL)
	require.True(t, afterMips.DontFragment)
	require.Equal(t, uint8(0x02), afterMips.TCPFlags)
	require.Equal(t, "64240_2-1-3-1-1-4_1460_8", afterMips.JA4T)
	require.True(t, afterMips.HeaderChecksumValid)
	require.True(t, afterMips.TCPChecksumValid)
	t.Logf("Verified L3/L4 SYN Rewrite: Linux SOCKS5 (%s -> %s), mipstack (%s -> %s)",
		beforeFp.JA4T, afterFp.JA4T, beforeMips.JA4T, afterMips.JA4T)
}
