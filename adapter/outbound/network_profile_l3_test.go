package outbound

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/stretchr/testify/require"
)

func runIPStackLoopbackHandshake(t *testing.T, mode string, networkProfile string, mtu uint32) dialer.PacketFingerprint {
	t.Helper()

	clientOpt := IPStackOption{
		Mode:           mode,
		NetworkProfile: networkProfile,
	}
	clientOpt.normalize()
	require.NoError(t, clientOpt.validate())

	serverOpt := IPStackOption{
		Mode: ipStackMips,
	}
	serverOpt.normalize()

	clientStack, err := newIPStack(clientOpt, []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, mtu)
	require.NoError(t, err)
	defer clientStack.Close()
	require.NoError(t, clientStack.Start())

	serverStack, err := newIPStack(serverOpt, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, mtu)
	require.NoError(t, err)
	defer serverStack.Close()
	require.NoError(t, serverStack.Start())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var synMu sync.Mutex
	var capturedSYN dialer.PacketFingerprint
	var synCaptured bool

	// Forward packets clientStack -> serverStack (with non-zero offset=16 like WireGuard)
	go func() {
		const offset = 16
		buf := make([]byte, 65535)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for {
			n, err := clientStack.Read(bufs, sizes, offset)
			if err != nil || n == 0 {
				return
			}
			pkt := buf[offset : offset+sizes[0]]
			if fp, ok := dialer.InspectPacketJA4T(pkt); ok && fp.IsSYN {
				synMu.Lock()
				if !synCaptured {
					capturedSYN = fp
					synCaptured = true
				}
				synMu.Unlock()
			}
			_, _ = serverStack.Write([][]byte{pkt}, 0)
		}
	}()

	// Forward packets serverStack -> clientStack
	go func() {
		buf := make([]byte, 65535)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for {
			n, err := serverStack.Read(bufs, sizes, 0)
			if err != nil || n == 0 {
				return
			}
			pkt := buf[:sizes[0]]
			_, _ = clientStack.Write([][]byte{pkt}, 0)
		}
	}()

	dstAddr := netip.MustParseAddrPort("10.0.0.1:8080")
	ln, err := serverStack.ListenTCP(ctx, "tcp4", dstAddr)
	require.NoError(t, err)
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		req := make([]byte, 64)
		n, err := conn.Read(req)
		if err != nil {
			serverDone <- err
			return
		}
		if n > 0 {
			_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}
		serverDone <- err
	}()

	conn, err := clientStack.DialTCP(ctx, "tcp4", netip.AddrPort{}, dstAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n"))
	require.NoError(t, err)
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	require.NoError(t, err)
	require.Contains(t, string(resp[:n]), "200 OK")
	require.NoError(t, <-serverDone)

	synMu.Lock()
	defer synMu.Unlock()
	require.True(t, synCaptured, "expected to capture outgoing TCP SYN packet from ipStack")
	return capturedSYN
}

func TestL3IPStackWindowsNetworkProfileBeforeAfterJA4T(t *testing.T) {
	origGlobal := dialer.DefaultNetworkProfile.Load()
	defer dialer.DefaultNetworkProfile.Store(origGlobal)
	dialer.DefaultNetworkProfile.Store(dialer.NetworkProfileOff)

	// 1. mipstack BEFORE (network-profile: off) -> Linux/mipstack SYN fingerprint
	mipsBefore := runIPStackLoopbackHandshake(t, ipStackMips, dialer.NetworkProfileOff, 1500)
	t.Logf("[mipstack BEFORE] TTL=%d DF=%v Win=%d MSS=%d WS=%d Opts=%s TS=%v JA4T=%s",
		mipsBefore.TTL, mipsBefore.DontFragment, mipsBefore.WindowSize, mipsBefore.MSS,
		mipsBefore.WindowScale, mipsBefore.TCPOptionsOrder, mipsBefore.HasTimestamp, mipsBefore.JA4T)
	require.Equal(t, 64, mipsBefore.TTL)
	require.Equal(t, uint16(65535), mipsBefore.WindowSize)
	require.True(t, mipsBefore.HasTimestamp)
	require.Equal(t, "65535_2-4-1-3-1-1-8_1460_8", mipsBefore.JA4T)

	// 2. mipstack AFTER (network-profile: windows) -> Exact Windows 10/11 SYN fingerprint
	mipsAfter := runIPStackLoopbackHandshake(t, ipStackMips, dialer.NetworkProfileWindows, 1500)
	t.Logf("[mipstack AFTER]  TTL=%d DF=%v Win=%d MSS=%d WS=%d Opts=%s TS=%v JA4T=%s",
		mipsAfter.TTL, mipsAfter.DontFragment, mipsAfter.WindowSize, mipsAfter.MSS,
		mipsAfter.WindowScale, mipsAfter.TCPOptionsOrder, mipsAfter.HasTimestamp, mipsAfter.JA4T)
	require.Equal(t, 128, mipsAfter.TTL)
	require.True(t, mipsAfter.DontFragment)
	require.Equal(t, uint16(64240), mipsAfter.WindowSize)
	require.Equal(t, 1460, mipsAfter.MSS)
	require.Equal(t, 8, mipsAfter.WindowScale)
	require.False(t, mipsAfter.HasTimestamp)
	require.Equal(t, "2-1-3-1-1-4", mipsAfter.TCPOptionsOrder)
	require.Equal(t, "64240_2-1-3-1-1-4_1460_8", mipsAfter.JA4T)
	require.True(t, mipsAfter.HeaderChecksumValid)
	require.True(t, mipsAfter.TCPChecksumValid)

	// 3. gVisor BEFORE vs AFTER (when built with with_gvisor)
	if features.WithGVisor {
		gvisorBefore := runIPStackLoopbackHandshake(t, ipStackGVisor, dialer.NetworkProfileOff, 1500)
		t.Logf("[gVisor BEFORE]   TTL=%d DF=%v Win=%d MSS=%d WS=%d Opts=%s TS=%v JA4T=%s",
			gvisorBefore.TTL, gvisorBefore.DontFragment, gvisorBefore.WindowSize, gvisorBefore.MSS,
			gvisorBefore.WindowScale, gvisorBefore.TCPOptionsOrder, gvisorBefore.HasTimestamp, gvisorBefore.JA4T)
		require.NotEqual(t, "64240_2-1-3-1-1-4_1460_8", gvisorBefore.JA4T)
		require.True(t, gvisorBefore.HasTimestamp)

		gvisorAfter := runIPStackLoopbackHandshake(t, ipStackGVisor, dialer.NetworkProfileWindows, 1500)
		t.Logf("[gVisor AFTER]    TTL=%d DF=%v Win=%d MSS=%d WS=%d Opts=%s TS=%v JA4T=%s",
			gvisorAfter.TTL, gvisorAfter.DontFragment, gvisorAfter.WindowSize, gvisorAfter.MSS,
			gvisorAfter.WindowScale, gvisorAfter.TCPOptionsOrder, gvisorAfter.HasTimestamp, gvisorAfter.JA4T)
		require.Equal(t, 128, gvisorAfter.TTL)
		require.True(t, gvisorAfter.DontFragment)
		require.Equal(t, uint16(64240), gvisorAfter.WindowSize)
		require.Equal(t, 1460, gvisorAfter.MSS)
		require.Equal(t, 8, gvisorAfter.WindowScale)
		require.False(t, gvisorAfter.HasTimestamp)
		require.Equal(t, "2-1-3-1-1-4", gvisorAfter.TCPOptionsOrder)
		require.Equal(t, "64240_2-1-3-1-1-4_1460_8", gvisorAfter.JA4T)
		require.True(t, gvisorAfter.HeaderChecksumValid)
		require.True(t, gvisorAfter.TCPChecksumValid)
	}
}
