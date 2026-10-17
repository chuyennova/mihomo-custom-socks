package config

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestParseNetworkProfileConfigAndBackwardCompatibility(t *testing.T) {
	origGlobal := dialer.DefaultNetworkProfile.Load()
	defer dialer.DefaultNetworkProfile.Store(origGlobal)
	dialer.DefaultNetworkProfile.Store(dialer.NetworkProfileOff)

	// 1. Default config without network-profile preserves baseline behavior (opt-in OFF)
	baselineYAML := []byte(`
mixed-port: 7890
mode: rule
proxies:
  - name: socks-baseline
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: true
`)
	rawBaseline, err := UnmarshalRawConfig(baselineYAML)
	require.NoError(t, err)
	genBaseline, err := parseGeneral(rawBaseline)
	require.NoError(t, err)
	require.Equal(t, "", genBaseline.NetworkProfile)
	proxiesBaseline, _, err := parseProxies(rawBaseline)
	require.NoError(t, err)
	pBaseline, ok := proxiesBaseline["socks-baseline"]
	require.True(t, ok)
	require.Equal(t, "", pBaseline.ProxyInfo().NetworkProfile)

	// 2. Global network-profile: windows + per-proxy network-profile: windows
	windowsYAML := []byte(`
mixed-port: 7890
mode: rule
network-profile: windows
proxies:
  - name: socks-win
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: true
    network-profile: windows
`)
	rawWin, err := UnmarshalRawConfig(windowsYAML)
	require.NoError(t, err)
	genWin, err := parseGeneral(rawWin)
	require.NoError(t, err)
	require.Equal(t, "windows", genWin.NetworkProfile)
	proxiesWin, _, err := parseProxies(rawWin)
	require.NoError(t, err)
	pWin, ok := proxiesWin["socks-win"]
	require.True(t, ok)
	require.Equal(t, "windows", pWin.ProxyInfo().NetworkProfile)

	// 3. Experimental fallback network-profile: windows
	expWinYAML := []byte(`
mixed-port: 7890
experimental:
  network-profile: windows
`)
	rawExp, err := UnmarshalRawConfig(expWinYAML)
	require.NoError(t, err)
	genExp, err := parseGeneral(rawExp)
	require.NoError(t, err)
	require.Equal(t, "windows", genExp.NetworkProfile)

	// 4. Invalid global network-profile is rejected
	invalidGlobalYAML := []byte(`
mixed-port: 7890
network-profile: invalid-profile-xyz
`)
	rawInvalidGlobal, err := UnmarshalRawConfig(invalidGlobalYAML)
	require.NoError(t, err)
	_, err = parseGeneral(rawInvalidGlobal)
	require.Error(t, err)

	// 5. Invalid per-proxy network-profile is rejected
	invalidProxyYAML := []byte(`
mixed-port: 7890
proxies:
  - name: socks-bad
    type: socks5
    server: 127.0.0.1
    port: 1080
    network-profile: invalid-profile-xyz
`)
	rawInvalidProxy, err := UnmarshalRawConfig(invalidProxyYAML)
	require.NoError(t, err)
	_, _, err = parseProxies(rawInvalidProxy)
	require.Error(t, err)
}

func TestSocks5OutboundWithWindowsNetworkProfileEndToEnd(t *testing.T) {
	origGlobal := dialer.DefaultNetworkProfile.Load()
	defer dialer.DefaultNetworkProfile.Store(origGlobal)
	dialer.DefaultNetworkProfile.Store(dialer.NetworkProfileOff)

	// Start mock target website server
	targetLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetLn.Close()
	targetAddr := targetLn.Addr().(*net.TCPAddr)

	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}
	}()

	// Start mock RFC 1928 SOCKS5 server
	socksLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer socksLn.Close()
	socksAddr := socksLn.Addr().(*net.TCPAddr)

	go func() {
		clientConn, err := socksLn.Accept()
		if err != nil {
			return
		}
		defer clientConn.Close()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(clientConn, greeting); err != nil {
			return
		}
		_, _ = clientConn.Write([]byte{0x05, 0x00})

		req := make([]byte, 10)
		if _, err := io.ReadFull(clientConn, req); err != nil {
			return
		}
		dstIP := net.IP(req[4:8])
		dstPort := int(binary.BigEndian.Uint16(req[8:10]))

		outConn, err := net.Dial("tcp4", (&net.TCPAddr{IP: dstIP, Port: dstPort}).String())
		if err != nil {
			return
		}
		defer outConn.Close()

		reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(reply[8:10], uint16(dstPort))
		_, _ = clientConn.Write(reply)

		go io.Copy(outConn, clientConn)
		io.Copy(clientConn, outConn)
	}()

	yamlBuf := []byte(`
mixed-port: 0
mode: rule
network-profile: windows
proxies:
  - name: socks5-win
    type: socks5
    server: 127.0.0.1
    port: ` + strconv.Itoa(socksAddr.Port) + `
    udp: true
    network-profile: windows
`)
	rawCfg, err := UnmarshalRawConfig(yamlBuf)
	require.NoError(t, err)
	gen, err := parseGeneral(rawCfg)
	require.NoError(t, err)
	dialer.DefaultNetworkProfile.Store(gen.NetworkProfile)

	proxies, _, err := parseProxies(rawCfg)
	require.NoError(t, err)
	proxy := proxies["socks5-win"]
	require.NotNil(t, proxy)

	beforeCount := dialer.AppliedProfileConnCount.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	meta := &C.Metadata{
		NetWork: C.TCP,
		DstIP:   targetAddr.AddrPort().Addr(),
		DstPort: uint16(targetAddr.Port),
	}
	conn, err := proxy.DialContext(ctx, meta)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	require.NoError(t, err)
	require.Contains(t, string(resp[:n]), "200 OK")

	require.Greater(t, dialer.AppliedProfileConnCount.Load(), beforeCount)
	last := dialer.LastAppliedProfileResult.Load()
	require.Equal(t, "windows", last.ProfileName)
	require.Equal(t, 128, last.ActualTTL)
	require.GreaterOrEqual(t, last.ActualRcvBuf, 64240)
}
