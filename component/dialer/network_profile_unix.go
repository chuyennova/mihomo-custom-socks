//go:build linux || darwin || freebsd || openbsd || netbsd

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

func bindNetworkProfileToDialer(spec NetworkProfileSpec, dialer *net.Dialer, _ string, _ netip.Addr) {
	addControlToDialer(dialer, networkProfileControl(spec))
}

func bindNetworkProfileToListenConfig(spec NetworkProfileSpec, lc *net.ListenConfig, _, _ string) {
	addControlToListenConfig(lc, networkProfileControl(spec))
}

func networkProfileControl(spec NetworkProfileSpec) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		res := NetworkProfileApplyResult{
			ProfileName:      spec.Name,
			Network:          network,
			Address:          address,
			ConfiguredTTL:    spec.IPv4TTL,
			ConfiguredDF:     spec.IPDontFragment,
			ConfiguredWindow: spec.TCPWindowSize,
			ConfiguredMSS:    spec.TCPMSS,
			ConfiguredWS:     spec.TCPWindowScale,
			TCPOptionsOrder:  spec.TCPOptionsOrder,
			TargetJA4T:       spec.TargetJA4T,
		}

		ctrlErr := c.Control(func(fd uintptr) {
			sock := int(fd)
			isIPv6 := strings.Contains(network, "6")

			if isIPv6 {
				if spec.IPv6HopLimit > 0 {
					if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, spec.IPv6HopLimit); err == nil {
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("IPV6_UNICAST_HOPS=%d", spec.IPv6HopLimit))
					}
					if v, err := syscall.GetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS); err == nil {
						res.ActualTTL = v
					}
				}
			} else {
				if spec.IPv4TTL > 0 {
					if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_TTL, spec.IPv4TTL); err == nil {
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("IP_TTL=%d", spec.IPv4TTL))
					}
					if v, err := syscall.GetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_TTL); err == nil {
						res.ActualTTL = v
					}
				}
			}

			if spec.TCPWindowSize > 0 {
				if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_RCVBUF, spec.TCPWindowSize); err == nil {
					res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("SO_RCVBUF=%d", spec.TCPWindowSize))
				}
				if v, err := syscall.GetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
					res.ActualRcvBuf = v
				}
			}

			if strings.HasPrefix(network, "tcp") {
				if spec.TCPNoDelay {
					if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err == nil {
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, "TCP_NODELAY=1")
					}
				}
				if spec.TCPMSS > 0 {
					if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, spec.TCPMSS); err == nil {
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("TCP_MAXSEG=%d", spec.TCPMSS))
					}
				}
			}
		})

		recordAppliedNetworkProfile(res)
		return ctrlErr
	}
}
