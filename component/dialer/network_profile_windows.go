//go:build windows

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

const (
	// winIPDontFragment is IP_DONTFRAGMENT (14) in Windows ws2ipdef.h (level IPPROTO_IP).
	winIPDontFragment = 14
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
			handle := syscall.Handle(fd)
			isIPv6 := strings.Contains(network, "6")

			if isIPv6 {
				if spec.IPv6HopLimit > 0 {
					if err := syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, spec.IPv6HopLimit); err == nil {
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("IPV6_UNICAST_HOPS=%d", spec.IPv6HopLimit))
					}
					if v, err := syscall.GetsockoptInt(handle, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS); err == nil {
						res.ActualTTL = v
					}
				}
			} else {
				if spec.IPv4TTL > 0 {
					if err := syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, syscall.IP_TTL, spec.IPv4TTL); err == nil {
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("IP_TTL=%d", spec.IPv4TTL))
					}
					if v, err := syscall.GetsockoptInt(handle, syscall.IPPROTO_IP, syscall.IP_TTL); err == nil {
						res.ActualTTL = v
					}
				}
				if spec.IPDontFragment {
					if err := syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, winIPDontFragment, 1); err == nil {
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, "IP_DONTFRAGMENT=1")
					}
					if v, err := syscall.GetsockoptInt(handle, syscall.IPPROTO_IP, winIPDontFragment); err == nil {
						res.ActualDF = v != 0
					}
				}
			}

			if spec.TCPWindowSize > 0 {
				if err := syscall.SetsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_RCVBUF, spec.TCPWindowSize); err == nil {
					res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("SO_RCVBUF=%d", spec.TCPWindowSize))
				}
				if v, err := syscall.GetsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
					res.ActualRcvBuf = v
				}
			}

			if strings.HasPrefix(network, "tcp") && spec.TCPNoDelay {
				if err := syscall.SetsockoptInt(handle, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err == nil {
					res.AppliedSocketOpts = append(res.AppliedSocketOpts, "TCP_NODELAY=1")
				}
			}
		})

		recordAppliedNetworkProfile(res)
		return ctrlErr
	}
}
