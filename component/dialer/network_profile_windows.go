//go:build windows

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"
)

const (
	// winIPDontFragment is IP_DONTFRAGMENT (14) in Windows ws2ipdef.h (level IPPROTO_IP).
	winIPDontFragment = 14
)

func getsockoptInt(handle syscall.Handle, level, opt int) (int, error) {
	var val int32
	optlen := int32(unsafe.Sizeof(val))
	err := syscall.Getsockopt(handle, int32(level), int32(opt), (*byte)(unsafe.Pointer(&val)), &optlen)
	return int(val), err
}

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
						res.ActualTTL = spec.IPv6HopLimit
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("IPV6_UNICAST_HOPS=%d", spec.IPv6HopLimit))
					}
					if v, err := getsockoptInt(handle, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS); err == nil && v > 0 {
						res.ActualTTL = v
					}
				}
			} else {
				if spec.IPv4TTL > 0 {
					if err := syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, syscall.IP_TTL, spec.IPv4TTL); err == nil {
						res.ActualTTL = spec.IPv4TTL
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("IP_TTL=%d", spec.IPv4TTL))
					}
					if v, err := getsockoptInt(handle, syscall.IPPROTO_IP, syscall.IP_TTL); err == nil && v > 0 {
						res.ActualTTL = v
					}
				}
				if spec.IPDontFragment {
					if err := syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, winIPDontFragment, 1); err == nil {
						res.ActualDF = true
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, "IP_DONTFRAGMENT=1")
					}
					if v, err := getsockoptInt(handle, syscall.IPPROTO_IP, winIPDontFragment); err == nil {
						res.ActualDF = v != 0
					}
				}
			}

			if spec.TCPWindowSize > 0 {
				if strings.HasPrefix(network, "tcp") {
					// On Windows 10/11 tcpip.sys, calling setsockopt(SO_RCVBUF, 64240) locks the
					// receive buffer at 64KB and disables Receive Window Auto-Tuning, which lowers
					// the SYN Window Scale option from WS=8 to WS=0. Preserving native Auto-Tuning
					// keeps Windows's native SYN Window=64240 and WS=8 intact.
					res.ActualRcvBuf = spec.TCPWindowSize
					if v, err := getsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil && v > 0 {
						res.ActualRcvBuf = v
					}
					res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("SO_RCVBUF=autotune(target=%d,WS=%d)", spec.TCPWindowSize, spec.TCPWindowScale))
				} else {
					if err := syscall.SetsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_RCVBUF, spec.TCPWindowSize); err == nil {
						res.ActualRcvBuf = spec.TCPWindowSize
						res.AppliedSocketOpts = append(res.AppliedSocketOpts, fmt.Sprintf("SO_RCVBUF=%d", spec.TCPWindowSize))
					}
					if v, err := getsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil && v > 0 {
						res.ActualRcvBuf = v
					}
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
