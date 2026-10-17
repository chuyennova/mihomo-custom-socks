//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd

package dialer

import (
	"net"
	"net/netip"
)

func bindNetworkProfileToDialer(_ NetworkProfileSpec, _ *net.Dialer, _ string, _ netip.Addr) {}

func bindNetworkProfileToListenConfig(_ NetworkProfileSpec, _ *net.ListenConfig, _, _ string) {}
