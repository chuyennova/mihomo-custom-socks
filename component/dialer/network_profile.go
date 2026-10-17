package dialer

import (
	"fmt"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/log"
)

const (
	NetworkProfileOff     = ""
	NetworkProfileWindows = "windows"
)

var (
	// DefaultNetworkProfile stores the global opt-in network profile name (e.g., "windows" or "").
	// When empty, Mihomo preserves 100% of its original baseline socket behavior.
	DefaultNetworkProfile = atomic.NewTypedValue[string](NetworkProfileOff)

	// LastAppliedProfileResult records the most recent socket-level application result for diagnostics and tests.
	LastAppliedProfileResult = atomic.NewTypedValue[NetworkProfileApplyResult](NetworkProfileApplyResult{})

	// AppliedProfileConnCount counts how many sockets have had an active NetworkProfile applied.
	AppliedProfileConnCount = atomic.NewInt64(0)

	loggedFirstApply sync.Map
)

// NetworkProfileSpec defines the target TCP/IP parameters for an OS network profile.
type NetworkProfileSpec struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	IPv4TTL         int    `json:"ipv4-ttl"`
	IPv6HopLimit    int    `json:"ipv6-hop-limit"`
	IPDontFragment  bool   `json:"ip-dont-fragment"`
	MTU             int    `json:"mtu"`
	TCPMSS          int    `json:"tcp-mss"`
	TCPWindowSize   int    `json:"tcp-window-size"`
	TCPWindowScale  int    `json:"tcp-window-scale"`
	TCPOptionsOrder string `json:"tcp-options-order"`
	TargetJA4T      string `json:"target-ja4t"`
	TCPNoDelay      bool   `json:"tcp-no-delay"`
}

// WindowsNetworkProfileSpec represents the standard Windows 10/11 x64 TCP/IP fingerprint parameters.
var WindowsNetworkProfileSpec = NetworkProfileSpec{
	Name:            NetworkProfileWindows,
	Description:     "Windows 10/11 x64 TCP/IP Network Profile",
	IPv4TTL:         128,
	IPv6HopLimit:    128,
	IPDontFragment:  true,
	MTU:             1500,
	TCPMSS:          1460,
	TCPWindowSize:   64240,
	TCPWindowScale:  8,
	TCPOptionsOrder: "2-1-3-1-1-4",
	TargetJA4T:      "64240_2-1-3-1-1-4_1460_8",
	TCPNoDelay:      true,
}

// NetworkProfileApplyResult captures both the configured target metrics and the actual kernel socket readback.
type NetworkProfileApplyResult struct {
	ProfileName       string
	Network           string
	Address           string
	ConfiguredTTL     int
	ActualTTL         int
	ConfiguredDF      bool
	ActualDF          bool
	ConfiguredWindow  int
	ActualRcvBuf      int
	ConfiguredMSS     int
	ConfiguredWS      int
	TCPOptionsOrder   string
	TargetJA4T        string
	AppliedSocketOpts []string
}

// NormalizeNetworkProfile normalizes and validates a user-configured network-profile value.
// Empty, "off", "none", "default", "disabled", or "false" disable the feature (opt-in off).
func NormalizeNetworkProfile(raw string) (string, error) {
	cleaned := strings.ToLower(strings.TrimSpace(raw))
	switch cleaned {
	case "", "off", "none", "default", "disabled", "false":
		return NetworkProfileOff, nil
	case "windows", "windows10", "windows11", "win10", "win11", "windows10-v1":
		return NetworkProfileWindows, nil
	default:
		return "", fmt.Errorf("invalid network-profile %q (supported values: windows, off, none, default)", raw)
	}
}

// ResolveNetworkProfile resolves the effective NetworkProfileSpec given an optional per-proxy override.
// Returns (spec, true) when an active profile is enabled, or (zero, false) when disabled.
func ResolveNetworkProfile(override string) (NetworkProfileSpec, bool) {
	profile := strings.TrimSpace(override)
	if profile == "" {
		profile = DefaultNetworkProfile.Load()
	}
	norm, err := NormalizeNetworkProfile(profile)
	if err != nil || norm == NetworkProfileOff {
		return NetworkProfileSpec{}, false
	}
	switch norm {
	case NetworkProfileWindows:
		return WindowsNetworkProfileSpec, true
	default:
		return NetworkProfileSpec{}, false
	}
}

func recordAppliedNetworkProfile(res NetworkProfileApplyResult) {
	LastAppliedProfileResult.Store(res)
	count := AppliedProfileConnCount.Add(1)
	if _, loaded := loggedFirstApply.LoadOrStore(res.ProfileName+":"+res.Network, true); !loaded {
		log.Infoln(
			"[NetworkProfile] Active socket intervention (#%d) profile=%s net=%s dst=%s | configured(TTL=%d, DF=%v, Win=%d, WS=%d, MSS=%d, Options=%s, JA4T=%s) | socket_applied(TTL=%d, DF=%v, SO_RCVBUF=%d, opts=%v)",
			count,
			res.ProfileName,
			res.Network,
			res.Address,
			res.ConfiguredTTL,
			res.ConfiguredDF,
			res.ConfiguredWindow,
			res.ConfiguredWS,
			res.ConfiguredMSS,
			res.TCPOptionsOrder,
			res.TargetJA4T,
			res.ActualTTL,
			res.ActualDF,
			res.ActualRcvBuf,
			res.AppliedSocketOpts,
		)
		return
	}
	log.Debugln(
		"[NetworkProfile] Applied (#%d) profile=%s net=%s dst=%s | socket_applied(TTL=%d, DF=%v, SO_RCVBUF=%d, opts=%v)",
		count,
		res.ProfileName,
		res.Network,
		res.Address,
		res.ActualTTL,
		res.ActualDF,
		res.ActualRcvBuf,
		res.AppliedSocketOpts,
	)
}
