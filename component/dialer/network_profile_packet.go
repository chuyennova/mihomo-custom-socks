package dialer

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/log"
)

const (
	ipProtoTCP = 6

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
	tcpFlagECE = 0x40
	tcpFlagCWR = 0x80

	tcpOptEnd           = 0
	tcpOptNOP           = 1
	tcpOptMSS           = 2
	tcpOptWindowScale   = 3
	tcpOptSACKPermitted = 4
	tcpOptTimestamp     = 8
)

var (
	// LastRewrittenSYNResult stores the before/after wire fingerprint of the most recently rewritten TCP SYN packet.
	LastRewrittenSYNResult = atomic.NewTypedValue[PacketRewriteResult](PacketRewriteResult{})

	// RewrittenPacketCount counts total L3/L4 packets modified by RewritePacketToWindowsProfile.
	RewrittenPacketCount = atomic.NewInt64(0)

	// RewrittenSYNCount counts total TCP SYN packets rewritten to the Windows Network Profile JA4T layout.
	RewrittenSYNCount = atomic.NewInt64(0)

	loggedFirstSYNRewrite sync.Map
)

// PacketFingerprint represents the actual wire-level L3/L4 TCP/IP characteristics extracted from a raw packet.
type PacketFingerprint struct {
	IPVersion           int    `json:"ip-version"`
	TTL                 int    `json:"ttl"`
	DontFragment        bool   `json:"dont-fragment"`
	IPID                uint16 `json:"ip-id"`
	TotalLength         int    `json:"total-length"`
	Protocol            int    `json:"protocol"`
	SrcPort             uint16 `json:"src-port"`
	DstPort             uint16 `json:"dst-port"`
	TCPFlags            uint8  `json:"tcp-flags"`
	IsSYN               bool   `json:"is-syn"`
	WindowSize          uint16 `json:"window-size"`
	MSS                 int    `json:"mss"`
	WindowScale         int    `json:"window-scale"`
	HasTimestamp        bool   `json:"has-timestamp"`
	HasSACKPermitted    bool   `json:"has-sack-permitted"`
	TCPOptionsOrder     string `json:"tcp-options-order"`
	JA4T                string `json:"ja4t"`
	HeaderChecksumValid bool   `json:"header-checksum-valid"`
	TCPChecksumValid    bool   `json:"tcp-checksum-valid"`
}

// PacketRewriteResult records the wire-level before and after state of a rewritten TCP SYN packet.
type PacketRewriteResult struct {
	ProfileName string            `json:"profile-name"`
	Before      PacketFingerprint `json:"before"`
	After       PacketFingerprint `json:"after"`
	Modified    bool              `json:"modified"`
}

// InspectPacketJA4T parses a raw IPv4 or IPv6 packet and extracts its L3/L4 fields and JA4T fingerprint.
func InspectPacketJA4T(pkt []byte) (PacketFingerprint, bool) {
	if len(pkt) < 20 {
		return PacketFingerprint{}, false
	}
	version := int(pkt[0] >> 4)
	var fp PacketFingerprint
	fp.IPVersion = version
	fp.WindowScale = -1

	var ipHdrLen int
	var totalLen int

	switch version {
	case 4:
		ipHdrLen = int(pkt[0]&0x0f) * 4
		if ipHdrLen < 20 || len(pkt) < ipHdrLen {
			return PacketFingerprint{}, false
		}
		totalLen = int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen < ipHdrLen || totalLen > len(pkt) {
			totalLen = len(pkt)
		}
		fp.TotalLength = totalLen
		fp.IPID = binary.BigEndian.Uint16(pkt[4:6])
		flagsFrag := binary.BigEndian.Uint16(pkt[6:8])
		fp.DontFragment = (flagsFrag & 0x4000) != 0
		fp.TTL = int(pkt[8])
		fp.Protocol = int(pkt[9])
		origSum := binary.BigEndian.Uint16(pkt[10:12])
		fp.HeaderChecksumValid = computeIPv4HeaderChecksum(pkt[:ipHdrLen]) == origSum
		if (flagsFrag & 0x3fff) != 0 {
			// Fragmented IPv4 packet without full L4 header at offset 0
			return fp, true
		}
	case 6:
		if len(pkt) < 40 {
			return PacketFingerprint{}, false
		}
		ipHdrLen = 40
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		totalLen = 40 + payloadLen
		if totalLen > len(pkt) {
			totalLen = len(pkt)
		}
		fp.TotalLength = totalLen
		fp.Protocol = int(pkt[6])
		fp.TTL = int(pkt[7])
		fp.HeaderChecksumValid = true
	default:
		return PacketFingerprint{}, false
	}

	if fp.Protocol != ipProtoTCP || totalLen < ipHdrLen+20 {
		return fp, true
	}

	tcp := pkt[ipHdrLen:totalLen]
	fp.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	fp.DstPort = binary.BigEndian.Uint16(tcp[2:4])
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return fp, false
	}
	fp.TCPFlags = tcp[13]
	fp.IsSYN = (fp.TCPFlags&tcpFlagSYN) != 0 && (fp.TCPFlags&tcpFlagACK) == 0
	fp.WindowSize = binary.BigEndian.Uint16(tcp[14:16])

	origTCPSum := binary.BigEndian.Uint16(tcp[16:18])
	fp.TCPChecksumValid = computeTCPChecksum(pkt[:totalLen], ipHdrLen) == origTCPSum

	opts := tcp[20:dataOff]
	var optKinds []string
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == tcpOptEnd {
			break
		}
		if kind == tcpOptNOP {
			optKinds = append(optKinds, "1")
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		optKinds = append(optKinds, strconv.Itoa(int(kind)))
		switch kind {
		case tcpOptMSS:
			if optLen == 4 {
				fp.MSS = int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
			}
		case tcpOptWindowScale:
			if optLen == 3 {
				fp.WindowScale = int(opts[i+2])
			}
		case tcpOptSACKPermitted:
			if optLen == 2 {
				fp.HasSACKPermitted = true
			}
		case tcpOptTimestamp:
			if optLen == 10 {
				fp.HasTimestamp = true
			}
		}
		i += optLen
	}

	fp.TCPOptionsOrder = strings.Join(optKinds, "-")
	wsVal := fp.WindowScale
	if wsVal < 0 {
		wsVal = 0
	}
	fp.JA4T = fmt.Sprintf("%d_%s_%d_%d", fp.WindowSize, fp.TCPOptionsOrder, fp.MSS, wsVal)
	return fp, true
}

// RewritePacketToWindowsProfile rewrites an outgoing raw IPv4 or IPv6 packet in-place to match
// the configured Windows Network Profile (TTL=128, DF=1, TCP SYN Window=64240, WS=8, Options=2-1-3-1-1-4 without Timestamp).
// buf must start at the beginning of the IP packet and have length >= pktLen (with extra tail capacity if SYN options grow).
func RewritePacketToWindowsProfile(buf []byte, pktLen int, spec NetworkProfileSpec) (newLen int, modified bool) {
	if pktLen < 20 || len(buf) < pktLen {
		return pktLen, false
	}

	version := int(buf[0] >> 4)
	var ipHdrLen int
	var totalLen int
	var proto int
	var fragmented bool

	switch version {
	case 4:
		ipHdrLen = int(buf[0]&0x0f) * 4
		if ipHdrLen < 20 || pktLen < ipHdrLen {
			return pktLen, false
		}
		totalLen = int(binary.BigEndian.Uint16(buf[2:4]))
		if totalLen < ipHdrLen || totalLen > pktLen {
			totalLen = pktLen
		}
		flagsFrag := binary.BigEndian.Uint16(buf[6:8])
		fragmented = (flagsFrag & 0x3fff) != 0
		if spec.IPv4TTL > 0 && buf[8] != uint8(spec.IPv4TTL) {
			buf[8] = uint8(spec.IPv4TTL)
			modified = true
		}
		if spec.IPDontFragment && !fragmented && (buf[6]&0x40) == 0 {
			buf[6] |= 0x40
			modified = true
		}
		proto = int(buf[9])
	case 6:
		if pktLen < 40 {
			return pktLen, false
		}
		ipHdrLen = 40
		payloadLen := int(binary.BigEndian.Uint16(buf[4:6]))
		totalLen = 40 + payloadLen
		if totalLen > pktLen {
			totalLen = pktLen
		}
		if spec.IPv6HopLimit > 0 && buf[7] != uint8(spec.IPv6HopLimit) {
			buf[7] = uint8(spec.IPv6HopLimit)
			modified = true
		}
		proto = int(buf[6])
	default:
		return pktLen, false
	}

	isFirstSYN := false
	var beforeFp PacketFingerprint
	if !fragmented && proto == ipProtoTCP && totalLen >= ipHdrLen+20 {
		tcpFlags := buf[ipHdrLen+13]
		dataOff := int(buf[ipHdrLen+12]>>4) * 4
		if dataOff >= 20 && totalLen >= ipHdrLen+dataOff {
			isFirstSYN = (tcpFlags&tcpFlagSYN) != 0 && (tcpFlags&tcpFlagACK) == 0
		}
	}

	if isFirstSYN {
		beforeFp, _ = InspectPacketJA4T(buf[:totalLen])
		tcpOff := ipHdrLen
		oldDataOff := int(buf[tcpOff+12]>>4) * 4
		payloadLen := totalLen - (tcpOff + oldDataOff)

		// Clear ECE/CWR on initial SYN to match standard Windows 10/11 SYN flags (0x02).
		buf[tcpOff+13] &^= (tcpFlagECE | tcpFlagCWR)

		// Set TCP Initial Window Size (64240 on Windows 10/11).
		targetWin := uint16(64240)
		if spec.TCPWindowSize > 0 && spec.TCPWindowSize <= 65535 {
			targetWin = uint16(spec.TCPWindowSize)
		}
		binary.BigEndian.PutUint16(buf[tcpOff+14:tcpOff+16], targetWin)

		// Determine MSS: preserve path/tunnel MSS if smaller than spec.TCPMSS, or clamp to spec.TCPMSS (1460).
		mss := beforeFp.MSS
		if mss <= 0 {
			mss = spec.TCPMSS
			if mss <= 0 {
				mss = 1460
			}
		} else if spec.TCPMSS > 0 && mss > spec.TCPMSS {
			mss = spec.TCPMSS
		}

		// Determine Window Scale (8 on Windows 10/11).
		ws := uint8(8)
		if spec.TCPWindowScale > 0 && spec.TCPWindowScale <= 14 {
			ws = uint8(spec.TCPWindowScale)
		} else if beforeFp.WindowScale >= 0 && beforeFp.WindowScale <= 14 {
			ws = uint8(beforeFp.WindowScale)
		}

		// Exact 12-byte Windows 10/11 TCP SYN Options layout: 2-1-3-1-1-4
		// [MSS(4), NOP(1), WS(3), NOP(1), NOP(1), SACK_PERM(2)]
		winOpts := [12]byte{
			tcpOptMSS, 4, byte(mss >> 8), byte(mss),
			tcpOptNOP,
			tcpOptWindowScale, 3, ws,
			tcpOptNOP, tcpOptNOP,
			tcpOptSACKPermitted, 2,
		}
		newDataOff := 20 + len(winOpts) // 32 bytes (doff = 8)
		newTotalLen := tcpOff + newDataOff + payloadLen

		if newTotalLen <= len(buf) {
			if payloadLen > 0 && newDataOff != oldDataOff {
				copy(buf[tcpOff+newDataOff:newTotalLen], buf[tcpOff+oldDataOff:totalLen])
			}
			copy(buf[tcpOff+20:tcpOff+newDataOff], winOpts[:])
			buf[tcpOff+12] = (uint8(newDataOff/4) << 4) | (buf[tcpOff+12] & 0x0f)

			if version == 4 {
				binary.BigEndian.PutUint16(buf[2:4], uint16(newTotalLen))
			} else if version == 6 {
				binary.BigEndian.PutUint16(buf[4:6], uint16(newTotalLen-ipHdrLen))
			}
			totalLen = newTotalLen
			pktLen = newTotalLen

			// Recompute TCP checksum over pseudo-header + rewritten TCP segment.
			binary.BigEndian.PutUint16(buf[tcpOff+16:tcpOff+18], 0)
			tcpSum := computeTCPChecksum(buf[:totalLen], ipHdrLen)
			binary.BigEndian.PutUint16(buf[tcpOff+16:tcpOff+18], tcpSum)
			modified = true
		}
	}

	if version == 4 && modified {
		binary.BigEndian.PutUint16(buf[10:12], 0)
		ipSum := computeIPv4HeaderChecksum(buf[:ipHdrLen])
		binary.BigEndian.PutUint16(buf[10:12], ipSum)
	}

	if modified {
		RewrittenPacketCount.Add(1)
		if isFirstSYN {
			afterFp, _ := InspectPacketJA4T(buf[:totalLen])
			res := PacketRewriteResult{
				ProfileName: spec.Name,
				Before:      beforeFp,
				After:       afterFp,
				Modified:    true,
			}
			LastRewrittenSYNResult.Store(res)
			synCount := RewrittenSYNCount.Add(1)
			if _, loaded := loggedFirstSYNRewrite.LoadOrStore(spec.Name, true); !loaded {
				log.Infoln(
					"[NetworkProfile] Active L3/L4 SYN packet rewrite (#%d) profile=%s | before(TTL=%d, DF=%v, JA4T=%s, TS=%v) -> after(TTL=%d, DF=%v, JA4T=%s, TS=%v)",
					synCount,
					spec.Name,
					beforeFp.TTL,
					beforeFp.DontFragment,
					beforeFp.JA4T,
					beforeFp.HasTimestamp,
					afterFp.TTL,
					afterFp.DontFragment,
					afterFp.JA4T,
					afterFp.HasTimestamp,
				)
			} else {
				log.Debugln(
					"[NetworkProfile] Rewrote L3/L4 SYN (#%d) profile=%s | %s -> %s (TTL=%d)",
					synCount,
					spec.Name,
					beforeFp.JA4T,
					afterFp.JA4T,
					afterFp.TTL,
				)
			}
		}
	}

	return pktLen, modified
}

func computeIPv4HeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func computeTCPChecksum(ipPkt []byte, ipHdrLen int) uint16 {
	if len(ipPkt) < ipHdrLen+20 {
		return 0
	}
	version := ipPkt[0] >> 4
	tcp := ipPkt[ipHdrLen:]
	tcpLen := len(tcp)

	var sum uint32
	switch version {
	case 4:
		for i := 12; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ipPkt[i : i+2]))
		}
		sum += uint32(ipProtoTCP)
		sum += uint32(tcpLen)
	case 6:
		for i := 8; i < 40; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ipPkt[i : i+2]))
		}
		sum += uint32(tcpLen >> 16)
		sum += uint32(tcpLen & 0xffff)
		sum += uint32(ipProtoTCP)
	default:
		return 0
	}

	for i := 0; i+1 < tcpLen; i += 2 {
		if i == 16 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if tcpLen%2 == 1 {
		sum += uint32(tcp[tcpLen-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
