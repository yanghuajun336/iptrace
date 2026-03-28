package tracer

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildIPv4Header constructs a minimal 20-byte IPv4 header for testing.
// Only protocol, src, and dst fields are populated (checksum etc. left zero).
func buildIPv4Header(proto byte, src, dst net.IP) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45          // version=4, IHL=5
	hdr[9] = proto         // protocol
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	return hdr
}

// buildPortHeader constructs a 4-byte TCP/UDP port header (src, dst).
func buildPortHeader(src, dst uint16) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], src)
	binary.BigEndian.PutUint16(hdr[2:4], dst)
	return hdr
}

// buildAttr encodes a single netlink TLV attribute (little-endian len/type).
func buildAttr(attrType uint16, value []byte) []byte {
	nlaLen := 4 + len(value)
	b := make([]byte, (nlaLen+3)&^3)
	binary.LittleEndian.PutUint16(b[0:2], uint16(nlaLen))
	binary.LittleEndian.PutUint16(b[2:4], attrType)
	copy(b[4:], value)
	return b
}

func joinAttrs(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestNftParsePacketHeaders_TCP(t *testing.T) {
	src := net.ParseIP("43.139.105.42")
	dst := net.ParseIP("10.4.0.4")
	ipHdr := buildIPv4Header(6, src, dst)        // proto=6 (TCP)
	tHdr := buildPortHeader(55000, 80)

	attrs := joinAttrs(
		buildAttr(nftaTraceNetworkHeader, ipHdr),
		buildAttr(nftaTraceTransportHeader, tHdr),
	)

	gotSrc, gotDst, gotProto, gotSrcPort, gotDstPort := nftParsePacketHeaders(attrs)

	if gotSrc != "43.139.105.42" {
		t.Errorf("srcIP = %q; want 43.139.105.42", gotSrc)
	}
	if gotDst != "10.4.0.4" {
		t.Errorf("dstIP = %q; want 10.4.0.4", gotDst)
	}
	if gotProto != "tcp" {
		t.Errorf("proto = %q; want tcp", gotProto)
	}
	if gotSrcPort != 55000 {
		t.Errorf("srcPort = %d; want 55000", gotSrcPort)
	}
	if gotDstPort != 80 {
		t.Errorf("dstPort = %d; want 80", gotDstPort)
	}
}

func TestNftParsePacketHeaders_UDP(t *testing.T) {
	src := net.ParseIP("192.168.1.100")
	dst := net.ParseIP("8.8.8.8")
	ipHdr := buildIPv4Header(17, src, dst)       // proto=17 (UDP)
	tHdr := buildPortHeader(12345, 53)

	attrs := joinAttrs(
		buildAttr(nftaTraceNetworkHeader, ipHdr),
		buildAttr(nftaTraceTransportHeader, tHdr),
	)

	gotSrc, gotDst, gotProto, gotSrcPort, gotDstPort := nftParsePacketHeaders(attrs)

	if gotProto != "udp" {
		t.Errorf("proto = %q; want udp", gotProto)
	}
	if gotSrc != "192.168.1.100" {
		t.Errorf("srcIP = %q; want 192.168.1.100", gotSrc)
	}
	if gotDst != "8.8.8.8" {
		t.Errorf("dstIP = %q; want 8.8.8.8", gotDst)
	}
	if gotSrcPort != 12345 {
		t.Errorf("srcPort = %d; want 12345", gotSrcPort)
	}
	if gotDstPort != 53 {
		t.Errorf("dstPort = %d; want 53", gotDstPort)
	}
}

func TestNftParsePacketHeaders_ICMP_NoPort(t *testing.T) {
	src := net.ParseIP("1.2.3.4")
	dst := net.ParseIP("5.6.7.8")
	ipHdr := buildIPv4Header(1, src, dst) // proto=1 (ICMP)

	attrs := buildAttr(nftaTraceNetworkHeader, ipHdr)
	// No transport header for ICMP.

	_, _, gotProto, gotSrcPort, gotDstPort := nftParsePacketHeaders(attrs)

	if gotProto != "icmp" {
		t.Errorf("proto = %q; want icmp", gotProto)
	}
	if gotSrcPort != 0 || gotDstPort != 0 {
		t.Errorf("ICMP ports should be 0; got %d/%d", gotSrcPort, gotDstPort)
	}
}

func TestNftParsePacketHeaders_TooShort(t *testing.T) {
	// Header shorter than 20 bytes → all fields empty/zero.
	attrs := buildAttr(nftaTraceNetworkHeader, make([]byte, 10))
	gotSrc, gotDst, gotProto, _, _ := nftParsePacketHeaders(attrs)
	if gotSrc != "" || gotDst != "" || gotProto != "" {
		t.Errorf("short header should yield empty fields, got src=%q dst=%q proto=%q",
			gotSrc, gotDst, gotProto)
	}
}

func TestNftParsePacketHeaders_NoAttrs(t *testing.T) {
	// Completely empty attrs → no panic, all fields zero.
	gotSrc, gotDst, gotProto, gotSrcPort, gotDstPort := nftParsePacketHeaders(nil)
	if gotSrc != "" || gotDst != "" || gotProto != "" || gotSrcPort != 0 || gotDstPort != 0 {
		t.Error("empty attrs should yield all-zero fields without panic")
	}
}
