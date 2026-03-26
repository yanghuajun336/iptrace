package tracer

// nfttrace.go implements a NETLINK_NETFILTER socket listener for NFT_MSG_TRACE
// events.  This is the correct trace mechanism for iptables-nft (nf_tables)
// systems: when a TRACE rule fires, the kernel emits NFT_MSG_TRACE messages
// via the NFNLGRP_NFTRACE multicast group.
//
// Protocol:
//  1. socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)
//  2. bind(0, 0)
//  3. setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, NFNLGRP_NFTRACE=9)
//  4. loop: Recvfrom → ParseNetlinkMessage → filter NFT_MSG_TRACE → decode
//
// Constants verified against /usr/include/linux/netfilter/nfnetlink.h:
//   NFNL_SUBSYS_NFTABLES = 10  (NOT 12 which is NFNL_SUBSYS_HOOK)
//   NFNLGRP_NFTRACE      = 9   (NOT 1 which is NFNLGRP_CONNTRACK_NEW)

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
	"iptrace/pkg/model"
)

// NFT subsystem / message-type constants
// Source of truth: /usr/include/linux/netfilter/nfnetlink.h
const (
	nfnlSubsysNFTables = 10 // NFNL_SUBSYS_NFTABLES (verified: NOT 12 which is NFNL_SUBSYS_HOOK)
	nftMsgTrace        = 17 // NFT_MSG_TRACE
	nfnlgrpNFTrace     = 9  // NFNLGRP_NFTRACE – multicast group for trace events (NOT 1=CONNTRACK_NEW, NOT 7=NFNLGRP_NFTABLES)

	// NFT trace types (enum nft_trace_types)
	nftTracetypePolicy = 1 // NFT_TRACETYPE_POLICY – chain default policy applied
	nftTracetypeReturn = 2 // NFT_TRACETYPE_RETURN – returned from sub-chain
	nftTracetypeRule   = 3 // NFT_TRACETYPE_RULE   – matched a rule

	// NFTA_TRACE attribute types (enum nft_trace_attributes)
	nftaTraceTable           = 1  // string
	nftaTraceChain           = 2  // string
	nftaTraceRuleHandle      = 3  // BE64
	nftaTraceType            = 4  // BE32
	nftaTraceVerdict         = 5  // nested attrs
	nftaTraceID              = 6  // BE32 (unique per packet)
	nftaTraceNetworkHeader   = 8  // raw bytes (IP header)
	nftaTraceTransportHeader = 9  // raw bytes (TCP/UDP header)
	nftaTraceNFProto         = 15 // BE32 (address family)
	nftaTracePolicy          = 16 // BE32 (default policy code)

	// NFTA_VERDICT attribute types (nested inside NFTA_TRACE_VERDICT)
	nftaVerdictCode  = 1 // BE32 (int32 verdict code)
	nftaVerdictChain = 2 // string (jump target chain)
)

// nftTraceListener holds an open NETLINK_NETFILTER socket subscribed to
// NFNLGRP_NFTABLES.
type nftTraceListener struct {
	fd int
}

// openNFTTraceSocket creates and configures the NFT trace socket.
func openNFTTraceSocket() (*nftTraceListener, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("create NETLINK_NETFILTER socket: %w", err)
	}

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind netlink socket: %w", err)
	}

	// Subscribe to NFNLGRP_NFTRACE (group 9) multicast group to receive
	// NFT_MSG_TRACE events.  Note: NFNLGRP_NFTABLES (group 7) carries table/chain
	// change notifications, NOT trace events.  NFNLGRP_NFTRACE is the correct group.
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, nfnlgrpNFTrace); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("join NFNLGRP_NFTRACE: %w", err)
	}

	return &nftTraceListener{fd: fd}, nil
}

// Close releases the socket.
func (n *nftTraceListener) Close() error {
	return unix.Close(n.fd)
}

// ReadEvents receives NFT_MSG_TRACE messages and sends decoded TraceStep values
// to out.  Returns when ctx is cancelled or a fatal socket error occurs.
// The caller is responsible for closing out.
func (n *nftTraceListener) ReadEvents(ctx context.Context, out chan<- model.TraceStep) {
	tv := unix.Timeval{Sec: 0, Usec: 200_000}
	_ = unix.SetsockoptTimeval(n.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		nr, _, err := unix.Recvfrom(n.fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			return
		}

		msgs, err := syscall.ParseNetlinkMessage(buf[:nr])
		if err != nil {
			continue
		}

		for _, msg := range msgs {
			if msg.Header.Type != uint16(nfnlSubsysNFTables<<8|nftMsgTrace) {
				continue
			}
			step, err := decodeNFTTraceMsg(msg.Data)
			if err != nil {
				continue
			}
			select {
			case out <- step:
			case <-ctx.Done():
				return
			}
		}
	}
}

// decodeNFTTraceMsg parses a raw NFT_MSG_TRACE payload into a TraceStep.
// Layout: 4-byte nfgenmsg header, then netlink TLV attributes.
func decodeNFTTraceMsg(data []byte) (model.TraceStep, error) {
	if len(data) < 4 {
		return model.TraceStep{}, fmt.Errorf("nft trace msg too short: %d bytes", len(data))
	}
	attrs := data[4:] // skip nfgenmsg header

	table := nftAttrString(attrs, nftaTraceTable)
	chain := nftAttrString(attrs, nftaTraceChain)
	traceType := nftAttrU32(attrs, nftaTraceType)
	ruleHandle := nftAttrU64(attrs, nftaTraceRuleHandle)
	traceID := nftAttrU32(attrs, nftaTraceID)

	action := nftResolveAction(attrs, traceType)
	matched := traceType == nftTracetypeRule

	// Parse 5-tuple from network/transport header attrs.
	srcIP, dstIP, proto, srcPort, dstPort := nftParsePacketHeaders(attrs)

	return model.TraceStep{
		TraceID:    traceID,
		PktSrcIP:   srcIP,
		PktDstIP:   dstIP,
		PktProto:   proto,
		PktSrcPort: srcPort,
		PktDstPort: dstPort,
		HookPoint:  chain,
		Table:      table,
		Chain:      chain,
		RuleNumber: int(ruleHandle),
		Action:     action,
		Matched:    matched,
	}, nil
}

// nftParsePacketHeaders extracts the 5-tuple from NFTA_TRACE_NETWORK_HEADER
// (IPv4 header) and NFTA_TRACE_TRANSPORT_HEADER (TCP/UDP header).
// Returns empty strings/zeros on any parse failure.
func nftParsePacketHeaders(attrs []byte) (srcIP, dstIP, proto string, srcPort, dstPort uint16) {
	ipHdr := nftAttrRaw(attrs, nftaTraceNetworkHeader)
	if len(ipHdr) < 20 {
		return
	}

	// IPv4 header layout (RFC 791):
	//   byte  9 : protocol
	//   bytes 12-15 : src addr
	//   bytes 16-19 : dst addr
	protoNum := ipHdr[9]
	srcIP = net.IP(ipHdr[12:16]).String()
	dstIP = net.IP(ipHdr[16:20]).String()

	switch protoNum {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 1:
		proto = "icmp"
	default:
		proto = fmt.Sprintf("proto%d", protoNum)
	}

	// TCP/UDP share the same port layout at the start of their headers:
	//   bytes 0-1 : source port (big-endian)
	//   bytes 2-3 : destination port (big-endian)
	if protoNum == 6 || protoNum == 17 {
		tHdr := nftAttrRaw(attrs, nftaTraceTransportHeader)
		if len(tHdr) >= 4 {
			srcPort = binary.BigEndian.Uint16(tHdr[0:2])
			dstPort = binary.BigEndian.Uint16(tHdr[2:4])
		}
	}
	return
}

// nftResolveAction determines the action string from trace type and verdict attributes.
func nftResolveAction(attrs []byte, traceType uint32) string {
	switch traceType {
	case nftTracetypePolicy:
		// Try nested verdict first, then the flat POLICY attribute
		if va := nftAttrNested(attrs, nftaTraceVerdict); va != nil {
			return nftVerdictString(va)
		}
		policy := nftAttrU32(attrs, nftaTracePolicy)
		if policy == 0 {
			return "DROP"
		}
		return "ACCEPT"
	case nftTracetypeReturn:
		return "RETURN"
	case nftTracetypeRule:
		if va := nftAttrNested(attrs, nftaTraceVerdict); va != nil {
			return nftVerdictString(va)
		}
		return "CONTINUE"
	}
	return "UNKNOWN"
}

// nftVerdictString converts a nested verdict attribute set to a human string.
func nftVerdictString(attrs []byte) string {
	code := int32(nftAttrU32(attrs, nftaVerdictCode))
	chain := nftAttrString(attrs, nftaVerdictChain)
	switch code {
	case 0:  // NF_DROP
		return "DROP"
	case 1:  // NF_ACCEPT
		return "ACCEPT"
	case -1: // NFT_CONTINUE
		return "CONTINUE"
	case -3: // NFT_JUMP
		if chain != "" {
			return "JUMP:" + chain
		}
		return "JUMP"
	case -4: // NFT_GOTO
		if chain != "" {
			return "GOTO:" + chain
		}
		return "GOTO"
	case -5: // NFT_RETURN
		return "RETURN"
	default:
		return fmt.Sprintf("VERDICT(%d)", code)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Netlink attribute helpers (big-endian values, as used by nf_tables)
// ──────────────────────────────────────────────────────────────────────────────

func nftAttrString(data []byte, wantType uint16) string {
	val := nftAttrRaw(data, wantType)
	if val == nil {
		return ""
	}
	s := string(val)
	if len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}

func nftAttrU32(data []byte, wantType uint16) uint32 {
	val := nftAttrRaw(data, wantType)
	if len(val) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(val)
}

func nftAttrU64(data []byte, wantType uint16) uint64 {
	val := nftAttrRaw(data, wantType)
	if len(val) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(val)
}

// nftAttrNested returns the raw payload of a nested attribute, stripping the
// NLA_F_NESTED bit (0x8000) when looking for the type.
func nftAttrNested(data []byte, wantType uint16) []byte {
	return nftAttrRaw(data, wantType)
}

// nftAttrRaw walks netlink TLV attributes and returns the value bytes for the
// first attribute matching wantType (ignoring NLA_F_NESTED / NLA_F_NET_BYTEORDER).
func nftAttrRaw(data []byte, wantType uint16) []byte {
	for len(data) >= 4 {
		nlaLen := binary.LittleEndian.Uint16(data[0:2])
		nlaType := binary.LittleEndian.Uint16(data[2:4]) & 0x1FFF // strip flag bits

		if nlaLen < 4 || int(nlaLen) > len(data) {
			break
		}

		if nlaType == wantType {
			return data[4:nlaLen]
		}

		aligned := (nlaLen + 3) &^ 3
		if int(aligned) > len(data) {
			break
		}
		data = data[aligned:]
	}
	return nil
}
