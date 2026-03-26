package tracer

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"iptrace/pkg/model"
)

// DecodeNFLOGPrefix parses a xt_TRACE NFLOG prefix string into a TraceStep.
//
// The kernel emits the prefix in the format:
//
//	"TRACE: <table>:<chain>:<type>:<rulenum>"
//
// Where <type> is one of "rule", "policy", or "return".
// Example: "TRACE: filter:INPUT:rule:1"
func DecodeNFLOGPrefix(prefix string) (model.TraceStep, error) {
	// Strip null terminator if present (NFLOG strings are null-terminated)
	prefix = strings.TrimRight(prefix, "\x00")
	prefix = strings.TrimSpace(prefix)

	const traceMarker = "TRACE: "
	if !strings.HasPrefix(prefix, traceMarker) {
		return model.TraceStep{}, fmt.Errorf("not a TRACE prefix: %q", prefix)
	}
	rest := strings.TrimPrefix(prefix, traceMarker)

	parts := strings.SplitN(rest, ":", 4)
	if len(parts) != 4 {
		return model.TraceStep{}, fmt.Errorf("invalid TRACE prefix %q: expected table:chain:type:rulenum", prefix)
	}

	table := parts[0]
	chain := parts[1]
	traceType := parts[2] // "rule", "policy", "return"
	ruleNum := 0
	if parts[3] != "" {
		n, err := strconv.Atoi(parts[3])
		if err != nil {
			return model.TraceStep{}, fmt.Errorf("invalid rule number %q in prefix: %w", parts[3], err)
		}
		ruleNum = n
	}

	// Derive action and matched flag from the trace type
	action := "CONTINUE"
	matched := false
	switch traceType {
	case "rule":
		matched = true
		action = "CONTINUE" // will be updated by caller if terminal
	case "policy":
		action = "POLICY"
	case "return":
		action = "RETURN"
	}

	return model.TraceStep{
		HookPoint:  chain, // the chain is the effective hook point for display
		Table:      table,
		Chain:      chain,
		RuleNumber: ruleNum,
		Action:     action,
		Matched:    matched,
	}, nil
}

// DecodeNFLOGPacket parses a raw NFLOG netlink attribute payload and returns a TraceStep.
// The payload begins immediately after the 4-byte nfgenmsg header.
//
// Attribute layout (netlink TLV, little-endian):
//
//	[nla_len uint16][nla_type uint16][value...][padding to 4-byte align]
//
// We look for NFULA_PREFIX (type 10) to find the xt_TRACE prefix string.
func DecodeNFLOGPacket(payload []byte) (model.TraceStep, error) {
	// Skip nfgenmsg header: family(1) + version(1) + res_id(2) = 4 bytes
	if len(payload) < 4 {
		return model.TraceStep{}, fmt.Errorf("payload too short: %d bytes", len(payload))
	}
	attrs := payload[4:]

	prefix := extractNetlinkAttr(attrs, nfulaPrefix)
	if prefix == "" {
		return model.TraceStep{}, fmt.Errorf("NFULA_PREFIX attribute not found in NFLOG message")
	}
	return DecodeNFLOGPrefix(prefix)
}

// extractNetlinkAttr walks netlink TLV attributes and returns the string value
// of the first attribute matching the given type, or "" if not found.
func extractNetlinkAttr(data []byte, wantType uint16) string {
	for len(data) >= 4 {
		nlaLen := binary.LittleEndian.Uint16(data[0:2])
		nlaType := binary.LittleEndian.Uint16(data[2:4]) & 0x1FFF // mask NLA_F_NESTED / NLA_F_NET_BYTEORDER

		if nlaLen < 4 || int(nlaLen) > len(data) {
			break // corrupt attribute
		}

		if nlaType == wantType {
			return string(data[4:nlaLen])
		}

		// Advance to next attribute (4-byte aligned)
		aligned := (uint16(nlaLen) + 3) & ^uint16(3)
		if int(aligned) > len(data) {
			break
		}
		data = data[aligned:]
	}
	return ""
}

// DecodeMockEvent parses a synthetic event string (used in test mode only).
// Format: "hook=X table=Y chain=Z rule=N action=A"
func DecodeMockEvent(line string) (model.TraceStep, error) {
	fields := strings.Fields(line)
	kv := map[string]string{}
	for _, f := range fields {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			continue
		}
		kv[parts[0]] = parts[1]
	}

	ruleNum := 0
	if kv["rule"] != "" {
		n, err := strconv.Atoi(kv["rule"])
		if err != nil {
			return model.TraceStep{}, fmt.Errorf("invalid rule number: %w", err)
		}
		ruleNum = n
	}

	return model.TraceStep{
		HookPoint:  kv["hook"],
		Table:      kv["table"],
		Chain:      kv["chain"],
		RuleNumber: ruleNum,
		Action:     kv["action"],
	}, nil
}
