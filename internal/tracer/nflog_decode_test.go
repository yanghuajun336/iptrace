package tracer

import (
	"encoding/binary"
	"testing"
)

func TestDecodeMockEvent(t *testing.T) {
	line := "hook=PREROUTING table=raw chain=PREROUTING rule=1 action=CONTINUE"
	step, err := DecodeMockEvent(line)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if step.HookPoint != "PREROUTING" || step.Table != "raw" || step.RuleNumber != 1 {
		t.Fatalf("unexpected step: %+v", step)
	}
}

func TestDecodeNFLOGPrefix_Rule(t *testing.T) {
	step, err := DecodeNFLOGPrefix("TRACE: filter:INPUT:rule:3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if step.Table != "filter" {
		t.Errorf("table: got %q want %q", step.Table, "filter")
	}
	if step.Chain != "INPUT" {
		t.Errorf("chain: got %q want %q", step.Chain, "INPUT")
	}
	if step.RuleNumber != 3 {
		t.Errorf("rule number: got %d want 3", step.RuleNumber)
	}
	if !step.Matched {
		t.Error("expected Matched=true for trace type 'rule'")
	}
	if step.Action != "CONTINUE" {
		t.Errorf("action: got %q want CONTINUE", step.Action)
	}
}

func TestDecodeNFLOGPrefix_Policy(t *testing.T) {
	step, err := DecodeNFLOGPrefix("TRACE: filter:INPUT:policy:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if step.Action != "POLICY" {
		t.Errorf("action: got %q want POLICY", step.Action)
	}
	if step.Matched {
		t.Error("expected Matched=false for trace type 'policy'")
	}
}

func TestDecodeNFLOGPrefix_Return(t *testing.T) {
	step, err := DecodeNFLOGPrefix("TRACE: filter:MY_CHAIN:return:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if step.Action != "RETURN" {
		t.Errorf("action: got %q want RETURN", step.Action)
	}
}

func TestDecodeNFLOGPrefix_NullTerminated(t *testing.T) {
	// NFLOG prefix strings are null-terminated in the kernel
	_, err := DecodeNFLOGPrefix("TRACE: raw:PREROUTING:rule:1\x00")
	if err != nil {
		t.Fatalf("should handle null-terminated prefix: %v", err)
	}
}

func TestDecodeNFLOGPrefix_InvalidFormat(t *testing.T) {
	cases := []string{
		"",
		"NOT A TRACE PREFIX",
		"TRACE: notenoughcolons",
	}
	for _, c := range cases {
		if _, err := DecodeNFLOGPrefix(c); err == nil {
			t.Errorf("expected error for input %q", c)
		}
	}
}

func TestDecodeNFLOGPacket_ExtractsPrefix(t *testing.T) {
	prefix := "TRACE: mangle:PREROUTING:rule:2"

	// Build a minimal fake NFLOG payload:
	//   4 bytes nfgenmsg (family=AF_INET, version=0, res_id=0)
	//   nla for NFULA_PREFIX (type=10)
	nfgen := []byte{0x02, 0x00, 0x00, 0x00} // AF_INET=2
	nlaData := []byte(prefix)
	nlaLen := uint16(4 + len(nlaData))
	aligned := (nlaLen + 3) &^ 3
	nla := make([]byte, aligned)
	binary.LittleEndian.PutUint16(nla[0:2], nlaLen)
	binary.LittleEndian.PutUint16(nla[2:4], nfulaPrefix) // type=10
	copy(nla[4:], nlaData)

	payload := append(nfgen, nla...)

	step, err := DecodeNFLOGPacket(payload)
	if err != nil {
		t.Fatalf("DecodeNFLOGPacket failed: %v", err)
	}
	if step.Table != "mangle" || step.Chain != "PREROUTING" || step.RuleNumber != 2 {
		t.Errorf("unexpected step: %+v", step)
	}
}

