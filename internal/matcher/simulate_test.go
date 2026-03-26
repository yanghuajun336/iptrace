package matcher

import (
	"fmt"
	"testing"

	"iptrace/pkg/model"
)

func TestSimulate_DropRuleMatched(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP", Target: "DROP"},
						},
					},
				},
			},
		},
	}

	packet := model.Packet{
		Protocol: "tcp",
		SrcIP:    "1.2.3.4",
		DstIP:    "10.0.0.1",
		SrcPort:  12345,
		DstPort:  8080,
	}

	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if result.Verdict != "DROP" {
		t.Fatalf("expect DROP, got %s", result.Verdict)
	}
	if result.VerdictRule == nil || result.VerdictRule.RuleNumber != 1 {
		t.Fatalf("expect verdict from rule #1")
	}
}

func TestSimulate_NonTerminalRuleRecordedOnce(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j LOG", Target: "LOG"},
						},
					},
				},
			},
		},
	}

	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 12345, DstPort: 8080}

	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if len(result.Steps) != 1 {
		t.Fatalf("expect one recorded step, got %d", len(result.Steps))
	}
	if result.Steps[0].Action != "LOG" {
		t.Fatalf("expect matched LOG action, got %s", result.Steps[0].Action)
	}
	if result.Verdict != "ACCEPT" {
		t.Fatalf("expect default policy ACCEPT, got %s", result.Verdict)
	}
}

// TestSimulate_MultiTable verifies traversal across raw→filter tables.
func TestSimulate_MultiTable(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "raw",
				Chains: []model.Chain{
					{Name: "PREROUTING", DefaultPolicy: "ACCEPT", Rules: []model.Rule{}},
				},
			},
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A INPUT -s 9.9.9.9 -j DROP", Target: "DROP"},
							{Number: 2, RawText: "-A INPUT -s 1.2.3.4 -j REJECT", Target: "REJECT"},
						},
					},
				},
			},
		},
	}

	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80}

	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if result.Verdict != "REJECT" {
		t.Fatalf("expect REJECT, got %s", result.Verdict)
	}
}

// TestSimulate_JumpToCustomChain verifies JUMP/RETURN recursion.
func TestSimulate_JumpToCustomChain(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A INPUT -j MY_CHAIN", Target: "MY_CHAIN"},
						},
					},
					{
						Name: "MY_CHAIN",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A MY_CHAIN -s 5.5.5.5 -j DROP", Target: "DROP"},
							{Number: 2, RawText: "-A MY_CHAIN -s 1.2.3.4 -j ACCEPT", Target: "ACCEPT"},
						},
					},
				},
			},
		},
	}

	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80}

	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if result.Verdict != "ACCEPT" {
		t.Fatalf("expect ACCEPT from custom chain, got %s", result.Verdict)
	}
}

// TestSimulate_ReturnFromCustomChain verifies RETURN falls back to parent chain.
func TestSimulate_ReturnFromCustomChain(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "DROP", // default policy should apply after RETURN
						Rules: []model.Rule{
							{Number: 1, RawText: "-A INPUT -j SUB", Target: "SUB"},
						},
					},
					{
						Name: "SUB",
						Rules: []model.Rule{
							// RETURN immediately without matching
							{Number: 1, RawText: "-A SUB -s 9.9.9.9 -j RETURN", Target: "RETURN"},
						},
					},
				},
			},
		},
	}

	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80}

	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	// SUB doesn't match 1.2.3.4, returns to INPUT, INPUT has no more rules → default DROP
	if result.Verdict != "DROP" {
		t.Fatalf("expect DROP from default policy after RETURN, got %s", result.Verdict)
	}
}

// TestSimulate_CIDRMatch verifies /24 subnet matching.
func TestSimulate_CIDRMatch(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A INPUT -s 192.168.1.0/24 -j DROP", Target: "DROP"},
						},
					},
				},
			},
		},
	}

	// Packet from 192.168.1.50 should match the /24 rule
	packet := model.Packet{Protocol: "tcp", SrcIP: "192.168.1.50", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80}
	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if result.Verdict != "DROP" {
		t.Fatalf("expect DROP for 192.168.1.50 matching 192.168.1.0/24, got %s", result.Verdict)
	}

	// Packet from 192.168.2.1 should NOT match
	packet2 := model.Packet{Protocol: "tcp", SrcIP: "192.168.2.1", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80}
	result2, err := Simulate(packet2, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if result2.Verdict != "ACCEPT" {
		t.Fatalf("expect ACCEPT for 192.168.2.1 not matching 192.168.1.0/24, got %s", result2.Verdict)
	}
}

// TestSimulate_RealSnapshotFormat_WithMatchModule mirrors the exact rule format
// produced by iptables-save (including -m tcp extension module flag).
// Regression test for: -A INPUT -s X/32 -p tcp -m tcp --dport 80 -j DROP
func TestSimulate_RealSnapshotFormat_WithMatchModule(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							{
								Number:  1,
								RawText: "-A INPUT -s 43.139.105.42/32 -p tcp -m tcp --dport 80 -j DROP",
								Target:  "DROP",
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		packet  model.Packet
		verdict string
	}{
		{
			name:    "matching src+proto+dport → DROP",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "43.139.105.42", DstIP: "49.51.72.122", SrcPort: 90, DstPort: 80},
			verdict: "DROP",
		},
		{
			name:    "different src → ACCEPT (default policy)",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "49.51.72.122", SrcPort: 90, DstPort: 80},
			verdict: "ACCEPT",
		},
		{
			name:    "same src but different dport → ACCEPT",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "43.139.105.42", DstIP: "49.51.72.122", SrcPort: 90, DstPort: 443},
			verdict: "ACCEPT",
		},
		{
			name:    "same src but udp → ACCEPT",
			packet:  model.Packet{Protocol: "udp", SrcIP: "43.139.105.42", DstIP: "49.51.72.122", SrcPort: 90, DstPort: 80},
			verdict: "ACCEPT",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Simulate(tc.packet, rs)
			if err != nil {
				t.Fatalf("simulate failed: %v", err)
			}
			if result.Verdict != tc.verdict {
				t.Fatalf("expect %s, got %s", tc.verdict, result.Verdict)
			}
		})
	}
}

// TestSimulate_RealSnapshotFormat_MultiTable mirrors the full snapshot.rules structure:
// raw (PREROUTING with -d constraints) + filter (INPUT with DROP rule).
func TestSimulate_RealSnapshotFormat_MultiTable(t *testing.T) {
	// Mirrors actual snapshot.rules structure
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "raw",
				Chains: []model.Chain{
					{
						Name:          "PREROUTING",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							// -d 172.x.x.x rules should NOT match our test packet
							{Number: 1, RawText: "-A PREROUTING -d 172.18.0.2/32 -j DROP", Target: "DROP"},
							{Number: 2, RawText: "-A PREROUTING -d 172.19.0.2/32 -j DROP", Target: "DROP"},
						},
					},
					{Name: "OUTPUT", DefaultPolicy: "ACCEPT"},
				},
			},
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A INPUT -s 43.139.105.42/32 -p tcp -m tcp --dport 80 -j DROP", Target: "DROP"},
						},
					},
					{Name: "FORWARD", DefaultPolicy: "DROP"},
					{Name: "OUTPUT", DefaultPolicy: "ACCEPT"},
				},
			},
		},
	}

	tests := []struct {
		name    string
		packet  model.Packet
		verdict string
	}{
		{
			name:    "blocked src hits filter/INPUT DROP → DROP",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "43.139.105.42", DstIP: "49.51.72.122", SrcPort: 90, DstPort: 80},
			verdict: "DROP",
		},
		{
			name:    "unrelated src → ACCEPT default",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "8.8.8.8", DstIP: "49.51.72.122", SrcPort: 5000, DstPort: 80},
			verdict: "ACCEPT",
		},
		{
			name:    "packet to raw PREROUTING dst → DROP in raw",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "1.1.1.1", DstIP: "172.18.0.2", SrcPort: 1234, DstPort: 80},
			verdict: "DROP",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Simulate(tc.packet, rs)
			if err != nil {
				t.Fatalf("simulate failed: %v", err)
			}
			if result.Verdict != tc.verdict {
				t.Fatalf("[%s] expect %s, got %s", tc.name, tc.verdict, result.Verdict)
			}
		})
	}
}

// TestSimulate_RealSnapshotFormat_DockerChains mirrors snapshot.rules with
// INPUT → custom chain jumps (INPUT path only; FORWARD chains are out of scope
// for locally-destined packet simulation).
func TestSimulate_RealSnapshotFormat_DockerChains(t *testing.T) {
	rs := model.RuleSet{
		Tables: []model.Table{
			{
				Name: "filter",
				Chains: []model.Chain{
					{
						Name:          "INPUT",
						DefaultPolicy: "ACCEPT",
						Rules: []model.Rule{
							// Jump to allow-list check
							{Number: 1, RawText: "-A INPUT -j ALLOW_LIST", Target: "ALLOW_LIST"},
						},
					},
					{
						// ALLOW_LIST: drop a known bad actor, return for everyone else
						Name: "ALLOW_LIST",
						Rules: []model.Rule{
							{Number: 1, RawText: "-A ALLOW_LIST -s 5.5.5.5 -j DROP", Target: "DROP"},
							{Number: 2, RawText: "-A ALLOW_LIST -j RETURN", Target: "RETURN"},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		packet  model.Packet
		verdict string
	}{
		{
			name:    "blocked IP in custom chain → DROP",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "5.5.5.5", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80},
			verdict: "DROP",
		},
		{
			name:    "allowed IP: RETURN from custom chain → INPUT default ACCEPT",
			packet:  model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 1234, DstPort: 80},
			verdict: "ACCEPT",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Simulate(tc.packet, rs)
			if err != nil {
				t.Fatalf("simulate failed: %v", err)
			}
			if result.Verdict != tc.verdict {
				t.Fatalf("[%s] expect %s, got %s", tc.name, tc.verdict, result.Verdict)
			}
		})
	}
}

// TestSimulate_1000Rules_AllMiss verifies default policy applied after exhausting all rules.
func TestSimulate_1000Rules_AllMiss(t *testing.T) {
	rules := make([]model.Rule, 1000)
	for i := range rules {
		rules[i] = model.Rule{
			Number:  i + 1,
			RawText: fmt.Sprintf("-A INPUT -s 10.0.%d.%d -p tcp --dport 8080 -j DROP", (i/256)%256, i%256),
			Target:  "DROP",
		}
	}
	rs := model.RuleSet{
		Tables: []model.Table{{
			Name: "filter",
			Chains: []model.Chain{{
				Name:          "INPUT",
				DefaultPolicy: "ACCEPT",
				Rules:         rules,
			}},
		}},
	}

	// Packet from an IP not in any rule should hit default ACCEPT
	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 5000, DstPort: 8080}
	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if result.Verdict != "ACCEPT" {
		t.Fatalf("expect ACCEPT (default policy), got %s", result.Verdict)
	}
	if len(result.Steps) != 1000 {
		t.Fatalf("expect 1000 steps recorded, got %d", len(result.Steps))
	}
}

// TestSimulate_1000Rules_HitLast verifies that the last rule is still evaluated.
func TestSimulate_1000Rules_HitLast(t *testing.T) {
	rules := make([]model.Rule, 1000)
	for i := range rules {
		rules[i] = model.Rule{
			Number:  i + 1,
			RawText: fmt.Sprintf("-A INPUT -s 10.0.%d.%d -p tcp --dport 8080 -j DROP", (i/256)%256, i%256),
			Target:  "DROP",
		}
	}
	// Override last rule to match a specific IP
	rules[999] = model.Rule{
		Number:  1000,
		RawText: "-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP",
		Target:  "DROP",
	}
	rs := model.RuleSet{
		Tables: []model.Table{{
			Name: "filter",
			Chains: []model.Chain{{
				Name:          "INPUT",
				DefaultPolicy: "ACCEPT",
				Rules:         rules,
			}},
		}},
	}

	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 5000, DstPort: 8080}
	result, err := Simulate(packet, rs)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if result.Verdict != "DROP" {
		t.Fatalf("expect DROP from rule #1000, got %s", result.Verdict)
	}
	if result.VerdictRule == nil || result.VerdictRule.RuleNumber != 1000 {
		t.Fatalf("expect verdict from rule #1000, got %v", result.VerdictRule)
	}
}

