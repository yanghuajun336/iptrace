package matcher

import (
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
