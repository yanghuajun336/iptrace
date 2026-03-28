package output

import (
	"strings"
	"testing"

	"iptrace/pkg/model"
)

func TestRenderBriefPacket_ShowsVerdictRule(t *testing.T) {
	text := RenderBriefPacket([]model.TraceStep{{
		Table:      "filter",
		Chain:      "INPUT",
		RuleNumber: 86,
		Action:     "DROP",
		RawRule:    "-A INPUT -p tcp -m tcp --dport 80 -j DROP",
	}})

	checks := []string{
		"DROP",
		"filter/INPUT",
		"rule#86",
		"|__ -A INPUT -p tcp -m tcp --dport 80 -j DROP",
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Fatalf("brief output missing %q\nGot:\n%s", want, text)
		}
	}
}

func TestRenderVerbosePacket_GroupsSameChain(t *testing.T) {
	text := RenderVerbosePacket([]model.TraceStep{
		{HookPoint: "PREROUTING", Table: "raw", Chain: "PREROUTING", RuleNumber: 11, Action: "CONTINUE", RawRule: "-A PREROUTING -p tcp --dport 80 -j MARK"},
		{HookPoint: "PREROUTING", Table: "raw", Chain: "PREROUTING", RuleNumber: 12, Action: "CONTINUE", RawRule: "-A PREROUTING -s 10.0.0.0/8 -j ACCEPT"},
		{HookPoint: "INPUT", Table: "filter", Chain: "INPUT", RuleNumber: 86, Action: "DROP", RawRule: "-A INPUT -p tcp -m tcp --dport 80 -j DROP"},
	}, 1, 0x1a2b3c4d)

	if strings.Count(text, "raw/PREROUTING") != 1 {
		t.Fatalf("expected PREROUTING chain header once, got:\n%s", text)
	}
	checks := []string{
		"|__ rule#11     CONTINUE",
		"|__ rule#12     CONTINUE",
		"|__ rule#86     DROP",
		"-A INPUT -p tcp -m tcp --dport 80 -j DROP",
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Fatalf("verbose output missing %q\nGot:\n%s", want, text)
		}
	}
}