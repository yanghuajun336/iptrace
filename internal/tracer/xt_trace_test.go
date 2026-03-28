package tracer

import (
	"testing"

	"iptrace/pkg/model"
)

func TestFilterDisplaySteps_FiltersInjectedTraceRule(t *testing.T) {
	filter := TraceFilter{SrcIP: "43.139.105.42/32", Protocol: "tcp", DstPort: 80}
	steps := []model.TraceStep{
		{Table: "raw", Chain: "PREROUTING", RuleNumber: 1, Action: "CONTINUE", RawRule: "-A PREROUTING -s 43.139.105.42/32 -p tcp --dport 80 -j TRACE"},
		{Table: "filter", Chain: "INPUT", RuleNumber: 86, Action: "DROP", RawRule: "-A INPUT -p tcp -m tcp --dport 80 -j DROP"},
	}

	got := FilterDisplaySteps(steps, filter)
	if len(got) != 1 {
		t.Fatalf("expected 1 visible step, got %d", len(got))
	}
	if got[0].Chain != "INPUT" {
		t.Fatalf("expected INPUT step to remain, got %+v", got[0])
	}
}

func TestFilterDisplaySteps_LeavesUserTraceRuleUntouched(t *testing.T) {
	filter := TraceFilter{SrcIP: "43.139.105.42/32", Protocol: "tcp", DstPort: 80}
	steps := []model.TraceStep{{
		Table: "raw", Chain: "PREROUTING", RuleNumber: 9, Action: "CONTINUE",
		RawRule: "-A PREROUTING -s 43.139.105.42/32 -p tcp --dport 80 -j TRACE --trace-note user",
	}}

	got := FilterDisplaySteps(steps, filter)
	if len(got) != 1 {
		t.Fatalf("expected custom TRACE-like rule to remain visible, got %d steps", len(got))
	}
}