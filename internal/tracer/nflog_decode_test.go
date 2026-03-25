package tracer

import "testing"

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
