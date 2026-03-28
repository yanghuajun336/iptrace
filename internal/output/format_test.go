package output

import (
	"strings"
	"testing"

	"iptrace/pkg/model"
)

func TestRenderHumanAndJSON(t *testing.T) {
	result := model.TraceResult{
		Backend: "iptables-legacy",
		Packet: model.Packet{
			Protocol: "tcp",
			SrcIP:    "1.1.1.1",
			DstIP:    "2.2.2.2",
			SrcPort:  1234,
			DstPort:  80,
		},
		Verdict: "DROP",
	}

	human := RenderHuman(result)
	if !strings.Contains(human, "Verdict: DROP") {
		t.Fatalf("human output should contain verdict, got: %s", human)
	}
	// No VerdictRule set → Rule: line must NOT appear.
	if strings.Contains(human, "Rule:") {
		t.Fatalf("human output should not contain Rule: when VerdictRule is nil, got: %s", human)
	}

	jsonText, err := RenderJSON(result)
	if err != nil {
		t.Fatalf("json render failed: %v", err)
	}
	if !strings.Contains(jsonText, `"verdict":"DROP"`) {
		t.Fatalf("json output should contain verdict field, got: %s", jsonText)
	}
}

// TestRenderHuman_RuleField verifies that Rule: is emitted when VerdictRule carries a RawRule.
func TestRenderHuman_RuleField(t *testing.T) {
	verdictStep := &model.TraceStep{
		Table:      "filter",
		Chain:      "INPUT",
		RuleNumber: 86,
		Action:     "DROP",
		RawRule:    "-A INPUT -p tcp -m tcp --dport 80 -j DROP",
	}
	result := model.TraceResult{
		Backend: "iptables-nft",
		Packet: model.Packet{
			Protocol: "tcp",
			SrcIP:    "43.139.105.42",
			DstIP:    "49.51.72.122",
			SrcPort:  0,
			DstPort:  80,
		},
		Verdict:     "DROP",
		VerdictRule: verdictStep,
	}

	human := RenderHuman(result)
	expected := []string{
		"Backend: iptables-nft",
		"Packet:  tcp 43.139.105.42:0 -> 49.51.72.122:80",
		"Verdict: DROP",
		"Rule:    -A INPUT -p tcp -m tcp --dport 80 -j DROP",
	}
	for _, want := range expected {
		if !strings.Contains(human, want) {
			t.Errorf("RenderHuman missing %q\nGot:\n%s", want, human)
		}
	}
}
