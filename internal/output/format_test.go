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

	jsonText, err := RenderJSON(result)
	if err != nil {
		t.Fatalf("json render failed: %v", err)
	}
	if !strings.Contains(jsonText, `"verdict":"DROP"`) {
		t.Fatalf("json output should contain verdict field, got: %s", jsonText)
	}
}
