package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"iptrace/pkg/model"
)

func RenderHuman(result model.TraceResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Backend: %s\n", result.Backend)
	fmt.Fprintf(&b, "Packet:  %s %s:%d -> %s:%d\n", result.Packet.Protocol, result.Packet.SrcIP, result.Packet.SrcPort, result.Packet.DstIP, result.Packet.DstPort)
	fmt.Fprintf(&b, "Verdict: %s\n", result.Verdict)
	return b.String()
}

func RenderJSON(result model.TraceResult) (string, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
