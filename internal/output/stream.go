package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"iptrace/pkg/model"
)

// ─── Per-step rendering (used in JSON mode and verbose path) ──────────────────

// RenderStepNDJSON encodes a single TraceStep as a newline-delimited JSON object.
func RenderStepNDJSON(step model.TraceStep) (string, error) {
	data, err := json.Marshal(step)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ─── Per-packet rendering ─────────────────────────────────────────────────────

// RenderBriefPacket emits one compact verdict line per packet, followed by
// the raw rule text of the matching step (if available).
//
// Output format (drop):   [15:04:05.000] DROP    filter/INPUT  rule#85
//                           └─ ip saddr 43.139.105.42 tcp dport 80 drop
// Output format (accept): [15:04:05.000] ACCEPT
func RenderBriefPacket(steps []model.TraceStep) string {
	if len(steps) == 0 {
		return ""
	}
	ts := time.Now().Format("15:04:05.000")

	// Prefer first DROP/REJECT as the definitive verdict.
	for _, s := range steps {
		if s.Action == "DROP" || s.Action == "REJECT" {
			line := fmt.Sprintf("[%s] %-7s  %s/%s  rule#%d\n",
				ts, s.Action, s.Table, s.Chain, s.RuleNumber)
			if s.RawRule != "" {
				line += fmt.Sprintf("  └─ %s\n", s.RawRule)
			}
			return line
		}
	}

	// No DROP/REJECT – packet was accepted.
	return fmt.Sprintf("[%s] ACCEPT\n", ts)
}

// RenderVerbosePacket emits a clearly bounded block showing every traversal step.
//
// Example:
//
//	══ Packet #1  id=0x1a2b3c4d  43.139.105.42:55000 → 10.4.0.4:80 tcp ══════
//	  PREROUTING   raw/PREROUTING         rule#107   CONTINUE
//	▶ INPUT        filter/INPUT           rule#85    DROP
//	      └─ ip saddr 43.139.105.42 tcp dport 80 drop
//	────────────────────────────────────────────────────────────────────────────
func RenderVerbosePacket(steps []model.TraceStep, pktNum int, traceID uint32) string {
	const width = 76
	var b strings.Builder

	// Build header: ID + 5-tuple from the first step that carries packet info.
	idStr := ""
	if traceID != 0 {
		idStr = fmt.Sprintf("  id=0x%08x", traceID)
	}
	tupleStr := ""
	for _, s := range steps {
		if s.PktSrcIP != "" && s.PktDstIP != "" {
			if s.PktProto == "tcp" || s.PktProto == "udp" {
				tupleStr = fmt.Sprintf("  %s:%d → %s:%d %s",
					s.PktSrcIP, s.PktSrcPort, s.PktDstIP, s.PktDstPort, s.PktProto)
			} else if s.PktProto != "" {
				tupleStr = fmt.Sprintf("  %s → %s  %s", s.PktSrcIP, s.PktDstIP, s.PktProto)
			} else {
				tupleStr = fmt.Sprintf("  %s → %s", s.PktSrcIP, s.PktDstIP)
			}
			break
		}
	}
	title := fmt.Sprintf("══ Packet #%d%s%s ", pktNum, idStr, tupleStr)
	padding := width - len(title)
	if padding < 4 {
		padding = 4
	}
	fmt.Fprintf(&b, "%s%s\n", title, strings.Repeat("═", padding))

	// Steps
	for _, s := range steps {
		marker := "  "
		if s.Action == "DROP" || s.Action == "REJECT" {
			marker = "▶ "
		}
		tableChain := fmt.Sprintf("%s/%s", s.Table, s.Chain)
		fmt.Fprintf(&b, "%s%-16s  %-30s  rule#%-6d %s\n",
			marker, s.HookPoint, tableChain, s.RuleNumber, s.Action)
		if s.RawRule != "" {
			fmt.Fprintf(&b, "      └─ %s\n", s.RawRule)
		}
	}

	// Footer
	fmt.Fprintln(&b, strings.Repeat("─", width))
	return b.String()
}
