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
// the iptables-format rule text of the matching step (if available).
//
// Drop example:
//
//	[21:51:51.143] DROP     filter/INPUT  rule#86
//	        |__ -A INPUT -p tcp -m tcp --dport 80 -j DROP
//
// Accept example:
//
//	[21:51:51.143] ACCEPT
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
				line += fmt.Sprintf("        |__ %s\n", s.RawRule)
			}
			return line
		}
	}

	// No DROP/REJECT – packet was accepted.
	return fmt.Sprintf("[%s] ACCEPT\n", ts)
}

// RenderVerbosePacket emits a multi-line block showing every traversal step,
// with a plain-text rule annotation for every matched step.
//
// Example:
//
//	─── Packet #1  id=0x1a2b3c4d  43.139.105.42:55000 → 10.4.0.4:80 tcp
//	PREROUTING        raw/PREROUTING              rule#107   CONTINUE
//	  |__ -A PREROUTING -j TRACE
//	INPUT             filter/INPUT                rule#85    DROP
//	  |__ -A INPUT -p tcp -m tcp --dport 80 -j DROP
func RenderVerbosePacket(steps []model.TraceStep, pktNum int, traceID uint32) string {
	var b strings.Builder

	// Header: ID + 5-tuple
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
	fmt.Fprintf(&b, "─── Packet #%d%s%s\n", pktNum, idStr, tupleStr)

	// Group by chain in first-seen order to avoid repeating the same chain name.
	type chainGroup struct {
		hookPoint string
		tableChain string
		steps []model.TraceStep
	}
	groups := make([]chainGroup, 0, len(steps))
	indexByKey := make(map[string]int)
	for _, s := range steps {
		key := s.HookPoint + "|" + s.Table + "/" + s.Chain
		idx, ok := indexByKey[key]
		if !ok {
			groups = append(groups, chainGroup{
				hookPoint: s.HookPoint,
				tableChain: fmt.Sprintf("%s/%s", s.Table, s.Chain),
				steps: []model.TraceStep{s},
			})
			indexByKey[key] = len(groups) - 1
			continue
		}
		groups[idx].steps = append(groups[idx].steps, s)
	}

	for _, group := range groups {
		fmt.Fprintf(&b, "%-18s  %s\n", group.hookPoint, group.tableChain)
		for _, s := range group.steps {
			fmt.Fprintf(&b, "  |__ rule#%-6d %s\n", s.RuleNumber, s.Action)
			if s.RawRule != "" {
				fmt.Fprintf(&b, "      %s\n", s.RawRule)
			}
		}
	}

	return b.String()
}
