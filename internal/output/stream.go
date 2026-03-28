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
       // 分隔线
       fmt.Fprintf(&b, "\n%s\n", strings.Repeat("─", 72))
       fmt.Fprintf(&b, "─── Packet #%d%s%s\n", pktNum, idStr, tupleStr)

       // 1. 按链分组，只保留每组最后一个 step
       type chainKey struct {
	       hookPoint string
	       table     string
	       chain     string
       }
       lastStepByChain := make(map[chainKey]model.TraceStep)
       chainOrder := make([]chainKey, 0, len(steps))
       seen := make(map[chainKey]bool)
       for _, s := range steps {
	       key := chainKey{s.HookPoint, s.Table, s.Chain}
	       lastStepByChain[key] = s
	       if !seen[key] {
		       chainOrder = append(chainOrder, key)
		       seen[key] = true
	       }
       }

       // 2. 逐链输出：链头+verdict，链下只显示最后命中的那条（如果有 RawRule）
       for _, key := range chainOrder {
	       s := lastStepByChain[key]
	       verdict := s.Action
	       if s.Action == "JUMP" && s.JumpTarget != "" {
		       verdict = "JUMP:" + s.JumpTarget
	       }
	       fmt.Fprintf(&b, "%-18s  %s  %s\n", key.hookPoint, key.table+"/"+key.chain, verdict)
	       if s.RuleNumber > 0 {
		       fmt.Fprintf(&b, "  |__ rule#%-6d %s\n", s.RuleNumber, s.Action)
		       if s.RawRule != "" {
			       fmt.Fprintf(&b, "      %s\n", s.RawRule)
		       }
	       }
       }

       return b.String()
}
