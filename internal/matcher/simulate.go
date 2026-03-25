package matcher

import (
	"fmt"
	"strconv"
	"strings"

	"iptrace/pkg/model"
)

func Simulate(packet model.Packet, rs model.RuleSet) (model.TraceResult, error) {
	if err := packet.Validate(); err != nil {
		return model.TraceResult{}, err
	}

	result := model.TraceResult{
		Packet:  packet,
		Backend: rs.Backend,
		Verdict: "ACCEPT",
	}

	for _, table := range rs.Tables {
		if table.Name != "filter" {
			continue
		}
		for _, chain := range table.Chains {
			if chain.Name != "INPUT" {
				continue
			}
			for _, rule := range chain.Rules {
				matched := ruleMatchesPacket(rule.RawText, packet)
				step := model.TraceStep{
					HookPoint:  "INPUT",
					Table:      table.Name,
					Chain:      chain.Name,
					RuleNumber: rule.Number,
					RawRule:    rule.RawText,
					Matched:    matched,
					Action:     "CONTINUE",
				}
				if matched {
					step.Action = strings.ToUpper(rule.Target)
					result.Steps = append(result.Steps, step)
					if step.Action == "DROP" || step.Action == "ACCEPT" || step.Action == "REJECT" {
						result.Verdict = step.Action
						result.VerdictRule = &result.Steps[len(result.Steps)-1]
						return result, nil
					}
				}
				result.Steps = append(result.Steps, step)
			}
			if chain.DefaultPolicy != "" {
				result.DefaultPolicyApplied = true
				result.Verdict = strings.ToUpper(chain.DefaultPolicy)
			}
			return result, nil
		}
	}

	return result, nil
}

func ruleMatchesPacket(raw string, packet model.Packet) bool {
	parts := strings.Fields(raw)
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "-s":
			if i+1 < len(parts) && parts[i+1] != packet.SrcIP {
				return false
			}
		case "-p":
			if i+1 < len(parts) && strings.ToLower(parts[i+1]) != packet.Protocol {
				return false
			}
		case "--dport":
			if i+1 < len(parts) {
				p, err := strconv.Atoi(parts[i+1])
				if err != nil || uint16(p) != packet.DstPort {
					return false
				}
			}
		}
	}
	return true
}

func ValidateRuleSet(rs model.RuleSet) error {
	if len(rs.Tables) == 0 {
		return fmt.Errorf("ruleset has no table")
	}
	return nil
}
