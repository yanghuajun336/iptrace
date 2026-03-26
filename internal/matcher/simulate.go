package matcher

import (
	"fmt"
	"strconv"
	"strings"

	"iptrace/pkg/model"
)

// tableOrder defines the traversal order for a packet moving toward a local process (INPUT path).
// Adjust as needed for FORWARD / OUTPUT paths if callers provide path hints.
var tableOrder = []string{"raw", "mangle", "nat", "filter"}

// standardChainsByTable maps each table to the chains traversed on the INPUT path
// (locally-destined packet: arrives → PREROUTING → routing → INPUT).
// FORWARD and OUTPUT chains are intentionally excluded; they apply to different
// packet paths and would produce incorrect verdicts for locally-destined traffic.
var standardChainsByTable = map[string][]string{
	"raw":    {"PREROUTING"},
	"mangle": {"PREROUTING", "INPUT"},
	"nat":    {"PREROUTING", "INPUT"},
	"filter": {"INPUT"},
}

// Simulate performs an offline traversal of the given rule set for the
// supplied packet, following Netfilter's table/chain execution order and
// resolving JUMP targets recursively.
//
// Limitations (documented):
//   - Traversal assumes an INPUT path (locally destined packet).
//   - nat/PREROUTING DNAT effects are NOT applied (offline simulation).
//   - Connection-tracking state (--ctstate) is not evaluated.
func Simulate(packet model.Packet, rs model.RuleSet) (model.TraceResult, error) {
	if err := packet.Validate(); err != nil {
		return model.TraceResult{}, err
	}

	result := model.TraceResult{
		Packet:  packet,
		Backend: rs.Backend,
		Verdict: "ACCEPT",
	}

	// Build a lookup map from table name → chain name → *model.Chain
	tableMap := buildTableMap(rs)

	for _, tableName := range tableOrder {
		table, ok := tableMap[tableName]
		if !ok {
			continue
		}
		chains := standardChainsByTable[tableName]
		for _, chainName := range chains {
			chain, ok := table[chainName]
			if !ok {
				continue
			}
			verdict, done, err := traverseChain(packet, tableName, chain, table, &result, 0)
			if err != nil {
				return result, err
			}
			if done {
				switch verdict {
				case "DROP", "REJECT":
					// Terminal verdicts immediately end the packet path
					result.Verdict = verdict
					return result, nil
				default:
					// ACCEPT (or policy ACCEPT) means this chain is satisfied;
					// continue traversal to the next chain/table in the pipeline.
				}
			}
		}
	}

	// All tables and chains traversed without a DROP/REJECT verdict.
	result.Verdict = "ACCEPT"
	return result, nil
}

// traverseChain walks a single chain and appends TraceSteps to result.
// Returns (verdict, terminal, error).
// terminal=true means traversal must stop (DROP/ACCEPT/REJECT reached).
// depth guards against infinite JUMP recursion (max 10 levels).
func traverseChain(
	packet model.Packet,
	tableName string,
	chain *model.Chain,
	tableChains map[string]*model.Chain,
	result *model.TraceResult,
	depth int,
) (verdict string, terminal bool, err error) {
	const maxDepth = 10
	if depth > maxDepth {
		return "", false, fmt.Errorf("JUMP recursion depth exceeded in table %s chain %s", tableName, chain.Name)
	}

	for _, rule := range chain.Rules {
		matched := ruleMatchesPacket(rule.RawText, packet)
		step := model.TraceStep{
			HookPoint:  chain.Name,
			Table:      tableName,
			Chain:      chain.Name,
			RuleNumber: rule.Number,
			RawRule:    rule.RawText,
			Matched:    matched,
			Action:     "CONTINUE",
		}

		if matched {
			target := strings.ToUpper(rule.Target)
			step.Action = target
			step.JumpTarget = rule.Target

			if isTerminalAction(target) {
				result.Steps = append(result.Steps, step)
				result.VerdictRule = &result.Steps[len(result.Steps)-1]
				return target, true, nil
			}

			if target == "RETURN" {
				result.Steps = append(result.Steps, step)
				return "", false, nil // return to caller chain
			}

			// JUMP to a custom chain
			if sub, ok := tableChains[rule.Target]; ok {
				result.Steps = append(result.Steps, step)
				v, done, err := traverseChain(packet, tableName, sub, tableChains, result, depth+1)
				if err != nil {
					return "", false, err
				}
				if done {
					return v, true, nil
				}
				continue // RETURN from sub-chain, continue this chain
			}
			// Unknown target — treat as CONTINUE
		}

		result.Steps = append(result.Steps, step)
	}

	// End of chain: apply default policy (standard chains only)
	if chain.DefaultPolicy != "" {
		policy := strings.ToUpper(chain.DefaultPolicy)
		result.DefaultPolicyApplied = true
		return policy, true, nil
	}

	return "", false, nil // custom chain exhausted without RETURN — fall through
}

// buildTableMap indexes the rule set for O(1) chain lookup.
func buildTableMap(rs model.RuleSet) map[string]map[string]*model.Chain {
	m := make(map[string]map[string]*model.Chain)
	for i, table := range rs.Tables {
		m[table.Name] = make(map[string]*model.Chain)
		for j := range table.Chains {
			m[table.Name][table.Chains[j].Name] = &rs.Tables[i].Chains[j]
		}
	}
	return m
}

// ruleMatchesPacket returns true when the iptables rule text matches the packet.
// Recognised match options: -s, -d, -p, --sport, --dport, --destination-port,
// -i (in-interface).  Unrecognised options are ignored (conservative = match).
func ruleMatchesPacket(raw string, packet model.Packet) bool {
	parts := strings.Fields(raw)
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "-s", "--source":
			if i+1 < len(parts) && !matchCIDR(parts[i+1], packet.SrcIP) {
				return false
			}
		case "-d", "--destination":
			if i+1 < len(parts) && !matchCIDR(parts[i+1], packet.DstIP) {
				return false
			}
		case "-p", "--protocol":
			if i+1 < len(parts) && strings.ToLower(parts[i+1]) != packet.Protocol {
				return false
			}
		case "--sport", "--source-port":
			// sport=0 means "any source port" – skip the check entirely
			if i+1 < len(parts) && packet.SrcPort != 0 {
				p, err := strconv.Atoi(parts[i+1])
				if err != nil || uint16(p) != packet.SrcPort {
					return false
				}
			}
		case "--dport", "--destination-port":
			if i+1 < len(parts) {
				p, err := strconv.Atoi(parts[i+1])
				if err != nil || uint16(p) != packet.DstPort {
					return false
				}
			}
		case "-i", "--in-interface":
			if i+1 < len(parts) && packet.InInterface != "" &&
				parts[i+1] != packet.InInterface {
				return false
			}
		}
	}
	return true
}

// matchCIDR compares an iptables address spec (plain IP or CIDR) against a
// packet IP string.  For plain IPs an exact match is required; CIDR matching
// falls back to prefix-length comparison for simplicity.
func matchCIDR(spec, ip string) bool {
	if !strings.Contains(spec, "/") {
		return spec == ip
	}
	// CIDR: compare the network prefix
	parts := strings.SplitN(spec, "/", 2)
	prefix := parts[0]
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return spec == ip
	}
	// Simple string-based prefix comparison (works for clean IPs, not octets)
	// For production use, net.ParseCIDR would be used; this avoids importing net.
	specOctets := strings.Split(prefix, ".")
	ipOctets := strings.Split(ip, ".")
	if len(specOctets) != 4 || len(ipOctets) != 4 {
		return spec == ip
	}
	fullOctets := mask / 8
	for i := 0; i < fullOctets && i < 4; i++ {
		if specOctets[i] != ipOctets[i] {
			return false
		}
	}
	return true
}

// ValidateRuleSet returns an error if the rule set has no tables.
func ValidateRuleSet(rs model.RuleSet) error {
	if len(rs.Tables) == 0 {
		return fmt.Errorf("ruleset has no table")
	}
	return nil
}

func isTerminalAction(action string) bool {
	switch action {
	case "DROP", "ACCEPT", "REJECT":
		return true
	}
	return false
}

