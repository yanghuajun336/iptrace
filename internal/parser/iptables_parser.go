package parser

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"iptrace/pkg/model"
)

func ParseIPTablesSave(r io.Reader) (model.RuleSet, error) {
	s := bufio.NewScanner(r)
	var rs model.RuleSet

	var currentTable *model.Table
	chainIndex := map[string]int{}

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "*") {
			tableName := strings.TrimPrefix(line, "*")
			rs.Tables = append(rs.Tables, model.Table{Name: tableName})
			currentTable = &rs.Tables[len(rs.Tables)-1]
			chainIndex = map[string]int{}
			continue
		}

		if line == "COMMIT" {
			currentTable = nil
			chainIndex = map[string]int{}
			continue
		}

		if currentTable == nil {
			continue
		}

		if strings.HasPrefix(line, ":") {
			// :INPUT ACCEPT [0:0]
			parts := strings.Fields(strings.TrimPrefix(line, ":"))
			if len(parts) < 2 {
				return rs, fmt.Errorf("invalid chain line: %s", line)
			}
			name := parts[0]
			policy := parts[1]
			currentTable.Chains = append(currentTable.Chains, model.Chain{Name: name, DefaultPolicy: policy})
			chainIndex[name] = len(currentTable.Chains) - 1
			continue
		}

		if strings.HasPrefix(line, "-A ") {
			parts := strings.Fields(line)
			if len(parts) < 4 {
				return rs, fmt.Errorf("invalid rule line: %s", line)
			}
			chainName := parts[1]
			target := parseTarget(parts)
			idx, ok := chainIndex[chainName]
			if !ok {
				currentTable.Chains = append(currentTable.Chains, model.Chain{Name: chainName})
				idx = len(currentTable.Chains) - 1
				chainIndex[chainName] = idx
			}
			chain := &currentTable.Chains[idx]
			chain.Rules = append(chain.Rules, model.Rule{
				Number:  len(chain.Rules) + 1,
				RawText: line,
				Target:  target,
			})
		}
	}

	if err := s.Err(); err != nil {
		return rs, err
	}

	return rs, nil
}

func parseTarget(parts []string) string {
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "-j" {
			return parts[i+1]
		}
	}
	return ""
}
