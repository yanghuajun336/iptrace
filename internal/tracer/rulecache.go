package tracer

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// RuleCache maps "table/chain/handle" → raw nft rule text.
// Built once at trace startup by querying the local nft ruleset.
type RuleCache struct {
	rules map[string]string
}

var reHandle = regexp.MustCompile(`#\s*handle\s+(\d+)\s*$`)

// BuildRuleCache runs "nft --handle list ruleset" and indexes all rules by
// table/chain/handle.  Returns an empty (no-op) cache if nft is unavailable
// or the command fails — callers must not treat this as an error.
func BuildRuleCache() *RuleCache {
	c := &RuleCache{rules: make(map[string]string)}

	out, err := exec.Command("nft", "--handle", "list", "ruleset").Output()
	if err != nil {
		return c // graceful degradation: RawRule stays empty
	}

	var curTable, curChain string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line == "{" {
			continue
		}
		if line == "}" {
			if curChain != "" {
				curChain = ""
			} else {
				curTable = ""
			}
			continue
		}
		// "table ip filter {" → parts[2] is the table name
		if strings.HasPrefix(line, "table ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				curTable = strings.TrimSuffix(parts[2], "{")
			}
			curChain = ""
			continue
		}
		// "chain INPUT {" → parts[1] is the chain name
		if strings.HasPrefix(line, "chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				curChain = strings.TrimSuffix(parts[1], "{")
			}
			continue
		}
		// Rule line: "ip saddr 43.139.105.42 tcp dport 80 drop # handle 85"
		m := reHandle.FindStringSubmatch(line)
		if m == nil || curTable == "" || curChain == "" {
			continue
		}
		handle, _ := strconv.Atoi(m[1])
		ruleText := strings.TrimSpace(reHandle.ReplaceAllString(line, ""))
		c.rules[fmt.Sprintf("%s/%s/%d", curTable, curChain, handle)] = ruleText
	}
	return c
}

// Lookup returns the raw nft rule text for the given table/chain/handle.
// Returns "" on cache miss or if nft was unavailable.
func (c *RuleCache) Lookup(table, chain string, handle int) string {
	if c == nil {
		return ""
	}
	return c.rules[fmt.Sprintf("%s/%s/%d", table, chain, handle)]
}
