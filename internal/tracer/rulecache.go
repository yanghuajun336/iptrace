package tracer

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// RuleCache maps "table/chain/handle" → iptables-format rule text (e.g. "-A INPUT ...").
//
// Building strategy for iptables-nft backend:
//  1. Run iptables-save  → ordered list of "-A CHAIN ..." per table/chain
//  2. Run nft --handle list ruleset → ordered list of handles per table/chain
//  3. Correlate by position: handle[i] ↔ iptables_rule[i]
//
// This works because iptables-nft preserves insertion order in both outputs.
// Falls back gracefully (empty cache) if either command is unavailable.
type RuleCache struct {
	rules map[string]string // "table/chain/handle" → "-A CHAIN ..."
}

var reHandle = regexp.MustCompile(`#\s*handle\s+(\d+)\s*$`)

// BuildRuleCache builds the cache.  Non-fatal: returns an empty (no-op) cache
// if iptables-save or nft are unavailable.
func BuildRuleCache() *RuleCache {
	c := &RuleCache{rules: make(map[string]string)}

	iptRules := loadIPTablesRules()  // table/chain → []"-A CHAIN ..."
	nftHandles := loadNFTHandles()   // table/chain → []handle (ordered)

	for chainKey, handles := range nftHandles {
		rules := iptRules[chainKey]
		for i, handle := range handles {
			if i >= len(rules) {
				break
			}
			c.rules[fmt.Sprintf("%s/%d", chainKey, handle)] = rules[i]
		}
	}
	return c
}

// loadIPTablesRules runs iptables-save and returns "table/chain" → []rule_text.
func loadIPTablesRules() map[string][]string {
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		out, err = exec.Command("iptables-legacy-save").Output()
		if err != nil {
			return map[string][]string{}
		}
	}
	return parseIPTablesRules(strings.NewReader(string(out)))
}

// parseIPTablesRules parses an iptables-save formatted stream and returns
// "table/chain" → ordered []"-A CHAIN ..." lines.
// Exported for testing.
func parseIPTablesRules(r io.Reader) map[string][]string {
	result := make(map[string][]string)
	var curTable string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "*"):
			curTable = strings.TrimPrefix(line, "*")
		case line == "COMMIT":
			curTable = ""
		case curTable != "" && strings.HasPrefix(line, "-A "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				key := fmt.Sprintf("%s/%s", curTable, parts[1])
				result[key] = append(result[key], line)
			}
		}
	}
	return result
}

// loadNFTHandles runs nft --handle list ruleset and returns
// "table/chain" → []handle in chain insertion order.
func loadNFTHandles() map[string][]int {
	result := make(map[string][]int)

	out, err := exec.Command("nft", "--handle", "list", "ruleset").Output()
	if err != nil {
		return result
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
		if strings.HasPrefix(line, "table ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				curTable = strings.TrimSuffix(parts[2], "{")
			}
			curChain = ""
			continue
		}
		if strings.HasPrefix(line, "chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				curChain = strings.TrimSuffix(parts[1], "{")
			}
			continue
		}
		m := reHandle.FindStringSubmatch(line)
		if m == nil || curTable == "" || curChain == "" {
			continue
		}
		handle, _ := strconv.Atoi(m[1])
		key := fmt.Sprintf("%s/%s", curTable, curChain)
		result[key] = append(result[key], handle)
	}
	return result
}

// Lookup returns the iptables-format rule text for the given table/chain/handle.
// Returns "" on cache miss or when the cache is unavailable.
func (c *RuleCache) Lookup(table, chain string, handle int) string {
	if c == nil {
		return ""
	}
	return c.rules[fmt.Sprintf("%s/%s/%d", table, chain, handle)]
}
