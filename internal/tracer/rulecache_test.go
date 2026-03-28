package tracer

import (
	"strings"
	"testing"
)

// TestRuleCacheLookup_HitAndMiss verifies index lookup and cache miss behaviour.
// Values use iptables-save format (the format BuildRuleCache now stores).
func TestRuleCacheLookup_HitAndMiss(t *testing.T) {
	c := &RuleCache{rules: map[string]string{
		"filter/INPUT/42":     "-A INPUT -s 1.2.3.4 -p tcp --dport 80 -j DROP",
		"filter/INPUT/7":      "-A INPUT -d 10.0.0.1 -j ACCEPT",
		"filter/OUTPUT/100":   "-A OUTPUT -d 8.8.8.8 -j DROP",
		"mangle/PREROUTING/3": "-A PREROUTING -j MARK --set-mark 0x1",
	}}

	tests := []struct {
		table, chain string
		handle       int
		want         string
	}{
		{"filter", "INPUT", 42, "-A INPUT -s 1.2.3.4 -p tcp --dport 80 -j DROP"},
		{"filter", "INPUT", 7, "-A INPUT -d 10.0.0.1 -j ACCEPT"},
		{"filter", "OUTPUT", 100, "-A OUTPUT -d 8.8.8.8 -j DROP"},
		{"mangle", "PREROUTING", 3, "-A PREROUTING -j MARK --set-mark 0x1"},
		// cache miss: unknown handle
		{"filter", "INPUT", 999, ""},
		// cache miss: unknown table
		{"nat", "PREROUTING", 1, ""},
	}

	for _, tt := range tests {
		got := c.Lookup(tt.table, tt.chain, tt.handle)
		if got != tt.want {
			t.Errorf("Lookup(%q, %q, %d) = %q; want %q",
				tt.table, tt.chain, tt.handle, got, tt.want)
		}
	}
}

// TestRuleCacheLookup_NilCache verifies that a nil *RuleCache never panics.
func TestRuleCacheLookup_NilCache(t *testing.T) {
	var c *RuleCache
	if got := c.Lookup("filter", "INPUT", 1); got != "" {
		t.Errorf("nil cache Lookup should return empty string, got %q", got)
	}
}

// TestBuildRuleCache_Unavailable verifies graceful degradation when iptables-save
// and nft are both absent (PATH set to empty directory).
func TestBuildRuleCache_Unavailable(t *testing.T) {
	t.Setenv("PATH", "/dev/null")
	c := BuildRuleCache()
	if c == nil {
		t.Fatal("BuildRuleCache must never return nil")
	}
	if got := c.Lookup("filter", "INPUT", 1); got != "" {
		t.Errorf("empty cache should return empty string, got %q", got)
	}
}

// TestLoadIPTablesRules_Parse verifies that loadIPTablesRules correctly indexes
// rules from an iptables-save format string.
func TestLoadIPTablesRules_Parse(t *testing.T) {
	// We test the parser directly by monkey-patching its input through the
	// internal helper; since it's package-private we call it via a wrapper
	// that accepts a reader.  Use the exported-for-test variant.
	input := `*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -s 1.2.3.4 -j DROP
-A OUTPUT -d 8.8.8.8 -j DROP
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
-A PREROUTING -j MARK --set-mark 0x1
-A PREROUTING -p udp --dport 53 -j MARK --set-mark 0x10
COMMIT
`
	result := parseIPTablesRules(strings.NewReader(input))

	checks := []struct {
		key  string
		idx  int
		want string
	}{
		{"filter/INPUT", 0, "-A INPUT -p tcp --dport 80 -j ACCEPT"},
		{"filter/INPUT", 1, "-A INPUT -p tcp --dport 443 -j ACCEPT"},
		{"filter/INPUT", 2, "-A INPUT -s 1.2.3.4 -j DROP"},
		{"filter/OUTPUT", 0, "-A OUTPUT -d 8.8.8.8 -j DROP"},
		{"mangle/PREROUTING", 0, "-A PREROUTING -j MARK --set-mark 0x1"},
		{"mangle/PREROUTING", 1, "-A PREROUTING -p udp --dport 53 -j MARK --set-mark 0x10"},
	}
	for _, tt := range checks {
		rules := result[tt.key]
		if tt.idx >= len(rules) {
			t.Errorf("key %q: want index %d but only %d rules", tt.key, tt.idx, len(rules))
			continue
		}
		if rules[tt.idx] != tt.want {
			t.Errorf("key %q index %d = %q; want %q", tt.key, tt.idx, rules[tt.idx], tt.want)
		}
	}
}

