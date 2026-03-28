package tracer

import (
	"testing"
)

// TestRuleCacheLookup_HitAndMiss verifies index lookup and cache miss behaviour.
func TestRuleCacheLookup_HitAndMiss(t *testing.T) {
	c := &RuleCache{rules: map[string]string{
		"filter/INPUT/42":     "ip saddr 1.2.3.4 tcp dport 80 drop",
		"filter/INPUT/7":      "ip daddr 10.0.0.1 accept",
		"filter/OUTPUT/100":   "ip daddr 8.8.8.8 drop",
		"mangle/PREROUTING/3": "meta mark set 0x1",
	}}

	tests := []struct {
		table, chain string
		handle       int
		want         string
	}{
		{"filter", "INPUT", 42, "ip saddr 1.2.3.4 tcp dport 80 drop"},
		{"filter", "INPUT", 7, "ip daddr 10.0.0.1 accept"},
		{"filter", "OUTPUT", 100, "ip daddr 8.8.8.8 drop"},
		{"mangle", "PREROUTING", 3, "meta mark set 0x1"},
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

// TestBuildRuleCache_NftUnavailable verifies graceful degradation when nft is absent.
func TestBuildRuleCache_NftUnavailable(t *testing.T) {
	// Shadow PATH so nft cannot be resolved.
	t.Setenv("PATH", "/dev/null")
	c := BuildRuleCache()
	if c == nil {
		t.Fatal("BuildRuleCache must never return nil")
	}
	// Empty cache must not panic on Lookup.
	if got := c.Lookup("filter", "INPUT", 1); got != "" {
		t.Errorf("empty cache should return empty string, got %q", got)
	}
}

