package parser

import (
	"strings"
	"testing"
)

func TestParseRuleSet_FilterInput(t *testing.T) {
	rules := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP
COMMIT
`

	rs, err := ParseIPTablesSave(strings.NewReader(rules))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(rs.Tables) != 1 {
		t.Fatalf("expect 1 table, got %d", len(rs.Tables))
	}
	if rs.Tables[0].Name != "filter" {
		t.Fatalf("expect table filter, got %s", rs.Tables[0].Name)
	}
	if len(rs.Tables[0].Chains) != 1 {
		t.Fatalf("expect 1 chain, got %d", len(rs.Tables[0].Chains))
	}
	chain := rs.Tables[0].Chains[0]
	if chain.Name != "INPUT" {
		t.Fatalf("expect INPUT chain, got %s", chain.Name)
	}
	if chain.DefaultPolicy != "ACCEPT" {
		t.Fatalf("expect default policy ACCEPT, got %s", chain.DefaultPolicy)
	}
	if len(chain.Rules) != 1 {
		t.Fatalf("expect 1 rule, got %d", len(chain.Rules))
	}
	if chain.Rules[0].Target != "DROP" {
		t.Fatalf("expect target DROP, got %s", chain.Rules[0].Target)
	}
}
