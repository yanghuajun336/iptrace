package main

import (
	"strings"
	"testing"
)

func TestUsageTextIncludesCommandGuidance(t *testing.T) {
	text := usageText()

	checks := []string{
		"Usage: iptrace <check|trace|export>",
		"check   离线推演规则快照",
		"trace   在线追踪报文路径",
		"export  导出当前规则快照",
		"iptrace check --src",
	}

	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Fatalf("usage text missing %q, got: %s", want, text)
		}
	}
}
