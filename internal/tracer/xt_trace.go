package tracer

import (
	"fmt"
	"os/exec"
	"strings"

	"iptrace/pkg/model"
)

// TraceFilter specifies optional packet-matching criteria to scope a TRACE rule.
// Zero-value fields are omitted (no restriction).
type TraceFilter struct {
	SrcIP    string // -s  e.g. "192.168.1.0/24"
	DstIP    string // -d  e.g. "10.0.0.1"
	Protocol string // -p  e.g. "tcp", "udp", "icmp"
	SrcPort  uint16 // --sport  (only meaningful when Protocol is tcp/udp)
	DstPort  uint16 // --dport  (only meaningful when Protocol is tcp/udp)
}

// InjectTraceRule inserts TRACE rules into the raw table for PREROUTING and OUTPUT chains.
// The optional filter scopes the rule to matching packets only.
// Rules are inserted at position 1 (top of chain) to catch all traffic before other rules.
func InjectTraceRule(filter TraceFilter) error {
	matchArgs := buildMatchArgs(filter)
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		args := []string{"-t", "raw", "-I", chain, "1"}
		args = append(args, matchArgs...)
		args = append(args, "-j", "TRACE")
		if err := runIPTables(args...); err != nil {
			// Attempt cleanup of already-inserted rules before returning
			_ = CleanupTraceRule(filter)
			return fmt.Errorf("inject TRACE %s: %w", chain, err)
		}
	}
	return nil
}

// CleanupTraceRule removes the TRACE rules that were previously injected.
// It is safe to call even if the rules do not exist (idempotent).
func CleanupTraceRule(filter TraceFilter) error {
	matchArgs := buildMatchArgs(filter)
	var lastErr error
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		args := []string{"-t", "raw", "-D", chain}
		args = append(args, matchArgs...)
		args = append(args, "-j", "TRACE")
		if err := runIPTables(args...); err != nil {
			lastErr = err // continue cleanup even if one chain fails
		}
	}
	return lastErr
}

// buildMatchArgs constructs iptables match arguments from a TraceFilter.
// Arguments are returned in the canonical iptables order.
func buildMatchArgs(f TraceFilter) []string {
	var args []string
	if f.SrcIP != "" {
		args = append(args, "-s", f.SrcIP)
	}
	if f.DstIP != "" {
		args = append(args, "-d", f.DstIP)
	}
	if f.Protocol != "" {
		args = append(args, "-p", strings.ToLower(f.Protocol))
		if f.SrcPort != 0 {
			args = append(args, "--sport", fmt.Sprintf("%d", f.SrcPort))
		}
		if f.DstPort != 0 {
			args = append(args, "--dport", fmt.Sprintf("%d", f.DstPort))
		}
	}
	return args
}

// FilterDisplaySteps removes trace-session housekeeping steps that should not be
// shown to the user, namely the program-injected raw table TRACE rules.
func FilterDisplaySteps(steps []model.TraceStep, filter TraceFilter) []model.TraceStep {
	if len(steps) == 0 {
		return nil
	}
	filtered := make([]model.TraceStep, 0, len(steps))
	for _, step := range steps {
		if isInjectedTraceStep(step, filter) {
			continue
		}
		filtered = append(filtered, step)
	}
	return filtered
}

func isInjectedTraceStep(step model.TraceStep, filter TraceFilter) bool {
	if step.Table != "raw" {
		return false
	}
	if step.Chain != "PREROUTING" && step.Chain != "OUTPUT" {
		return false
	}
	if step.RawRule == "" {
		return false
	}
	want := injectedTraceRuleText(step.Chain, filter)
	return strings.TrimSpace(step.RawRule) == want
}

func injectedTraceRuleText(chain string, filter TraceFilter) string {
	parts := []string{"-A", chain}
	parts = append(parts, buildMatchArgs(filter)...)
	parts = append(parts, "-j", "TRACE")
	return strings.Join(parts, " ")
}

// runIPTables executes an iptables command, trying iptables then iptables-legacy.
func runIPTables(args ...string) error {
	path, err := exec.LookPath("iptables")
	if err != nil {
		if path, err = exec.LookPath("iptables-legacy"); err != nil {
			return fmt.Errorf("iptables not found in PATH: %w", err)
		}
	}
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s: %w", path, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}
