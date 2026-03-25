package model

import (
	"fmt"
	"net"
)

type Backend string

const (
	BackendLegacy    Backend = "iptables-legacy"
	BackendNFT       Backend = "iptables-nft"
	BackendFirewalld Backend = "firewalld"
	BackendUnknown   Backend = "unknown"
)

type Packet struct {
	Protocol    string `json:"protocol"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	InInterface string `json:"in_interface,omitempty"`
}

type RuleSet struct {
	Backend    Backend  `json:"backend"`
	Tables     []Table  `json:"tables"`
	SourceFile string   `json:"source_file,omitempty"`
}

type Table struct {
	Name   string  `json:"name"`
	Chains []Chain `json:"chains"`
}

type Chain struct {
	Name          string `json:"name"`
	DefaultPolicy string `json:"default_policy,omitempty"`
	Rules         []Rule `json:"rules"`
}

type Rule struct {
	Number        int               `json:"number"`
	RawText       string            `json:"raw_text"`
	Target        string            `json:"target"`
	TargetOptions map[string]string `json:"target_options,omitempty"`
}

type TraceStep struct {
	HookPoint  string `json:"hook_point"`
	Table      string `json:"table"`
	Chain      string `json:"chain"`
	RuleNumber int    `json:"rule_number"`
	RawRule    string `json:"raw_rule,omitempty"`
	Matched    bool   `json:"matched"`
	Action     string `json:"action"`
	JumpTarget string `json:"jump_target,omitempty"`
}

type TraceResult struct {
	Packet               Packet      `json:"packet"`
	Backend              Backend     `json:"backend"`
	Steps                []TraceStep `json:"steps"`
	Verdict              string      `json:"verdict"`
	VerdictRule          *TraceStep  `json:"verdict_rule,omitempty"`
	DefaultPolicyApplied bool        `json:"default_policy_applied"`
	DurationMS           int64       `json:"duration_ms"`
}

func (p Packet) Validate() error {
	switch p.Protocol {
	case "tcp", "udp", "icmp", "all":
	default:
		return fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}

	if net.ParseIP(p.SrcIP) == nil {
		return fmt.Errorf("invalid src ip: %s", p.SrcIP)
	}
	if net.ParseIP(p.DstIP) == nil {
		return fmt.Errorf("invalid dst ip: %s", p.DstIP)
	}

	if p.Protocol == "tcp" || p.Protocol == "udp" {
		if p.SrcPort == 0 || p.DstPort == 0 {
			return fmt.Errorf("src/dst port are required for %s", p.Protocol)
		}
	}

	return nil
}
