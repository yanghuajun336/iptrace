package main

import (
	"errors"
	"os"

	"iptrace/internal/matcher"
	"iptrace/internal/output"
	"iptrace/internal/parser"
	"iptrace/pkg/model"
)

func runCheck(args []string) int {
	fs := newFlagSet("check")
	src := fs.String("src", "", "source ip")
	dst := fs.String("dst", "", "destination ip")
	proto := fs.String("proto", "", "protocol: tcp|udp|icmp")
	dport := fs.Uint("dport", 0, "destination port (required for tcp/udp)")
	rulesFile := fs.String("rules-file", "", "rules file path")
	format := fs.String("format", "human", "output format: human|json")
	if err := fs.Parse(args); err != nil {
		return exitWith(output.NewInputError(err.Error(), output.HintForError("invalid_packet")))
	}
	selectedFormat, err := parseFormat(*format)
	if err != nil {
		return exitWith(err)
	}

	if *src == "" || *dst == "" || *proto == "" {
		return exitWith(output.NewInputError("--src, --dst, --proto are required", output.HintForError("invalid_packet")))
	}
	if *rulesFile == "" {
		return exitWith(output.NewInputError("--rules-file is required", output.HintForError("missing_rules_file")))
	}

	packet := model.Packet{
		Protocol: *proto,
		SrcIP:    *src,
		DstIP:    *dst,
		DstPort:  uint16(*dport),
	}
	if err := packet.Validate(); err != nil {
		return exitWith(output.NewInputError(err.Error(), output.HintForError("invalid_packet")))
	}

	f, err := os.Open(*rulesFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return exitWith(output.NewEnvError("rules file \""+*rulesFile+"\" not found", output.HintForError("missing_rules_file")))
		}
		return exitWith(output.NewInternalError("open rules file failed: "+err.Error(), ""))
	}
	defer f.Close()

	ruleset, err := parser.ParseIPTablesSave(f)
	if err != nil {
		return exitWith(output.NewInternalError("parse rules failed: "+err.Error(), output.HintForError("parse_rules_failed")))
	}
	ruleset.Backend = model.BackendLegacy

	result, err := matcher.Simulate(packet, ruleset)
	if err != nil {
		return exitWith(output.NewInternalError("simulate failed: "+err.Error(), ""))
	}

	if selectedFormat == formatJSON {
		text, err := output.RenderJSON(result)
		if err != nil {
			return exitWith(output.NewInternalError("json render failed: "+err.Error(), ""))
		}
		_, _ = os.Stdout.WriteString(text + "\n")
		return output.ExitCodeOK
	}

	_, _ = os.Stdout.WriteString(output.RenderHuman(result))
	return output.ExitCodeOK
}
