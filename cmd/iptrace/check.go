package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"iptrace/internal/matcher"
	"iptrace/internal/output"
	"iptrace/internal/parser"
	"iptrace/pkg/model"
)

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	src := fs.String("src", "", "source ip")
	dst := fs.String("dst", "", "destination ip")
	proto := fs.String("proto", "", "protocol")
	sport := fs.Uint("sport", 0, "source port")
	dport := fs.Uint("dport", 0, "destination port")
	rulesFile := fs.String("rules-file", "", "rules file path")
	format := fs.String("format", "human", "output format: human|json")
	_ = fs.Parse(args)

	if *src == "" || *dst == "" || *proto == "" {
		fmt.Fprintln(os.Stderr, "error: --src, --dst, --proto are required")
		fmt.Fprintf(os.Stderr, "hint: %s\n", output.HintForError("invalid_packet"))
		return output.ExitCodeInputError
	}
	if *rulesFile == "" {
		fmt.Fprintln(os.Stderr, "error: --rules-file is required")
		fmt.Fprintf(os.Stderr, "hint: %s\n", output.HintForError("missing_rules_file"))
		return output.ExitCodeInputError
	}

	packet := model.Packet{
		Protocol: *proto,
		SrcIP:    *src,
		DstIP:    *dst,
		SrcPort:  uint16(*sport),
		DstPort:  uint16(*dport),
	}
	if err := packet.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "hint: %s\n", output.HintForError("invalid_packet"))
		return output.ExitCodeInputError
	}

	f, err := os.Open(*rulesFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "error: rules file %q not found\n", *rulesFile)
			fmt.Fprintf(os.Stderr, "hint: %s\n", output.HintForError("missing_rules_file"))
			return output.ExitCodeEnvError
		}
		fmt.Fprintf(os.Stderr, "error: open rules file failed: %v\n", err)
		return output.ExitCodeInternalErr
	}
	defer f.Close()

	ruleset, err := parser.ParseIPTablesSave(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse rules failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "hint: %s\n", output.HintForError("parse_rules_failed"))
		return output.ExitCodeInternalErr
	}
	ruleset.Backend = model.BackendLegacy

	result, err := matcher.Simulate(packet, ruleset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: simulate failed: %v\n", err)
		return output.ExitCodeInternalErr
	}

	if *format == "json" {
		text, err := output.RenderJSON(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: json render failed: %v\n", err)
			return output.ExitCodeInternalErr
		}
		fmt.Println(text)
		return output.ExitCodeOK
	}

	fmt.Print(output.RenderHuman(result))
	return output.ExitCodeOK
}
