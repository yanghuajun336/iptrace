package main

import (
	"context"
	"os"
	"time"

	"iptrace/internal/output"
	"iptrace/internal/tracer"
)

func runTrace(args []string) int {
	fs := newFlagSet("trace")
	_ = fs.String("src", "", "source ip filter")
	_ = fs.String("dst", "", "destination ip filter")
	_ = fs.String("proto", "", "protocol filter")
	_ = fs.Uint("sport", 0, "source port filter")
	_ = fs.Uint("dport", 0, "destination port filter")
	format := fs.String("format", "human", "output format: human|json")
	timeout := fs.Duration("timeout", 2*time.Second, "trace timeout")
	if err := fs.Parse(args); err != nil {
		return exitWith(output.NewInputError(err.Error(), output.HintForError("invalid_packet")))
	}
	selectedFormat, err := parseFormat(*format)
	if err != nil {
		return exitWith(err)
	}

	testMode := testModeEnabled()
	isRoot := os.Geteuid() == 0 && !forceNotRoot()
	if !isRoot && !testMode {
		return exitWith(output.NewEnvError("trace requires root privileges", output.HintForError("trace_requires_root")))
	}

	s := tracer.NewSession(tracer.SessionOptions{TestMode: testMode})
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	events, err := s.Start(ctx)
	if err != nil {
		return exitWith(output.NewInternalError("start trace session failed: "+err.Error(), ""))
	}
	defer s.Stop()

	for step := range events {
		if selectedFormat == formatJSON {
			line, err := output.RenderStepNDJSON(step)
			if err != nil {
				return exitWith(output.NewInternalError("render step json failed: "+err.Error(), ""))
			}
			_, _ = os.Stdout.WriteString(line + "\n")
			continue
		}
		_, _ = os.Stdout.WriteString(output.RenderStepHuman(step) + "\n")
	}

	return output.ExitCodeOK
}
