package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"iptrace/internal/output"
	"iptrace/internal/tracer"
)

func runTrace(args []string) int {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	_ = fs.String("src", "", "source ip filter")
	_ = fs.String("dst", "", "destination ip filter")
	_ = fs.String("proto", "", "protocol filter")
	_ = fs.Uint("sport", 0, "source port filter")
	_ = fs.Uint("dport", 0, "destination port filter")
	format := fs.String("format", "human", "output format: human|json")
	timeout := fs.Duration("timeout", 2*time.Second, "trace timeout")
	_ = fs.Parse(args)

	testMode := os.Getenv("IPTRACE_TEST_MODE") == "1"
	forceNotRoot := os.Getenv("IPTRACE_FORCE_NOT_ROOT") == "1"
	isRoot := os.Geteuid() == 0 && !forceNotRoot
	if !isRoot && !testMode {
		fmt.Fprintln(os.Stderr, "error: trace requires root privileges")
		fmt.Fprintln(os.Stderr, "hint: try: sudo iptrace trace ...")
		return output.ExitCodeEnvError
	}

	s := tracer.NewSession(tracer.SessionOptions{TestMode: testMode})
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	events, err := s.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: start trace session failed: %v\n", err)
		return output.ExitCodeInternalErr
	}
	defer s.Stop()

	for step := range events {
		if *format == "json" {
			line, err := output.RenderStepNDJSON(step)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: render step json failed: %v\n", err)
				return output.ExitCodeInternalErr
			}
			fmt.Println(line)
			continue
		}
		fmt.Println(output.RenderStepHuman(step))
	}

	return output.ExitCodeOK
}
