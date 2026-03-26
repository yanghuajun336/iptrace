package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"iptrace/internal/output"
	"iptrace/internal/tracer"
	"iptrace/pkg/model"
)

func runTrace(args []string) int {
	fs := newFlagSet("trace")
	src := fs.String("src", "", "source IP filter (e.g. 192.168.1.0/24)")
	dst := fs.String("dst", "", "destination IP filter")
	proto := fs.String("proto", "", "protocol filter: tcp|udp|icmp")
	sport := fs.Uint("sport", 0, "source port filter (requires --proto tcp|udp)")
	dport := fs.Uint("dport", 0, "destination port filter (requires --proto tcp|udp)")
	format := fs.String("format", "human", "output format: human|json")
	// 默认 0 = 不超时，Ctrl+C 停止；正值为有限超时
	timeout := fs.Duration("timeout", 0, "trace timeout; 0 = no timeout (Ctrl+C to stop)")
	var verbose bool
	fs.BoolVar(&verbose, "verbose", false, "print full packet traversal path (default: verdict-only summary)")
	fs.BoolVar(&verbose, "v", false, "short for --verbose")

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

	filter := tracer.TraceFilter{
		SrcIP:    *src,
		DstIP:    *dst,
		Protocol: *proto,
		SrcPort:  uint16(*sport),
		DstPort:  uint16(*dport),
	}

	s := tracer.NewSession(tracer.SessionOptions{
		TestMode: testMode,
		Filter:   filter,
	})

	// Build context: honour --timeout if > 0, otherwise wait for signal.
	baseCtx := context.Background()
	var cancel context.CancelFunc
	if *timeout > 0 {
		baseCtx, cancel = context.WithTimeout(baseCtx, *timeout)
	} else {
		baseCtx, cancel = context.WithCancel(baseCtx)
	}
	defer cancel()

	// Trap SIGINT / SIGTERM for clean exit and TRACE rule cleanup.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-baseCtx.Done():
		}
	}()

	events, err := s.Start(baseCtx)
	if err != nil {
		return exitWith(output.NewInternalError("start trace session failed: "+err.Error(), ""))
	}
	defer s.Stop()

	// Build nft rule lookup cache for verbose human output (best-effort).
	// Allows RenderVerbosePacket to show the raw rule text next to each step.
	var ruleCache *tracer.RuleCache
	if verbose && selectedFormat != formatJSON {
		ruleCache = tracer.BuildRuleCache()
	}

	if !testMode {
		if verbose {
			fmt.Fprintf(os.Stderr, "Tracing packets — verbose mode (Ctrl+C to stop)...\n")
		} else {
			fmt.Fprintf(os.Stderr, "Tracing packets (Ctrl+C to stop)...\n")
		}
	}

	// ── Packet-grouping buffer ─────────────────────────────────────────────
	// Steps with the same TraceID belong to the same in-flight packet.
	// We accumulate them and emit a single summary (brief) or a full block
	// (verbose) when the packet traversal is complete.

	type pktBuf struct {
		traceID uint32
		pktNum  int
		steps   []model.TraceStep
	}

	var cur *pktBuf
	pktCount := 0
	count := 0

	flush := func(buf *pktBuf) {
		if buf == nil || len(buf.steps) == 0 {
			return
		}
		if verbose {
			os.Stdout.WriteString(output.RenderVerbosePacket(buf.steps, buf.pktNum, buf.traceID))
		} else {
			os.Stdout.WriteString(output.RenderBriefPacket(buf.steps))
		}
	}

	// addTimeToVerdict adds a leading timestamp for test-mode mock events that
	// lack a real TraceID so we still see something sensible.
	_ = time.Now // keep import used even if format changes

	for step := range events {
		count++

		// Annotate with raw rule text from the nft ruleset (verbose only).
		if ruleCache != nil && step.RawRule == "" {
			step.RawRule = ruleCache.Lookup(step.Table, step.Chain, step.RuleNumber)
		}

		// JSON streaming: emit each step immediately, no buffering.
		if selectedFormat == formatJSON {
			line, err := output.RenderStepNDJSON(step)
			if err != nil {
				return exitWith(output.NewInternalError("render step json failed: "+err.Error(), ""))
			}
			_, _ = os.Stdout.WriteString(line + "\n")
			continue
		}

		// Detect packet boundary: TraceID change (or first step).
		// TraceID==0 means the step doesn't carry an ID (legacy path / mock);
		// in that case we never split, treating all steps as one stream.
		newPkt := cur == nil || (step.TraceID != 0 && step.TraceID != cur.traceID)
		if newPkt {
			flush(cur)
			pktCount++
			cur = &pktBuf{traceID: step.TraceID, pktNum: pktCount}
		}
		cur.steps = append(cur.steps, step)

		// A DROP/REJECT is terminal: no further steps will arrive for this packet.
		// Flush immediately so the user sees the result without waiting for the
		// next packet to trigger a boundary.
		if step.Action == "DROP" || step.Action == "REJECT" {
			flush(cur)
			cur = nil
		}
	}
	// Flush any in-flight packet (e.g. ACCEPT or timeout mid-packet).
	flush(cur)

	if !testMode && count == 0 {
		fmt.Fprintf(os.Stderr, "No trace events received. Check that:\n")
		fmt.Fprintf(os.Stderr, "  1. xt_LOG / nfnetlink_log kernel module is loaded\n")
		fmt.Fprintf(os.Stderr, "  2. Matching traffic was generated during the trace window\n")
		fmt.Fprintf(os.Stderr, "  3. The filter flags (--src / --proto / --dport) match the actual traffic\n")
	}

	return output.ExitCodeOK
}



