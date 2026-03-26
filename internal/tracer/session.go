package tracer

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"iptrace/pkg/model"
)

// SessionOptions configures a trace session.
type SessionOptions struct {
	TestMode bool
	Filter   TraceFilter // packet scope for TRACE rule injection (ignored in test mode)
}

// Session manages the lifecycle of a single trace session.
type Session struct {
	opt     SessionOptions
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
}

// NewSession creates a new, idle Session.
func NewSession(opt SessionOptions) *Session {
	return &Session{opt: opt}
}

// Start begins the trace session and returns a channel of TraceStep events.
// The channel is closed when the session ends.
func (s *Session) Start(ctx context.Context) (<-chan model.TraceStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil, errors.New("session already running")
	}

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.running = true

	events := make(chan model.TraceStep, 8)

	// ── Test mode ─────────────────────────────────────────────────────────────
	if s.opt.TestMode {
		go func() {
			defer close(events)
			step, _ := DecodeMockEvent("hook=PREROUTING table=raw chain=PREROUTING rule=1 action=CONTINUE")
			select {
			case events <- step:
			case <-runCtx.Done():
			}
		}()
		return events, nil
	}

	// ── Production path ────────────────────────────────────────────────────────

	// 1. Inject XT_TRACE rules into the raw table.
	if err := InjectTraceRule(s.opt.Filter); err != nil {
		cancel()
		s.running = false
		return nil, fmt.Errorf("inject XT_TRACE rule: %w", err)
	}

	// 2. Open listener appropriate for the detected iptables backend.
	//    - iptables-nft (nf_tables):  NFT_MSG_TRACE via NFNLGRP_NFTABLES
	//    - iptables-legacy:           NFLOG via NFNL_SUBSYS_ULOG
	isNFT := isNFTablesBackend()

	if isNFT {
		nl, err := openNFTTraceSocket()
		if err != nil {
			_ = CleanupTraceRule(s.opt.Filter)
			cancel()
			s.running = false
			return nil, fmt.Errorf("open NFT trace socket: %w", err)
		}
		go func() {
			defer func() {
				nl.Close()
				_ = CleanupTraceRule(s.opt.Filter)
				close(events)
			}()
			nl.ReadEvents(runCtx, events)
		}()
	} else {
		nl, err := openNFLOGSocket()
		if err != nil {
			_ = CleanupTraceRule(s.opt.Filter)
			cancel()
			s.running = false
			return nil, fmt.Errorf("open NFLOG socket: %w", err)
		}
		go func() {
			defer func() {
				nl.Close()
				_ = CleanupTraceRule(s.opt.Filter)
				close(events)
			}()
			nl.ReadEvents(runCtx, events)
		}()
	}

	return events, nil
}

// Stop cancels the running session.
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil
	}
	s.cancel()
	s.running = false
	time.Sleep(50 * time.Millisecond)
	return nil
}

// isNFTablesBackend returns true when the system iptables binary uses the
// nf_tables backend ("nf_tables" in `iptables --version` output).
func isNFTablesBackend() bool {
	out, err := exec.Command("iptables", "--version").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "nf_tables")
}


