package tracer

import (
	"context"
	"errors"
	"sync"
	"time"

	"iptrace/pkg/model"
)

type SessionOptions struct {
	TestMode bool
}

type Session struct {
	opt     SessionOptions
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
}

func NewSession(opt SessionOptions) *Session {
	return &Session{opt: opt}
}

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
	go func() {
		defer close(events)
		if s.opt.TestMode {
			step, _ := DecodeMockEvent("hook=PREROUTING table=raw chain=PREROUTING rule=1 action=CONTINUE")
			events <- step
			return
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				step, _ := DecodeMockEvent("hook=INPUT table=filter chain=INPUT rule=0 action=CONTINUE")
				events <- step
			}
		}
	}()

	return events, nil
}

func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil
	}
	s.cancel()
	s.running = false
	return nil
}
