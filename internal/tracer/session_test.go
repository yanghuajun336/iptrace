package tracer

import (
	"context"
	"testing"
	"time"
)

func TestSessionStartStop(t *testing.T) {
	s := NewSession(SessionOptions{TestMode: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, err := s.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	select {
	case <-events:
		// ok
	case <-ctx.Done():
		t.Fatal("expected at least one event")
	}

	if err := s.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}
