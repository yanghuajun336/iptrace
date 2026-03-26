package integration

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"iptrace/internal/matcher"
	"iptrace/internal/parser"
	"iptrace/internal/tracer"
	"iptrace/pkg/model"
)

func TestOfflineCheck_PerfBudget1000Rules(t *testing.T) {
	var b strings.Builder
	b.WriteString("*filter\n:INPUT ACCEPT [0:0]\n")
	for i := 1; i <= 1000; i++ {
		fmt.Fprintf(&b, "-A INPUT -s 10.0.0.%d -p tcp --dport %d -j ACCEPT\n", (i%250)+1, 1000+i)
	}
	b.WriteString("-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP\nCOMMIT\n")

	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 12345, DstPort: 8080}

	start := time.Now()
	ruleset, err := parser.ParseIPTablesSave(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parse rules failed: %v", err)
	}
	ruleset.Backend = model.BackendLegacy
	result, err := matcher.Simulate(packet, ruleset)
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	elapsed := time.Since(start)

	if result.Verdict != "DROP" {
		t.Fatalf("expect DROP verdict, got %s", result.Verdict)
	}
	if elapsed > time.Second {
		t.Fatalf("offline simulate exceeded budget: %s", elapsed)
	}
}

func TestTrace_FirstEventLatencyBudget(t *testing.T) {
	session := tracer.NewSession(tracer.SessionOptions{TestMode: true})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	events, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("start trace session failed: %v", err)
	}
	defer session.Stop()

	step, ok := <-events
	if !ok {
		t.Fatal("expect at least one trace step")
	}
	if step.HookPoint == "" {
		t.Fatal("expect trace step hook point")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("first event exceeded budget: %s", elapsed)
	}
}

func TestTrace_MemoryBudget(t *testing.T) {
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	session := tracer.NewSession(tracer.SessionOptions{TestMode: true})
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	events, err := session.Start(ctx)
	if err != nil {
		t.Fatalf("start trace session failed: %v", err)
	}

	count := 0
	for range events {
		count++
	}
	if err := session.Stop(); err != nil {
		t.Fatalf("stop trace session failed: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if count == 0 {
		t.Fatal("expect trace session to emit events")
	}
	delta := int64(after.Alloc) - int64(before.Alloc)
	if delta < 0 {
		delta = 0
	}
	if delta > 50*1024*1024 {
		t.Fatalf("memory growth exceeded budget: %d bytes", delta)
	}
}

func BenchmarkOfflineCheck1000Rules(b *testing.B) {
	var rules strings.Builder
	rules.WriteString("*filter\n:INPUT ACCEPT [0:0]\n")
	for i := 1; i <= 1000; i++ {
		fmt.Fprintf(&rules, "-A INPUT -s 10.0.0.%d -p tcp --dport %d -j ACCEPT\n", (i%250)+1, 1000+i)
	}
	rules.WriteString("-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP\nCOMMIT\n")

	packet := model.Packet{Protocol: "tcp", SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 12345, DstPort: 8080}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ruleset, err := parser.ParseIPTablesSave(strings.NewReader(rules.String()))
		if err != nil {
			b.Fatalf("parse rules failed: %v", err)
		}
		ruleset.Backend = model.BackendLegacy
		if _, err := matcher.Simulate(packet, ruleset); err != nil {
			b.Fatalf("simulate failed: %v", err)
		}
	}
}
