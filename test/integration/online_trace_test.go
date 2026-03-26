package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnlineTrace_WithMockEvents(t *testing.T) {
	cmd := exec.Command("go", "run", "./cmd/iptrace", "trace", "--src", "1.2.3.4")
	cmd.Dir = projectRoot(t)
	cmd.Env = append(os.Environ(), "IPTRACE_TEST_MODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expect success, got err=%v, out=%s", err, string(out))
	}
	text := string(out)
	// In brief mode the mock event is rendered as a single ACCEPT verdict line.
	if !strings.Contains(text, "ACCEPT") {
		t.Fatalf("expect ACCEPT in trace output, got: %s", text)
	}
}

func _unused() string {
	return filepath.Join(".")
}
