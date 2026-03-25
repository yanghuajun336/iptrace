package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportThenCheck(t *testing.T) {
	root := projectRoot(t)
	outFile := filepath.Join(t.TempDir(), "snapshot.rules")

	exportCmd := exec.Command("go", "run", "./cmd/iptrace", "export", "--output", outFile)
	exportCmd.Dir = root
	exportCmd.Env = append(os.Environ(), "IPTRACE_TEST_MODE=1")
	if out, err := exportCmd.CombinedOutput(); err != nil {
		t.Fatalf("export failed: err=%v out=%s", err, string(out))
	}

	checkCmd := exec.Command("go", "run", "./cmd/iptrace", "check", "--src", "1.2.3.4", "--dst", "10.0.0.1", "--proto", "tcp", "--sport", "12345", "--dport", "8080", "--rules-file", outFile)
	checkCmd.Dir = root
	out, err := checkCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("check failed: err=%v out=%s", err, string(out))
	}
	if !strings.Contains(string(out), "Verdict: DROP") {
		t.Fatalf("expect DROP, got: %s", string(out))
	}
}
