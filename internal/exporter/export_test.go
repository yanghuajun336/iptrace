package exporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportRules(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "snapshot.rules")
	backend, n, err := ExportRules(outFile, true)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if backend == "" {
		t.Fatal("expect backend to be detected")
	}
	if n == 0 {
		t.Fatalf("expect rule count > 0")
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output failed: %v", err)
	}
	if !strings.Contains(string(data), "*filter") {
		t.Fatalf("expect iptables-save format, got: %s", string(data))
	}
}
