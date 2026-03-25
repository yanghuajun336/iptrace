package contract

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportContract(t *testing.T) {
	root := projectRoot(t)

	t.Run("缺少 output 参数返回输入错误", func(t *testing.T) {
		cmd := exec.Command("go", "run", "./cmd/iptrace", "export")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expect non-zero exit, got success: %s", string(out))
		}
		if !strings.Contains(string(out), "hint:") {
			t.Fatalf("expect actionable hint, got: %s", string(out))
		}
	})

	t.Run("导出规则快照成功", func(t *testing.T) {
		outFile := filepath.Join(t.TempDir(), "snapshot.rules")
		cmd := exec.Command("go", "run", "./cmd/iptrace", "export", "--output", outFile)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "IPTRACE_TEST_MODE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expect success, got err=%v, out=%s", err, string(out))
		}
		if _, err := os.Stat(outFile); err != nil {
			t.Fatalf("expect output file exists: %v", err)
		}
		if !strings.Contains(string(out), "Exported") {
			t.Fatalf("unexpected output: %s", string(out))
		}
	})

	t.Run("JSON 导出摘要包含 backend 字段", func(t *testing.T) {
		outFile := filepath.Join(t.TempDir(), "snapshot.rules")
		cmd := exec.Command("go", "run", "./cmd/iptrace", "export", "--output", outFile, "--format", "json")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "IPTRACE_TEST_MODE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expect success, got err=%v, out=%s", err, string(out))
		}

		var payload map[string]any
		if err := json.Unmarshal(out, &payload); err != nil {
			t.Fatalf("expect valid json, got err=%v, out=%s", err, string(out))
		}
		if payload["backend"] != "iptables-legacy" {
			t.Fatalf("expect backend field, got: %v", payload)
		}
	})
}
