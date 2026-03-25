package contract

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTraceContract(t *testing.T) {
	root := projectRoot(t)

	t.Run("非 root 且未显式允许时返回环境错误", func(t *testing.T) {
		cmd := exec.Command("go", "run", "./cmd/iptrace", "trace", "--src", "1.2.3.4")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "IPTRACE_FORCE_NOT_ROOT=1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expect non-zero exit, got success: %s", string(out))
		}
		if !strings.Contains(string(out), "requires root") {
			t.Fatalf("expect root hint, got: %s", string(out))
		}
	})

	t.Run("模拟模式可成功输出事件", func(t *testing.T) {
		cmd := exec.Command("go", "run", "./cmd/iptrace", "trace", "--src", "1.2.3.4")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "IPTRACE_TEST_MODE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expect success, got err=%v, out=%s", err, string(out))
		}
		if !strings.Contains(string(out), "PREROUTING") {
			t.Fatalf("expect trace output, got: %s", string(out))
		}
	})
}

func _unusedPath() string {
	return filepath.Join(".")
}
