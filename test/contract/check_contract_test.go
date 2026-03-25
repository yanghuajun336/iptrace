package contract

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckContract(t *testing.T) {
	t.Run("缺少 rules-file 参数返回输入错误", func(t *testing.T) {
		cmd := exec.Command("go", "run", "./cmd/iptrace", "check", "--src", "1.2.3.4", "--dst", "10.0.0.1", "--proto", "tcp", "--dport", "8080")
		cmd.Dir = projectRoot(t)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expect non-zero exit, got success: %s", string(out))
		}
	})

	t.Run("合法规则下输出 DROP 判决", func(t *testing.T) {
		rules := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP
COMMIT
`
		tmp := filepath.Join(t.TempDir(), "snapshot.rules")
		if err := os.WriteFile(tmp, []byte(rules), 0o644); err != nil {
			t.Fatalf("write temp rules failed: %v", err)
		}

		cmd := exec.Command("go", "run", "./cmd/iptrace", "check", "--src", "1.2.3.4", "--dst", "10.0.0.1", "--proto", "tcp", "--sport", "12345", "--dport", "8080", "--rules-file", tmp)
		cmd.Dir = projectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expect success, got err=%v, out=%s", err, string(out))
		}
		if !strings.Contains(string(out), "Verdict: DROP") {
			t.Fatalf("expect DROP verdict, got: %s", string(out))
		}
	})
}

func projectRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "../.."))
}
