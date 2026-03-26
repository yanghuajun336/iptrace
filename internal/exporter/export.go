package exporter

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"iptrace/pkg/model"
)

const sampleRules = `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP
COMMIT
`

func ExportRules(outputPath string, testMode bool) (model.Backend, int, error) {
	content, backend, err := exportContent(testMode)
	if err != nil {
		return model.BackendUnknown, 0, err
	}
	if err := os.WriteFile(outputPath, []byte(content), 0o644); err != nil {
		return model.BackendUnknown, 0, err
	}
	return backend, countRules(content), nil
}

func exportContent(testMode bool) (string, model.Backend, error) {
	if testMode {
		return sampleRules, model.BackendLegacy, nil
	}

	if out, err := runCommand("iptables-save"); err == nil && strings.TrimSpace(out) != "" {
		return out, model.BackendLegacy, nil
	}

	if out, err := runCommand("iptables-nft-save"); err == nil && strings.TrimSpace(out) != "" {
		return out, model.BackendNFT, nil
	}

	return "", model.BackendUnknown, fmt.Errorf("no supported rules export command found (iptables-save/iptables-nft-save)")
}

func runCommand(name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func countRules(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-A ") {
			count++
		}
	}
	return count
}
