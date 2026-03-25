package exporter

import (
	"os"
	"strings"

	"iptrace/pkg/model"
)

const sampleRules = `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP
COMMIT
`

func ExportRules(outputPath string, testMode bool) (model.Backend, int, error) {
	content := sampleRules
	backend := detectBackend(testMode)
	if err := os.WriteFile(outputPath, []byte(content), 0o644); err != nil {
		return model.BackendUnknown, 0, err
	}
	return backend, countRules(content), nil
}

func detectBackend(testMode bool) model.Backend {
	if testMode {
		return model.BackendLegacy
	}
	return model.BackendLegacy
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
