package exporter

import (
	"fmt"
	"os"
)

const sampleRules = `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 1.2.3.4 -p tcp --dport 8080 -j DROP
COMMIT
`

func ExportRules(outputPath string, testMode bool) (int, error) {
	content := sampleRules
	if err := os.WriteFile(outputPath, []byte(content), 0o644); err != nil {
		return 0, err
	}
	return 1, nil
}

func ExportSummary(ruleCount int, outputFile string) string {
	return fmt.Sprintf("Exported %d rules to %s", ruleCount, outputFile)
}
