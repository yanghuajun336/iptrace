package output

import (
	"encoding/json"
	"fmt"
)

type ExportSummary struct {
	Status     string `json:"status"`
	Backend    string `json:"backend"`
	RuleCount  int    `json:"rule_count"`
	OutputFile string `json:"output_file"`
}

func RenderExportSummaryHuman(summary ExportSummary) string {
	return fmt.Sprintf("Exported %d rules from %s to %s", summary.RuleCount, summary.Backend, summary.OutputFile)
}

func RenderExportSummaryJSON(summary ExportSummary) (string, error) {
	data, err := json.Marshal(summary)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
