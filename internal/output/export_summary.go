package output

import "fmt"

func RenderExportSummaryHuman(ruleCount int, outputFile string) string {
	return fmt.Sprintf("Exported %d rules to %s", ruleCount, outputFile)
}
