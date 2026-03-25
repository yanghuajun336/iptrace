package main

import (
	"flag"
	"fmt"
	"os"

	"iptrace/internal/exporter"
	"iptrace/internal/output"
)

func runExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	outFile := fs.String("output", "", "output rules file")
	format := fs.String("format", "human", "output format: human|json")
	_ = fs.Parse(args)

	if *outFile == "" {
		fmt.Fprintln(os.Stderr, "error: --output is required")
		return output.ExitCodeInputError
	}

	testMode := os.Getenv("IPTRACE_TEST_MODE") == "1"
	ruleCount, err := exporter.ExportRules(*outFile, testMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: export failed: %v\n", err)
		return output.ExitCodeInternalErr
	}

	if *format == "json" {
		fmt.Printf("{\"status\":\"ok\",\"rule_count\":%d,\"output_file\":%q}\n", ruleCount, *outFile)
		return output.ExitCodeOK
	}

	fmt.Println(output.RenderExportSummaryHuman(ruleCount, *outFile))
	return output.ExitCodeOK
}
