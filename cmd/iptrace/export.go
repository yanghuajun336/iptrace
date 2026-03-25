package main

import (
	"os"

	"iptrace/internal/exporter"
	"iptrace/internal/output"
)

func runExport(args []string) int {
	fs := newFlagSet("export")
	outFile := fs.String("output", "", "output rules file")
	format := fs.String("format", "human", "output format: human|json")
	if err := fs.Parse(args); err != nil {
		return exitWith(output.NewInputError(err.Error(), output.HintForError("missing_output_file")))
	}
	selectedFormat, err := parseFormat(*format)
	if err != nil {
		return exitWith(err)
	}

	if *outFile == "" {
		return exitWith(output.NewInputError("--output is required", output.HintForError("missing_output_file")))
	}

	backend, ruleCount, err := exporter.ExportRules(*outFile, testModeEnabled())
	if err != nil {
		return exitWith(output.NewInternalError("export failed: "+err.Error(), ""))
	}
	summary := output.ExportSummary{Status: "ok", Backend: string(backend), RuleCount: ruleCount, OutputFile: *outFile}

	if selectedFormat == formatJSON {
		text, err := output.RenderExportSummaryJSON(summary)
		if err != nil {
			return exitWith(output.NewInternalError("render export summary failed: "+err.Error(), ""))
		}
		_, _ = os.Stdout.WriteString(text + "\n")
		return output.ExitCodeOK
	}

	_, _ = os.Stdout.WriteString(output.RenderExportSummaryHuman(summary) + "\n")
	return output.ExitCodeOK
}
