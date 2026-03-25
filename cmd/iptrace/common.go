package main

import (
	"flag"
	"io"
	"os"
	"strings"

	"iptrace/internal/output"
)

const (
	formatHuman = "human"
	formatJSON  = "json"
)

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFormat(value string) (string, error) {
	switch strings.ToLower(value) {
	case "", formatHuman:
		return formatHuman, nil
	case formatJSON:
		return formatJSON, nil
	default:
		return "", output.NewInputError("unsupported --format value", output.HintForError("invalid_format"))
	}
}

func exitWith(err error) int {
	return output.WriteError(os.Stderr, err)
}

func testModeEnabled() bool {
	return os.Getenv("IPTRACE_TEST_MODE") == "1"
}

func forceNotRoot() bool {
	return os.Getenv("IPTRACE_FORCE_NOT_ROOT") == "1"
}
