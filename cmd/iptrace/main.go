package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(runArgs(os.Args[1:]))
}

func runArgs(args []string) int {
	if len(args) < 1 {
		printUsage()
		return 1
	}

	switch args[0] {
	case "check":
		return runCheck(args[1:])
	case "trace":
		return runTrace(args[1:])
	case "export":
		return runExport(args[1:])
	case "-h", "--help", "help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "error: unknown subcommand %q\n", args[0])
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Println("Usage: iptrace <check|trace|export> [flags]")
}
