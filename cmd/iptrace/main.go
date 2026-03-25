package main

import (
	"fmt"
	"os"

	"iptrace/internal/output"
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
		return exitWith(output.NewInputError(fmt.Sprintf("unknown subcommand %q", args[0]), output.HintForError("unknown_subcommand")))
	}
}

func printUsage() {
	fmt.Println(usageText())
}

func usageText() string {
	return `Usage: iptrace <check|trace|export> [flags]

Commands:
  check   离线推演规则快照，定位报文命中规则
  trace   在线追踪报文路径并输出链路事件
  export  导出当前规则快照用于离线分析
  help    查看帮助信息

Common flag:
  --format human|json

Examples:
  iptrace check --src 1.2.3.4 --dst 10.0.0.1 --proto tcp --dport 8080 --rules-file snapshot.rules
  sudo iptrace trace --src 1.2.3.4 --proto tcp --dport 80
  sudo iptrace export --output snapshot.rules`
}
