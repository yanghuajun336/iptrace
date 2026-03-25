package output

func HintForError(kind string) string {
	switch kind {
	case "missing_rules_file":
		return "请确认 --rules-file 指向存在的 iptables-save 规则文件"
	case "missing_output_file":
		return "请使用 --output 指定导出文件路径，例如：iptrace export --output snapshot.rules"
	case "invalid_packet":
		return "请检查 --src/--dst/--proto/--sport/--dport 参数是否完整且格式正确"
	case "invalid_format":
		return "请使用 --format human 或 --format json"
	case "parse_rules_failed":
		return "请确认规则文件为有效的 iptables-save 格式并包含 COMMIT"
	case "trace_requires_root":
		return "请使用 sudo 重新执行 trace，或授予 CAP_NET_ADMIN 权限"
	case "unknown_subcommand":
		return "请运行 iptrace help 查看可用子命令与示例"
	default:
		return "请检查命令参数与运行环境后重试"
	}
}
