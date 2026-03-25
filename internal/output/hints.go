package output

func HintForError(kind string) string {
	switch kind {
	case "missing_rules_file":
		return "请确认 --rules-file 指向存在的 iptables-save 规则文件"
	case "invalid_packet":
		return "请检查 --src/--dst/--proto/--sport/--dport 参数是否完整且格式正确"
	case "parse_rules_failed":
		return "请确认规则文件为有效的 iptables-save 格式并包含 COMMIT"
	default:
		return "请检查命令参数与运行环境后重试"
	}
}
