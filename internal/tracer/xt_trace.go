package tracer

// InjectTraceRule/ CleanupTraceRule 当前为占位实现。
// 后续将接入真实 iptables raw 表注入逻辑与异常清理逻辑。

func InjectTraceRule() error {
	return nil
}

func CleanupTraceRule() error {
	return nil
}
