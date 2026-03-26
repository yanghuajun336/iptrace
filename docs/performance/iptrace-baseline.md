# iptrace 性能基线

## 1. 基线来源

本基线来源于实现阶段的性能预算测试：

- `test/integration/perf_budget_test.go`
- 全量回归报告：`test/integration/test-report.txt`

## 2. 目标预算（来自规格）

- **SC-003**：在线追踪首条输出延迟 ≤ 3s
- **SC-006**：1000 条规则下单报文离线推演 ≤ 1s
- **SC-007**：在线追踪长时运行内存增长 ≤ 50MB（低流量场景基准）

## 3. 当前验证项

### 3.1 离线推演预算

测试：`TestOfflineCheck_PerfBudget1000Rules`

验证：

- 构造 1000+ 规则样本；
- 完成解析 + 推演；
- 断言总耗时不超过 1s。

结论：当前实现通过。

### 3.2 在线首条输出预算

测试：`TestTrace_FirstEventLatencyBudget`

验证：

- 启动会话；
- 读取首条事件；
- 断言首条事件延迟不超过 3s。

结论：当前实现通过。

### 3.3 内存增长预算

测试：`TestTrace_MemoryBudget`

验证：

- 启动受控追踪会话；
- 比较前后内存分配差值；
- 断言增长不超过 50MB。

结论：当前实现通过。

## 4. 使用方式

```bash
go test ./test/integration -run 'TestOfflineCheck_PerfBudget1000Rules|TestTrace_FirstEventLatencyBudget|TestTrace_MemoryBudget'
```

## 5. 后续维护

1. 每次追踪器或匹配器变更后必须重跑预算测试；
2. 若预算超限，需在 PR 中附优化说明或豁免记录；
3. 后续可补充长时 CPU 观测和真实内核环境基线。
