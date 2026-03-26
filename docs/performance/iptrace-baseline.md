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

### 3.4 长时运行预算（SC-007 补充验收）

脚本：`test/integration/sc007_longrun.sh`

产物：

- `test/integration/sc007-report.md`
- `test/integration/sc007-trace-output.log`

说明：

- 当前仓库内已提供可执行长时观测脚本；
- 在受限测试模式下可验证采样流程、报告格式与阈值计算；
- **600 秒 / 真实内核环境 / 真实 root 权限** 的最终基线仍需在线下或预发布环境复测后归档。

当前状态：**已建立流程，仓内样例报告为预演结果，不替代真实环境最终基线**。

## 4. 使用方式

```bash
go test ./test/integration -run 'TestOfflineCheck_PerfBudget1000Rules|TestTrace_FirstEventLatencyBudget|TestTrace_MemoryBudget'
./test/integration/sc007_longrun.sh
USE_TEST_MODE=0 DURATION_SEC=600 ./test/integration/sc007_longrun.sh
```

## 5. 后续维护

1. 每次追踪器或匹配器变更后必须重跑预算测试；
2. 若预算超限，需在 PR 中附优化说明或豁免记录；
3. 真实发布前必须至少执行一次 `USE_TEST_MODE=0 DURATION_SEC=600 ./test/integration/sc007_longrun.sh` 并归档报告；
4. 后续可补充更细粒度 CPU 曲线与真实内核环境基线。
