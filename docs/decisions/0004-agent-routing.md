# ADR 0004：配置化代理与模型路由

状态：已接受

## 决策

项目级 custom agents 使用官方 `.codex/agents/*.toml`。默认路由：Sol 处理协调、
复杂判断、关键批判和报告；Terra 处理流量/源码/候选分析；Luna 处理去重、分类和
格式转换。可移植 `model_reasoning_effort` 只使用官方示例确认的 `high`/`medium`。

模型回退由 BudoBugs orchestration 显式尝试下一个路由并写 AuditEvent；不声称
Codex config 存在未公开的 fallback 键。

## 后果

quality-first 与 economy 路由是用户配置，不改变证据门。模型不可用会降级任务，
但不会把未完成判断标为通过。
