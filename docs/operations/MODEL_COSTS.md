# 模型成本与外部服务

模型、OOB、云扫描器、代理和漏洞数据库可能产生费用、速率限制、数据传输和服务条款义务。`config/defaults.yaml` 的 token budget 是本地配置上限，不是价格估算、费用承诺或供应商配额。

Hunt 默认使用 `agent_mode=disabled`。启用 Codex advisory 前先检查预算上界；dry-run 不创建
run/cost 记录、不启动 hunt、也不访问 target（CLI 仍会初始化本地状态目录/SQLite）：

```powershell
uv run budo hunt <engagement-id> --agent-mode codex --dry-run --json
uv run budo hunt <engagement-id> --agent-mode codex --json
```

dry-run 不猜测 provider 美元价格；有模型调用时 `estimated_cost_usd` 为 `null`，实际账单仍以
provider 收据为准。每个确定性阶段都会写本地耗时和零模型 token 记录；实际 advisory 另写
模型、thread、token、缓存、耗时和 JSONL 事件。Codex CLI 同时接收任务专用 JSON Schema；
同一 run 内完全相同且已成功的 advisory 由输入摘要、路由和推理强度生成缓存键，命中时写
`CACHE_HIT` 且不会产生新的模型调用或 CostRecord。模型不可用或输出非 JSON 时保存
`DEGRADED`/`INVALID_OUTPUT` 工件并继续确定性流程，不伪造成功。

AI 只提供受约束 advisory：候选排序必须是全部现有 hypothesis ID 的精确排列；独立 critic
可以否决确定性的 `CONFIRMED`，却不能将 `HOLD/KILL` 升级。Evidence Gate、scope、负对照和
人工提交边界始终由本地确定性代码控制。

使用前：选择批准的 provider/model，设置项目范围内的预算，最小化输入，记录 provider、模型、请求类别、时间和实际用量收据。密钥仅放环境变量或系统 keyring；不要写入 engagement、报告、HAR、Git 或聊天记录。

HexStrike 的 bounded localhost 适配器已完成无模型凭据的实际验证；这不证明其他 lab-ai 或其
模型计费路径可用。PentestGPT、Strix、Shannon、CAI 和 VulneraMCP 只有在隔离实验、真实
health receipt 和用户明确承担 provider/工具成本时才启用；出现预算、数据驻留或服务条款
不确定时停止。
