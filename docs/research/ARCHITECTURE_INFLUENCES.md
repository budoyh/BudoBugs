# 架构影响与 clean-room 边界

## 采纳的设计思想

- **Invariant-First**：候选从安全不变量、信任边界、执行点和能力增量开始；
  Gate 必须有正常/负对照、最强正常解释与反证。
- **BugReaper/公开报告方法**：理论候选先排误报，事实、推断和未验证内容分层；
  报告第一句陈述已证明能力，不靠扫描器严重度。
- **PentestGPT**：阶段输出落盘、会话可恢复、主协调器只保留结构化摘要。
- **Strix/Shannon/CAI**：并行 specialist、工作 PoC、对抗批判和模型路由；
  BudoBugs 不继承其自主利用权限。
- **HexStrike/VulneraMCP**：工具 capability manifest 与 MCP 编排；BudoBugs
  去除任意命令面，由 registry 与 policy 注入 engagement target。
- **Caido/Burp/ZAP**：统一历史查询、Replay、单请求、导出和 evidence reference；
  proprietary/GPL 部分留在进程外。
- **ProjectDiscovery**：小工具可组合，但由 coordinator 按信息增益选择，不做
  “全部跑一遍”。

## BudoBugs 自有统一层

```text
engagement authorization
        |
scope + mode policy
        |
phase DAG ---- immutable JSONL events ---- SQLite materialized state
        |
typed tool registry -> no-shell wrapper -> normalized artifact receipt
        |
traffic/object/state model -> hypotheses -> controlled validation
        |
negative control -> refutation -> evidence gate -> independent critic
        |
submission-ready report (human review only)
```

所有状态、Schema、工具参数、收据、门禁、critic 和报告生成器均为本仓库
clean-room 实现。上游自报 `PASS`、扫描器结果或 prompt 文本不能改变状态机。

## 未采纳

- 无 engagement 的任意目标发现与自动扩散。
- agent 直接拼 shell 或从响应正文生成命令。
- 自动提交 SRC 报告。
- program 模式默认调用全自动利用框架。
- 把 proprietary、GPL/AGPL 或 NOASSERTION 源码复制进 core。
- 用 mock/self-report 代替本地真实请求、进程退出码和 artifact receipt。
