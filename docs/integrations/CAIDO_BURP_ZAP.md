# Caido、Burp 与 ZAP 边界

三者都是 optional extended integration，不是 finding 证据来源。先创建并授权 engagement，随后才可在其 scope 内导入或读取数据。

| 集成 | 上游和许可证 | 当前 BudoBugs 接口 | 状态边界 |
|---|---|---|---|
| Caido | 锁定的官方 `@caido/sdk-client`，MIT；社区 MCP 非官方 | `caido-configure` 将 PAT 存 keyring；doctor 实际调用 SDK health，search/get/replay/export 统一归一化 | PAT 不入 Git/模型；control plane 默认只允许 loopback。 |
| Burp MCP | PortSwigger 官方 BApp，GPL-3.0 | localhost `127.0.0.1:9876/mcp` initialize/list tools；history、HTTP/1.1/2 replay、Repeater 和 export 按 capability 调用 | 用户自行安装/许可；不复制或重分发 GPL 代码。 |
| ZAP | ZAP 2.17.0/Automation Framework，Apache-2.0 | 固定 digest，localhost `127.0.0.1:8090` version/history/replay/export；`lab zap-scan` 运行真实作业 | Automation plan 仅指向 Docker fixture；alert 须经 BudoBugs 证据门。 |

不要以代理 UI 已打开、端口已监听或 health 成功推断写操作、scan scope 或报告资格已获授权。
