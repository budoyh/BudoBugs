# 故障排查

| 现象 | 先做什么 | 不应做什么 |
|---|---|---|
| Docker 不可用 | `budo lab up --native-only`，保留 `NEEDS_RUNTIME` | 不启用系统功能、重启或拉取未知镜像。 |
| `lab up` 失败 | `budo lab status --json`；检查 Docker daemon 与 compose 输出 | 不把失败的镜像 tag 改为 `latest`。 |
| Caido/Burp/ZAP 未就绪 | `budo proxy doctor --json`；复核 [MANUAL_ONCE](../MANUAL_ONCE.md) | 不粘贴 PAT、Cookie 或 GUI 导出的配置。 |
| report 被拒绝 | `budo findings validate <id>`，补足所列证据 | 不改写断言来满足 gate。 |
| 工具缺少 | `budo tools health --profile <name>` | 不把缺 runtime/credential/license 视为 PASS。 |
| 不确定是否能恢复 | `budo status <engagement>` 与 `budo timeline <engagement>` | 不删除运行目录。 |

若 CLI 崩溃，记录命令、退出码、BudoBugs 版本、OS、run id 和已脱敏的末尾错误。不要把目标响应或完整 token 贴到 issue。
