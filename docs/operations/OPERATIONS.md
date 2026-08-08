# 日常运行

先执行 `uv run budo doctor --json`，保存其输出为环境事实。状态含义：`PASS` 为该检查实际成功；`NEEDS_RUNTIME`、`NEEDS_CREDENTIAL`、`NEEDS_LICENSE`、`UNSUPPORTED` 为缺少前置条件；`FAIL` 为检查失败。不要用文档、配置或自报 PASS 代替收据。

使用 `budo tools list --profile core|extended|lab-ai` 查看登记，而不是假设工具已安装。`budo tools update --dry-run` 只输出人工审查提示，不会更新。`budo tools clean --yes` 和 `budo lab clean --yes` 有删除效果，运行前确认范围。

运行后使用 `budo status <engagement>`、`budo timeline <engagement>`、`budo findings list <engagement>` 查看恢复状态。发生错误时保留最小日志和 run id，参见 [故障排查](../tutorials/TROUBLESHOOTING.md)。
