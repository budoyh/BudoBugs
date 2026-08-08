# 恢复与停止

`budo hunt <engagement> --resume` 用于从已有 engagement 恢复；先使用 `budo status` 和 `budo timeline` 确认 run 与工件，再决定是否恢复。不要删除 `runs/`、`findings/` 或 `.budobugs/` 来“修复”失败，除非任务所有者明确授权并已保存必要收据。

安全停止顺序：停止主动适配器/外部请求，执行 `budo lab down`（如适用），撤销暴露 token，记录 run id、错误、scope 和已执行动作。若有容器/镜像问题，保留 image tag/digest（若已知）与最小日志；不要改用 `latest` 覆盖证据。

`budo uninstall --keep-data --yes` 只清理 BudoBugs 专用工具目录并保留研究数据。它不是 Docker volume、云服务、账户或凭据的清理工具。
