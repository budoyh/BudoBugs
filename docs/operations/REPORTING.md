# 报告生成与打包

报告只能从已存在的 finding 生成：

```bash
uv run budo findings validate <finding-id>
uv run budo report generate <finding-id> --platform butian
uv run budo report pack <finding-id>
```

`findings validate` 会从 finding pack 的当前工件重新计算 critic-confirmed Evidence Gate；失败或
缺少证据时不得通过改写报告文字绕过。`report generate` 默认平台为 `butian`，生成 Markdown、
HTML、finding JSON、evidence manifest 和人工复核清单。`report pack` 在创建 ZIP 前再次执行
证据一致性检查和自动 secret/PII scan；发现未脱敏内容时直接拒绝打包。

自动扫描不能判断所有业务敏感信息。人工复核仍须确认报告只包含最小证明、账号使用别名、
请求响应均在 scope、截图没有个人信息，并且 cleanup 状态真实。

生成不等于提交。目标项目的报告格式、加密上传、披露窗口、重复规则与自动化限制仍由人工负责。
