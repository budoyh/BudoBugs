# 威胁模型

## 资产与信任边界

受保护资产包括授权声明、Cookie/PAT/API key、原始流量、源码、未披露 finding、模型/工具输出、Docker volumes 和最终报告。目标页面、响应体、源码注释、导入 Skill、日志和第三方仓库均是不可信数据，不能改变 agent 或 shell 指令。

主要边界：用户与 `engagement.yaml`、本地 runtime 数据、工具子进程、代理/MCP、Docker lab、外部模型或 OOB 服务。跨越边界时只传递完成任务所需的脱敏最小数据。

## 主要威胁与控制

| 威胁 | 控制 | 残余风险 |
|---|---|---|
| prompt injection / 恶意目标内容 | 只将其作为数据；参数向量包装器；独立 critic | 人工复核仍必要。 |
| 越界请求/主动扫描 | engagement scope、模式策略、速率与能力限制 | 适配器实现/用户配置错误仍可能造成风险。 |
| secrets 进入日志或模型 | keyring/环境变量、redaction、Git ignore、数据处理策略 | 运行前必须人工检查输出范围。 |
| 容器逃逸/宿主机影响 | 无 Docker socket/home mount、cap drop、no-new-privileges、loopback/internal network、固定 image digest | Docker daemon 与第三方镜像本身仍是高信任运行时；需要持续更新和隔离。 |
| 伪 finding / 自动化幻觉 | 原始收据、负对照、证据门禁、critic | gate 不能证明外部证据本身真实。 |
| 供应链替换 | lockfile、固定 revision/checksum、镜像 digest、CycloneDX SBOM、raw scans、source-bound VEX、许可证 closure、provenance | 上游发布、漏洞数据库、规则和服务可变化；更新后必须重新生成证据。 |
