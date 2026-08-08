# 上游评估

核验日期：2026-08-08（Asia/Shanghai）。本评估以官方仓库、官方文档、
LICENSE 和 GitHub release/API 为一手证据。第三方仓库中的提示词、Skill、
脚本和命令均按不可信数据处理，研究阶段未执行其代码。

## Codex 能力基线

| 能力 | 官方证据 | 对 BudoBugs 的结论 |
|---|---|---|
| Agent Skills | [Build skills](https://learn.chatgpt.com/docs/build-skills) | 仓库 Skill 放 `.agents/skills/`；`SKILL.md` 必须含 `name` 与 `description`，`agents/openai.yaml` 仅是可选 UI/依赖元数据。 |
| AGENTS.md | [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md) | 项目根规则与更近目录规则按根到 CWD 合并；它是指令层，不是 OS 权限边界。 |
| Custom subagents | [Subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents) | `.codex/agents/*.toml` 至少定义 `name`、`description`、`developer_instructions`；研究角色使用只读 sandbox。 |
| MCP | [MCP](https://learn.chatgpt.com/docs/extend/mcp) | 支持 stdio 与 Streamable HTTP；使用 tool allowlist、环境变量 token、localhost 监听和 fail-closed `required`。 |
| Codex SDK | [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk) | TypeScript SDK适合嵌入式 thread；Python SDK仍为 beta。核心系统以可审计 `codex exec --json` 适配器为稳定基线。 |
| 非交互与恢复 | [Non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode) | JSONL 事件、结构化输出、session resume 均有官方契约；BudoBugs 保存 thread id 与原始事件。 |
| 配置 | [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) | 官方没有公开的跨模型 fallback 键。BudoBugs 自己记录路由回退，不能把 transport retry 误称模型回退。 |

官方模型页确认 `gpt-5.6-sol`、`gpt-5.6-terra` 和 `gpt-5.6-luna`。
Codex CLI 配置可移植推理档采用 `high`/`medium`；产品界面的 `ultra` 或 API
的 `max` 不假定为所有 CLI 版本都接受。

## 漏洞研究方法与代理框架

| 上游 | 锁定身份 | 许可证 | 活跃度/安装 | 处理方式 |
|---|---|---|---|---|
| [MoonFuji/invariant-first-bug-bounty](https://github.com/MoonFuji/invariant-first-bug-bounty) | `e5af2d2179350fe49629f861b625523900854852` | MIT | 4 commits、无 release，维护样本小 | 仅吸收不变量、能力增量、负对照、反证、重复语义与证据门思想；BudoBugs 自行实现机械门禁。 |
| [yafet-dev/bugbounty-codex-skills](https://github.com/yafet-dev/bugbounty-codex-skills) | `32c45d5efc5069452b054b5b129f609296888b51` | NOASSERTION | 1 commit，无 LICENSE | 不复制、不分发；只把公开漏洞类别视为通用背景知识。 |
| [shaniidev/bug-reaper](https://github.com/shaniidev/bug-reaper) | `af84333a29699a52b9d23c271a437f503c697534` | MIT | 小型仓库 | 只吸收 Recon→Audit→Validate→Report 和误报排除方法。 |
| [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) | `45eb49b370dcc5cd19268acf958c8119dbe2afbe`, release `v4.0.0` | MIT，另有 TERMS | 活跃、安装器会引入大量工具/API | extended/lab-ai 方法参考；不执行其安装器。 |
| [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | `e8b1bb77d1ac00329675cec3b060aba971ec1ac8` | MIT | Python 3.12+/uv；可容器化 | lab-ai 外部适配；吸收阶段产物、会话恢复、工具记录，默认关闭遥测。 |
| [usestrix/strix](https://github.com/usestrix/strix) | `f8a8801d5672529ddf66271415ed3ec379186842` | Apache-2.0 | 活跃；Docker sandbox 与模型 key | lab-ai 隔离适配；结果仍经 BudoBugs validator/critic。 |
| [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) | `760a1402287bd67e568405141dda43016f339a80` | AGPL-3.0 | 活跃，TypeScript/pnpm/Docker | 仅外部容器或思想吸收，绝不复制进 core。 |
| [aliasrobotics/CAI](https://github.com/aliasrobotics/CAI) | `62871b6f5a4b8951b2f4dd94dbb301ac306b3a65` | MIT 源码；外部服务另有条款 | 活跃，PyPI/多 provider | lab-ai；区分开源代码与私有服务许可。 |
| [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | `d689933ff579d839c676c82b231f8e98326c5f04` | MIT | 150+ 工具、任意命令路由、已有安全议题 | 高风险 lab-ai；不暴露任意命令接口，只吸收 capability manifest/health 思想。 |
| [telmon95/VulneraMCP](https://github.com/telmon95/VulneraMCP) | `0dd7eed838d3740d4eda592803368138aad28bda` | MIT | Node/Docker/PostgreSQL | lab-ai；外部进程适配，敏感流量库与工具链隔离。 |
| [zebbern/zebbern-kali-mcp](https://github.com/zebbern/zebbern-kali-mcp) | `30190b5a707985a06d724a1cbc4f9eb2fa1e3b8c` | NOASSERTION | 含任意命令、VPN、pivot、reverse shell | 不纳入；权利和安全边界均不满足。 |

## 代理与流量上游

| 上游 | 锁定身份 | 许可证 | 结论 |
|---|---|---|---|
| [caido/skills](https://github.com/caido/skills) | `95c91ed77cb0ed7c3b3337c396866ffc30d687f9` | MIT | extended，可选安装；真实流量/PAT 不进入 Git 或模型上下文。 |
| [caido/sdk-js](https://github.com/caido/sdk-js) | `1bdd37ddefdea728b3b8da646a25429892f9bb8e` | MIT | extended，受控 adapter 优先使用官方 SDK。 |
| [c0tton-fluff/caido-mcp-server](https://github.com/c0tton-fluff/caido-mcp-server) | `c2d71ebd815e0383ad31eff3e4f5ec0f3738fa08` | MIT | 社区项目，不是 Caido 官方 MCP；仅作兼容适配参考。 |
| [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) | `5f76126409780ecba2b766c7f7388f465c5b5f94`, `v1.3.0` | GPL-3.0 | 官方 Burp BApp/MCP；仅 localhost 进程外接入，不复制 GPL 源码。 |
| [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) | ZAP stable add-on，源码在 `zap-extensions/addOns/automation` | Apache-2.0 | extended executor；可吸收 YAML plan、job tests 和 exit status，但扫描告警不是 finding 证据。 |

## 供应链决定

1. release asset 使用官方 URL、固定 tag，并在安装时校验上游发布的 checksum；
   没有上游 checksum 时由安装收据记录下载源、大小和本地计算值，状态为
   `QUALIFIED` 而非签名验证通过。
2. 容器使用 tag 加 manifest digest；未取得 digest 时 doctor 返回
   `NEEDS_RUNTIME`/`UNVERIFIED_IMAGE`，不能自动拉取 `latest`。
3. Nuclei templates、漏洞数据库、Semgrep rules 和 Playwright browser revision
   是独立制品，必须随更新收据冻结。
4. 任何 NOASSERTION 内容都不复制；GPL/AGPL 只通过进程/容器边界连接。

## 研究局限

- HEAD 和 release 是 2026-08-08 快照，更新前须重新核验。
- 仓库许可证不覆盖全部传递依赖、容器基础镜像、数据库、浏览器组件或商业服务条款。
- 未运行第三方安装器；运行兼容性由 tool installer healthcheck 和 lab receipt
  独立判定。
