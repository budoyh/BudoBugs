# 许可证矩阵

核验快照：2026-08-09。表中 SPDX/条款来自固定版本的上游 LICENSE 或包元数据，不自动
覆盖传递依赖、规则库、漏洞数据库、镜像层和商业服务。BudoBugs 源码为 Apache-2.0；
第三方组件不因接入而被重新授权。

## 发布内生产依赖

| 范围 | 固定依据 | 许可证证据 | 发布处理 |
|---|---|---|---|
| Python production | `uv.lock` | `release/licenses/python-production.json`：57 个包，0 unresolved | Wheel/source 分发时保留适用的 LICENSE/NOTICE。 |
| Node production | `pnpm-lock.yaml` | `release/licenses/node-production.json`：16 个包，0 unresolved | 包含 Codex 全平台 optional package family；保留适用 notice。 |
| Source SBOM | release source tree | `release/sbom/source.cdx.json` | CycloneDX 组件清单；不替代许可证清单。 |
| Playwright | 1.62.0，Apache-2.0 | Python 包元数据和上游 NOTICE | 运行时依赖。 |
| Chromium | Playwright revision，多许可证 | Playwright 下载制品自带 notices | 用户本地下载；不装入 BudoBugs wheel/source。独立再分发时另审。 |
| Caido SDK | `@caido/sdk-client` 0.5.0，MIT | Node 生产清单 | 可选本地适配；Caido 产品条款另计。 |
| Codex SDK/CLI packages | 0.147.0，Apache-2.0 | Node 生产清单 | 可选 integration；模型/API 服务条款另计。 |

发布验证器从两个 lockfile 独立重建 production closure，逐项比对名称、版本、重复项和
许可证解析状态；不能用手写汇总替代机器清单。生成器遇到当前 OS 未安装的条件依赖时，
只允许复用清单中名称、锁定版本和已解析许可证完全匹配的记录，并标记元数据来源；版本
变化或许可证未解析都会失败，不能以平台差异缩小闭包。

## 用户级外部工具

| 组件/家族 | SPDX/条款 | 接入方式 | 复制/分发决策 |
|---|---|---|---|
| ProjectDiscovery：subfinder、dnsx、httpx、katana、urlfinder、nuclei、interactsh-client | MIT | 固定版本外部二进制 | 不复制源码；用户级安装，保留上游许可。 |
| gau、ffuf、feroxbuster、Dalfox、mitmproxy、Gitleaks、yq | MIT | 固定版本外部 CLI | 不打包进 wheel；独立二进制保留许可。 |
| waybackurls | Unlicense | 固定 commit/version 外部 CLI | 允许使用；安装时保留上游声明。 |
| Arjun | AGPL-3.0 | 独立 `uv tool` venv/进程 | 不并入 core 源码或发行镜像。 |
| Semgrep CE | LGPL-2.1 | 独立 CLI/WSL venv | 不复制源码，不混淆 Pro 条款。 |
| Trivy、OSV-Scanner、Syft、Grype | Apache-2.0 | 外部 release 工具 | 不打包；数据库和规则另行适用其条款。 |
| jq | MIT，含 ICU/文档 notices | 固定 release 二进制 | 保留 bundled notices。 |
| ripgrep | MIT OR Unlicense | 固定 release 二进制 | 选择 MIT。 |
| fd | MIT OR Apache-2.0 | 固定 release 二进制 | 选择 MIT。 |
| Miller | BSD-2-Clause | 固定 release 二进制 | 保留 BSD 声明。 |
| SQLite | Public Domain | Python sqlite3 / 可选 CLI | 允许；不把 SQLite CLI 重新授权。 |

## 代理、框架和商业边界

| 组件 | SPDX/条款 | BudoBugs 处理 |
|---|---|---|
| Caido Skills/SDK | MIT | 只接官方 SDK；社区 MCP 仅兼容性研究，不宣称官方。PAT/产品条款另计。 |
| Burp MCP | GPL-3.0 | 用户在自行许可的 Burp 中安装官方 BApp；BudoBugs 仅连接 localhost MCP，不重分发。 |
| OWASP ZAP | Apache-2.0 | 固定 digest 外部容器/进程；add-ons 和层 notice 保持独立。 |
| invariant-first | MIT | 只 clean-room 吸收通用证据方法，来源记录在 architecture influences。 |
| bugbounty-codex-skills | NOASSERTION | 不复制、不形成依赖。 |
| BugReaper | MIT | 只吸收通用误报排除与报告思想。 |
| claude-bug-bounty | MIT + TERMS | 只作方法研究；额外 TERMS 仍适用。 |
| PentestGPT | MIT | 外部 lab-ai 进程；缺模型 key 时 `NEEDS_CREDENTIAL`。 |
| Strix | Apache-2.0 | 外部 lab-ai 容器/进程。 |
| Shannon | AGPL-3.0 / 商业双轨 | 外部 lab-only 边界，不复制源码。 |
| CAI | MIT 源码 + 服务条款 | 开源运行时与私有服务条款分层。 |
| HexStrike AI | MIT | 外部 lab-only；固定 commit、锁依赖、loopback 补丁和受限 API。已有真实 localhost receipt。 |
| VulneraMCP | MIT | 外部 lab-ai 进程；不复制。 |
| zebbern-kali-mcp | audit-required / NOASSERTION | 禁止自动安装和纳入发行。 |

## Docker runtime 镜像

| 镜像家族 | 根项目许可证边界 | 当前处理 |
|---|---|---|
| Juice Shop 20.1.1 | MIT；层/依赖独立 | `tag@sha256`，隔离训练运行时，不嵌入发行物。 |
| WebGoat 2025.3 | GPL-2.0-or-later；层独立 | `tag@sha256`，runtime-only；独立再分发需履行 GPL/source 义务。 |
| crAPI 1.1.6 | Apache-2.0 根项目；MailHog/层独立 | 各组件 `tag@sha256`，runtime-only。 |
| Alpine / PostgreSQL / MongoDB / Chroma | 多组件 / PostgreSQL License / SSPL-1.0 server / Apache-2.0 | 固定 digest 的支撑镜像；不装入 BudoBugs 发行物。 |
| ZAP 2.17.0 | Apache-2.0；add-ons/层独立 | 固定 digest，runtime-only。 |
| BudoBugs fixture / loopback proxy | Apache-2.0 仓库源码；固定基础镜像 | 本地构建。fixture 有 Trivy、raw Grype、source-bound OpenVEX 和 provenance。 |

Compose 的所有外部镜像必须带 64 位 manifest digest；发布验证器机械拒绝裸 tag。镜像层
许可证不能由根项目 LICENSE 推定。BudoBugs 不分发这些第三方 runtime 镜像；若用户制作
离线镜像包或二次分发，必须单独生成层级 SBOM/notice 并履行上游义务。

## 直接复用与证据边界

BudoBugs 没有复制上述框架的源码、提示词或 payload 集合。固定 commit、许可证、活跃度、
供应链风险和最终接入决策见 [UPSTREAM_EVALUATION](UPSTREAM_EVALUATION.md)；实际发布边界见
[THIRD_PARTY_NOTICES](../../THIRD_PARTY_NOTICES.md)。许可证清单、SBOM、安全报告、VEX、
HexStrike receipt 和 provenance 均由 `scripts/verify_release.py` 校验。服务条款、目标授权、
漏洞披露责任和商业许可证仍需用户本人确认。
