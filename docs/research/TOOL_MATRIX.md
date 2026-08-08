# 工具矩阵

版本核验日期：2026-08-08。锁定值同时维护在
`tools/lock/tool-lock.yaml`；该文件是执行器的机械输入，本表是审计说明。

## Core profile

| 工具 | 固定版本 | 许可证 | 平台 | 最小 healthcheck | 网络/变更边界 |
|---|---|---|---|---|---|
| Python | 3.12 | PSF | Windows/WSL/Linux | `python --version` 且主次版本为 3.12 | 仓库 `.venv`，不改系统 Python |
| uv | 0.11.26 环境基线 | Apache-2.0/MIT | Windows/WSL/Linux | `uv --version` | 依赖只按 `uv.lock` |
| Node.js | 24.14.0 环境基线 | MIT | Windows/WSL/Linux | `node --version` | 不运行不可信 lifecycle script |
| pnpm | 11.1.3 环境基线 | MIT | Windows/WSL/Linux | `pnpm --version` | frozen lockfile |
| Go | 1.26.5 | BSD-3-Clause | Windows/WSL/Linux | `go version` + 固定模块 smoke | 仅向 BudoBugs 用户目录安装工具 |
| Docker | Windows CLI 29.7.2 / WSL Engine 29.1.3 | Apache-2.0 | Windows/WSL/Linux | engine info + Compose config + 实际容器 health | 不挂 Docker socket/home；不启 privileged |
| jq | jq-1.8.2 | MIT + bundled notices | Windows/WSL/Linux | `jq --version` | 本地数据转换 |
| yq | v4.53.3 | MIT | Windows/WSL/Linux | `yq --version` | 默认只读 |
| ripgrep | 15.2.0 | MIT/Unlicense | Windows/WSL/Linux | `rg --version` | 本地枚举 |
| fd | v10.4.2 | MIT/Apache-2.0 | Windows/WSL/Linux | `fd --version` | 本地枚举 |
| Miller | v6.20.2 | BSD-2-Clause | Windows/WSL/Linux | `mlr --version` | 流式结构化数据 |
| SQLite CLI | 3.53.4 | Public Domain | Windows/WSL/Linux | `sqlite3 --version` | wrapper 禁止 `.shell`/`.system` |
| Playwright Python | 1.62.0 | Apache-2.0 | Windows/WSL/Linux | 启动并关闭锁定 Chromium | 浏览器 profile/下载/账号隔离 |
| Chromium | Playwright Python 1.62.0 revision | 多许可证 | Windows/WSL/Linux | headless page smoke | 不使用系统浏览器 profile |
| subfinder | v2.15.0 | MIT | Windows/WSL/Linux | `subfinder -version` | 被动源/API，program 必须在 scope |
| dnsx | v1.3.0 | MIT | Windows/WSL/Linux | `dnsx -version` | 主动 DNS，限定 resolver/QPS |
| httpx | v1.10.0 | MIT | Windows/WSL/Linux | `httpx -version` | HTTP 请求，限定 host/速率/重定向 |
| katana | v1.7.0 | MIT | Windows/WSL/Linux | `katana -version` | crawler，限定深度/页面/并发 |
| urlfinder | v0.0.3 | MIT | Windows/WSL/Linux | `urlfinder -h` | 被动归档源，维护较弱 |
| gau | v2.2.4 | MIT | Windows/WSL/Linux | `gau --version` | 第三方 archive 查询 |
| waybackurls | v0.1.0 | Unlicense（安装时复核） | Windows/WSL/Linux | `waybackurls -h` | Wayback 外部查询 |
| nuclei | v3.11.0 | MIT | Windows/WSL/Linux | `nuclei -version` | 模板/协议 allowlist，冻结模板 |
| ffuf | v2.2.1 | MIT | Windows/WSL/Linux | `ffuf -V` | 主动 fuzz，限速/并发 |
| feroxbuster | v2.13.1 | MIT | Windows/WSL/Linux | `feroxbuster --version` | 递归放大，限定深度 |
| Arjun | 2.2.7 | AGPL-3.0 | 独立 venv | `arjun -h` | 进程外；主动参数发现 |
| Dalfox | v3.2.0 | MIT | Windows/WSL/Linux | `dalfox version` | XSS payload/OOB 受策略限制 |
| mitmproxy | v12.2.3 | MIT | Windows/WSL/Linux | `mitmproxy --version` | 仅 loopback；CA 不全局安装 |
| Gitleaks | v8.30.1 | MIT | Windows/WSL/Linux | `gitleaks version` | 命中内容按 secret 处理 |
| Semgrep CE | v1.172.0 | LGPL-2.1 | 独立 venv/container | `semgrep --version` | 本地规则、关闭遥测 |
| Trivy | v0.73.0 | Apache-2.0 | Windows/WSL/Linux | `trivy --version` | DB 独立冻结 |
| OSV-Scanner | v2.5.0 | Apache-2.0 | Windows/WSL/Linux | `osv-scanner --version` | API/离线 DB 状态入收据 |

## Extended profile

| 工具 | 固定版本 | 许可证 | Healthcheck/状态 |
|---|---|---|---|
| Caido Skills | commit `95c91ed77cb0ed7c3b3337c396866ffc30d687f9` | MIT | Skill 结构验证；GUI/PAT 可为 `NEEDS_CREDENTIAL` |
| Caido SDK | commit `1bdd37ddefdea728b3b8da646a25429892f9bb8e` | MIT | npm package + localhost API probe |
| Burp MCP | v1.3.0 | GPL-3.0 | localhost MCP initialize；无 Burp 为 `NEEDS_LICENSE` |
| ZAP | 2.17.0，`sha256:781a2bda...f5081ef` | Apache-2.0 | 实际 daemon version API、history/replay 和 Automation Framework fixture 作业 |
| interactsh-client | v1.3.1 | MIT | `interactsh-client -version`；外部 OOB 默认禁用 |
| Syft | v1.50.0 | Apache-2.0 | `syft version` |
| Grype | v0.116.1 | Apache-2.0 | `grype version` + DB 状态 |

## Lab profile

| 靶场 | 固定版本 | 许可证 | 监听与健康检查 |
|---|---|---|---|
| OWASP Juice Shop | v20.1.1 | MIT | `127.0.0.1:3000` HTTP readiness |
| OWASP WebGoat | v2025.3 | GPL-2.0-or-later | `127.0.0.1:8080`/`9090` HTTP readiness |
| OWASP crAPI | v1.1.6 | Apache-2.0 | compose health + loopback gateway |
| BudoBugs fixture | release source 2026.8.8 | Apache-2.0 | native/Docker `127.0.0.1:8765/healthz`；两账号 E2E、证据门和报告闭环 |

## Lab-AI profile

PentestGPT、Strix、Shannon、CAI、HexStrike AI、VulneraMCP 的适配器均为外部容器/进程。
HexStrike AI 已在固定 commit 上完成真实 localhost 安装、loopback health 和
`intelligence/analyze-target` 调用；脱敏收据位于
`release/validation/hexstrike-localhost.json`，且记录未调用任意命令端点。其余框架在缺少
用户模型 key/runtime/license 时保持 `NEEDS_CREDENTIAL`、`NEEDS_RUNTIME` 或
`NEEDS_LICENSE`。doctor 状态枚举为 `PASS`、`NEEDS_RUNTIME`、`NEEDS_CREDENTIAL`、
`NEEDS_LICENSE`、`UNSUPPORTED`、`FAIL`；program 模式禁止 lab-ai 自主执行。

## 通用 wrapper 约束

- 只接受类型化参数向量，不使用 shell。
- target 必须由当前 engagement 解析并通过 excluded/scope 检查。
- timeout、并发、重试、输出目录、退出码、stdout/stderr、脱敏和审计事件
  统一记录。
- active 工具默认不因属于 core 而自动获准；profile 表示安装集合，不表示
  运行权限。
