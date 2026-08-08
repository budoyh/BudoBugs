# 建设环境快照

采集时间：2026-08-09（Asia/Shanghai），Windows 11 x64。以下是实际执行的 health/version
结果，不代表其他主机自动满足相同前置条件。

| 项目 | 当前实测事实 | 运行边界 |
|---|---|---|
| Python | 仓库 `.venv`：CPython 3.12.13 | `uv sync --frozen` 管理；不覆盖系统 Python/Conda。 |
| uv | 0.11.26 | Python 依赖按 `uv.lock`。 |
| Node / pnpm | Node 24.14.0；pnpm 11.1.3 | Node 依赖按 `pnpm-lock.yaml`。 |
| Git / GitHub CLI | Git 2.52.0；gh 2.97.0；`budoyh` keyring 登录有效 | origin 由 release verifier 检查为 `budoyh/BudoBugs`；不 force push。 |
| WSL2 | `BudoBugs-Ubuntu-24.04`，WSL2，运行中 | 专用于 Linux-only 工具和 Docker daemon。 |
| Docker / Compose | WSL client/server 29.1.3；Compose 2.40.3 | Windows PATH 不暴露全局 Docker；BudoBugs 自动通过专用 WSL 调用。 |
| Go | BudoBugs 用户目录中的 Go 1.26.5 Windows runtime | 不写系统 Go；Go 工具安装到专用 `bin`。 |
| Semgrep | WSL 隔离 venv 1.172.0 | Windows 原生 wheel 不可用；doctor 实际跨 WSL health。 |
| Java | Windows Java 8u421 | WebGoat/ZAP 使用容器，不依赖宿主旧 Java。 |
| Playwright / Chromium | Playwright 1.62.0；Chromium 151.0.7922.34 启动/关闭 probe PASS | 使用隔离 profile，不读取系统浏览器 profile。 |
| Codex CLI | PATH CLI 0.132.0 | 集成通过锁定 SDK/CLI 协议 smoke；不改用户全局配置。 |

`uv run budo doctor --json` 的环境检查全部 PASS；整体为 WARN，因为未提供 Caido PAT、
Burp 许可证/BApp 和其余可选 lab-ai 模型凭据。43 个 registry 工具中 35 个完成实际版本或
最小运行 health，8 个保持准确的 `NEEDS_CREDENTIAL` / `NEEDS_LICENSE`。其中 HexStrike AI
固定 commit 的 loopback server 和真实 localhost 分析调用为 PASS；Kali MCP 因许可证未确认
明确返回 `NEEDS_LICENSE`。

核心用户级工具的实测 PASS 包括 Go、jq、yq、ripgrep、fd、SQLite、Playwright/Chromium、
subfinder、dnsx、httpx、katana、urlfinder、gau、waybackurls、nuclei、ffuf、feroxbuster、
Arjun、Dalfox、mitmproxy、Gitleaks、Semgrep、Trivy、OSV-Scanner、Syft、Grype、
interactsh-client、Docker、ZAP 和 HexStrike AI。单个工具的完整观察、实际路径和版本证据
由 `budo tools health --json` 动态生成；文档不能替代当次收据。

本快照只记录建设主机。最终发布状态还必须以 CI、`scripts/verify_release.py`、远端
`origin/main` 等值检查和干净工作树为准。
