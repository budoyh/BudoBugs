# 一次性人工配置

本页只列出代码不能替用户完成的 GUI、账户、许可证、密钥和授权动作。它不替代
`engagement.yaml`，也不允许把缺失前置条件写成 PASS。

## Docker 与 WSL2

1. Windows 用户安装并启动 Docker Desktop；需要 Linux 工具时启用 WSL2 Ubuntu 24.04。
   系统功能启用、重启和 Docker 许可确认必须由用户完成。
2. 不向容器挂载 Docker socket、用户 home、SSH 目录、浏览器 profile、真实 SRC 凭据或
   未披露 finding。
3. 执行 `uv run budo lab status --json`。Docker 不可用时使用
   `uv run budo lab up --native-only`，不要伪造 Compose PASS。
4. 完整靶场执行 `uv run budo lab up`；ZAP daemon 执行
   `uv run budo lab up --extended`。停止使用 `uv run budo lab down`。
5. `docker/compose.yaml` 中外部镜像已固定为 `tag@sha256`。变更版本或平台时必须重新核对
   digest、启动/健康检查、供应链扫描和许可证边界，不能改成 `latest`。

## Caido

Caido 是可选 extended 集成。安装并登录用户本人控制的 Caido instance，按 Caido 当前产品
界面创建最小权限、可撤销的 PAT。社区 Caido MCP 不是官方组件；BudoBugs 使用锁定的官方
`@caido/sdk-client` bridge。

PowerShell 配置：

```powershell
$env:CAIDO_PAT = '<PAT>'
uv run budo proxy caido-configure --url http://127.0.0.1:8080 --pat-env CAIDO_PAT --json
Remove-Item Env:CAIDO_PAT
uv run budo proxy doctor --json
```

默认只允许 loopback control plane。PAT 写入系统 keyring；在 keyring 不可用时，BudoBugs
使用权限受限的本地 fallback store。PAT 不写入 engagement、日志、HAR、Git、报告或模型
输入。`proxy doctor` 只证明当前 SDK/control plane 协商结果，不证明 target 授权或 finding。

## Burp MCP

1. 用户自行安装并接受 Burp Community/Professional 的适用许可证。
2. 在 Burp 中安装 PortSwigger 官方 MCP Server BApp，并将监听限制为 localhost。
3. 默认 MCP URL 为 `http://127.0.0.1:9876/mcp`；如本机配置不同，只在当前进程设置
   `BUDOBUGS_BURP_MCP_URL`。
4. 执行 `uv run budo proxy doctor --json`。BudoBugs 会实际 initialize/list tools，并根据
   返回 capability 区分 Community/limited 与 Professional-capable；不会猜测许可证版本。

BudoBugs 不安装或重新分发 Burp/BApp。Collaborator 只有在服务实际暴露能力且 engagement
模式允许时才可使用；默认 program 流程不把它当必需能力。

## ZAP

`uv run budo lab up --extended` 启动固定 digest 的 ZAP 2.17.0，宿主机只监听
`127.0.0.1:8090`。`docker/profiles/zap-automation.yaml` 只面向 Docker 内的 BudoBugs
fixture；执行 `uv run budo lab zap-scan --json` 运行真实 Automation Framework 作业。

当前 lab 配置关闭 API key，原因是 control plane 只在隔离 Docker lab/loopback 上使用。
不要把该配置暴露到 LAN、公网或真实 target。ZAP alert 只是候选，必须再通过 scope、负对照、
证据门和独立 critic。

## 模型和外部服务

如果启用 Codex SDK、云模型、OOB、Caido cloud 或其他外部服务，由用户选择获批 provider，
确认费用、地域、保留政策和服务条款，并通过环境变量或系统 keyring 输入 API key。不要把
密钥写入 `.env`、YAML、Git、报告、HAR、聊天或 issue。

启用前选择 `config/models.yaml` 的 `quality-first` 或 `economy` 路由，并检查
`config/defaults.yaml` 的 engagement/phase token budget。先运行
`budo hunt <id> --agent-mode codex --dry-run --json`，确认调用与 token 上界后再去掉
`--dry-run`。没有 CLI 登录/模型权限时，本地确定性处理、native/Docker fixture、证据门和
报告仍可运行；advisory 必须保存真实 `DEGRADED` 收据，不能把模型缺失转换为 PASS。

## Lab-AI

Lab-AI 只允许在 localhost/Docker 内网、无真实凭据、无 Docker socket、最小网络出口和人工
观察下运行。`budo tools install --profile lab-ai` 自动安装的 HexStrike 适配器会固定上游
commit、校验 MIT LICENSE、同步 exact lock、绑定 `127.0.0.1:18889` 并拒绝非 loopback
target。验证命令：

```powershell
pwsh -NoProfile -File scripts/hexstrike-lab-ai.ps1 -Action install
pwsh -NoProfile -File scripts/hexstrike-lab-ai.ps1 -Action up
pwsh -NoProfile -File scripts/hexstrike-lab-ai.ps1 -Action validate -Target http://127.0.0.1:8765/healthz
pwsh -NoProfile -File scripts/hexstrike-lab-ai.ps1 -Action down
```

该适配器不暴露 HexStrike 任意命令路由。PentestGPT、Strix、Shannon、CAI 和 VulneraMCP
仍需用户输入各自模型 key/接受上游条款；Kali MCP 的许可证未能确认，因此保持禁用。一个
外部框架的 PASS 不会授权其他框架或 program target。

## 正式 SRC 自有测试账号

用户只提供本人创建且在项目授权范围内的测试账号。使用
`budo engagement account-set <id> --alias <name> --headers-env <ENV>` 从临时环境变量导入请求头，
导入后立即清除变量。不要输入意外发现的凭据、第三方账号或真实受害者数据。验证码、MFA、
登录和账号创建只能由用户在受控浏览器中完成；系统随后使用保存的 secret reference 恢复。

## 最终报告

用户必须人工复核 target/scope、请求响应、脱敏、影响、CVSS、重复风险、清理状态和披露窗口，
再在 SRC 平台提交。BudoBugs 不自动登录或点击提交。平台要求的加密上传、额外附件、法律条款
和披露沟通也由用户本人完成。
