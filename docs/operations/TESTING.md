# 测试、覆盖率与发布验收

所有自动化测试只访问临时目录、`127.0.0.1` 或 Docker 内网；CI 不接触真实 SRC。跳过项、
运行时缺失和外部凭据缺失不能写成 PASS。

## 静态质量

```powershell
uv sync --frozen --extra dev
pnpm install --frozen-lockfile
uv run ruff check .
uv run ruff format --check .
uv run mypy src
pnpm run check
pnpm run lint:markdown
uv run yamllint .github .agents/skills config docker tools
uv run shellcheck scripts/*.sh
```

CI 另用 checksum-verified Hadolint 2.15.1 检查全部 Dockerfile。GitHub Actions 和 pre-commit
依赖都固定到 40 位 commit；`verify_release.py` 会拒绝浮动 action revision。

## 非 Docker 测试与核心覆盖率

```powershell
uv run playwright install chromium
uv run pytest tests/unit tests/integration tests/e2e tests/security -m "not docker" --cov=budobugs --cov-report=term-missing --cov-report=xml --cov-fail-under=85
```

该命令同时运行：Schema、授权/scope、状态机、恢复、流量归一化、两账号模型、redaction、
prompt/path/command injection、工具 wrapper、source scan、代理失败语义、MCP stdio、CLI smoke、
证据/报告一致性和真实 native Playwright E2E。E2E 会先在 `TRAFFIC_MODEL`（已含浏览器/流量
复杂上下文）主动中断，再验证 snapshot/receipt 后从下一阶段使用同一 run id 恢复；它必须产生
一个 critic-confirmed finding 和一个被 critic KILL 的伪候选。

85% 是 `pyproject.toml` 明确列出的确定性核心 branch-coverage 门禁。CLI、宿主/WSL 安装器、
GUI/MCP 网络适配器、lab 生命周期和 TUI 不计入这个百分比，但并非未测试：它们由独立的
协议、失败语义、CLI、MCP、Docker、ZAP 和 E2E 测试覆盖。报告覆盖率时必须称为“核心门禁
覆盖率”，不能冒充全仓所有适配器的行覆盖率。

## Docker 与 ZAP

CI-sized 的真实 fixture build 和 ZAP Automation Framework 作业：

```powershell
$env:BUDOBUGS_RUN_DOCKER_TESTS = "1"
uv run pytest tests/integration/test_docker_compose.py -k "not full" -q
Remove-Item Env:BUDOBUGS_RUN_DOCKER_TESTS
```

完整靶场会启动 fixture、Juice Shop、WebGoat、crAPI、ZAP 和 loopback proxy，核对六个
host port 均为 `127.0.0.1`，执行真实 ZAP 作业，最后 `down --remove-orphans`：

```powershell
$env:BUDOBUGS_RUN_FULL_DOCKER_TESTS = "1"
uv run pytest tests/integration/test_docker_compose.py -k full -q
Remove-Item Env:BUDOBUGS_RUN_FULL_DOCKER_TESTS
```

测试使用临时 Compose project name，因此不会把配置解析 PASS 当作容器运行 PASS。失败时先
保存脱敏 compose/log 收据，再执行 `uv run budo lab down`；不要删除 volumes 来掩盖故障。

## Skills、秘密和供应链

```powershell
uv run python scripts/verify_skills.py
uv run pytest .agents/skills -q
uv run python scripts/secret_scan.py --path .
uv run python scripts/generate_license_inventory.py --check
uv run python scripts/verify_release.py --source
```

Skill verifier 要求 14 个 Skill 的 `SKILL.md`、`agents/openai.yaml`、input/output JSON Schema、
示例、校验脚本和测试逐项一致。Release verifier 从原始 JSON 重新计算：Gitleaks、Semgrep、
OSV、Trivy filesystem/image、raw Grype、OpenVEX、最终 Grype、SBOM、许可证 closure、
HexStrike receipt、容器/action pin 和 provenance；发现 scanner error、secret、未解释
high/critical、VEX/source/image identity drift 或 artifact digest drift 即失败。

发布扫描不使用 `--ignore-unfixed` 或 `--only-fixed`。Grype 的 raw severe records 必须完整保留；
只有逐 CVE、有官方引用、与 exact source/image 绑定的 OpenVEX `not_affected` 决策可以从阻断
集合移入 reviewed 集合。

## 构建和干净环境 smoke

```powershell
uv build
uv tool run --from twine==6.2.0 twine check dist/*
$smoke = Join-Path $env:TEMP "budobugs-release-smoke"
uv venv $smoke
uv pip install --python (Join-Path $smoke "Scripts\python.exe") (Get-ChildItem dist\*.whl | Select-Object -First 1).FullName
& (Join-Path $smoke "Scripts\budo.exe") version --json
```

提交并推送后，最终验收使用不带 `--source` 的 `scripts/verify_release.py`。该模式额外要求：
当前分支为 `main`、工作树无 tracked/untracked 改动、origin URL 精确匹配、local HEAD 与
`refs/remotes/origin/main` 相同。CI 全绿和该本地 PASS 缺一不可。
