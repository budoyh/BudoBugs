# First Lab

本教程只针对 native fixture `http://127.0.0.1:8765`。不要替换为外部域名。

1. 运行 `uv sync --frozen --extra dev`，然后 `uv run budo doctor --json`。若环境依赖缺失，保留输出状态。
2. 执行 `uv run budo lab up --native-only`，再用 `uv run budo lab status --json` 确认 fixture。Docker 不可用不阻止这个 native 路径。
3. 创建、验证并人工授权 lab engagement：

```bash
uv run budo engagement new --id first-lab --mode lab --target http://127.0.0.1:8765 --vendor local-fixture --attestation "I own and authorize this isolated local fixture."
uv run budo engagement validate first-lab
uv run budo engagement authorize first-lab
```

4. 执行 `uv run budo hunt first-lab --json`。记录 `run_id`、状态及 confirmed/killed finding id；不要把预期输出预先称为 PASS。
5. 用 `findings list`、`status` 和 `timeline` 检查工件。结束时 `uv run budo lab down`。

若要使用 Docker 靶场或 ZAP，先读 [MANUAL_ONCE](../MANUAL_ONCE.md)。
