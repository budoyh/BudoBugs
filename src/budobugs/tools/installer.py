"""Idempotent, profile-scoped dependency installation without arbitrary shell expansion."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_path

from budobugs.core.paths import PathBoundaryError


@dataclass(frozen=True, slots=True)
class InstallReceipt:
    component: str
    status: str
    observation: str


_GO_PACKAGES = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.15.0",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.0",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@v1.7.0",
    "urlfinder": "github.com/projectdiscovery/urlfinder/cmd/urlfinder@v0.0.3",
    "gau": "github.com/lc/gau/v2/cmd/gau@v2.2.4",
    "waybackurls": "github.com/tomnomnom/waybackurls@v0.1.0",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.0",
    "ffuf": "github.com/ffuf/ffuf/v2@v2.2.1",
    "interactsh-client": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.3.1",
}


class ToolInstaller:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.data_root = Path(user_data_path("budobugs", ensure_exists=True)).resolve()
        self.bin_dir = self.data_root / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)

    def install(self, profile: str) -> list[InstallReceipt]:
        if profile not in {"core", "extended", "lab-ai"}:
            raise ValueError(f"unknown profile: {profile}")
        receipts: list[InstallReceipt] = []
        if profile == "core":
            receipts.extend(self._core())
        elif profile == "extended":
            receipts.append(
                self._run(
                    "interactsh-client",
                    ["go", "install", _GO_PACKAGES["interactsh-client"]],
                    env=self._go_environment(),
                )
            )
            if os.name == "nt":
                receipts.append(
                    self._run(
                        "extended-release-tools",
                        [
                            "pwsh",
                            "-NoProfile",
                            "-File",
                            str(self.root / "scripts" / "install-release-tools.ps1"),
                            "-Profile",
                            "extended",
                        ],
                        cwd=self.root,
                    )
                )
            receipts.extend(
                [
                    InstallReceipt("zap", "NEEDS_RUNTIME", "run `budo lab up --extended` to pull and verify ZAP"),
                    InstallReceipt("caido", "NEEDS_CREDENTIAL", "adapter is ready; GUI/PAT setup is manual"),
                    InstallReceipt("burp-mcp", "NEEDS_LICENSE", "adapter is ready; Burp installation is manual"),
                ]
            )
        else:
            receipts.append(
                self._run(
                    "hexstrike-ai",
                    ["uv", "run", "python", str(self.root / "scripts" / "hexstrike_lab_ai.py"), "install"],
                    cwd=self.root,
                )
            )
            receipts.extend(
                InstallReceipt(name, "NEEDS_CREDENTIAL", "isolated adapter is present; see docs/MANUAL_ONCE.md")
                for name in ("pentestgpt", "strix", "shannon", "cai", "vulneramcp")
            )
            receipts.append(
                InstallReceipt(
                    "kali-mcp",
                    "NEEDS_LICENSE",
                    "upstream has no verified license; adapter remains disabled",
                )
            )
        return receipts

    def _core(self) -> list[InstallReceipt]:
        receipts = [
            self._run("uv-sync", ["uv", "sync", "--frozen", "--extra", "dev"], cwd=self.root),
            self._run(
                "pnpm-install",
                ["pnpm", "install", "--frozen-lockfile"],
                cwd=self.root,
            ),
            self._run(
                "playwright-chromium",
                ["uv", "run", "playwright", "install", "chromium"],
                cwd=self.root,
            ),
        ]
        if os.name == "nt":
            receipts.append(
                self._run(
                    "core-release-tools",
                    [
                        "pwsh",
                        "-NoProfile",
                        "-File",
                        str(self.root / "scripts" / "install-release-tools.ps1"),
                        "-Profile",
                        "core",
                    ],
                    cwd=self.root,
                )
            )
        go_executable = shutil.which("go") or str(self.data_root / "runtimes" / "go-1.26.5" / "go" / "bin" / "go.exe")
        if not Path(go_executable).is_file():
            receipts.extend(
                InstallReceipt(name, "NEEDS_RUNTIME", "Go toolchain is not installed")
                for name in _GO_PACKAGES
                if name != "interactsh-client"
            )
        else:
            for name, package in _GO_PACKAGES.items():
                if name == "interactsh-client":
                    continue
                receipts.append(
                    self._run(
                        name,
                        [go_executable, "install", package],
                        env=self._go_environment(),
                    )
                )
        for name, package in {
            "arjun": "arjun==2.2.7",
            "mitmproxy": "mitmproxy==12.2.3",
        }.items():
            receipts.append(self._run(name, ["uv", "tool", "install", "--force", package]))
        if os.name == "nt":
            receipts.append(
                InstallReceipt(
                    "semgrep",
                    "NEEDS_RUNTIME",
                    "Semgrep native Windows wheels are unavailable; bootstrap installs it in the dedicated WSL runtime",
                )
            )
        else:
            receipts.append(self._run("semgrep", ["uv", "tool", "install", "--force", "semgrep==1.172.0"]))
        return receipts

    def _go_environment(self) -> dict[str, str]:
        return {
            "GOBIN": str(self.bin_dir),
            "GOPROXY": os.environ.get("BUDOBUGS_GOPROXY", "https://proxy.golang.org,direct"),
        }

    @staticmethod
    def _run(
        component: str,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> InstallReceipt:
        environment = os.environ.copy()
        environment.update(env or {})
        data_bin = str(Path(user_data_path("budobugs")) / "bin")
        environment["PATH"] = os.pathsep.join((data_bin, environment.get("PATH", "")))
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=1800,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return InstallReceipt(component, "FAIL", str(exc))
        text = (result.stdout + result.stderr).strip()
        return InstallReceipt(
            component,
            "PASS" if result.returncode == 0 else "FAIL",
            text[-500:] or f"exit={result.returncode}",
        )

    def clean(self) -> Path:
        expected = Path(user_data_path("budobugs")).resolve()
        if self.data_root != expected or self.data_root.parent == self.data_root:
            raise PathBoundaryError("refusing to clean an unexpected tool directory")
        if self.data_root.exists():
            shutil.rmtree(self.data_root)
        return self.data_root
