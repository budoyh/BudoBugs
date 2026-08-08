"""Persistent, isolated Playwright contexts with trace/HAR/screenshots."""

from __future__ import annotations

import json
import os
from contextlib import suppress
from pathlib import Path

from playwright.async_api import BrowserContext, Page, Playwright, Route, async_playwright

from budobugs.core.io import atomic_write_json, atomic_write_text
from budobugs.core.paths import safe_join
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.core.redaction import redact_text
from budobugs.models import Engagement
from budobugs.models.base import utc_now


class BrowserSessionManager:
    def __init__(self, root: Path, engagement: Engagement, *, headless: bool = True) -> None:
        self.root = root.resolve()
        self.engagement = engagement
        self.headless = headless
        self._playwright: Playwright | None = None
        self._contexts: dict[str, BrowserContext] = {}
        self._step_counts: dict[str, int] = {}

    async def start(self) -> None:
        if self._playwright is None:
            self.root.mkdir(parents=True, exist_ok=True)
            self._playwright = await async_playwright().start()

    async def context(self, account_alias: str) -> BrowserContext:
        if self._playwright is None:
            await self.start()
        if account_alias in self._contexts:
            return self._contexts[account_alias]
        assert self._playwright is not None
        account_root = safe_join(self.root, account_alias)
        account_root.mkdir(parents=True, exist_ok=True)
        context = await self._playwright.chromium.launch_persistent_context(
            user_data_dir=account_root / "profile",
            headless=self.headless,
            accept_downloads=True,
            downloads_path=account_root / "downloads",
            record_har_path=account_root / "traffic.har",
            ignore_https_errors=False,
        )
        await context.route("**/*", self._scope_route)
        await context.tracing.start(screenshots=True, snapshots=True, sources=False)
        self._contexts[account_alias] = context
        return context

    async def _scope_route(self, route: Route) -> None:
        decision = target_allowed(self.engagement, route.request.url)
        if decision.allowed:
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    async def open(self, account_alias: str, url: str) -> Page:
        require_allowed(target_allowed(self.engagement, url))
        context = await self.context(account_alias)
        page = await context.new_page()
        await page.goto(url, wait_until="domcontentloaded")
        await self._capture_dom(account_alias, page, "open")
        self._log_step(account_alias, "open", page.url)
        return page

    async def screenshot(self, account_alias: str, page: Page, step: str) -> Path:
        safe_step = "".join(char if char.isalnum() or char in "-_" else "_" for char in step)[:80]
        destination = safe_join(self.root, account_alias, "screenshots", f"{safe_step}.png")
        destination.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=destination, full_page=True)
        atomic_write_json(
            destination.with_suffix(destination.suffix + ".metadata.json"),
            {
                "captured_at": utc_now().isoformat(),
                "step": step,
                "account_alias": account_alias,
                "url": redact_text(page.url),
            },
        )
        self._log_step(account_alias, f"screenshot:{step}", page.url)
        return destination

    async def pause_for_login(self, account_alias: str, url: str) -> Page:
        """Open a headed context, pause for user login/MFA, then persist private browser state."""

        if self.headless:
            raise RuntimeError("interactive login requires BrowserSessionManager(headless=False)")
        page = await self.open(account_alias, url)
        self._log_step(account_alias, "interactive-login-paused", page.url)
        await page.pause()
        state_path = safe_join(self.root, account_alias, "storage-state.json")
        context = await self.context(account_alias)
        await context.storage_state(path=state_path)
        with suppress(OSError):
            os.chmod(state_path, 0o600)
        await self._capture_dom(account_alias, page, "post-login")
        self._log_step(account_alias, "interactive-login-complete", page.url)
        return page

    async def _capture_dom(self, account_alias: str, page: Page, step: str) -> Path:
        sequence = self._step_counts.get(account_alias, 0) + 1
        self._step_counts[account_alias] = sequence
        safe_step = "".join(char if char.isalnum() or char in "-_" else "_" for char in step)[:80]
        destination = safe_join(self.root, account_alias, "dom", f"{sequence:04d}-{safe_step}.html")
        content = redact_text(await page.content()) or ""
        atomic_write_text(destination, content)
        return destination

    def _log_step(self, account_alias: str, action: str, url: str) -> None:
        path = safe_join(self.root, account_alias, "steps.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": utc_now().isoformat(),
            "account_alias": account_alias,
            "action": action,
            "url": redact_text(url),
        }
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    async def stop(self) -> None:
        for alias, context in list(self._contexts.items()):
            trace = safe_join(self.root, alias, "trace.zip")
            await context.tracing.stop(path=trace)
            await context.close()
        self._contexts.clear()
        self._step_counts.clear()
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None
