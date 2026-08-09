"""Persistent, isolated Playwright contexts with trace/HAR/screenshots."""

from __future__ import annotations

import json
import os
from contextlib import suppress
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from playwright.async_api import BrowserContext, Page, Playwright, Route, async_playwright

from budobugs.core.io import atomic_write_json, atomic_write_text
from budobugs.core.paths import safe_join
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.core.redaction import redact_text
from budobugs.models import Engagement
from budobugs.models.base import utc_now


def browser_artifact_paths(root: Path) -> list[str]:
    """Return useful run artifacts while keeping browser credentials private."""

    root = root.resolve()
    result: list[str] = []
    if not root.is_dir():
        return result
    for account_root in sorted(root.iterdir()):
        if not account_root.is_dir() or account_root.is_symlink():
            continue
        for name in ("traffic.har", "trace.zip", "steps.jsonl", "console.json", "responses.json"):
            path = account_root / name
            if path.is_file() and not path.is_symlink():
                result.append(str(path))
        for pattern in ("dom/*.html", "screenshots/*.png", "screenshots/*.metadata.json", "downloads/*"):
            result.extend(
                str(path) for path in sorted(account_root.glob(pattern)) if path.is_file() and not path.is_symlink()
            )
    return list(dict.fromkeys(result))


class BrowserSessionManager:
    def __init__(
        self,
        root: Path,
        engagement: Engagement,
        *,
        headless: bool = True,
        account_headers: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.engagement = engagement
        self.headless = headless
        self._playwright: Playwright | None = None
        self._contexts: dict[str, BrowserContext] = {}
        self._step_counts: dict[str, int] = {}
        self._account_headers = account_headers or {}

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
        headers = self._account_headers.get(account_alias)
        if headers:
            await context.set_extra_http_headers(headers)
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

    async def explore(
        self,
        account_alias: str,
        url: str,
        *,
        max_pages: int = 12,
        create_harmless_object: bool = False,
    ) -> dict[str, object]:
        """Traverse scoped navigation and record DOM, JS, API, forms, and safe state changes."""

        page = await self.open(account_alias, url)
        console_rows: list[dict[str, str]] = []
        responses: list[dict[str, object]] = []
        page.on(
            "console",
            lambda message: console_rows.append(
                {"type": message.type, "text": (redact_text(message.text) or "")[:1000]}
            ),
        )
        page.on(
            "response",
            lambda response: responses.append({"url": redact_text(response.url) or "", "status": response.status}),
        )
        created: list[str] = []
        if create_harmless_object and await page.locator("[data-budobugs-safe-create='true']").count():
            marker = f"budobugs-{account_alias}-harmless"
            field = page.locator("[data-budobugs-safe-create='true'] input").first
            if await field.count():
                await field.fill(marker)
                async with page.expect_response(lambda item: target_allowed(self.engagement, item.url).allowed):
                    await page.locator("[data-budobugs-safe-create='true'] button[type='submit']").first.click()
                created.append(marker)
                await self._capture_dom(account_alias, page, "created-harmless-object")
                await self.screenshot(account_alias, page, "created-harmless-object")

        visited: list[str] = [page.url]
        discovered: list[str] = []
        scripts: list[str] = []
        forms: list[dict[str, object]] = []
        queue: list[str] = []
        blocked_words = {"logout", "delete", "remove", "payment", "purchase", "destroy", "unsubscribe"}
        while len(visited) <= max_pages:
            links = await page.locator("a[href]").evaluate_all(
                "elements => elements.map(element => element.getAttribute('href')).filter(Boolean)"
            )
            script_values = await page.locator("script[src]").evaluate_all(
                "elements => elements.map(element => element.src).filter(Boolean)"
            )
            form_values = await page.locator("form").evaluate_all(
                "elements => elements.map(element => ({method: (element.method || 'GET').toUpperCase(), "
                "action: element.action, names: Array.from(element.elements).map(item => item.name).filter(Boolean)}))"
            )
            scripts.extend(str(item) for item in script_values if isinstance(item, str))
            forms.extend(item for item in form_values if isinstance(item, dict))
            for value in links:
                if not isinstance(value, str):
                    continue
                resolved = urljoin(page.url, value)
                discovered.append(resolved)
                parsed = urlsplit(resolved)
                if (
                    target_allowed(self.engagement, resolved).allowed
                    and parsed.scheme in {"http", "https"}
                    and not any(word in resolved.lower() for word in blocked_words)
                    and resolved not in visited
                    and resolved not in queue
                ):
                    queue.append(resolved)
            if not queue or len(visited) >= max_pages:
                break
            next_url = queue.pop(0)
            await page.goto(next_url, wait_until="domcontentloaded")
            visited.append(page.url)
            await self._capture_dom(account_alias, page, f"visit-{len(visited)}")
            await self.screenshot(account_alias, page, f"visit-{len(visited)}")
            self._log_step(account_alias, "explore", page.url)
        state_path = safe_join(self.root, account_alias, "storage-state.json")
        context = await self.context(account_alias)
        await context.storage_state(path=state_path)
        with suppress(OSError):
            os.chmod(state_path, 0o600)
        console_path = safe_join(self.root, account_alias, "console.json")
        response_path = safe_join(self.root, account_alias, "responses.json")
        atomic_write_json(console_path, console_rows)
        atomic_write_json(response_path, responses)
        await page.close()
        return {
            "account_alias": account_alias,
            "visited_urls": list(dict.fromkeys(visited)),
            "discovered_urls": list(dict.fromkeys(discovered)),
            "scripts": list(dict.fromkeys(scripts)),
            "forms": forms,
            "responses": responses,
            "created_harmless_objects": created,
            "artifacts": [str(state_path), str(console_path), str(response_path)],
        }

    async def submit_form(
        self,
        account_alias: str,
        url: str,
        *,
        fields: dict[str, str],
        submit_selector: str = "button[type='submit']",
    ) -> dict[str, object]:
        """Execute one typed form action; callers must provide only self-owned test data."""

        page = await self.open(account_alias, url)
        for name, value in fields.items():
            selector = f"[name={json.dumps(name)}]"
            if not await page.locator(selector).count():
                await page.close()
                raise RuntimeError(f"form field is not present: {name}")
            await page.locator(selector).first.fill(value)
        async with page.expect_response(lambda item: target_allowed(self.engagement, item.url).allowed) as pending:
            await page.locator(submit_selector).first.click()
        response = await pending.value
        await self._capture_dom(account_alias, page, "typed-form")
        screenshot = await self.screenshot(account_alias, page, "typed-form")
        result = {
            "url": response.url,
            "status": response.status,
            "page_url": page.url,
            "screenshot": str(screenshot),
        }
        await page.close()
        return result

    def artifact_paths(self) -> list[str]:
        return browser_artifact_paths(self.root)

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
