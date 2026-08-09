"""Persistent, isolated Playwright contexts with trace/HAR/screenshots."""

from __future__ import annotations

import json
import os
import re
from contextlib import suppress
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from playwright.async_api import BrowserContext, Page, Playwright, Route, async_playwright

from budobugs.core.io import atomic_write_json, atomic_write_text
from budobugs.core.paths import ensure_private_directory, safe_join
from budobugs.core.policy import require_allowed, target_allowed, websocket_target_allowed
from budobugs.core.redaction import redact_headers, redact_text
from budobugs.models import Engagement
from budobugs.models.base import utc_now


def browser_artifact_paths(root: Path) -> list[str]:
    """Return only Codex-visible, redacted browser audit artifacts.

    Persistent profiles, raw HAR files, storage state and Playwright traces are
    deliberately kept in the private browser root.  They must never become a
    run artifact reference merely because they sit next to a public audit file.
    """

    root = root.resolve()
    result: list[str] = []
    if not root.is_dir():
        return result
    for account_root in sorted(root.iterdir()):
        if not account_root.is_dir() or account_root.is_symlink():
            continue
        for pattern in (
            "traffic*.har",
            "steps.jsonl",
            "console*.json",
            "responses*.json",
            "dom/*.html",
            "screenshots/*.png",
            "screenshots/*.metadata.json",
        ):
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
        artifact_suffix: str = "",
        private_root: Path | None = None,
    ) -> None:
        if artifact_suffix and not re.fullmatch(r"-[A-Za-z0-9_-]{1,80}", artifact_suffix):
            raise ValueError("browser artifact suffix must contain only safe filename characters")
        self.root = root.resolve()
        # ``root`` is deliberately the public run-artifact area.  Production
        # callers pass a private runtime directory outside the Codex cwd for
        # browser profiles/HAR/traces; retaining ``root`` as the default keeps
        # the standalone fixture helper backwards compatible.
        self.private_root = (private_root or self.root).resolve()
        self.engagement = engagement
        self.headless = headless
        self.artifact_suffix = artifact_suffix
        self._playwright: Playwright | None = None
        self._contexts: dict[str, BrowserContext] = {}
        self._step_counts: dict[str, int] = {}
        self._trace_segment_counts: dict[str, int] = {}
        self._account_headers = account_headers or {}
        self._websocket_har_aliases: set[str] = set()

    async def start(self) -> None:
        if self._playwright is None:
            self.root.mkdir(parents=True, exist_ok=True)
            ensure_private_directory(self.private_root)
            self._playwright = await async_playwright().start()

    async def context(self, account_alias: str) -> BrowserContext:
        if self._playwright is None:
            await self.start()
        if account_alias in self._contexts:
            return self._contexts[account_alias]
        assert self._playwright is not None
        account_root = safe_join(self.root, account_alias)
        account_root.mkdir(parents=True, exist_ok=True)
        private_account_root = safe_join(self.private_root, account_alias)
        ensure_private_directory(private_account_root)
        context = await self._playwright.chromium.launch_persistent_context(
            user_data_dir=private_account_root / "profile",
            headless=self.headless,
            accept_downloads=True,
            downloads_path=private_account_root / "downloads",
            record_har_path=private_account_root / f"traffic{self.artifact_suffix}.har",
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
        decision = (
            websocket_target_allowed(self.engagement, route.request.url)
            if urlsplit(route.request.url).scheme.lower() in {"ws", "wss"}
            else target_allowed(self.engagement, route.request.url)
        )
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
                "url": self._redact_har_url(page.url),
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
        state_path = safe_join(self.private_root, account_alias, "storage-state.json")
        context = await self.context(account_alias)
        await context.storage_state(path=state_path)
        with suppress(OSError):
            os.chmod(state_path, 0o600)
        atomic_write_json(
            safe_join(self.private_root, account_alias, "login-complete.json"),
            {"account_alias": account_alias, "completed_at": utc_now().isoformat()},
        )
        await self._capture_dom(account_alias, page, "post-login")
        self._log_step(account_alias, "interactive-login-complete", page.url)
        return page

    def has_completed_login(self, account_alias: str) -> bool:
        """Return whether the user already completed the one-time login/MFA pause."""

        marker = safe_join(self.private_root, account_alias, "login-complete.json")
        profile = safe_join(self.private_root, account_alias, "profile")
        return marker.is_file() and not marker.is_symlink() and profile.is_dir() and not profile.is_symlink()

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
                {"type": message.type, "text": self._redact_har_text(message.text)[:1000]}
            ),
        )
        page.on(
            "response",
            lambda response: responses.append({"url": self._redact_har_url(response.url), "status": response.status}),
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
        state_path = safe_join(self.private_root, account_alias, "storage-state.json")
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
            "visited_urls": list(dict.fromkeys(self._redact_har_url(str(item)) for item in visited)),
            "discovered_urls": list(dict.fromkeys(self._redact_har_url(str(item)) for item in discovered)),
            "scripts": list(dict.fromkeys(self._redact_har_url(str(item)) for item in scripts)),
            "forms": [
                {
                    **item,
                    "action": self._redact_har_url(str(item["action"]))
                    if isinstance(item.get("action"), str)
                    else item.get("action"),
                }
                for item in forms
            ],
            "responses": responses,
            "created_harmless_objects": created,
            "artifacts": [str(console_path), str(response_path)],
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
            "url": self._redact_har_url(response.url),
            "status": response.status,
            "page_url": self._redact_har_url(page.url),
            "screenshot": str(screenshot),
        }
        await page.close()
        return result

    async def request_json(
        self,
        account_alias: str,
        *,
        method: str,
        url: str,
        body: object | None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """Make one bounded API request through the account's browser context.

        ``BrowserContext.request`` shares the persistent profile's cookies.  It
        lets a pre-authorized setup recipe work after an interactive MFA login,
        without copying browser credentials into the executor or a proxy log.
        """

        require_allowed(target_allowed(self.engagement, url))
        context = await self.context(account_alias)
        request_headers = dict(headers or {})
        payload: str | None = None
        if body is not None:
            request_headers.setdefault("Content-Type", "application/json")
            payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        response = await context.request.fetch(
            url,
            method=method,
            headers=request_headers or None,
            data=payload,
        )
        text = self._redact_har_text(await response.text())
        self._log_step(account_alias, f"browser-api:{method}", url)
        return {
            "url": self._redact_har_url(url),
            "method": method,
            "status": response.status,
            "response_preview": text[:1000],
        }

    async def websocket_interaction(
        self,
        account_alias: str,
        *,
        url: str,
        send_text: str | None,
        expected_json_pointer: str | None,
        expected_json_value: object | None,
        step: str,
    ) -> dict[str, object]:
        """Execute one bounded WebSocket handshake in an existing account context.

        The browser owns authentication through its persistent profile and
        context headers.  Raw frames (including caller-supplied ``send_text``)
        are intentionally kept only in memory for predicate evaluation: the
        durable receipt contains event metadata, never frame payloads.
        """

        require_allowed(websocket_target_allowed(self.engagement, url))
        context = await self.context(account_alias)
        page = await context.new_page()
        try:
            parsed = urlsplit(url)
            origin_url = urlunsplit(
                ("https" if parsed.scheme.casefold() == "wss" else "http", parsed.netloc, "/", "", "")
            )
            # A WebSocket constructed in about:blank uses an opaque Origin.
            # Navigate to the policy-checked mapped origin first so real
            # servers receive the account context's same-origin Origin header.
            require_allowed(target_allowed(self.engagement, origin_url))
            await page.goto(origin_url, wait_until="domcontentloaded")
            # Preserve the trace preceding this action, discard only the
            # WebSocket segment, then resume tracing for subsequent browser
            # evidence.  HAR is sanitized after context close when its writer
            # has flushed all WS frame records.
            await self._split_trace_before_websocket(context, account_alias, step)
            self._websocket_har_aliases.add(account_alias)
            result = await page.evaluate(
                """async ({ url, sendText }) => await new Promise((resolve) => {
                    let done = false;
                    let opened = false;
                    let errored = false;
                    let messageText = null;
                    let closeCode = null;
                    const finish = (reason) => {
                        if (done) return;
                        done = true;
                        clearTimeout(timer);
                        resolve({ opened, errored, messageText, closeCode, reason });
                    };
                    const socket = new WebSocket(url);
                    const timer = setTimeout(() => {
                        try { socket.close(4000, 'bounded-timeout'); } catch (_) {}
                        finish('timeout');
                    }, 10000);
                    socket.addEventListener('open', () => {
                        opened = true;
                        if (sendText !== null) socket.send(sendText);
                    });
                    socket.addEventListener('message', async (event) => {
                        if (typeof event.data === 'string') {
                            messageText = event.data;
                        } else if (event.data instanceof Blob) {
                            messageText = await event.data.text();
                        } else {
                            messageText = String(event.data);
                        }
                        try { socket.close(1000, 'bounded-complete'); } catch (_) {}
                    });
                    socket.addEventListener('error', () => { errored = true; });
                    socket.addEventListener('close', (event) => {
                        closeCode = event.code;
                        finish('close');
                    });
                })""",
                {"url": url, "sendText": send_text},
            )
            if not isinstance(result, dict):
                raise RuntimeError("browser WebSocket result is not an object")
            message = result.get("messageText")
            message_text = message if isinstance(message, str) else None
            predicate_present = expected_json_pointer is not None
            predicate_matched = self._websocket_json_predicate(
                message_text,
                expected_json_pointer,
                expected_json_value,
            )
            safe_step = "".join(char if char.isalnum() or char in "-_" else "_" for char in step)[:80]
            receipt = safe_join(self.root, account_alias, "websocket", f"{safe_step}.json")
            atomic_write_json(
                receipt,
                {
                    "captured_at": utc_now().isoformat(),
                    "account_alias": account_alias,
                    "url": self._redact_har_url(url),
                    "origin_navigation_url": self._redact_har_url(origin_url),
                    "opened": bool(result.get("opened")),
                    "errored": bool(result.get("errored")),
                    "event": "message" if message_text is not None else "close",
                    "close_code": result.get("closeCode") if isinstance(result.get("closeCode"), int) else None,
                    "completion_reason": result.get("reason") if isinstance(result.get("reason"), str) else "unknown",
                    "message_received": message_text is not None,
                    "message_length": len(message_text) if message_text is not None else 0,
                    "json_predicate_present": predicate_present,
                    "json_predicate_matched": predicate_matched,
                    "frame_payload_persisted": False,
                    "websocket_trace_segment_persisted": False,
                },
            )
            self._log_step(account_alias, "websocket", url)
            return {
                "opened": bool(result.get("opened")),
                "errored": bool(result.get("errored")),
                "event": "message" if message_text is not None else "close",
                "close_code": result.get("closeCode") if isinstance(result.get("closeCode"), int) else None,
                "origin_navigation_url": self._redact_har_url(origin_url),
                "json_predicate_present": predicate_present,
                "json_predicate_matched": predicate_matched,
                "receipt": str(receipt),
            }
        finally:
            if account_alias in self._websocket_har_aliases:
                await self._discard_websocket_trace_segment(context)
            with suppress(Exception):
                await page.close()

    @staticmethod
    def _websocket_json_predicate(
        message: str | None,
        pointer: str | None,
        expected_value: object | None,
    ) -> bool:
        if pointer is None:
            return message is not None
        if message is None:
            return False
        try:
            current: object = json.loads(message)
        except json.JSONDecodeError:
            return False
        for token in pointer.lstrip("/").split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and token in current:
                current = current[token]
            elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
                current = current[int(token)]
            else:
                return False
        return current == expected_value

    def artifact_paths(self) -> list[str]:
        return browser_artifact_paths(self.root)

    async def _capture_dom(self, account_alias: str, page: Page, step: str) -> Path:
        if account_alias not in self._step_counts:
            dom_root = safe_join(self.root, account_alias, "dom")
            existing = [
                int(match.group(1))
                for path in dom_root.glob("*.html")
                if (match := re.match(r"^(\d+)-", path.name)) is not None
            ]
            self._step_counts[account_alias] = max(existing, default=0)
        sequence = self._step_counts[account_alias] + 1
        self._step_counts[account_alias] = sequence
        safe_step = "".join(char if char.isalnum() or char in "-_" else "_" for char in step)[:80]
        destination = safe_join(self.root, account_alias, "dom", f"{sequence:04d}-{safe_step}.html")
        content = self._redact_har_text(await page.content())
        atomic_write_text(destination, content)
        return destination

    def _log_step(self, account_alias: str, action: str, url: str) -> None:
        path = safe_join(self.root, account_alias, "steps.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": utc_now().isoformat(),
            "account_alias": account_alias,
            "action": action,
            "url": self._redact_har_url(url),
        }
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    async def stop(self) -> None:
        for alias, context in list(self._contexts.items()):
            private_account_root = safe_join(self.private_root, alias)
            trace = private_account_root / f"trace{self.artifact_suffix}.zip"
            # A browser driver can already be gone while an agent failure is
            # unwinding.  Continue closing every remaining account instead of
            # masking the persisted loop checkpoint with a teardown failure.
            with suppress(Exception):
                await context.tracing.stop(path=trace)
            with suppress(Exception):
                await context.close()
            if alias in self._websocket_har_aliases:
                self._sanitize_websocket_har(private_account_root / f"traffic{self.artifact_suffix}.har")
            self._export_sanitized_har(
                private_account_root / f"traffic{self.artifact_suffix}.har",
                safe_join(self.root, alias, f"traffic{self.artifact_suffix}.har"),
            )
        self._contexts.clear()
        self._step_counts.clear()
        self._trace_segment_counts.clear()
        self._websocket_har_aliases.clear()
        if self._playwright is not None:
            with suppress(Exception):
                await self._playwright.stop()
            self._playwright = None

    async def _split_trace_before_websocket(self, context: BrowserContext, account_alias: str, step: str) -> None:
        if account_alias not in self._trace_segment_counts:
            account_root = safe_join(self.private_root, account_alias)
            existing = [
                int(match.group(1))
                for path in account_root.glob("trace-pre-ws-*.zip")
                if (match := re.match(r"^trace-pre-ws-(\d+)-", path.name)) is not None
            ]
            self._trace_segment_counts[account_alias] = max(existing, default=0)
        sequence = self._trace_segment_counts[account_alias] + 1
        self._trace_segment_counts[account_alias] = sequence
        safe_step = "".join(char if char.isalnum() or char in "-_" else "_" for char in step)[:80]
        before = safe_join(
            self.private_root,
            account_alias,
            f"trace-pre-ws-{sequence:04d}-{safe_step}{self.artifact_suffix}.zip",
        )
        await context.tracing.stop(path=before)
        await context.tracing.start(screenshots=True, snapshots=True, sources=False)

    @staticmethod
    async def _discard_websocket_trace_segment(context: BrowserContext) -> None:
        """End the just-recorded WS segment without an artifact, then resume tracing."""

        with suppress(Exception):
            await context.tracing.stop()
        with suppress(Exception):
            await context.tracing.start(screenshots=True, snapshots=True, sources=False)

    @staticmethod
    def _sanitize_websocket_har(path: Path) -> None:
        """Remove raw WebSocket HAR entries after the browser flushes them.

        The separately emitted WebSocket receipt keeps handshake/event/predicate
        evidence without retaining caller input or server message payloads.
        """

        if not path.is_file() or path.is_symlink():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            entries = payload["log"]["entries"]
            if not isinstance(entries, list):
                return
            payload["log"]["entries"] = [
                entry
                for entry in entries
                if not (
                    isinstance(entry, dict)
                    and isinstance(entry.get("request"), dict)
                    and urlsplit(str(entry["request"].get("url", ""))).scheme.casefold() in {"ws", "wss"}
                )
            ]
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return
        atomic_write_json(path, payload)

    @staticmethod
    def _export_sanitized_har(source: Path, destination: Path) -> None:
        """Copy only a redacted HAR projection into the public run artifacts.

        Playwright persists request cookies and authorization values in the raw
        HAR.  The raw file remains in ``private_root`` for the local operator;
        the run receives a structurally useful but non-replayable audit copy.
        """

        if not source.is_file() or source.is_symlink():
            return
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
            entries = payload["log"]["entries"]
            if not isinstance(entries, list):
                return
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for side in ("request", "response"):
                message = entry.get(side)
                if not isinstance(message, dict):
                    continue
                headers = message.get("headers")
                if isinstance(headers, list):
                    values = {
                        str(item.get("name", "")): str(item.get("value", ""))
                        for item in headers
                        if isinstance(item, dict) and isinstance(item.get("name"), str)
                    }
                    message["headers"] = [
                        {"name": name, "value": value} for name, value in redact_headers(values).items()
                    ]
                if side == "request" and isinstance(message.get("url"), str):
                    message["url"] = BrowserSessionManager._redact_har_url(message["url"])
                for body_key in ("postData", "content"):
                    body = message.get(body_key)
                    if isinstance(body, dict) and isinstance(body.get("text"), str):
                        body["text"] = BrowserSessionManager._redact_har_text(body["text"])
        atomic_write_json(destination, payload)

    @staticmethod
    def _redact_har_url(value: str) -> str:
        parsed = urlsplit(value)
        sensitive = {
            "token",
            "access_token",
            "id_token",
            "refresh_token",
            "authorization",
            "cookie",
            "session",
            "api_key",
            "apikey",
            "secret",
            "password",
        }
        query = urlencode(
            [
                (name, "<REDACTED:query>" if name.casefold() in sensitive else redact_text(item) or "")
                for name, item in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            doseq=True,
        )
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))

    @staticmethod
    def _redact_har_text(value: str) -> str:
        redacted = redact_text(value) or ""
        # HAR often stores form bodies rather than JSON.  Cover those explicit
        # credential assignments too, without retaining an opaque token value.
        return re.sub(
            r"(?i)(?P<prefix>(?:^|[&;\s\"'>])(?:token|access_token|id_token|refresh_token|authorization|cookie|session|api[_-]?key|secret|password)[\"']?\s*[:=]\s*[\"']?)(?P<value>[^&;\s\"'<>]+)",
            r"\g<prefix><REDACTED:body>",
            redacted,
        )
