"""Optional Stage-0 Headless Browser DOM Hydration (SPA Support, P0 #2).

Always routes browser requests through the Go loopback SSRF-enforcing HTTP/CONNECT proxy
when provided so dynamic SPA routes cannot pivot into internal/loopback or cloud metadata IPs.
Degrades cleanly to an empty unavailable payload when Playwright/Chromium is not installed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

_LINK_ATTR_RE = re.compile(r"""(?:src|href|action)=["']([^"'#]+)["']""", re.IGNORECASE)


def _find_chromium_binary() -> str | None:
    candidates = [
        "google-chrome",
        "chromium",
        "chromium-browser",
        "chrome",
        "msedge",
    ]
    for name in candidates:
        found = shutil.which(name)
        if found:
            return found

    if os.name == "nt":
        win_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ]
        for p in win_paths:
            if Path(p).is_file():
                return p
    return None


def _extract_dom_links(base_url: str, html_text: str) -> list[str]:
    base_host = (urlparse(base_url).hostname or "").lower()
    seen: list[str] = []
    seen_set: set[str] = set()
    for m in _LINK_ATTR_RE.finditer(html_text):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("data:", "javascript:", "mailto:")):
            continue
        joined = urljoin(base_url, raw)
        parsed = urlparse(joined)
        if parsed.scheme not in {"http", "https"}:
            continue
        host = (parsed.hostname or "").lower()
        if base_host and host and host != base_host and not host.endswith(f".{base_host}"):
            continue
        if joined not in seen_set:
            seen_set.add(joined)
            seen.append(joined)
        if len(seen) >= 60:
            break
    return seen


def hydrate_spa_target(
    target_url: str,
    proxy_url: str | None = None,
    timeout_ms: int = 12000,
) -> dict[str, Any]:
    """Attempts Stage-0 SPA DOM + XHR hydration through Playwright or headless Chromium."""
    parsed_target = urlparse(target_url)
    if parsed_target.scheme not in {"http", "https"}:
        return {
            "final_url": target_url,
            "hydrated_html": None,
            "xhr_urls": [],
            "hydrated": False,
            "hydrator_engine": "rejected",
            "reason": "Unsupported URL scheme for SPA hydrator",
        }

    # Try Playwright first if installed
    playwright_err = ""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore

        launch_args = ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
        proxy_cfg = {"server": proxy_url} if proxy_url else None
        captured_urls: list[str] = []
        seen_urls: set[str] = set()
        target_host = (parsed_target.hostname or "").lower()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=launch_args, proxy=proxy_cfg)
            try:
                context = browser.new_context(ignore_https_errors=False)
                page = context.new_page()

                def _on_request(req: Any) -> None:
                    try:
                        req_url = str(req.url)
                        u = urlparse(req_url)
                        h = (u.hostname or "").lower()
                        if (
                            u.scheme in {"http", "https"}
                            and len(captured_urls) < 60
                            and req_url not in seen_urls
                            and (h == target_host or h.endswith(f".{target_host}"))
                        ):
                            seen_urls.add(req_url)
                            captured_urls.append(req_url)
                    except Exception:
                        pass

                page.on("request", _on_request)
                page.goto(target_url, wait_until="networkidle", timeout=timeout_ms)
                final_url = page.url or target_url
                html_content = page.content() or ""
                for dom_link in _extract_dom_links(final_url, html_content):
                    if dom_link not in seen_urls and len(captured_urls) < 60:
                        seen_urls.add(dom_link)
                        captured_urls.append(dom_link)
                return {
                    "final_url": final_url,
                    "hydrated_html": html_content,
                    "xhr_urls": captured_urls,
                    "hydrated": True,
                    "hydrator_engine": "playwright",
                }
            finally:
                browser.close()
    except ImportError:
        pass
    except Exception as exc:
        # Fall through to Chromium CLI attempt or graceful skip
        playwright_err = str(exc)

    chrome_bin = _find_chromium_binary()
    if chrome_bin:
        cmd = [
            chrome_bin,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--virtual-time-budget=4000",
            "--dump-dom",
        ]
        if proxy_url:
            cmd.append(f"--proxy-server={proxy_url}")
        cmd.append(target_url)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(5, timeout_ms // 1000 + 3),
                check=False,
            )
            if proc.returncode == 0 and "<html" in proc.stdout.lower():
                dom_links = _extract_dom_links(target_url, proc.stdout)
                return {
                    "final_url": target_url,
                    "hydrated_html": proc.stdout,
                    "xhr_urls": dom_links,
                    "hydrated": True,
                    "hydrator_engine": "chromium_cli",
                }
        except Exception:
            pass

    return {
        "final_url": target_url,
        "hydrated_html": None,
        "xhr_urls": [],
        "hydrated": False,
        "hydrator_engine": "unavailable",
        "reason": playwright_err or "No Playwright or Chromium binary detected; Stage 1 Rust spider used directly",
    }


def write_spa_seed(
    target_url: str,
    out_path: str,
    proxy_url: str | None = None,
    timeout_ms: int = 12000,
) -> dict[str, Any]:
    dest = Path(out_path)
    if dest.exists() and dest.is_symlink():
        raise PermissionError(f"CWE-377 violation: destination {dest} is a symlink")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise PermissionError(f"CWE-377 violation: destination {dest} is a symlink")
    payload = hydrate_spa_target(target_url, proxy_url=proxy_url, timeout_ms=timeout_ms)
    dest.write_text(json.dumps(payload), encoding="utf-8")
    return payload
