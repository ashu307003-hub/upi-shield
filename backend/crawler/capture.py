import asyncio
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import Browser, Playwright, async_playwright

OUT = Path("data/captures")
_playwright: Playwright | None = None
_browser: Browser | None = None
_browser_lock = asyncio.Lock()


async def _get_browser() -> Browser:
    global _playwright, _browser

    if _browser is not None and _browser.is_connected():
        return _browser

    async with _browser_lock:
        if _browser is not None and _browser.is_connected():
            return _browser

        if _playwright is None:
            _playwright = await async_playwright().start()

        _browser = await _playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
            ],
        )

        return _browser


async def close_capture_browser() -> None:
    global _playwright, _browser

    browser, playwright = _browser, _playwright
    _browser = None
    _playwright = None

    try:
        if browser is not None:
            await browser.close()
    finally:
        if playwright is not None:
            await playwright.stop()


async def capture(url: str, timeout_ms: int = 20000, output_dir: Path = OUT) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url must be an absolute http(s) URL")
    output_dir.mkdir(parents=True, exist_ok=True)
    url_id = hashlib.sha1(url.encode()).hexdigest()[:16]
    shot_path = output_dir / f"{url_id}.png"
    dom_path = output_dir / f"{url_id}.html"
    net_path = output_dir / f"{url_id}.json"

    browser = await _get_browser()
    ctx = await browser.new_context(viewport={"width": 1366, "height": 900}, locale="en-IN")
    try:
        page = await ctx.new_page()
        requests_log: list[dict[str, str]] = []
        responses_log: list[dict[str, object]] = []
        page.on("request", lambda request: requests_log.append({"url": request.url, "method": request.method, "resource": request.resource_type}))
        page.on("response", lambda response: responses_log.append({"url": response.url, "status": response.status, "resource": response.request.resource_type}))
        result = {"url": url, "url_id": url_id, "ok": False, "requests": str(net_path)}
        try:
            resp = await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(800)
            await page.screenshot(path=str(shot_path), full_page=True)
            html = await page.content()
            dom_path.write_text(html, encoding="utf-8")
            net_path.write_text(json.dumps({"requests": requests_log, "responses": responses_log}, indent=2), encoding="utf-8")
            result.update({
                "ok": True, "status": resp.status if resp else None, "final_url": page.url,
                "title": await page.title(), "screenshot": str(shot_path), "dom": str(dom_path),
                "network": str(net_path), "redirects": [{"url": r["url"], "status": r["status"]} for r in responses_log if r["resource"] == "document"],
            })
        except Exception as error:
            result["error"] = str(error)
    finally:
        await ctx.close()

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m backend.crawler.capture https://authorized.example")
    print(json.dumps(asyncio.run(capture(sys.argv[1])), indent=2))
