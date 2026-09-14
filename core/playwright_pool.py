"""
Playwright 浏览器池 - 单例模式

统一管理 Chromium 浏览器实例，避免频繁启动/关闭带来的性能开销。

使用方式：
    from web_audit.core.playwright_pool import get_browser, get_context

    # 获取共享浏览器
    browser = get_browser()

    # 创建独立的上下文（隔离 cookies/缓存）
    context = browser.new_context(...)
    page = context.new_page()
    # ... 使用完毕后只关闭 context，不关闭 browser

    # 程序结束时释放资源
    shutdown_browser()
"""
import threading
from typing import Optional

_browser = None
_playwright = None
_lock = threading.Lock()


def get_browser():
    """
    获取共享的 Chromium 浏览器实例（线程安全）。

    首次调用时启动浏览器，后续调用复用同一实例。
    """
    global _browser, _playwright

    if _browser is not None:
        return _browser

    with _lock:
        # 双重检查锁定
        if _browser is not None:
            return _browser

        from playwright.sync_api import sync_playwright
        _playwright = sync_playwright().start()
        _browser = _playwright.chromium.launch(headless=True)
        print("[PlaywrightPool] 浏览器实例已启动（单例模式）")
        return _browser


def shutdown_browser():
    """
    关闭浏览器并释放资源。

    应在流水线结束时调用（如 main.py 的 finally 块）。
    """
    global _browser, _playwright

    with _lock:
        if _browser is not None:
            try:
                _browser.close()
            except Exception:
                pass
            _browser = None

        if _playwright is not None:
            try:
                _playwright.stop()
            except Exception:
                pass
            _playwright = None

        print("[PlaywrightPool] 浏览器实例已关闭")


def is_available() -> bool:
    """检查 Playwright 是否可用（仅检查是否已安装，不启动浏览器）。"""
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        return False
