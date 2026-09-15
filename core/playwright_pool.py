"""
Playwright 浏览器池 - 线程本地单例模式

每个线程拥有独立的 Chromium 浏览器实例，避免 greenlet 跨线程切换问题。
同一线程内的调用复用同一实例，避免频繁启动/关闭带来的性能开销。

使用方式：
    from web_audit.core.playwright_pool import get_browser, get_context

    # 获取当前线程的浏览器
    browser = get_browser()

    # 创建独立的上下文（隔离 cookies/缓存）
    context = browser.new_context(...)
    page = context.new_page()
    # ... 使用完毕后只关闭 context，不关闭 browser

    # 程序结束时释放所有线程的资源
    shutdown_browser()
"""
import threading
from typing import Optional

# 线程本地存储：每个线程有自己的 browser 和 playwright 实例
_local = threading.local()
# 跟踪所有线程的浏览器实例，以便统一关闭
_all_browsers = []
_all_playwrights = []
_lock = threading.Lock()


def get_browser():
    """
    获取当前线程的 Chromium 浏览器实例（线程安全）。

    每个线程首次调用时启动浏览器，后续调用复用同一实例。
    不同线程各自拥有独立的浏览器实例。
    """
    # 检查当前线程是否已有浏览器实例
    if hasattr(_local, 'browser') and _local.browser is not None:
        return _local.browser

    # 为当前线程创建新的浏览器实例
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(headless=True)
    except Exception:
        # chromium.launch() 失败时，必须 stop 已启动的 playwright，否则子进程泄漏
        try:
            pw.stop()
        except Exception:
            pass
        raise

    # 保存到线程本地
    _local.browser = browser
    _local.playwright = pw

    # 记录到全局列表，用于统一关闭
    with _lock:
        _all_browsers.append(browser)
        _all_playwrights.append(pw)

    print(f"[PlaywrightPool] 浏览器实例已启动（线程: {threading.current_thread().name}）")
    return browser


def shutdown_browser():
    """
    关闭当前线程的浏览器并释放资源。

    每个线程只关闭自己的浏览器实例，不影响其他线程。
    应在每个线程的流水线结束时调用（如 run_pipeline 的 finally 块）。
    """
    browser = getattr(_local, 'browser', None)
    pw = getattr(_local, 'playwright', None)

    if browser is not None:
        try:
            browser.close()
        except Exception:
            pass
        _local.browser = None

        # 从全局列表中移除
        with _lock:
            if browser in _all_browsers:
                _all_browsers.remove(browser)

    if pw is not None:
        try:
            pw.stop()
        except Exception:
            pass
        _local.playwright = None

        with _lock:
            if pw in _all_playwrights:
                _all_playwrights.remove(pw)

    print(f"[PlaywrightPool] 浏览器实例已关闭（线程: {threading.current_thread().name}）")


def is_available() -> bool:
    """检查 Playwright 是否可用（仅检查是否已安装，不启动浏览器）。"""
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        return False
