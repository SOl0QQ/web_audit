"""
核心：统一 HTTP 请求封装器

所有模块的 HTTP 请求都通过此类发出，集中处理：
- TLS 警告压制
- 会话复用 (Session)
- 统一 User-Agent 与 Headers
- 超时与错误处理
- Playwright 渲染（处理 SPA/JS 动态页面），自动降级为 requests
"""
import time
import urllib3
import requests
from requests import Response
from typing import Optional, Dict, Any
from web_audit.config.settings import (
    REQUEST_TIMEOUT,
    REQUEST_VERIFY_SSL,
    REQUEST_HEADERS,
    PLAYWRIGHT_RENDER_TIMEOUT,
)
from web_audit.core.performance_monitor import get_perf_monitor

# 全局禁用 InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 检测 Playwright 是否可用（通过浏览器池检测）
try:
    from web_audit.core.playwright_pool import is_available as _playwright_is_available
    _PLAYWRIGHT_AVAILABLE = _playwright_is_available()
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


class Requester:
    """统一 HTTP 请求封装，所有审计模块均通过此类与目标通信。"""

    def __init__(
        self,
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: int = REQUEST_TIMEOUT,
        verify_ssl: bool = REQUEST_VERIFY_SSL,
    ):
        import os
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(REQUEST_HEADERS)

        # 允许通过环境变量 AUDIT_COOKIE 或 COOKIE 注入自定义登录 Cookie
        env_cookie = os.getenv("AUDIT_COOKIE", "") or os.getenv("COOKIE", "")
        if env_cookie:
            self.session.headers["Cookie"] = env_cookie.strip()
            print(f"[Requester] 从环境变量加载自定义 Cookie 标头: {env_cookie[:30]}...")

        if extra_headers:
            self.session.headers.update(extra_headers)

    @staticmethod
    def _apply_encoding(resp: Response) -> None:
        """
        为响应推断并应用字符编码。

        直接调用 resp.apparent_encoding 存在两个风险：
          1. charset_normalizer/chardet 对部分响应（如某些压缩流、二进制）
             可能抛出 LookupError，导致整个请求被当作失败。
          2. 对大响应体会重新解码全部内容，性能开销大。
        这里做防御性处理：优先使用 Content-Type 声明的编码，
        其次尝试推断，最后回退到 UTF-8，确保任何情况下都不抛异常。
        """
        try:
            # 1) 优先使用响应头中声明的编码（最可靠、零开销）
            if resp.encoding:
                return
            # 2) 尝试内容推断；失败则回退 UTF-8
            try:
                inferred = resp.apparent_encoding
                if inferred:
                    resp.encoding = inferred
                    return
            except Exception:
                pass
            # 3) 最终回退
            resp.encoding = "utf-8"
        except Exception:
            # 兜底：任何异常都不应让请求本身失败
            resp.encoding = "utf-8"

    def get(self, url: str, **kwargs) -> Optional[Response]:
        """发送 GET 请求，返回 Response 或 None（出错时）。"""
        start = time.time()
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            duration = time.time() - start
            self._apply_encoding(resp)
            get_perf_monitor().record_http(
                method="GET",
                url=url,
                duration=duration,
                status_code=resp.status_code,
                success=True
            )
            return resp
        except Exception as e:
            duration = time.time() - start
            get_perf_monitor().record_http(
                method="GET",
                url=url,
                duration=duration,
                success=False,
                error=str(e)
            )
            print(f"[Requester] GET 失败 {url}: {e}")
            return None

    def post(self, url: str, data: Any = None, **kwargs) -> Optional[Response]:
        """发送 POST 请求，返回 Response 或 None（出错时）。"""
        start = time.time()
        try:
            resp = self.session.post(
                url, data=data, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            duration = time.time() - start
            self._apply_encoding(resp)
            get_perf_monitor().record_http(
                method="POST",
                url=url,
                duration=duration,
                status_code=resp.status_code,
                success=True
            )
            return resp
        except Exception as e:
            duration = time.time() - start
            get_perf_monitor().record_http(
                method="POST",
                url=url,
                duration=duration,
                success=False,
                error=str(e)
            )
            print(f"[Requester] POST 失败 {url}: {e}")
            return None

    def fetch_rendered_html(self, url: str) -> Optional[str]:
        """
        获取页面完整渲染后的 HTML（等待 JS 执行完毕）。

        优先使用 Playwright（处理 SPA/Vue/React 等动态页面），
        若 Playwright 未安装则自动降级为普通 requests.get()。

        Args:
            url: 目标页面 URL

        Returns:
            渲染后的 HTML 字符串，失败返回 None
        """
        if _PLAYWRIGHT_AVAILABLE:
            return self._fetch_with_playwright(url)
        else:
            print(f"[Requester] Playwright 未安装，降级为 requests（SPA 页面可能解析不完整）")
            print(f"[Requester] 提示：pip install playwright && playwright install chromium")
            resp = self.get(url)
            return resp.text if resp else None

    def _fetch_with_playwright(self, url: str) -> Optional[str]:
        """
        使用 Playwright headless chromium 渲染页面，等待网络空闲后返回 DOM。
        并将当前的 requests.Session 中的 cookies 和 headers 同步到浏览器。
        使用浏览器池复用 Chromium 实例，避免频繁启动/关闭。
        """
        try:
            from web_audit.core.playwright_pool import get_browser
            browser = get_browser()

            # 准备 Playwright 需要的 cookie 格式
            pw_cookies = []
            import urllib.parse
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.hostname

            for c in self.session.cookies:
                pw_cookies.append({
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain if c.domain else domain,
                    "path": c.path if c.path else "/"
                })

            # 构建 extra_http_headers 并强行禁用缓存
            extra_headers = {}
            for k, v in self.session.headers.items():
                if k.lower() not in ['connection', 'accept-encoding', 'content-length']:
                    extra_headers[k] = v
            extra_headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            extra_headers["Pragma"] = "no-cache"

            # 创建独立上下文（用完即关，不污染共享浏览器）
            context = browser.new_context(
                user_agent=self.session.headers.get("User-Agent", REQUEST_HEADERS["User-Agent"]),
                ignore_https_errors=not self.verify_ssl,
                extra_http_headers=extra_headers
            )

            try:
                # 注入 Cookies
                if pw_cookies:
                    context.add_cookies(pw_cookies)

                page = context.new_page()

                # 使用路由拦截禁用浏览器缓存（比 _cb=时间戳 更可靠）
                def disable_cache(route):
                    route.continue_(headers={
                        **route.request.headers,
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache"
                    })

                page.route("**/*", disable_cache)

                # 使用 domcontentloaded 策略，避免 networkidle 在持续请求的页面上卡死
                # 等待 DOM 加载完成后，再额外等待 2 秒让 JS 渲染完成
                print(f"[Requester] Playwright 开始渲染 (超时: {PLAYWRIGHT_RENDER_TIMEOUT}秒): {url}")
                start_time = time.time()
                page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_RENDER_TIMEOUT * 1000)
                page.wait_for_timeout(2000)  # 额外等待2秒确保动态内容渲染
                render_time = time.time() - start_time

                html = page.content()
                print(f"[Requester] ✅ Playwright 渲染成功 (耗时: {render_time:.2f}秒): {url}")
                return html
            finally:
                context.close()  # 只关闭上下文，不关闭浏览器
        except Exception as e:
            print(f"[Requester] Playwright 渲染失败 {url}: {e}，降级为 requests")
            # 直接传递 headers 参数，避免修改 session.headers 导致多线程竞态
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache"
                }
            )
            self._apply_encoding(resp)
            return resp.text if resp else None

    def fetch_network_resources(self, url: str) -> set:
        """
        使用 Playwright 真实浏览器访问指定 URL，并在后台监听网络层。
        截获页面在加载时所发起的所有资源请求（AJAX, 图片, 静态资源等）。
        解决前端框架 SPA (Vue/React) 在上传后通过异步请求获取图片列表的寻址难题。
        使用浏览器池复用 Chromium 实例。
        """
        from web_audit.config.settings import KATANA_ENABLED
        if not KATANA_ENABLED:
            return set()

        collected_urls = set()
        print(f"[Requester] 启动 Playwright 网络拦截器，监听目标: {url}")

        try:
            from web_audit.core.playwright_pool import get_browser
            browser = get_browser()

            # 准备 Playwright 需要的 cookie 格式，维持身份验证
            pw_cookies = []
            import urllib.parse
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.hostname

            for c in self.session.cookies:
                pw_cookies.append({
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain if c.domain else domain,
                    "path": c.path if c.path else "/"
                })

            extra_headers = {k: v for k, v in self.session.headers.items()
                           if k.lower() not in ['connection', 'accept-encoding', 'content-length']}

            # 强行禁用服务器端/CDN缓存
            extra_headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            extra_headers["Pragma"] = "no-cache"

            # 创建独立上下文（用完即关，不污染共享浏览器）
            context = browser.new_context(
                user_agent=self.session.headers.get("User-Agent", REQUEST_HEADERS["User-Agent"]),
                ignore_https_errors=not self.verify_ssl,
                extra_http_headers=extra_headers
            )

            try:
                if pw_cookies:
                    context.add_cookies(pw_cookies)

                page = context.new_page()

                # 提取主站域名用于过滤
                import urllib.parse
                target_domain = urllib.parse.urlparse(url).hostname or ""

                # 设置网络请求监听器
                def handle_request(request):
                    # 只保留同域名/子域名的请求，过滤第三方资源
                    request_domain = urllib.parse.urlparse(request.url).hostname or ""
                    if request_domain and (request_domain == target_domain or request_domain.endswith("." + target_domain)):
                        # 忽略直接导航到主页面的请求
                        if request.url != url:
                            collected_urls.add(request.url)

                page.on("request", handle_request)

                # 使用路由拦截禁用浏览器缓存（比 _cb=时间戳 更可靠）
                def disable_cache(route):
                    route.continue_(headers={
                        **route.request.headers,
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache"
                    })

                page.route("**/*", disable_cache)

                # 访问页面，等待网络空闲以确保异步请求都发出了
                page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)

                print(f"[Requester] Playwright 拦截完成，共捕获 {len(collected_urls)} 个网络请求")
                return collected_urls
            finally:
                context.close()  # 只关闭上下文，不关闭浏览器

        except Exception as e:
            print(f"[Requester] Playwright 网络拦截失败 {url}: {e}")
            return set()

    def close(self):
        """关闭 Session，释放连接资源。"""
        self.session.close()
