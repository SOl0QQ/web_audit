"""
核心：统一 HTTP 请求封装器

所有模块的 HTTP 请求都通过此类发出，集中处理：
- TLS 警告压制
- 会话复用 (Session)
- 统一 User-Agent 与 Headers
- 超时与错误处理
- Playwright 渲染（处理 SPA/JS 动态页面），自动降级为 requests
"""
import urllib3
import requests
from requests import Response
from typing import Optional, Dict, Any
from web_audit.config.settings import (
    REQUEST_TIMEOUT,
    REQUEST_VERIFY_SSL,
    REQUEST_HEADERS,
)

# 全局禁用 InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 检测 Playwright 是否可用（可选依赖，未安装时自动降级）
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
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
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(REQUEST_HEADERS)
        if extra_headers:
            self.session.headers.update(extra_headers)

    def get(self, url: str, **kwargs) -> Optional[Response]:
        """发送 GET 请求，返回 Response 或 None（出错时）。"""
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            resp.encoding = resp.apparent_encoding
            return resp
        except Exception as e:
            print(f"[Requester] GET 失败 {url}: {e}")
            return None

    def post(self, url: str, data: Any = None, **kwargs) -> Optional[Response]:
        """发送 POST 请求，返回 Response 或 None（出错时）。"""
        try:
            resp = self.session.post(
                url, data=data, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            resp.encoding = resp.apparent_encoding
            return resp
        except Exception as e:
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
        """
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                
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

                # 构建 extra_http_headers
                extra_headers = {}
                for k, v in self.session.headers.items():
                    if k.lower() not in ['connection', 'accept-encoding', 'content-length']:
                        extra_headers[k] = v

                context = browser.new_context(
                    user_agent=self.session.headers.get("User-Agent", REQUEST_HEADERS["User-Agent"]),
                    ignore_https_errors=not self.verify_ssl,
                    extra_http_headers=extra_headers
                )
                
                # 注入 Cookies
                if pw_cookies:
                    context.add_cookies(pw_cookies)

                page = context.new_page()
                # networkidle: 网络连接数 < 2 持续 500ms，确保 JS 渲染完成
                page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                html = page.content()
                browser.close()
                print(f"[Requester] Playwright 渲染成功 (携带 Session 状态): {url}")
                return html
        except Exception as e:
            print(f"[Requester] Playwright 渲染失败 {url}: {e}，降级为 requests")
            resp = self.get(url)
            return resp.text if resp else None

    def fetch_network_resources(self, url: str) -> set:
        """
        使用 Playwright 真实浏览器访问指定 URL，并在后台监听网络层。
        截获页面在加载时所发起的所有资源请求（AJAX, 图片, 静态资源等）。
        解决前端框架 SPA (Vue/React) 在上传后通过异步请求获取图片列表的寻址难题。
        """
        from web_audit.config.settings import KATANA_ENABLED
        if not KATANA_ENABLED:
            return set()
            
        collected_urls = set()
        print(f"[Requester] 启动 Playwright 网络拦截器，监听目标: {url}")
        
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                
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

                context = browser.new_context(
                    user_agent=self.session.headers.get("User-Agent", REQUEST_HEADERS["User-Agent"]),
                    ignore_https_errors=not self.verify_ssl,
                    extra_http_headers=extra_headers
                )
                
                if pw_cookies:
                    context.add_cookies(pw_cookies)

                page = context.new_page()
                
                # 设置网络请求监听器，并强制禁用浏览器本地缓存
                page.route("**/*", lambda route: route.continue_())
                
                def handle_request(request):
                    # 忽略直接导航到主页面的请求
                    if request.url != url:
                        collected_urls.add(request.url)
                        
                page.on("request", handle_request)
                
                # 访问页面，等待网络空闲以确保异步请求都发出了
                # 添加一个随机参数彻底打穿静态页面缓存
                import time
                busting_url = f"{url}?_cb={int(time.time() * 1000)}" if "?" not in url else f"{url}&_cb={int(time.time() * 1000)}"
                page.goto(busting_url, wait_until="networkidle", timeout=self.timeout * 1000)
                browser.close()
                
                print(f"[Requester] Playwright 拦截完成，共捕获 {len(collected_urls)} 个网络请求")
                return collected_urls
                
        except Exception as e:
            print(f"[Requester] Playwright 网络拦截失败 {url}: {e}")
            return set()

    def close(self):
        """关闭 Session，释放连接资源。"""
        self.session.close()
