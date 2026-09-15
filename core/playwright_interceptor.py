"""
动态无头浏览器拦截器 (Playwright Interceptor)

用于处理 AJAX 表单（action 为空）的场景，通过真实点击提交按钮，
监听底层网络请求，从而捕获真实的后端 API 提交路径。
使用浏览器池复用 Chromium 实例。
"""
import time
from typing import Optional

class PlaywrightInterceptor:
    """使用 Playwright 动态拦截网络请求"""

    def __init__(self, timeout_ms: int = 30000):
        self.timeout_ms = timeout_ms

    def intercept_form_action(self, target_url: str, cookies: list = None) -> Optional[str]:
        """
        打开页面，监听网络请求，自动点击登录/上传按钮，
        返回拦截到的 POST/PUT 真实提交地址。
        """
        intercepted_url = None

        try:
            from web_audit.core.playwright_pool import get_browser
            browser = get_browser()

            # 创建独立上下文（用完即关，不污染共享浏览器）
            context = browser.new_context(ignore_https_errors=True)

            try:
                if cookies:
                    # 转换 requests cookies 到 Playwright 格式
                    pw_cookies = []
                    import urllib.parse
                    parsed_url = urllib.parse.urlparse(target_url)
                    domain = parsed_url.hostname
                    for c in cookies:
                        pw_cookies.append({
                            "name": c.name,
                            "value": c.value,
                            "domain": c.domain or domain,
                            "path": c.path or "/"
                        })
                    context.add_cookies(pw_cookies)

                page = context.new_page()

                # 定义网络拦截回调
                def handle_request(request):
                    nonlocal intercepted_url
                    # 如果发现页面发出了 POST 或 PUT 请求，记录下来
                    if request.method in ("POST", "PUT"):
                        # 排除一些明显的静态资源和日志上报
                        if not any(ext in request.url.lower() for ext in [".png", ".jpg", ".css", ".js", "google-analytics"]):
                            print(f"      [Playwright] 拦截到网络请求: [{request.method}] {request.url} (类型: {request.resource_type})")
                            if not intercepted_url:
                                intercepted_url = request.url

                page.on("request", handle_request)

                print(f"      [Playwright] 正在加载页面: {target_url}")
                # 使用 networkidle 确保页面完全加载，但设置合理超时
                page.goto(target_url, timeout=self.timeout_ms, wait_until="networkidle")

                # 等待一会儿确保 JS 加载完成
                page.wait_for_timeout(1000)

                # 启发式填充表单（尽可能填充文本框和密码框，防止前端验证失败）
                print("      [Playwright] 正在填充测试数据...")
                # 使用短超时快速失败，避免卡住
                try:
                    text_inputs = page.locator("input[type='text'], input[type='email']").all()
                    for inp in text_inputs:
                        inp.fill("testuser", timeout=2000)
                except Exception:
                    pass

                try:
                    password_inputs = page.locator("input[type='password']").all()
                    for inp in password_inputs:
                        inp.fill("Test@1234", timeout=2000)
                except Exception:
                    pass

                # 处理文件上传框
                try:
                    file_inputs = page.locator("input[type='file']").all()
                    for inp in file_inputs:
                        import tempfile
                        import os
                        tmp_path = None
                        try:
                            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
                                tmp.write(b"dummy image data")
                                tmp_path = tmp.name
                            inp.set_input_files(tmp_path, timeout=2000)
                        finally:
                            # 清理临时文件
                            if tmp_path and os.path.exists(tmp_path):
                                try:
                                    os.unlink(tmp_path)
                                except Exception:
                                    pass
                except Exception:
                    pass

                # 寻找提交按钮并点击
                print("      [Playwright] 尝试点击提交/上传按钮...")
                try:
                    submit_buttons = page.locator("button[type='submit'], input[type='submit']").all()
                    if not submit_buttons:
                        submit_buttons = page.locator("button:has-text('Login'), button:has-text('Sign'), button:has-text('Submit'), button:has-text('登录'), button:has-text('登入'), button:has-text('Upload'), button:has-text('Save'), button:has-text('上传'), button:has-text('保存')").all()

                    if submit_buttons:
                        # 使用 JS 原生 click，完全無視 display:none 或不可見的限制
                        submit_buttons[0].evaluate("el => el.click()")
                        # 点击后等待一会儿，让 AJAX 请求发出去
                        page.wait_for_timeout(2000)
                    else:
                        print("      [Playwright] 未找到明显的提交按钮。")
                except Exception as e:
                    print(f"      [Playwright] 点击按钮失败: {e}")

            except Exception as e:
                print(f"      [Playwright] 执行过程中发生异常: {e}")
            finally:
                context.close()  # 只关闭上下文，不关闭浏览器

        except Exception as e:
            print(f"      [Playwright] 浏览器启动失败: {e}")

        return intercepted_url
