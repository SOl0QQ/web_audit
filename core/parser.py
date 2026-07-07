"""
核心：网页 HTML/DOM 解析器

负责将原始 HTML 解析为各模块需要的结构化特征数据：
- 提取表单 (form/input)
- 提取候选链接
- 提取页面文本片段
- 识别文件上传表单
- 提取登录页精细化高信号特征 (get_auth_signals)
- 提取全量链接供 LLM 排序 (get_all_links)
"""
import urllib.parse
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup


class PageParser:
    """HTML 页面结构化解析器。"""

    LOGIN_KEYWORDS = [
        "login", "signin", "sign-in", "log-in",
        "登录", "登入", "注册", "进入", "portal",
        "console", "控制台", "oauth", "auth",
    ]

    def __init__(self, html: str, base_url: str):
        self.base_url = base_url
        self.soup = BeautifulSoup(html, "html.parser")

    @property
    def title(self) -> str:
        """返回页面标题。"""
        return self.soup.title.get_text(strip=True) if self.soup.title else ""

    @property
    def text_snippet(self) -> str:
        """返回页面纯文本片段（去噪），最多 1000 字符。"""
        return self.soup.get_text(separator=" ", strip=True)[:1000]

    def get_forms(self) -> List[Dict[str, Any]]:
        """提取页面中所有表单及其输入字段信息。
        包含标准的 <form> 以及无 <form> 标签包裹的“虚拟表单”（针对 AJAX 提交）。
        """
        forms = []
        covered_inputs = set()

        # 1. 提取标准表单
        for form in self.soup.find_all("form"):
            inputs = []
            for inp in form.find_all("input"):
                covered_inputs.add(inp)
                inputs.append({
                    "type": inp.get("type", "text"),
                    "name": inp.get("name", "") or inp.get("id", ""), # AJAX 表单常没 name 只有 id
                    "id": inp.get("id", ""),
                    "value": inp.get("value", ""),
                    "placeholder": inp.get("placeholder", ""),
                    "accept": inp.get("accept", ""),  # 文件上传的 accept 属性
                })
            # 同时收集 <select> 和 <textarea>
            selects = [s.get("name", "") or s.get("id", "") for s in form.find_all("select")]
            textareas = [t.get("name", "") or t.get("id", "") for t in form.find_all("textarea")]
            forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", "get").lower(),
                "id": form.get("id", ""),
                "enctype": form.get("enctype", ""),     # multipart/form-data 表示文件上传
                "inputs": inputs,
                "selects": selects,
                "textareas": textareas,
                "raw_html": str(form),
            })
            
        # 2. 提取游离的 Input (虚拟表单，主要针对 SPA / 纯 AJAX)
        orphan_inputs = []
        for inp in self.soup.find_all("input"):
            if inp not in covered_inputs:
                orphan_inputs.append({
                    "type": inp.get("type", "text"),
                    "name": inp.get("name", "") or inp.get("id", ""),
                    "id": inp.get("id", ""),
                    "value": inp.get("value", ""),
                    "placeholder": inp.get("placeholder", ""),
                    "accept": inp.get("accept", ""),
                })
        
        # 如果存在游离输入框，组装成一个虚拟表单
        if orphan_inputs:
            orphan_selects = [s.get("name", "") or s.get("id", "") for s in self.soup.find_all("select") if not s.find_parent("form")]
            orphan_textareas = [t.get("name", "") or t.get("id", "") for t in self.soup.find_all("textarea") if not t.find_parent("form")]
            
            forms.append({
                "action": "",  # 虚拟表单无 action，将触发后续的 LLM AJAX 推理
                "method": "post",  # AJAX 默认猜 POST
                "id": "virtual_ajax_form",
                "enctype": "",
                "inputs": orphan_inputs,
                "selects": orphan_selects,
                "textareas": orphan_textareas,
                "raw_html": "<virtual_form>游离的 AJAX 提交字段</virtual_form>", # 避免存放超大外层 html
            })

        return forms

    def get_auth_signals(self) -> Dict[str, Any]:
        """
        专门为登录页识别提取高信号特征（精细化、低噪声）。

        相比 to_features() 提供的原始 HTML 转储，本方法只保留
        对"是否为登录页"判断真正有意义的信号：

        信号权重（由高到低）：
          1. password_inputs   — 存在密码框（最强信号）
          2. form_actions      — 表单 action 含认证语义路径
          3. button_texts      — 提交按钮文字含登录语义
          4. headings          — H1/H2/H3 标题含登录关键词
          5. meta_description  — meta description 含认证关键词
        """
        # 1. 密码类 input（最强信号）
        password_inputs = [
            {
                "name": inp.get("name", ""),
                "id": inp.get("id", ""),
                "placeholder": inp.get("placeholder", ""),
            }
            for inp in self.soup.find_all("input", type="password")
        ]

        # 2. 所有文本/邮件类 input（用于判断用户名框）
        text_inputs = [
            {
                "type": inp.get("type", "text"),
                "name": inp.get("name", ""),
                "id": inp.get("id", ""),
                "placeholder": inp.get("placeholder", ""),
            }
            for inp in self.soup.find_all("input")
            if inp.get("type", "text").lower() in ("text", "email", "tel")
        ]

        # 3. 提交/按钮文字
        button_texts = [
            btn.get_text(strip=True)
            for btn in self.soup.find_all(
                ["button", "input"],
                attrs={"type": ["submit", "button"]}
            )
        ]

        # 4. 表单 action 路径（绝对路径）
        form_actions = [
            urllib.parse.urljoin(self.base_url, f.get("action", ""))
            for f in self.soup.find_all("form")
        ]

        # 5. H1/H2/H3 标题文字
        headings = [
            h.get_text(strip=True)
            for h in self.soup.find_all(["h1", "h2", "h3"])
        ]

        # 6. meta description
        meta_tag = self.soup.find("meta", attrs={"name": "description"})
        meta_desc = meta_tag.get("content", "") if meta_tag else ""

        return {
            "url": self.base_url,
            "title": self.title,
            "password_inputs": password_inputs,
            "text_inputs": text_inputs[:10],          # 限制数量防止溢出
            "button_texts": button_texts[:10],
            "form_actions": form_actions,
            "headings": headings[:5],
            "meta_description": meta_desc,
        }

    @staticmethod
    def is_static_resource(url_or_path: str) -> bool:
        """检查是否是明显的静态资源后缀，这类链接不需要进行动态安全审计。"""
        import urllib.parse
        path = urllib.parse.urlparse(url_or_path).path.lower()
        static_extensions = (
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.mp4', '.mp3', '.avi', '.wav', '.webm',
            '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
            '.xml', '.txt', '.csv', '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx'
        )
        return path.endswith(static_extensions)

    def get_all_links(self, limit: int = 100) -> List[Dict[str, str]]:
        """提取页面中所有的同域或相关链接，用于构建攻击面。"""
        links = []
        seen = set()

        # 1. 提取傳統的 a 標籤與 iframe
        for tag in self.soup.find_all(["a", "iframe"]):
            href = tag.get("href") or tag.get("src")
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            
            if self.is_static_resource(href):
                continue
            
            full_url = urllib.parse.urljoin(self.base_url, href)
            if full_url in seen:
                continue
            seen.add(full_url)
            
            text = tag.get_text(strip=True)[:30] if tag.name == "a" else "iframe"
            links.append({
                "text": text or href[:20],
                "url": full_url,
            })

        # 2. 靜態原始碼審查 (LinkFinder 風格)：擷取 JS 中的 API 端點
        import re
        js_sources = self.get_javascript_sources()
        js_text = "\n".join(js_sources.get("inline", []))
        
        # 匹配常見的 AJAX 呼叫 ($.get, fetch, window.open 等)，抓出裡面長得像 URL 的字串
        ajax_patterns = [
            r'\$\.(?:get|post|ajax)\s*\(\s*[\'"]([^\'"]+\.[a-zA-Z0-9]{2,4}[^\'"]*)[\'"]',
            r'fetch\s*\(\s*[\'"]([^\'"]+\.[a-zA-Z0-9]{2,4}[^\'"]*)[\'"]',
            r'window\.open\s*\(\s*[\'"]([^\'"]+\.[a-zA-Z0-9]{2,4}[^\'"]*)[\'"]',
            r'window\.location(?:\.href)?\s*=\s*[\'"]([^\'"]+\.[a-zA-Z0-9]{2,4}[^\'"]*)[\'"]'
        ]
        
        for pattern in ajax_patterns:
            for match in re.findall(pattern, js_text):
                # 清除 JS 變數拼接痕跡 (如 "api.php?id=" + id)
                clean_path = match.split("?")[0].split("+")[0].split('"')[0].split("'")[0].strip()
                if not clean_path or len(clean_path) < 3: continue
                
                full_url = urllib.parse.urljoin(self.base_url, clean_path)
                if full_url in seen: continue
                seen.add(full_url)
                
                links.append({
                    "text": "[JS_API] " + clean_path[:15],
                    "url": full_url,
                })

        return links[:limit]

    def get_upload_forms(self) -> List[Dict[str, Any]]:
        """筛选出包含文件上传控件的表单。"""
        upload_forms = []
        for form in self.get_forms():
            has_file_input = any(
                inp["type"].lower() == "file" for inp in form["inputs"]
            )
            is_multipart = "multipart" in form.get("enctype", "").lower()
            if has_file_input or is_multipart:
                upload_forms.append(form)
        return upload_forms

    def get_login_candidate_links(self, limit: int = 15) -> List[Dict[str, str]]:
        """提取页面中可能导向登录页的候选链接。"""
        links = []
        for a in self.soup.find_all("a", href=True):
            href = a["href"]
            text = a.get_text(strip=True)
            if any(
                kw in href.lower() or kw in text.lower()
                for kw in self.LOGIN_KEYWORDS
            ):
                full_url = urllib.parse.urljoin(self.base_url, href)
                links.append({"text": text, "url": full_url})
        return links[:limit]

    def get_all_form_params(self) -> List[Dict[str, Any]]:
        """返回所有表单的参数列表及默认值（用于 SQL 注入检测的输入点枚举）。"""
        params_list = []
        for form in self.get_forms():
            action_url = urllib.parse.urljoin(self.base_url, form["action"]) or self.base_url
            injectable_params = []
            default_values = {}
            is_login_form = False
            
            for inp in form["inputs"]:
                name = inp.get("name") or inp.get("id")
                if not name:
                    continue
                    
                inp_type = inp.get("type", "").lower()
                val = inp.get("value", "")
                
                # 记录所有字段的默认值（尤其是 hidden, submit, radio 等）
                default_values[name] = val
                
                if inp_type == "password":
                    is_login_form = True
                    
                # 只有非隐藏、非提交类的输入框才作为注入测试点
                if inp_type not in ("submit", "button", "image", "reset", "file", "hidden", "radio", "checkbox"):
                    injectable_params.append(name)
                    
            if injectable_params:
                params_list.append({
                    "action": action_url,
                    "method": form["method"],
                    "params": injectable_params,
                    "default_values": default_values,
                    "is_login_form": is_login_form,
                    "form_id": form.get("id", ""),
                    "raw_action": form.get("action", ""),
                    "raw_html": form.get("raw_html", "")
                })
        return params_list

    def get_javascript_sources(self) -> Dict[str, Any]:
        """提取页面中所有的内联和外联 Javascript，用于辅助推断 AJAX 行为。"""
        inline_scripts = []
        external_scripts = []

        for script in self.soup.find_all("script"):
            src = script.get("src")
            if src:
                # Get the domain of base_url
                parsed_base = urllib.parse.urlparse(self.base_url)
                base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
                
                # 仅保留相对路径或同源脚本
                if src.startswith("http") and not src.startswith(base_domain):
                    pass # ignore external domains
                else:
                    if not src.startswith("http"):
                        full_url = urllib.parse.urljoin(self.base_url, src)
                    else:
                        full_url = src
                    if full_url not in external_scripts:
                        external_scripts.append(full_url)
            else:
                text = script.get_text(strip=True)
                if text:
                    inline_scripts.append(text)

        return {
            "inline": inline_scripts,
            "external_urls": external_scripts
        }


    def to_features(self) -> Dict[str, Any]:
        """导出为标准特征字典（供 LangChain Chain 使用）。"""
        return {
            "url": self.base_url,
            "title": self.title,
            "forms": self.get_forms(),
            "candidate_links": self.get_login_candidate_links(),
            "upload_forms": self.get_upload_forms(),
            "snippet": self.text_snippet,
        }