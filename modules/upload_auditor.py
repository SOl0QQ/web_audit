"""
模块 3：文件上传功能识别 + 安全检查

本模块包含两个子功能：
  A. UploadIdentifierModule - 识别页面中的文件上传功能点
  B. UploadSecurityAuditModule - 对上传端点进行安全控制项审查：
       - MIME 类型校验（Content-Type 欺骗检测）
       - 文件扩展名校验（黑名单/白名单策略）
       - 文件名路径穿越保护
"""
import os
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from web_audit.modules.base_module import BaseModule
from web_audit.core.requester import Requester
from web_audit.core.parser import PageParser
from prd.web_audit.core.llm_factory_test import get_llm
from web_audit.config.settings import (
    ALLOWED_MIME_TYPES,
    ALLOWED_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 模块 A：上传功能识别
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UploadFormInfo(BaseModel):
    """单个上传表单的结构化信息。"""
    action_url: str = Field(description="表单提交的目标 URL")
    method: str = Field(description="HTTP 方法 (post/get)")
    file_input_names: List[str] = Field(description="文件 input 的 name 属性列表")
    accepted_types: List[str] = Field(
        description="input accept 属性声明的允许类型（客户端限制，可绕过）",
        default=[]
    )
    is_multipart: bool = Field(description="enctype 是否为 multipart/form-data")


class UploadIdentifierModule(BaseModule):
    """文件上传功能点识别模块。"""

    name = "upload_identifier"

    def __init__(self, requester: Requester):
        super().__init__(requester)

    def run(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """扫描指定页面，识别所有文件上传表单。若已认证，进行保守深度的后台探索。"""
        result = self._base_result(url)
        is_authenticated = (context or {}).get("is_authenticated", False)
        
        visited = set()
        all_upload_forms = []

        print(f"  [UploadIdentifier] 开始扫描目标: {url} (已登录: {is_authenticated})")
        
        # 1. 检查首页 (Landing Page)
        resp = self.requester.get(url)
        if not resp:
            result["summary"] = "无法访问目标页面"
            return result
            
        visited.add(url)
        parser = PageParser(resp.text, url)
        forms = parser.get_upload_forms()
        
        for f in forms:
            f["source_url"] = url
            f["referer_url"] = None  # 根页面没有父级
        all_upload_forms.extend(forms)
        
        # 2. 如果首页没找到，且是已认证状态，进行后台探索 (Depth=2)
        if not all_upload_forms and is_authenticated:
            print("  [UploadIdentifier] 首页未发现上传点，启动安全后台探索...")
            
            # Phase 1: 寻找带 Upload 关键词的正向链接
            keyword_links = self._extract_upload_candidate_links(parser)
            phase1_found = False
            
            if keyword_links:
                print(f"  [UploadIdentifier] Phase 1: 发现 {len(keyword_links)} 个疑似上传链接，优先探索")
                for link in keyword_links:
                    href = link["url"]
                    if not self._is_same_domain(url, href): continue
                    if href in visited: continue
                    visited.add(href)
                    
                    print(f"    → [Phase1] 探索可疑上传页: {href} ({link['text']})")
                    sub_resp = self.requester.get(href)
                    if not sub_resp: continue
                        
                    sub_parser = PageParser(sub_resp.text, href)
                    sub_forms = sub_parser.get_upload_forms()
                    
                    if sub_forms:
                        print(f"      ✅ Phase 1 发现上传点！")
                        for f in sub_forms: 
                            f["source_url"] = href
                            f["referer_url"] = url  # 记录是由首页点进来的
                        all_upload_forms.extend(sub_forms)
                        phase1_found = True
                        break
                        
            # Phase 2: 如果 Phase 1 没找到，启动基于 UPLOAD_MAX_DEPTH 的广度优先搜索 (BFS)
            if not phase1_found:
                from web_audit.config.settings import UPLOAD_MAX_DEPTH, UPLOAD_MAX_PAGES
                print(f"  [UploadIdentifier] Phase 1 未发现，启动 Phase 2 深度安全遍历 (最大深度: {UPLOAD_MAX_DEPTH}, 最大探索页面数: {UPLOAD_MAX_PAGES})...")
                from collections import deque
                
                # 队列存储元组: (当前页面URL, 当前深度, 父页面URL)
                queue = deque([(url, 1, None)])
                pages_crawled = 0
                
                # 为了在 BFS 中提取当前页面的链接，我们需要解析
                # 但首字母页面已经解析过了，所以缓存一下
                url_parser_map = {url: parser}
                
                while queue and pages_crawled < UPLOAD_MAX_PAGES:
                    current_url, current_depth, parent_url = queue.popleft()
                    
                    # 避免深度超过配置
                    if current_depth > UPLOAD_MAX_DEPTH:
                        continue
                        
                    try:
                        if current_url in url_parser_map:
                            current_parser = url_parser_map[current_url]
                        else:
                            print(f"    → [Phase2] (Depth:{current_depth}) 探索页面: {current_url}")
                            resp = self.requester.get(current_url)
                            if not resp: continue
                            current_parser = PageParser(resp.text, current_url)
                            
                            # 检查当前页面本身是否有上传表单
                            current_forms = current_parser.get_upload_forms()
                            if current_forms:
                                print(f"      ✅ Phase 2 在深度 {current_depth} 发现上传点！({current_url})")
                                for f in current_forms: 
                                    f["source_url"] = current_url
                                    f["referer_url"] = parent_url  # 记录是由哪个父页面点击进来的
                                all_upload_forms.extend(current_forms)
                                break  # 找到就停止整个 BFS
                                
                        pages_crawled += 1
                        
                        # 如果没有找到，提取当前页面的安全链接加入队列，深度+1
                        all_links = current_parser.get_all_links(limit=200)
                        safe_links = [l for l in all_links if self._is_safe_link(l) and self._is_same_domain(url, l["url"])]
                        
                        for link in safe_links:
                            href = link["url"]
                            if href not in visited:
                                visited.add(href)
                                queue.append((href, current_depth + 1, current_url))
                                
                    except Exception as e:
                        print(f"    [Error] 探索 {current_url} 時發生例外: {e}")
                        import traceback
                        traceback.print_exc()
                        continue
                        
            # Phase 3: Katana 動態探索 (Headless Browser)
            if not all_upload_forms:
                from web_audit.config.settings import TOOL_DISCOVERY_ENABLED, KATANA_ENABLED
                if TOOL_DISCOVERY_ENABLED and KATANA_ENABLED:
                    print(f"  [UploadIdentifier] Phase 2 未发现，启动 Phase 3 (Katana 动态爬虫) 寻找隐藏端点...")
                    from web_audit.core.tool_discovery import KatanaRunner
                    katana = KatanaRunner()
                    
                    # 传入我们当前 Session 的 cookies 给 Katana
                    current_cookies = self.requester.session.cookies.get_dict()
                    katana_urls = katana.run(url, cookies=current_cookies)
                    
                    if katana_urls:
                        print(f"  [UploadIdentifier] Katana 发现 {len(katana_urls)} 个 URL，开始验证...")
                        # 过滤非同域 URL 并去重已访问的
                        new_urls = [u for u in katana_urls if self._is_same_domain(url, u) and u not in visited]
                        
                        for k_url in new_urls:
                            visited.add(k_url)
                            try:
                                print(f"    → [Phase3] 检查 Katana 发现的页面: {k_url}")
                                k_resp = self.requester.get(k_url)
                                if not k_resp: continue
                                
                                k_parser = PageParser(k_resp.text, k_url)
                                k_forms = k_parser.get_upload_forms()
                                if k_forms:
                                    print(f"      ✅ Phase 3 在 Katana 发现的动态页面中找到上传点！({k_url})")
                                    for f in k_forms: f["source_url"] = k_url
                                    all_upload_forms.extend(k_forms)
                                    break
                            except Exception as e:
                                continue
                        
        # 4. 整理结果
        if not all_upload_forms:
            result["summary"] = "未发现文件上传功能"
            return result

        import urllib.parse
        from web_audit.modules.sqli_detector import AJAX_INFER_PROMPT, AJAXActionInferResult
        from prd.web_audit.core.llm_factory_test import get_llm
        llm = get_llm()
        ajax_chain = AJAX_INFER_PROMPT | llm.with_structured_output(AJAXActionInferResult)

        for form in all_upload_forms:
            source = form.get("source_url", url)
            
            raw_action = form.get("action", "")
            form_id = form.get("id", "")
            action_url = urllib.parse.urljoin(source, raw_action) or source
            method = form["method"]
            
            # AJAX Infer Logic
            if (raw_action == "" or raw_action == "#" or action_url == source) and form_id:
                print(f"  [UploadIdentifier] 表单 '{form_id}' 疑似 AJAX 提交，正在提取业务 JS 源码并请求 LLM 推断...")
                
                # 取得來源網頁的 JavaScript
                js_sources = parser.get_javascript_sources() if source == url else PageParser(self.requester.get(source).text, source).get_javascript_sources()
                js_text_blocks = js_sources["inline"]
                
                # 過濾常見的大型第三方庫
                blacklisted_libs = ["jquery", "bootstrap", "vue", "react", "angular", "tinymce", "chart", "vendor", "sweetalert"]
                
                for js_url in js_sources["external_urls"]:
                    if any(lib in js_url.lower() for lib in blacklisted_libs):
                        continue # 跳過龐大的第三方庫
                        
                    js_resp = self.requester.get(js_url)
                    if js_resp and js_resp.status_code == 200:
                        js_text_blocks.append(f"// URL: {js_url}\n" + js_resp.text)
                
                combined_js = "\n\n".join(js_text_blocks)
                
                # 直接保留前 40000 字元 (約 10k tokens，完全在 Gemma 4 處理範圍內)
                combined_js = combined_js[:40000]
                
                if combined_js.strip():
                    try:
                        infer_result = ajax_chain.invoke({
                            "form_id": form_id,
                            "form_html": form.get("raw_html", ""),
                            "base_url": source,
                            "js_sources": combined_js
                        })
                        if infer_result and infer_result.real_url:
                            action_url = urllib.parse.urljoin(source, infer_result.real_url)
                            method = infer_result.method.lower()
                            print(f"  [UploadIdentifier] 🎯 提取到真实上传接口: {action_url}")
                            form["action"] = action_url
                    except Exception as e:
                        print(f"  [UploadIdentifier] AJAX 接口推断失败: {e}")
            file_inputs = [
                inp["name"] or inp["id"]
                for inp in form["inputs"]
                if inp["type"].lower() == "file"
            ]
            accepted = [
                inp["accept"]
                for inp in form["inputs"]
                if inp["type"].lower() == "file" and inp.get("accept")
            ]

            finding = UploadFormInfo(
                action_url=action_url,
                method=form["method"],
                file_input_names=[f for f in file_inputs if f],
                accepted_types=accepted,
                is_multipart="multipart" in form.get("enctype", "").lower(),
            )
            finding_dict = finding.model_dump()
            finding_dict["found_on_page"] = source # 附加来源页信息
            result["findings"].append(finding_dict)
            print(f"  [UploadIdentifier] 成功记录上传端点: {action_url} (来源: {source})")

        result["summary"] = f"共发现 {len(result['findings'])} 个文件上传功能点。"
        return result

    def _extract_upload_candidate_links(self, parser: PageParser) -> List[Dict[str, str]]:
        """从页面中提取可能包含文件上传的菜单链接。"""
        # 支援多國語言的上傳、文件、個人資料相關關鍵字
        keywords = [
            # 英文 (English)
            "upload", "file", "avatar", "profile", "document", "media", "picture", "photo", "attachment",
            # 簡體中文
            "上传", "文件", "头像", "资料", "附件", "图片", "个人信息",
            # 繁體中文
            "上傳", "檔案", "頭像", "資料", "附件", "圖片", "個人資訊",
            # 日文 (Japanese)
            "アップロード", "ファイル", "アバター", "プロフィール", "写真", "画像",
            # 韓文 (Korean)
            "업로드", "파일", "아바타", "프로필", "사진",
            # 西班牙文 (Spanish)
            "subir", "archivo", "perfil", "foto", "imagen", "documento",
            # 法文 (French)
            "télécharger", "envoyer", "fichier", "profil", "photo", "image",
            # 俄文 (Russian)
            "загрузить", "файл", "профиль", "фото", "аватар",
            # 德文 (German)
            "hochladen", "datei", "profil", "bild", "foto"
        ]
        
        candidates = []
        for link in parser.get_all_links(limit=100):
            text = link["text"].lower()
            href = link["url"].lower()
            
            # 过滤登出链接，防止破坏会话
            if any(k in href or k in text for k in ["logout", "signout", "logoff", "登出", "退出"]):
                continue
                
            if any(k in text or k in href for k in keywords):
                candidates.append(link)
                
        return candidates

    def _is_safe_link(self, link: Dict[str, str]) -> bool:
        """检查链接是否包含危险动作关键词，防止在已登录状态下误触发删除/修改等操作。"""
        # 破坏性、修改性、系统级高危操作关键词 (多国语言)
        dangerous_keywords = [
            # 英文
            "delete", "remove", "drop", "clear", "empty", "truncate", "destroy",
            "update", "edit", "modify", "change", "save",
            "reset", "install", "uninstall", "restart", "shutdown", "reboot",
            "logout", "signout", "logoff",
            # 中文
            "删除", "清除", "清空", "修改", "编辑", "更新", "保存",
            "重置", "安装", "重启", "设定", "登出", "退出",
            "刪除", "編輯", "設定",
            # 日文
            "削除", "クリア", "変更", "更新", "保存", "リセット", "ログアウト",
            # 其他常见动作参数
            "action=delete", "do=remove", "action=edit"
        ]
        
        text = link["text"].lower()
        href = link["url"].lower()
        
        # 如果 href 是锚点或无效协议，认为不安全(不需要探索)
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            return False
            
        # 检查是否包含危险词汇
        for k in dangerous_keywords:
            if k in text or k in href:
                print(f"    [安全拦截] 过滤高危链接: {link['url']} (匹配关键词: '{k}')")
                return False
                
        return True

    def _is_same_domain(self, base_url: str, target_url: str) -> bool:
        """检查目标 URL 是否与基础 URL 属于同一个主域名 (如 testfire.net)"""
        from urllib.parse import urlparse
        
        base_host = urlparse(base_url).hostname or ""
        target_host = urlparse(target_url).hostname or ""
        
        def get_main_domain(h: str) -> str:
            if not h: return ""
            parts = h.split('.')
            if len(parts) <= 2: return h
            # 处理常见后缀如 co.uk, com.cn
            if parts[-2] in ["co", "com", "org", "net", "gov", "edu", "ac"]:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
            
        return get_main_domain(base_host) == get_main_domain(target_host)


