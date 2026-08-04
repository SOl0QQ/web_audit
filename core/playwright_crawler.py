"""
核心：Playwright 模擬點擊爬蟲

使用真實瀏覽器模擬用戶點擊行為，遍歷後台所有可達頁面，發現上傳點。
專為 SPA 框架（Vue/React/Angular）和重度 JS 渲染的後台系統設計。

核心能力：
  - 自動同步 requests.Session 的 cookies，保持已認證狀態
  - 智能提取可點擊元素（菜單、Tab、按鈕、鏈接）
  - 安全過濾：避免點擊刪除/登出等危險操作
  - URL 去重：基於結構化簽名避免重複訪問
  - 上傳表單檢測：標準 <input type="file"> + Dropzone/WebUploader 等 JS 組件
"""
import urllib.parse
from typing import List, Dict, Any, Optional, Set
from collections import deque

from web_audit.core.requester import Requester
from web_audit.core.parser import PageParser
from web_audit.config.settings import (
    REQUEST_HEADERS,
    REQUEST_VERIFY_SSL,
    PLAYWRIGHT_CRAWLER_TIMEOUT,
)

# 檢測 Playwright 是否可用
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


class PlaywrightSiteCrawler:
    """
    使用 Playwright 真實瀏覽器模擬點擊，遍歷後台所有頁面。
    自動同步 requests.Session 的 cookies，保持已認證狀態。
    """

    # 危險操作關鍵詞（多國語言）— 避免點擊這些按鈕
    DANGEROUS_KEYWORDS = [
        # 英文
        "delete", "remove", "drop", "clear", "empty", "truncate", "destroy",
        "reset", "install", "uninstall", "restart", "shutdown", "reboot",
        "logout", "signout", "logoff", "sign out", "log out",
        # 中文
        "删除", "清除", "清空", "重置", "安裝", "卸載", "重啟", "關機", "登出", "退出", "註銷",
        "刪除",
        # 日文
        "削除", "クリア", "リセット", "ログアウト",
        # 韓文
        "삭제", "로그아웃",
        # 西班牙文
        "eliminar", "borrar", "cerrar sesión", "salir",
        # 法文
        "supprimer", "déconnexion", "quitter",
        # 俄文
        "удалить", "выход",
        # 德文
        "löschen", "abmelden", "abmelden",
    ]

    # 上傳相關關鍵詞（多國語言）— 優先探索
    UPLOAD_KEYWORDS = [
        # 英文
        "upload", "file", "avatar", "profile", "document", "media",
        "picture", "photo", "attachment", "import",
        # 簡體中文
        "上传", "文件", "头像", "资料", "附件", "图片", "个人信息", "导入",
        # 繁體中文
        "上傳", "檔案", "頭像", "資料", "附件", "圖片", "個人資訊", "匯入",
        # 日文
        "アップロード", "ファイル", "アバター", "プロフィール", "写真", "画像",
        # 韓文
        "업로드", "파일", "아바타", "프로필", "사진",
        # 西班牙文
        "subir", "archivo", "perfil", "foto", "imagen", "documento",
        # 法文
        "télécharger", "envoyer", "fichier", "profil", "photo", "image",
        # 俄文
        "загрузить", "файл", "профиль", "фото", "аватар",
        # 德文
        "hochladen", "datei", "profil", "bild", "foto",
    ]

    def __init__(
        self,
        requester: Requester,
        max_pages: int = 50,
        max_depth: int = 3,
        timeout_ms: int = PLAYWRIGHT_CRAWLER_TIMEOUT,
    ):
        self.requester = requester
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout_ms = timeout_ms

    def crawl_and_find_uploads(self, start_url: str) -> List[Dict[str, Any]]:
        """
        主入口：從起始頁面開始，模擬點擊遍歷所有可達頁面，
        返回發現的所有上傳表單信息列表。

        返回格式與 UploadIdentifierModule 的 findings 一致：
        [{action_url, method, file_input_names, accepted_types, is_multipart,
          source_url, referer_url}]

        Args:
            start_url: 起始頁面 URL（通常是 bypass 後的後台首頁）

        Returns:
            去重後的上傳表單列表
        """
        if not _PLAYWRIGHT_AVAILABLE:
            print("  [PlaywrightCrawler] Playwright 未安裝，跳過模擬點擊爬取。")
            return []

        print(f"\n  [PlaywrightCrawler] 啟動模擬點擊爬蟲 (最大頁面數: {self.max_pages}, 最大深度: {self.max_depth})")
        print(f"  [PlaywrightCrawler] 起始 URL: {start_url}")

        all_upload_forms: List[Dict[str, Any]] = []
        visited_urls: Set[str] = set()          # 精確 URL 去重
        visited_patterns: Set[str] = set()      # 結構化簽名去重
        pages_crawled = 0

        # BFS 隊列：(url, depth, referer_url)
        queue: deque = deque()
        queue.append((start_url, 0, None))

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)

                # 構建 Playwright context（同步 Session cookies）
                context = self._build_browser_context(browser, start_url)
                page = context.new_page()

                # 禁用瀏覽器緩存
                page.route("**/*", lambda route: route.continue_())

                while queue and pages_crawled < self.max_pages:
                    current_url, current_depth, referer_url = queue.popleft()

                    if current_depth > self.max_depth:
                        continue

                    # URL 去重
                    if current_url in visited_urls:
                        continue
                    sig = self._get_url_signature(current_url)
                    if sig in visited_patterns:
                        continue

                    visited_urls.add(current_url)
                    visited_patterns.add(sig)
                    pages_crawled += 1

                    print(f"    → [Phase4] (Depth:{current_depth}, Page:{pages_crawled}/{self.max_pages}) 探索: {current_url}")

                    try:
                        # 訪問頁面
                        page.goto(current_url, wait_until="networkidle", timeout=self.timeout_ms)
                        page.wait_for_timeout(1000)  # 額外等待 JS 渲染

                        # 檢查上傳表單
                        upload_forms = self._check_for_upload_forms(page, current_url)
                        if upload_forms:
                            print(f"      ✅ Phase 4 在頁面發現 {len(upload_forms)} 個上傳點！({current_url})")
                            for f in upload_forms:
                                f["source_url"] = current_url
                                f["referer_url"] = referer_url
                            all_upload_forms.extend(upload_forms)

                        # 提取可點擊元素並加入隊列
                        if current_depth < self.max_depth:
                            clickable_elements = self._extract_clickable_elements(page, current_url)
                            safe_elements = [e for e in clickable_elements if self._is_safe_to_click(e)]

                            for elem in safe_elements:
                                next_url = elem.get("url")
                                if next_url and next_url not in visited_urls:
                                    next_sig = self._get_url_signature(next_url)
                                    if next_sig not in visited_patterns:
                                        if self._is_same_domain(start_url, next_url):
                                            queue.append((next_url, current_depth + 1, current_url))

                    except Exception as e:
                        print(f"    [Phase4 Error] 探索 {current_url} 時發生異常: {e}")
                        continue

                browser.close()

        except Exception as e:
            print(f"  [PlaywrightCrawler] 瀏覽器啟動失敗: {e}")
            return []

        print(f"  [PlaywrightCrawler] 爬取完畢。共探索 {pages_crawled} 個頁面，發現 {len(all_upload_forms)} 個上傳點。")
        return all_upload_forms

    def _build_browser_context(self, browser, start_url: str):
        """
        構建 Playwright 瀏覽器上下文，同步 requests.Session 的 cookies 和 headers。
        複用 Requester._fetch_with_playwright() 的模式。
        """
        pw_cookies = []
        parsed_url = urllib.parse.urlparse(start_url)
        domain = parsed_url.hostname

        # 同步 Session cookies
        for c in self.requester.session.cookies:
            pw_cookies.append({
                "name": c.name,
                "value": c.value,
                "domain": c.domain if c.domain else domain,
                "path": c.path if c.path else "/"
            })

        # 同步 headers
        extra_headers = {}
        for k, v in self.requester.session.headers.items():
            if k.lower() not in ['connection', 'accept-encoding', 'content-length']:
                extra_headers[k] = v
        extra_headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        extra_headers["Pragma"] = "no-cache"

        context = browser.new_context(
            user_agent=self.requester.session.headers.get("User-Agent", REQUEST_HEADERS["User-Agent"]),
            ignore_https_errors=not REQUEST_VERIFY_SSL,
            extra_http_headers=extra_headers
        )

        if pw_cookies:
            context.add_cookies(pw_cookies)

        return context

    def _extract_clickable_elements(self, page, current_url: str) -> List[Dict[str, Any]]:
        """
        提取頁面中所有可點擊元素。

        返回格式：[{url, text, type, selector}]
        - url: 點擊後可能導航到的 URL
        - text: 元素文字內容
        - type: 元素類型 (link, button, menu_item, tab)
        - selector: CSS 選擇器（用於點擊）
        """
        elements = []
        seen_urls = set()

        try:
            # 1. 提取 <a> 標籤（導航鏈接）
            for a_tag in page.query_selector_all("a[href]"):
                try:
                    href = a_tag.get_attribute("href") or ""
                    text = a_tag.inner_text(timeout=1000).strip()[:50]

                    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue

                    # 轉換為絕對 URL
                    full_url = urllib.parse.urljoin(current_url, href)

                    # 過濾靜態資源
                    if PageParser.is_static_resource(full_url):
                        continue

                    if full_url not in seen_urls:
                        seen_urls.add(full_url)
                        elements.append({
                            "url": full_url,
                            "text": text or href[:30],
                            "type": "link",
                        })
                except Exception:
                    continue

            # 2. 提取菜單項（li, div[role="menuitem"]）
            for menu_item in page.query_selector_all("li a, [role='menuitem'] a, [role='tab'] a, .nav-item a, .menu-item a"):
                try:
                    href = menu_item.get_attribute("href") or ""
                    text = menu_item.inner_text(timeout=1000).strip()[:50]

                    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue

                    full_url = urllib.parse.urljoin(current_url, href)
                    if PageParser.is_static_resource(full_url):
                        continue

                    if full_url not in seen_urls:
                        seen_urls.add(full_url)
                        elements.append({
                            "url": full_url,
                            "text": text,
                            "type": "menu_item",
                        })
                except Exception:
                    continue

            # 3. 提取 Tab 標籤（可能切換到含上傳功能的面板）
            for tab in page.query_selector_all("[role='tab'], .tab-item, .nav-tabs li, .tabs li"):
                try:
                    # Tab 可能通過 data-target 或 href 指向內容面板
                    href = tab.get_attribute("href") or tab.get_attribute("data-target") or ""
                    text = tab.inner_text(timeout=1000).strip()[:50]

                    if href and not href.startswith("#"):
                        full_url = urllib.parse.urljoin(current_url, href)
                        if not PageParser.is_static_resource(full_url) and full_url not in seen_urls:
                            seen_urls.add(full_url)
                            elements.append({
                                "url": full_url,
                                "text": text,
                                "type": "tab",
                            })
                except Exception:
                    continue

            # 4. 提取按鈕（可能觸發 Modal 彈窗含上傳功能）
            # 注意：按鈕通常不會導航到新頁面，但可能打開含上傳功能的 Modal
            # 這裡我們只記錄按鈕的文字，不加入隊列（因為無法預知 URL）
            # 未來可以擴展為：點擊按鈕 → 等待 Modal 出現 → 檢查 Modal 內容

        except Exception as e:
            print(f"    [Phase4] 提取可點擊元素時發生異常: {e}")

        return elements

    def _check_for_upload_forms(self, page, url: str) -> List[Dict[str, Any]]:
        """
        檢查當前渲染頁面是否存在上傳表單。

        檢測策略：
        1. 標準 <input type="file">
        2. Dropzone.js 組件（div.dropzone, div[data-dz-upload]）
        3. WebUploader / Layui upload 等國產 UI 庫
        4. 自定義拖拽上傳區域

        返回格式與 PageParser.get_upload_forms() 一致。
        """
        upload_forms = []

        try:
            # 獲取渲染後的 HTML
            html_content = page.content()
            if not html_content:
                return []

            # 使用 PageParser 提取標準上傳表單
            parser = PageParser(html_content, url)
            standard_forms = parser.get_upload_forms()
            upload_forms.extend(standard_forms)

            # 檢測 JS 上傳組件（Dropzone, WebUploader 等）
            js_upload_indicators = [
                "dropzone",
                "dz-upload",
                "webuploader",
                "layui-upload",
                "element-ui-upload",
                "el-upload",
                "ant-upload",
                "upload-btn",
                "file-upload",
            ]

            page_text_lower = html_content.lower()
            has_js_upload = any(indicator in page_text_lower for indicator in js_upload_indicators)

            if has_js_upload and not standard_forms:
                # 發現 JS 上傳組件但沒有標準表單，嘗試提取
                # 這裡我們返回一個標記，讓後續的 AJAX 推斷邏輯處理
                print(f"      [Phase4] 檢測到 JS 上傳組件，正在提取...")

                # 嘗試找到包含 file input 的表單（可能是隱藏的）
                file_inputs = page.query_selector_all("input[type='file']")
                if file_inputs:
                    for fi in file_inputs:
                        try:
                            name = fi.get_attribute("name") or fi.get_attribute("id") or "file"
                            accept = fi.get_attribute("accept") or ""

                            # 嘗試找到包裹的表單
                            form_elem = fi.evaluate("""el => {
                                const form = el.closest('form');
                                return form ? {
                                    action: form.action || '',
                                    method: form.method || 'post',
                                    enctype: form.enctype || ''
                                } : null;
                            }""")

                            if form_elem:
                                upload_forms.append({
                                    "action": form_elem.get("action", ""),
                                    "method": form_elem.get("method", "post"),
                                    "enctype": form_elem.get("enctype", "multipart/form-data"),
                                    "inputs": [{
                                        "type": "file",
                                        "name": name,
                                        "id": fi.get_attribute("id") or "",
                                        "accept": accept,
                                    }],
                                    "selects": [],
                                    "textareas": [],
                                    "raw_html": "<js_upload_component>",
                                })
                        except Exception:
                            continue

        except Exception as e:
            print(f"    [Phase4] 檢查上傳表單時發生異常: {e}")

        return upload_forms

    def _is_same_domain(self, base_url: str, target_url: str) -> bool:
        """
        檢查目標 URL 是否與基礎 URL 屬於同一個主域名。
        複用 UploadIdentifierModule._is_same_domain() 邏輯。
        """
        base_host = urllib.parse.urlparse(base_url).hostname or ""
        target_host = urllib.parse.urlparse(target_url).hostname or ""

        def get_main_domain(h: str) -> str:
            if not h:
                return ""
            parts = h.split('.')
            if len(parts) <= 2:
                return h
            # 處理常見後綴如 co.uk, com.cn
            if parts[-2] in ["co", "com", "org", "net", "gov", "edu", "ac"]:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])

        return get_main_domain(base_host) == get_main_domain(target_host)

    def _is_safe_to_click(self, element_info: Dict[str, Any]) -> bool:
        """
        安全過濾：避免點擊危險操作按鈕。
        複用 UploadIdentifierModule._is_safe_link() 的危險關鍵詞列表。
        """
        text = element_info.get("text", "").lower()
        url = element_info.get("url", "").lower()

        # 過濾無效協議
        if url.startswith(("#", "javascript:", "mailto:", "tel:")):
            return False

        # 檢查危險關鍵詞
        for keyword in self.DANGEROUS_KEYWORDS:
            if keyword in text or keyword in url:
                return False

        return True

    def _get_url_signature(self, url: str) -> str:
        """
        生成 URL 的結構化簽名，用於去重。
        複用 UploadIdentifierModule._get_url_signature() 邏輯。
        """
        import re

        parsed = urllib.parse.urlparse(url)
        query_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # 決定頁面功能的路由/動作參數（必須保留參數值）
        ACTION_PARAMS = {
            "act", "action", "m", "a", "c", "do", "mod", "module", "op", "operation",
            "type", "func", "function", "controller", "view", "page_name", "cmd", "step"
        }

        sig_parts = []
        for k in sorted(query_dict.keys()):
            val_list = query_dict[k]
            k_lower = k.lower()
            if k_lower in ACTION_PARAMS:
                v = ",".join(sorted(val_list))
                sig_parts.append(f"{k}={v}")
            else:
                if k_lower in ("id", "p", "page", "offset", "limit", "timestamp", "t", "_"):
                    sig_parts.append(f"{k}={{id}}")
                else:
                    norm_vals = []
                    for v in val_list:
                        if v.isdigit():
                            norm_vals.append("{id}")
                        else:
                            norm_vals.append(v)
                    sig_parts.append(f"{k}={','.join(sorted(set(norm_vals)))}")

        query_sig = "&".join(sig_parts)

        path = parsed.path
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)

        return f"{parsed.netloc}{path}?{query_sig}"
