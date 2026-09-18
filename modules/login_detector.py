"""
模块 1：登录页面识别（三层架构）

识别流程：
  ┌──────────────────────────────────────────────────────────┐
  │  Layer 1: 广度发现层（外部工具）                           │
  │    ├── Katana 主动爬虫（JS 渲染，跟踪所有链接）             │
  │    └── Dirsearch 目录爆破（发现无链接隐藏路径）             │
  │                         ↓ 合并去重 URL 池                 │
  ├──────────────────────────────────────────────────────────┤
  │  Layer 2: LLM 精准过滤层                                  │
  │    ├── 关键词预排序（login/admin/signin 优先）              │
  │    └── Gemini 逐 URL 语义判断（置信度 > 0.8 即命中）        │
  │                         ↓                                │
  ├──────────────────────────────────────────────────────────┤
  │  Layer 3: 输出登录页 URL                                  │
  └──────────────────────────────────────────────────────────┘

降级策略（任意层失败自动切换）：
  - 若外部工具未安装/禁用 → 退回递归 LLM 爬虫
  - 若工具结果 LLM 过滤未命中 → 额外补跑递归 LLM 爬虫
"""
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from web_audit.modules.base_module import BaseModule
from web_audit.core.requester import Requester
from web_audit.core.parser import PageParser
from web_audit.core.llm_factory import get_llm
from web_audit.core.tool_discovery import ToolDiscovery
from web_audit.core.playwright_interceptor import PlaywrightInterceptor
from web_audit.config.settings import (
    CRAWLER_MAX_DEPTH,
    TOOL_DISCOVERY_ENABLED,
    PLAYWRIGHT_CRAWLER_TIMEOUT,
)


# ── 登录相关关键词（用于 Layer 2 预排序）──────────────────────
_LOGIN_KEYWORDS = [
    "login", "signin", "sign-in", "log-in",
    "admin", "管理", "登录", "登入",
    "portal", "console", "控制台", "oauth", "auth",
    "account", "user", "member", "wp-login",
    "index/login", "user/login", "manage",
]


# ── Pydantic 结构化输出模型 ────────────────────────────────────
class LoginDetectorResult(BaseModel):
    is_login_page: bool = Field(
        description="当前页面是否是登录页面（包含用户名/密码/验证码输入框，或专门用于登录/认证的表单）"
    )
    confidence: float = Field(
        description="判定是否为登录页面的置信度，范围 0.0 到 1.0"
    )
    reason: str = Field(
        description="【核心推理過程】請強制按以下步驟思考並輸出：Step1: 檢查表單是否有 action 屬性。Step2: 若 action 為空，去 snippet 中尋找 fetch/ajax 等真實的 JS 提交位址。Step3: 綜合判斷是否為登入頁面。"
    )
    potential_login_links: Optional[List[str]] = Field(
        description="如果当前页面不是登录页，提取最可能导向登录页的链接列表",
        default=[]
    )


# ── 方案三：批量 LLM 判断模型 ────────────────────────────────────
class BatchUrlFilterResult(BaseModel):
    """批量 URL 筛选结果 - 仅根据 URL 路径特征快速判断"""
    likely_login_urls: List[str] = Field(
        description="最可能是登录页的 URL 列表（路径特征明显）",
        default=[]
    )
    possible_login_urls: List[str] = Field(
        description="可能是登录页的 URL 列表（需要进一步验证）",
        default=[]
    )
    reason: str = Field(
        description="筛选理由",
        default=""
    )


# ── 方案三：批量 LLM 判断 Prompt ─────────────────────────────────
BATCH_URL_FILTER_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个网络安全专家，需要根据 URL 路径特征快速筛选出**明确是登录页**的 URL。

**必须严格判断，宁缺勿滥！**

**高概率是登录页的特征（必须同时满足多个）**：
- 路径明确包含: login, signin, sign-in, log-in, wp-login, admin/login, user/login
- 路径以 .php, .asp, .aspx, .jsp 结尾且包含 login/signin 关键词
- 路径是 /admin, /manage, /console 等明确的后台入口

**以下情况绝对不是登录页（必须排除）**：
- 路径是注册页: register, signup, regis, join, create-account
- 路径是账户页: account, profile, my-account, dashboard（除非明确是登录）
- 路径是表单页: form, contact, inquiry, application
- 路径是短路径或缩写: /cu, /p, /cp（除非明确是 login 缩写）
- 路径是客户相关: customer, client, member（除非明确是登录入口）
- 路径过深（超过2层目录）

**判断原则**：
- likely_login_urls: 只有路径明确包含 login/signin/admin 的才放入
- possible_login_urls: 只有非常可疑的才放入，宁可漏掉也不要误报
- 如果不确定，就不要放入任何列表

请从给定的 URL 列表中筛选出**明确是登录页**的 URL。"""),
    ("human", """请严格分析以下 URL 列表，只筛选出明确是登录页的 URL：

{urls}

请返回结构化的筛选结果。记住：宁缺勿滥！""")
])


# ── LangChain Prompt ───────────────────────────────────────────
LOGIN_DETECT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个专业的网络安全和网页结构分析助手。
你的任务是根据提取出的网页特征，判断当前网页是否是【登录页面】。

**登录页面定义**：
1. 包含允许用户输入凭证（用户名、邮箱、密码、验证码、手机号）进行身份验证的表单。
2. 仅包含"搜索框"或"订阅邮件"的页面不算登录页面。
3. 包含直接登录入口的第三方授权跳转页也算登录页。

**强制推理链 (Chain of Thought) 要求**：
针对本地模型，你必须严格遵循以下步骤进行推理，并将完整过程写入 `reason` 字段：
[Step 1] 观察表单 (forms)：表单的 `action` 属性是否为空 (`""` 或 `"#"` )？
[Step 2] 深度挖掘 (AJAX 检查)：如果发现表单 `action` 为空，这极大概率是 AJAX 动态表单！你必须仔细去 `snippet` (文本片段) 中寻找 `fetch`, `$.ajax`, `$.post` 或其他包含 API 路径（如 `/api/login`）的 JS 代码。
[Step 3] 综合判决：根据表单输入框类型以及找到的真实提交地址，做出最终判定。

如果当前页面**不是**登录页，请从 candidate_links 中筛选最可能导向登录页的链接。"""),
    ("human", """请分析以下网页特征：
URL: {url}
网页标题: {title}
页面表单结构: {forms}
页面关键候选链接: {candidate_links}
页面文本片段: {snippet}

请严格遵守推理链要求，给出结构化的判定结果。""")
])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 登录页识别模块（三层架构）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class LoginDetectorModule(BaseModule):
    """登录页面识别模块（三层架构：工具发现 → LLM 过滤 → 递归补充）。"""

    name = "login_detector"

    def __init__(self, requester: Requester):
        super().__init__(requester)
        llm = get_llm()
        self._chain = LOGIN_DETECT_PROMPT | llm.with_structured_output(LoginDetectorResult)
        # 方案三：批量 LLM 判断链
        self._batch_chain = BATCH_URL_FILTER_PROMPT | llm.with_structured_output(BatchUrlFilterResult)
        self._tool_discovery = ToolDiscovery()

    # ── 公共入口 ────────────────────────────────────────────────

    def run(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        仅负责通过外部工具进行广度发现，返回去重、预排序后的候选 URL 列表。
        后续的 LLM 验证将交由流水线主控程序 (main.py) 并发执行。
        """
        result = self._base_result(url)
        candidates = self.discover_candidates(url)

        if candidates:
            result["findings"] = [{"candidate_url": c} for c in candidates]
            result["summary"] = f"发现 {len(candidates)} 个候选登录页，准备交由流水线并发验证。"
        else:
            result["summary"] = "未能在目标站点发现任何候选 URL。"

        return result

    def discover_candidates(self, start_url: str) -> List[str]:
        """
        使用 Katana/Dirsearch 获取 URL，并经过过滤和关键词预排序，返回候选列表。
        不再进行阻塞式的 LLM 检测。
        """
        candidate_urls: List[str] = []

        if TOOL_DISCOVERY_ENABLED:
            discovered = self._tool_discovery.discover(start_url)
            candidate_urls.extend(discovered)
        else:
            print("\n  [Layer 1] TOOL_DISCOVERY_ENABLED=False，跳过外部工具。")

        if start_url not in candidate_urls:
            candidate_urls.insert(0, start_url)

        # 1. 安全加固：确保 candidate_urls 中没有缺少 scheme 的裸域名
        # 2. 跨域过滤：排除与起始域名不一致的外部链接
        # 3. URL 清理：修复错误的 URL 拼接
        import urllib.parse
        start_parsed = urllib.parse.urlparse(start_url)
        start_domain = start_parsed.hostname or ""

        safe_candidates = []
        for c in candidate_urls:
            c = c.strip()
            if not c:
                continue

            # 清理 URL 中的反斜杠（%5C 或 \）
            c = c.replace('%5C', '/').replace('\\', '/')

            # 修复错误的 URL 拼接（如 https://domain.com/https://domain.com/path）
            # 如果路径中包含完整的 URL，提取正确的部分
            if 'http://' in c or 'https://' in c:
                # 找到最后一个 http:// 或 https://
                last_http_idx = max(c.rfind('http://'), c.rfind('https://'))
                if last_http_idx > 0:
                    c = c[last_http_idx:]

            if not c.startswith("http://") and not c.startswith("https://"):
                c = "http://" + c

            c_parsed = urllib.parse.urlparse(c)
            c_domain = c_parsed.hostname or ""

            # 放宽跨域检测：只要主域名互相包含（例如 www.btec.ac.th 和 btec.ac.th）就视为同站
            if c_domain and start_domain:
                if start_domain not in c_domain and c_domain not in start_domain:
                    continue

            from web_audit.core.parser import PageParser
            if PageParser.is_static_resource(c):
                continue

            if c not in safe_candidates:
                safe_candidates.append(c)
        candidate_urls = safe_candidates

        print(f"\n{'─' * 50}")
        print(f"  [发现完毕] 外部工具共收集到 {len(candidate_urls)} 个去重后的候选 URL")
        print(f"{'─' * 50}")

        prioritized = self._prioritize_urls(candidate_urls)

        # ── 方案三：批量 LLM 筛选 ──────────────────────────────────
        # 在逐个验证之前，先用批量 LLM 快速筛选，减少后续验证次数
        print(f"\n{'─' * 50}")
        print(f"  [Layer 2] 批量 LLM 预筛选（减少后续逐个验证次数）")
        print(f"{'─' * 50}")
        batch_filtered = self.batch_filter_urls(prioritized)

        # ── 阶段2：HTML 特征检测（检查是否有密码框）──────────────────
        # 登录页的核心特征是有密码输入框，这比 URL 路径可靠得多
        print(f"\n{'─' * 50}")
        print(f"  [Layer 2.5] HTML 特征检测（检查密码框）")
        print(f"{'─' * 50}")
        html_filtered = self.batch_check_password_field(batch_filtered)

        return html_filtered

    # ── Layer 2 辅助：关键词预排序 ──────────────────────────────

    def _prioritize_urls(self, urls: List[str]) -> List[str]:
        """
        将 URL 列表按"是否含登录关键词"分为两组：
          高优先（含关键词）→ 低优先（其他）

        关键词命中的 URL 优先送入 LLM 检测，可大幅减少 LLM 调用次数。
        """
        high: List[str] = []
        low: List[str] = []

        for url in urls:
            url_lower = url.lower()
            if any(kw in url_lower for kw in _LOGIN_KEYWORDS):
                high.append(url)
            else:
                low.append(url)

        print(f"  [Layer 2] 预排序: {len(high)} 个高优先 URL + {len(low)} 个低优先 URL")
        if high:
            print(f"  [Layer 2] 高优先样本: {high[:5]}")

        return high + low

    # ── 方案三：批量 LLM URL 筛选 ─────────────────────────────────

    def batch_filter_urls(self, urls: List[str], batch_size: int = 20) -> List[str]:
        """
        方案三：批量 LLM 判断 - 将多个 URL 打包发送给 LLM，快速筛选出可能是登录页的 URL。

        优势：
          - 之前：100 个 URL → 100 次 LLM 调用
          - 之后：100 个 URL → 5 次 LLM 调用（每次 20 个）

        Args:
            urls: 候选 URL 列表
            batch_size: 每批处理的 URL 数量

        Returns:
            经过 LLM 筛选后的候选 URL 列表（likely + possible）
        """
        if not urls:
            return []

        # 如果 URL 数量少于 batch_size，直接一批处理
        if len(urls) <= batch_size:
            return self._batch_llm_filter(urls)

        # 分批处理
        all_filtered: List[str] = []
        total_batches = (len(urls) + batch_size - 1) // batch_size

        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            batch_num = i // batch_size + 1
            print(f"\n  [批量筛选] 第 {batch_num}/{total_batches} 批 ({len(batch)} 个 URL)...")

            filtered = self._batch_llm_filter(batch)
            all_filtered.extend(filtered)

        # 去重
        seen: set = set()
        deduped: List[str] = []
        for u in all_filtered:
            if u not in seen:
                seen.add(u)
                deduped.append(u)

        print(f"\n  [批量筛选] 完成: {len(urls)} → {len(deduped)} 个候选 URL")
        return deduped

    def _batch_llm_filter(self, urls: List[str]) -> List[str]:
        """
        单批次 LLM 筛选 - 根据 URL 路径特征快速判断。
        """
        if not urls:
            return []

        # 构建 URL 列表字符串
        urls_text = "\n".join(f"- {url}" for url in urls)

        try:
            result: BatchUrlFilterResult = self._batch_chain.invoke({
                "urls": urls_text,
            })

            # 合并 likely 和 possible
            filtered = result.likely_login_urls + result.possible_login_urls

            print(f"  [批量筛选] likely={len(result.likely_login_urls)}, "
                  f"possible={len(result.possible_login_urls)}, "
                  f"排除={len(urls) - len(filtered)}")

            if result.likely_login_urls:
                print(f"  [批量筛选] 高概率登录页: {result.likely_login_urls[:5]}")

            return filtered

        except Exception as e:
            print(f"  [批量筛选] ❌ LLM 调用失败: {e}，返回全部 URL")
            return urls

    # ── 阶段2：HTML 特征检测（检查密码框）────────────────────────────

    def batch_check_password_field(self, urls: List[str]) -> List[str]:
        """
        阶段2：HTML 特征检测 - 检查页面是否包含密码输入框。

        登录页的核心特征是有 type="password" 的输入框，这比 URL 路径可靠得多。
        只保留有密码框的 URL，大幅减少后续 LLM 调用次数。

        Args:
            urls: 候选 URL 列表

        Returns:
            包含密码框的 URL 列表
        """
        if not urls:
            return []

        filtered: List[str] = []
        checked_count = 0

        for url in urls:
            checked_count += 1
            try:
                # 获取页面 HTML
                resp = self.requester.get(url)
                if not resp:
                    print(f"  [HTML检测] {checked_count}/{len(urls)} {url} - 无法访问，跳过")
                    continue

                # 解析 HTML 检查密码框
                parser = PageParser(resp.text, url)
                forms = parser.get_forms()

                has_password = False
                for form in forms:
                    inputs = form.get("inputs", [])
                    for inp in inputs:
                        if inp.get("type", "").lower() == "password":
                            has_password = True
                            break
                    if has_password:
                        break

                if has_password:
                    filtered.append(url)
                    print(f"  [HTML检测] {checked_count}/{len(urls)} {url} - ✅ 有密码框")
                else:
                    print(f"  [HTML检测] {checked_count}/{len(urls)} {url} - ❌ 无密码框，排除")

            except Exception as e:
                print(f"  [HTML检测] {checked_count}/{len(urls)} {url} - ❌ 检测失败: {e}")
                continue

        print(f"\n  [HTML检测] 完成: {len(urls)} → {len(filtered)} 个包含密码框的 URL")
        return filtered

    # ── Layer 2 辅助：单 URL LLM 判断 ───────────────────────────

    def _llm_check_url(self, url: str) -> Optional[LoginDetectorResult]:
        """
        拉取指定 URL 的页面内容，提取特征后交由 LLM 判断是否为登录页。

        Returns:
            LoginDetectorResult 或 None（请求/LLM 失败时）
        """
        print(f"\n  [LLM] 分析: {url}")

        resp = self.requester.get(url)
        if not resp:
            print(f"  [LLM] ⚠️  无法访问，跳过。")
            return None

        parser = PageParser(resp.text, url)
        features = parser.to_features()

        # ── JS 跳转/动态渲染页 防御机制 ──────────────────────────────
        # 如果页面没有任何表单，极有可能是遇到了 JS 跳转（如 window.location）或者需要纯 JS 渲染的 SPA
        if not features.get("forms") and len(resp.text) < 10000:
            print(f"  [System] 页面表单为空，疑似遇到 JS 动态跳转或 SPA 渲染页，启动 Playwright 深度抓取...")
            rendered_html = self.requester.fetch_rendered_html(url)
            if rendered_html and len(rendered_html) > len(resp.text):
                print(f"  [✅ Playwright] 深度抓取成功，重新解析页面特征...")
                parser = PageParser(rendered_html, url)
                features = parser.to_features()
                
        # ── 防御 LLM 幻觉 ──────────────────────────────
        # 经过 Playwright 深度渲染后，如果连一个 <form> 或游离的 <input> 都没有，那绝对不是登录页。
        # 直接拦截，防止 LLM 因为看到报错里的 password 字样而产生幻觉误判。
        if not features.get("forms"):
            print(f"  [System] 页面无任何表单或输入框，触发防幻觉机制，直接判定非登录页。")
            return LoginDetectorResult(
                is_login_page=False,
                confidence=1.0,
                reason="页面中不存在任何 HTML 表单或输入框控件（包括经过 JS 渲染后），物理上无法完成认证，为防止 LLM 幻觉直接拦截。",
                potential_login_links=[]
            )

        # ── 登录页探测阶段不启动动态拦截 ──────────────────────────────
        # 动态拦截（获取 AJAX 真实提交地址）应该在确认是登录页后，
        # 在 SQL 注入测试阶段才执行，避免对每个候选 URL 都启动 Playwright。

        try:
            result: LoginDetectorResult = self._chain.invoke({
                "url": features["url"],
                "title": features["title"],
                "forms": str(features["forms"]),
                "candidate_links": str(features["candidate_links"]),
                "snippet": features["snippet"],
            })

            icon = "✅" if (result.is_login_page and result.confidence > 0.8) else \
                   "🟡" if result.is_login_page else "❌"
            print(f"  [LLM] {icon} 登录页={result.is_login_page} "
                  f"置信度={result.confidence:.2f} | {result.reason[:60]}")

            return result

        except Exception as e:
            print(f"  [LLM] ❌ 调用失败: {e}")
            return None

    # ── 降级备选：递归 LLM 爬虫 ────────────────────────────────

    def _recursive_llm_crawl(
        self, start_url: str, max_depth: int = CRAWLER_MAX_DEPTH
    ) -> Optional[str]:
        """
        原始递归 LLM 爬虫（降级备选 / 补充探测）。

        逻辑：
          1. 对当前 URL 做 LLM 判断
          2. 若不是登录页，取 LLM 返回的 potential_login_links 加入下一轮
          3. 重复至 max_depth 层

        Args:
            start_url: 起始 URL
            max_depth: 最大递归深度

        Returns:
            命中的登录页 URL，或 None
        """
        print(f"\n{'─' * 50}")
        print(f"  [递归爬虫] 起始: {start_url}，最大深度: {max_depth}")
        print(f"{'─' * 50}")

        visited: set = set()
        to_visit: List[str] = [start_url]
        depth = 0

        while to_visit and depth < max_depth:
            current_level = list(to_visit)
            to_visit = []

            for url in current_level:
                if url in visited:
                    continue
                visited.add(url)

                print(f"\n  [递归爬虫] depth={depth} → {url}")
                llm_result = self._llm_check_url(url)
                if not llm_result:
                    continue

                # 命中
                if llm_result.is_login_page and llm_result.confidence > 0.8:
                    print(f"\n  [✅ 递归爬虫] 命中登录页: {url}")
                    return url

                # 未命中：将 LLM 推荐的候选链接加入下一层
                for link in (llm_result.potential_login_links or []):
                    if link and link not in visited:
                        to_visit.append(link)

            depth += 1

        print("\n  [递归爬虫] 已达最大深度，未找到登录页。")
        return None
