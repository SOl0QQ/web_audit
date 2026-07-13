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
    STRICT_LOGIN_CHECK,
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
        import urllib.parse
        start_parsed = urllib.parse.urlparse(start_url)
        start_domain = start_parsed.hostname or ""

        safe_candidates = []
        for c in candidate_urls:
            c = c.strip()
            if not c:
                continue
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
        return prioritized

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

        # ── 啟動 Playwright 動態攔截 ──────────────────────────────
        for f in features.get("forms", []):
            action = f.get("action", "")
            if not action or action == "#" or action == url:
                # 判斷是否為密碼表單
                has_password = any(inp.get("type", "").lower() == "password" for inp in f.get("inputs", []))
                if has_password:
                    print(f"  [Playwright] 發現空 action 的密碼表單，啟動動態攔截 (這可能需要幾秒鐘)...")
                    interceptor = PlaywrightInterceptor(timeout_ms=10000)
                    real_url = interceptor.intercept_form_action(url)
                    if real_url:
                        print(f"  [✅ Playwright] 成功攔截到真實 AJAX 端點: {real_url}")
                        f["action"] = real_url
                        f["_playwright_note"] = "注意：此 action 原本為空，這是 Playwright 動態攔截到的真實 AJAX 提交位址！"
                    break

        # ── 启发式硬规则（防漏报与防 LLM 崩溃机制） ──────────────────────────────
        # 如果表单中明确包含密码框，或者含有强烈的登录特征（如 email + login），直接判定为登录页！
        has_password = False
        login_hints = ["user", "name", "email", "login", "sign", "auth", "account", "log"]
        has_login_hint = False

        for f in features.get("forms", []):
            for inp in f.get("inputs", []):
                inp_type = inp.get("type", "").lower()
                inp_name = inp.get("name", "").lower()
                inp_id = inp.get("id", "").lower()
                
                if inp_type == "password" or "pass" in inp_name or "pwd" in inp_name:
                    has_password = True
                if any(hint in inp_name or hint in inp_id for hint in login_hints):
                    has_login_hint = True
                    
            # 检查 action 是否包含 login 特征
            action = f.get("action", "").lower()
            if any(hint in action for hint in login_hints):
                has_login_hint = True

        # 如果包含密码框，或者处于宽松模式且包含用户名/邮箱特征
        if has_password or (not STRICT_LOGIN_CHECK and has_login_hint):
            print(f"  [System] 启发式规则命中 (pwd={has_password}, hint={has_login_hint}): 明确具有认证表单特征，跳过 LLM！")
            return LoginDetectorResult(
                is_login_page=True,
                confidence=1.0,
                reason="[启发式规则] 页面包含明显的认证表单特征 (密码框或登录输入框)，直接进入漏洞测试链。",
                potential_login_links=[]
            )

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
