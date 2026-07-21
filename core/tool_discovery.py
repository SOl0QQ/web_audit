"""
核心：外部工具 URL 发现层

整合 katana（主动爬虫）与 dirsearch（目录爆破）两款工具，
作为登录页识别的第一层广度发现，将结果交由 LLM 精准过滤。

工具说明：
  - katana: 擅长 SPA/JS 动态页面的全链接爬取
    安装: go install github.com/projectdiscovery/katana/cmd/katana@latest

  - dirsearch: 字典爆破，发现无超链接的隐藏路径
    安装: pip install dirsearch  或  brew install dirsearch

各工具均做「未安装则跳过」处理，不会中断流水线。
"""
import re
import shutil
import subprocess
import urllib.parse
from typing import List

from web_audit.config.settings import (
    DIRSEARCH_ENABLED,
    DIRSEARCH_EXTENSIONS,
    DIRSEARCH_MAX_TIME,
    DIRSEARCH_PATH,
    DIRSEARCH_THREADS,
    DIRSEARCH_TIMEOUT,
    DIRSEARCH_WORDLIST,
    DIRSEARCH_MAX_RATE,
    KATANA_DEPTH,
    KATANA_ENABLED,
    KATANA_JS_CRAWL,
    KATANA_PATH,
    KATANA_REQUEST_TIMEOUT,
    KATANA_TIMEOUT,
    KATANA_RATE_LIMIT,
    TOOL_DISCOVERY_ENABLED,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Katana 爬虫封装
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class KatanaRunner:
    """
    封装 katana 主动爬虫，输出目标站点所有可达 URL。

    katana 优势：
      - 支持 headless 渲染（-jc），可爬取 Vue/React SPA 动态页面
      - 自动跟踪 JS 注入的链接，不依赖 HTML 中的静态 <a> 标签
      - 支持深度控制（-d），可控制爬取范围
    """

    def run(self, url: str, cookies: dict = None) -> List[str]:
        """
        运行 katana 并返回发现的 URL 列表。
        若工具未安装或执行失败，返回空列表（不中断流水线）。
        支持传入 cookies 字典以已登录状态爬取。
        """
        if not KATANA_ENABLED:
            print("  [Katana] 已在配置中禁用，跳过。")
            return []

        if not shutil.which(KATANA_PATH):
            print(f"  [Katana] ⚠️  未找到可执行文件 '{KATANA_PATH}'，跳过。")
            print(f"  [Katana]    安装: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            return []

        cmd = [
            KATANA_PATH,
            "-u", url,
            "-d", str(KATANA_DEPTH),
            "-silent",          # 仅输出 URL，不输出进度横幅
            "-nc",              # 禁用终端颜色
            "-timeout", str(KATANA_REQUEST_TIMEOUT),  # 单次 HTTP 请求超时（短）
            "-rl", str(KATANA_RATE_LIMIT),            # 速率限制：每秒最大请求数
            # 注意：这里用的是「单次请求超时」，不是进程总时限
            # Python deadline = KATANA_TIMEOUT 才是进程总截止时限
        ]
        if KATANA_JS_CRAWL:
            cmd.append("-jc")   # 启用 headless chromium 渲染（需安装 chromium）
            
        if cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            cmd.extend(["-H", f"Cookie: {cookie_str}"])

        print(f"  [Katana] 启动爬虫 (深度={KATANA_DEPTH}, JS渲染={'开' if KATANA_JS_CRAWL else '关'}, "
              f"请求超时={KATANA_REQUEST_TIMEOUT}s, 进程截止={KATANA_TIMEOUT}s)...")
        try:
            import time
            import tempfile
            import os as _os

            # 用临时文件接收输出，完全绕过 stdout 管道缓冲问题
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="katana_"
            ) as tmp:
                tmp_path = tmp.name

            cmd_with_out = cmd + ["-o", tmp_path]

            proc = subprocess.Popen(
                cmd_with_out,
                stdin=subprocess.DEVNULL,    # 明确关闭 stdin，防止任何环境下阻塞
                stdout=subprocess.DEVNULL,   # 输出已重定向到文件
                stderr=subprocess.DEVNULL,   # 忽略 banner/进度信息
            )

            urls: list = []
            deadline = time.monotonic() + KATANA_TIMEOUT
            seen: set = set()

            # 每 1s 读一次临时文件，收集新增 URL，直到 deadline
            while time.monotonic() < deadline:
                time.sleep(1)
                if _os.path.exists(tmp_path):
                    with open(tmp_path, "r", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("http") and line not in seen:
                                seen.add(line)
                                urls.append(line)
                if proc.poll() is not None:
                    break   # 进程已自然退出

            # 强制终止（如仍在运行）
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

            timed_out = proc.poll() is None  # True = 被我们强制截断

            # 最后再读一次文件，确保收集最终结果
            if _os.path.exists(tmp_path):
                with open(tmp_path, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("http") and line not in seen:
                            seen.add(line)
                            urls.append(line)
                _os.unlink(tmp_path)   # 清理临时文件

            if timed_out:
                print(f"  [Katana] ⏱️  {KATANA_TIMEOUT}s 截止，返回已发现 {len(urls)} 个 URL")
            else:
                print(f"  [Katana] ✅ 完成，共发现 {len(urls)} 个 URL")
            return urls

        except Exception as e:
            print(f"  [Katana] ❌ 执行失败: {e}")
            return []



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Dirsearch 目录爆破封装
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DirsearchRunner:
    """
    封装 dirsearch 目录爆破工具，发现站点中无超链接的隐藏路径。

    dirsearch 优势：
      - 基于字典枚举 /login /admin /wp-login.php 等常见路径
      - 无需页面内有超链接，适合发现孤立的后台入口
      - 支持多扩展名同时爆破（php/asp/jsp 等）
    """

    # dirsearch 实际输出格式（含时间戳 + 完整 URL）：
    #   [21:28:56] 200 -    3KB  - http://target.com/login.php
    #   [21:28:56] 302 -    0B   - http://target.com/admin  ->  /login.jsp
    # 主 URL 解析（2xx / 3xx 响应的发现 URL）
    _LINE_PATTERN = re.compile(
        r"^\[\d{2}:\d{2}:\d{2}\]\s+(2\d{2}|3\d{2})\s+-\s+\S+\s+-\s+(https?://\S+?)(?:\s+->|$)"
    )
    # 额外抽取 3xx 重定向目标（如 -> /login.jsp），本身也是高价值候选
    _REDIRECT_PATTERN = re.compile(r"->\s+(\S+)$")

    def run(self, url: str) -> List[str]:
        """
        运行 dirsearch 并返回成功响应路径的完整 URL 列表。
        若工具未安装或执行失败，返回空列表（不中断流水线）。
        """
        if not DIRSEARCH_ENABLED:
            print("  [Dirsearch] 已在配置中禁用，跳过。")
            return []

        if not shutil.which(DIRSEARCH_PATH):
            print(f"  [Dirsearch] ⚠️  未找到可执行文件 '{DIRSEARCH_PATH}'，跳过。")
            print(f"  [Dirsearch]    安装: pip install dirsearch")
            return []

        import os as _os
        cmd = [
            DIRSEARCH_PATH,
            "-u", url,
            "-e", DIRSEARCH_EXTENSIONS,
            "-t", str(DIRSEARCH_THREADS),
            "--max-rate", str(DIRSEARCH_MAX_RATE), # 速率限制：每秒最大请求数
            "--timeout", str(DIRSEARCH_TIMEOUT),
            "-q",           # 安静模式：只输出发现路径，不输出进度条
            "--no-color",   # 禁用 ANSI 颜色（便于正则解析）
        ]

        # 使用专用小字典（~80条登录路径），比默认字典快 10x
        if DIRSEARCH_WORDLIST and _os.path.isfile(DIRSEARCH_WORDLIST):
            cmd += ["-w", DIRSEARCH_WORDLIST]
            wordlist_desc = _os.path.basename(DIRSEARCH_WORDLIST)
        else:
            wordlist_desc = "默认字典"

        print(f"  [Dirsearch] 启动爆破 (线程={DIRSEARCH_THREADS}, 字典={wordlist_desc})...")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=DIRSEARCH_MAX_TIME + 10,   # 以 MAX_TIME 为进程总超时
            )
            urls = self._parse_output(url, proc.stdout)
            print(f"  [Dirsearch] ✅ 完成，共发现 {len(urls)} 个有效路径")
            return urls

        except subprocess.TimeoutExpired:
            print(f"  [Dirsearch] ⏱️  进程超时（>{DIRSEARCH_MAX_TIME}s），返回已收集结果。")
            return []
        except Exception as e:
            print(f"  [Dirsearch] ❌ 执行失败: {e}")
            return []

    def _parse_output(self, base_url: str, output: str) -> List[str]:
        """
        解析 dirsearch 默认输出格式，提取 2xx/3xx 响应的完整 URL。

        实际格式样例：
          [21:28:56] 200 -    3KB  - http://target.com/login.php
          [21:28:56] 302 -    0B   - http://target.com/admin  ->  /login.jsp

        策略：
          1. 从主 URL 列中提取被发现的路径（group 2）
          2. 对 3xx 响应额外提取重定向目标（-> /login.jsp），
             因为重定向目标本身往往就是登录页
        """
        base = base_url.rstrip("/")
        seen: set = set()
        urls: List[str] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = self._LINE_PATTERN.search(line)
            if not match:
                continue

            status_code = match.group(1)
            discovered_url = match.group(2).rstrip("/")

            # 主发现 URL 加入列表
            if discovered_url not in seen:
                seen.add(discovered_url)
                urls.append(discovered_url)

            # 对 3xx 响应，额外抽取重定向目标（转为绝对 URL）
            if status_code.startswith("3"):
                redirect_match = self._REDIRECT_PATTERN.search(line)
                if redirect_match:
                    redirect_path = redirect_match.group(1)
                    redirect_url = urllib.parse.urljoin(base + "/", redirect_path.lstrip("/"))
                    if redirect_url not in seen:
                        seen.add(redirect_url)
                        urls.append(redirect_url)

        return urls


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 统一调度入口
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ToolDiscovery:
    """
    第一层：广度 URL 发现。

    按顺序运行 katana（爬虫）和 dirsearch（爆破），
    合并并去重所有发现的 URL，交由后续 LLM 过滤层处理。

    设计原则：
      - 任意工具失败不影响整体流水线（优雅降级）
      - 结果去重保持首次出现顺序
      - 若 TOOL_DISCOVERY_ENABLED=False 直接返回空列表
    """

    def __init__(self):
        self._katana = KatanaRunner()
        self._dirsearch = DirsearchRunner()

    def discover(self, url: str) -> List[str]:
        """
        整合运行所有已启用的工具，返回去重后的候选 URL 列表。

        Args:
            url: 目标站点起始 URL

        Returns:
            去重后的候选 URL 列表（katana 结果在前，dirsearch 结果在后）
        """
        if not TOOL_DISCOVERY_ENABLED:
            return []

        # 全局优化：如果传入的 URL 带有常见文件后缀（如 /index.html, /login.php）
        # 将其退回到所在的目录层级，作为基础爬取起点。
        # 理由：
        # 1. 对 Katana：从 /login.php 开始爬通常爬不到什么（登录页很少有外部链接），退到目录能爬到更多隐藏入口。
        # 2. 对 Dirsearch：避免拼接出 /index.html/admin 这种无效的 404 路径。
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        if path.endswith(('.html', '.htm', '.php', '.jsp', '.asp', '.aspx')):
            path = path.rsplit('/', 1)[0] + '/'
            if not path.startswith('/'):
                path = '/' + path
            base_target = urllib.parse.urlunparse(parsed._replace(path=path))
        else:
            base_target = url

        print(f"\n{'─' * 50}")
        print(f"  [Layer 1] 外部工具 URL 发现: {base_target}")
        if base_target != url:
            print(f"  [System] 已自动将特定文件端点退回为目录起点 (避免爆破或爬虫卡死/无链可爬)")
        print(f"{'─' * 50}")

        all_urls: List[str] = []

        # 1. katana 爬虫（跟踪链接，处理 JS 渲染）
        katana_urls = self._katana.run(base_target)
        all_urls.extend(katana_urls)

        # 2. dirsearch 爆破（发现无链接的隐藏路径）
        dirsearch_urls = self._dirsearch.run(base_target)
        all_urls.extend(dirsearch_urls)

        # 去重（保持顺序）
        seen: set = set()
        deduped: List[str] = []
        for u in all_urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)

        print(f"\n  [Layer 1] 合并去重完成: katana={len(katana_urls)} + "
              f"dirsearch={len(dirsearch_urls)} → 共 {len(deduped)} 个不重复 URL")
        return deduped