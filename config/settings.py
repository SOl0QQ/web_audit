"""
全局配置文件
"""
import os
import shutil

# ── LLM 配置 ──────────────────────────────────────────────
LLM_PROVIDER = "ollama"          # "google" | "openai" | "ollama"
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL = "gemma4-31b-gpu"             # 若有其他本地模型（如 qwen2），可在此修改
LLM_TEMPERATURE = 0.0
OLLAMA_BASE_URL = "http://192.168.1.52:1234"

# ── HTTP 请求配置 ──────────────────────────────────────────
REQUEST_TIMEOUT = 15             # 请求超时秒数
REQUEST_VERIFY_SSL = False       # 渗透测试环境常关闭 SSL 校验
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ── 爬虫配置 ───────────────────────────────────────────────
# 1. 寻找登录页的爬虫配置
CRAWLER_MAX_DEPTH = 3            # 登录页递归查找的最大深度
CRAWLER_MAX_CANDIDATE_LINKS = 15 # 每页最多候选链接数

# 2. 寻找后台上传点的爬虫配置 (权重极高)
UPLOAD_MAX_DEPTH = 4             # 登录成功后，后台寻找上传点的最大深度
UPLOAD_MAX_PAGES = 100           # 登录成功后，最多安全遍历的后台页面数量

# ── 外部工具发现配置 ───────────────────────────────────────
# 设为 True 时，在爬虫发现阶段额外调用外部工具扩大 URL 覆盖范围
TOOL_DISCOVERY_ENABLED = True

# katana 配置（主动爬虫，擅长 SPA/JS 动态页面）
# 安装: go install github.com/projectdiscovery/katana/cmd/katana@latest
KATANA_ENABLED = True
KATANA_PATH = os.path.expanduser("~/go/bin/katana")  # go install 默认输出路径
KATANA_DEPTH = 3                 # 爬取深度
KATANA_TIMEOUT = 60              # Python 进程硬截止（秒）：到期强制终止，返回已收集结果
KATANA_REQUEST_TIMEOUT = 10      # 传给 katana 的单次 HTTP 请求超时（秒）
                                 # 两者需分开：REQUEST_TIMEOUT 短 → katana 能在 TIMEOUT 内爬多个页面
KATANA_RATE_LIMIT = 2           # katana 每秒最大请求数 (-rl 50)
KATANA_JS_CRAWL = True          # 默认关闭：纯 HTTP 模式秒级出结果
                                 # 对 Vue/React SPA 站点改为 True（需 Chromium 已下载）

# dirsearch 配置（目录爆破，发现无链接的隐藏路径）
# 安装: pip install dirsearch 或 git clone https://github.com/maurosoria/dirsearch
DIRSEARCH_ENABLED = True
DIRSEARCH_PATH = shutil.which("dirsearch") or "dirsearch"  # 自动检测 pip 安装位置
DIRSEARCH_EXTENSIONS = "php,asp,aspx,jsp,html"  # 探测文件扩展名
DIRSEARCH_TIMEOUT = 30           # 单个请求超时秒数
DIRSEARCH_THREADS = 1           # 并发线程数
DIRSEARCH_MAX_RATE = 2          # dirsearch 每秒最大请求数 (--max-rate 20)
# 登录页专用小字典（~80条），聚焦常见登录路径，快速精准
# 设为 None 则使用 dirsearch 默认字典（更全但耗时数分钟）
DIRSEARCH_WORDLIST = os.path.join(os.path.dirname(__file__), "login_wordlist.txt")
DIRSEARCH_MAX_TIME = 60          # dirsearch 进程最大运行时间（秒）

# ── 审计结果配置 ───────────────────────────────────────────
REPORT_OUTPUT_DIR = "./reports"  # 报告输出目录
REPORT_FORMAT = "json"           # "json" | "text"

# ── 上传安全审查配置 ────────────────────────────────────────
ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "application/pdf", "text/plain",
    "application/zip",
}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".pdf", ".txt", ".zip"}
DANGEROUS_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".jsp", ".jspx",
    ".py", ".rb", ".pl", ".cgi", ".sh",
    ".exe", ".bat", ".cmd",
}
