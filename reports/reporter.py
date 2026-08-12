"""
报告生成器

将各模块的审计结果汇总，输出为 JSON 或格式化文本报告。
"""
import csv
import json
import os
import threading
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Any
from web_audit.config.settings import REPORT_OUTPUT_DIR, REPORT_FORMAT, CSV_OUTPUT_PATH

# 全局文件锁，保证多线程并发扫描时 CSV 追加写入不会交错
_csv_lock = threading.Lock()

# CSV 列顺序（固定）
CSV_COLUMNS = [
    "domain",
    "login_page",
    "bypass_method",
    "upload_page",
    "webshell_success",
    "taken_time",
]


def _ensure_csv_header(path: str):
    """如果 CSV 文件不存在或为空，则写入表头。"""
    needs_header = (not os.path.exists(path)) or os.path.getsize(path) == 0
    if needs_header:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_COLUMNS)


def append_csv_row(row: Dict[str, Any], path: str = CSV_OUTPUT_PATH):
    """线程安全地追加一行 CSV 记录。"""
    with _csv_lock:
        _ensure_csv_header(path)
        with open(path, "a", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([row.get(c, "") for c in CSV_COLUMNS])


def build_csv_row(reporter: "Reporter") -> Dict[str, Any]:
    """从 Reporter 已收集的结果中提取一行 CSV 字段。

    字段提取规则：
      - domain:           目标域名（从 target_url 解析）
      - login_page:       登录页识别阶段发现的第一个候选 URL
      - bypass_method:    SQL 注入绕过成功时使用的 evidence/reason（若多条用 ' | ' 拼接）
      - upload_page:      文件上传功能识别阶段发现的第一个 action_url
      - webshell_success: 上传审计阶段确认的 webshell URL（若多个用 ' | ' 拼接）
      - taken_time:       该域名流水线总耗时（秒，保留 2 位小数）
    """
    # ── domain ──
    domain = reporter.target_url or ""
    try:
        parsed = urlparse(domain if "://" in domain else "http://" + domain)
        domain = parsed.netloc or domain
    except Exception:
        pass

    # ── login_page: 从 global_results 中找 login_detector 的第一个候选 ──
    login_page = ""
    for res in reporter.global_results:
        if res.get("module") == "login_detector":
            findings = res.get("findings") or []
            if findings:
                login_page = findings[0].get("candidate_url") or ""
            break

    # ── bypass_method / upload_page / webshell_success ──
    bypass_methods: List[str] = []
    upload_pages: List[str] = []
    webshell_successes: List[str] = []

    for _url, results in reporter.url_results.items():
        for res in results:
            module = res.get("module", "")
            findings = res.get("findings") or []

            # SQLi 模块：收集绕过成功的 evidence
            if module == "sqli_detector":
                for f in findings:
                    if f.get("is_bypassed"):
                        ev = f.get("evidence")
                        if isinstance(ev, list):
                            ev = "; ".join(str(e) for e in ev)
                        elif ev is None:
                            ev = f.get("reason") or f.get("payload") or ""
                        if ev:
                            bypass_methods.append(str(ev))

            # 上传识别模块：收集 action_url
            elif module == "upload_identifier":
                for f in findings:
                    action = f.get("action_url") or f.get("candidate_url") or ""
                    if action and action not in upload_pages:
                        upload_pages.append(action)

            # 统一上传审计模块：收集 webshell 路径
            elif module == "unified_upload_audit":
                for f in findings:
                    shell = f.get("shell_path") or f.get("url") or ""
                    strategy = f.get("strategy") or ""
                    if shell:
                        tag = f"{shell}" + (f" ({strategy})" if strategy else "")
                        webshell_successes.append(tag)

    return {
        "domain": domain,
        "login_page": login_page,
        "bypass_method": " | ".join(bypass_methods),
        "upload_page": " | ".join(upload_pages),
        "webshell_success": " | ".join(webshell_successes),
        "taken_time": round(reporter.total_time, 2) if reporter.total_time else "",
    }


class Reporter:
    """审计报告生成器。"""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.generated_at = datetime.now().isoformat()
        self.global_results: List[Dict[str, Any]] = []
        self.url_results: Dict[str, List[Dict[str, Any]]] = {}
        self.total_time: float = 0.0

    def add_global_result(self, module_result: Dict[str, Any]):
        """添加全局探测结果（例如初始的 URL 挖掘）。"""
        self.global_results.append(module_result)

    def add_result(self, url: str, module_result: Dict[str, Any]):
        """添加针对特定 URL 的审计结果。"""
        if url not in self.url_results:
            self.url_results[url] = []
        self.url_results[url].append(module_result)

    def generate(self) -> str:
        """生成并保存报告，返回报告文件路径。"""
        os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_host = self.target_url.replace("://", "_").replace("/", "_")[:50]
        filename = f"audit_{safe_host}_{timestamp}.{REPORT_FORMAT}"
        filepath = os.path.join(REPORT_OUTPUT_DIR, filename)

        report_data = {
            "target": self.target_url,
            "generated_at": self.generated_at,
            "total_execution_time_seconds": round(self.total_time, 2),
            "global_results": self.global_results,
            "scanned_urls": self.url_results,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            if REPORT_FORMAT == "json":
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            else:
                f.write(self._to_text(report_data))

        print(f"\n[Reporter] 报告已生成: {filepath}")
        return filepath

    def print_summary(self):
        """在终端打印审计摘要。"""
        print("\n" + "=" * 60)
        print(f"  Web 安全审计报告摘要")
        print(f"  目标: {self.target_url}")
        print(f"  时间: {self.generated_at}")
        if self.total_time > 0:
            print(f"  总耗时: {self.total_time:.2f} 秒")
        print("=" * 60)

        for result in self.global_results:
            module = result.get("module", "unknown")
            summary = result.get("summary", "")
            print(f"\n  [{module}] (全局阶段)")
            print(f"  摘要: {summary}")

        for url, results in self.url_results.items():
            print(f"\n  🎯 Target URL: {url}")
            for result in results:
                module = result.get("module", "unknown")
                summary = result.get("summary", "")
                findings_count = len(result.get("findings", []))
                time_spent = result.get("execution_time_seconds")
                print(f"    [{module}]")
                print(f"      摘要: {summary}")
                print(f"      发现数量: {findings_count}")
                if time_spent is not None:
                    print(f"      耗时: {time_spent} 秒")
        print("=" * 60)

    @staticmethod
    def _to_text(report_data: Dict[str, Any]) -> str:
        """格式化为纯文本。"""
        lines = [
            f"Web 安全审计报告",
            f"目标: {report_data['target']}",
            f"生成时间: {report_data['generated_at']}",
            f"总耗时: {report_data.get('total_execution_time_seconds', 0)} 秒",
            "-" * 60,
        ]
        if report_data.get("global_results"):
            lines.append("\n[全局阶段探测]")
            for result in report_data.get("global_results", []):
                lines.append(f"模块: {result.get('module', 'N/A')}")
                lines.append(f"摘要: {result.get('summary', 'N/A')}")
                
        for url, results in report_data.get("scanned_urls", {}).items():
            lines.append(f"\n🎯 URL: {url}")
            for result in results:
                lines.append(f"  模块: {result.get('module', 'N/A')}")
                lines.append(f"  耗时: {result.get('execution_time_seconds', 'N/A')} 秒")
                lines.append(f"  摘要: {result.get('summary', 'N/A')}")
                lines.append(f"  发现: {json.dumps(result.get('findings', []), ensure_ascii=False, indent=4)}")
                lines.append("")
        return "\n".join(lines)
