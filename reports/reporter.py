"""
报告生成器

将各模块的审计结果汇总，输出为 CSV、JSON 或格式化文本报告。
"""
import csv
import json
import os
from datetime import datetime
from typing import List, Dict, Any
from web_audit.config.settings import REPORT_OUTPUT_DIR, REPORT_FORMAT


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

        # 打印 Webshell 漏洞详情
        self._print_webshell_findings()

        print("=" * 60)

    def _print_webshell_findings(self):
        """打印所有发现的 Webshell 路径和漏洞详情。"""
        webshell_findings = []

        # 收集所有 unified_upload_audit 模块的 findings
        for url, results in self.url_results.items():
            for result in results:
                if result.get("module") == "unified_upload_audit":
                    for finding in result.get("findings", []):
                        if finding.get("shell_path"):
                            webshell_findings.append({
                                "target_url": url,
                                "upload_endpoint": finding.get("url", "N/A"),
                                "strategy": finding.get("strategy", "N/A"),
                                "payload_file": finding.get("payload_file", "N/A"),
                                "shell_path": finding.get("shell_path", "N/A"),
                                "severity": finding.get("severity", "Critical"),
                                "rce_output": finding.get("rce_output", "")[:200],  # 截断过长的输出
                            })

        if not webshell_findings:
            return

        print(f"\n{'─' * 60}")
        print(f"  🚨 Webshell/RCE 漏洞详情 (共 {len(webshell_findings)} 個)")
        print(f"{'─' * 60}")

        for idx, finding in enumerate(webshell_findings, 1):
            print(f"\n  [{idx}] {finding['severity']} - Webshell 上传成功")
            print(f"      上传端点: {finding['upload_endpoint']}")
            print(f"      绕过策略: {finding['strategy']}")
            print(f"      Payload 文件: {finding['payload_file']}")
            print(f"      Webshell 路径: {finding['shell_path']}")
            if finding['rce_output']:
                print(f"      RCE 输出: {finding['rce_output']}...")

        print(f"\n{'─' * 60}")

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

    def extract_csv_row(self) -> Dict[str, str]:
        """
        提取 CSV 報告所需的數據。

        返回格式：
        {
            "domain": "abc.com",
            "login_page": "abc.com/login",
            "bypass_method": "admin' OR '1'='1",
            "upload_page": "abc.com/shirt.php?action=insert",
            "webshell_success": "abc.com/logo/d49a0b656613cf356eff5c9dc0786949.php",
            "taken_time": "16min"
        }
        """
        import urllib.parse

        # 提取域名
        parsed = urllib.parse.urlparse(self.target_url)
        domain = parsed.netloc or parsed.path

        # 提取登錄頁
        login_page = ""
        for result in self.global_results:
            if result.get("module") == "login_detector":
                findings = result.get("findings", [])
                if findings:
                    login_page = findings[0].get("candidate_url", "")
                    # 轉換為相對路徑格式
                    if login_page:
                        lp_parsed = urllib.parse.urlparse(login_page)
                        login_page = f"{lp_parsed.netloc}{lp_parsed.path}"
                break

        # 提取 bypass 方法和 payload
        bypass_method = ""
        for url, results in self.url_results.items():
            for result in results:
                if result.get("module") == "sqli_detector":
                    for finding in result.get("findings", []):
                        if finding.get("is_bypassed"):
                            bypass_method = finding.get("payload", "")
                            break
                    if bypass_method:
                        break
            if bypass_method:
                break

        # 提取上傳頁面
        upload_pages = []
        for url, results in self.url_results.items():
            for result in results:
                if result.get("module") == "upload_identifier":
                    for finding in result.get("findings", []):
                        action_url = finding.get("action_url", "")
                        if action_url:
                            up_parsed = urllib.parse.urlparse(action_url)
                            upload_pages.append(f"{up_parsed.netloc}{up_parsed.path}")

        upload_page = "; ".join(upload_pages) if upload_pages else ""

        # 提取 Webshell 路徑
        webshell_paths = []
        for url, results in self.url_results.items():
            for result in results:
                if result.get("module") == "unified_upload_audit":
                    for finding in result.get("findings", []):
                        shell_path = finding.get("shell_path", "")
                        if shell_path:
                            sp_parsed = urllib.parse.urlparse(shell_path)
                            webshell_paths.append(f"{sp_parsed.netloc}{sp_parsed.path}")

        webshell_success = "; ".join(webshell_paths) if webshell_paths else ""

        # 格式化耗時
        total_seconds = int(self.total_time)
        if total_seconds >= 60:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            taken_time = f"{minutes}min{seconds}s" if seconds else f"{minutes}min"
        else:
            taken_time = f"{total_seconds}s"

        return {
            "domain": domain,
            "login_page": login_page,
            "bypass_method": bypass_method,
            "upload_page": upload_page,
            "webshell_success": webshell_success,
            "taken_time": taken_time,
        }

    @staticmethod
    def write_csv_report(rows: List[Dict[str, str]], output_dir: str = None) -> str:
        """
        將多個目標的結果寫入全局 CSV 報告。

        Args:
            rows: 每個目標的 CSV 數據行
            output_dir: 輸出目錄，默認為 REPORT_OUTPUT_DIR

        Returns:
            CSV 文件路徑
        """
        from web_audit.config.settings import CSV_REPORT_FILENAME

        if output_dir is None:
            output_dir = REPORT_OUTPUT_DIR

        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, CSV_REPORT_FILENAME)

        fieldnames = ["domain", "login_page", "bypass_method", "upload_page", "webshell_success", "taken_time"]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        print(f"\n[Reporter] CSV 報告已生成: {filepath}")
        return filepath
