"""
报告生成器

将各模块的审计结果汇总，输出为 JSON 或格式化文本报告。
"""
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
