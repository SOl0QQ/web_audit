"""
性能监控模块

自动收集 LLM 调用、HTTP 请求、模块执行的耗时数据，
用于定位性能瓶颈。
"""

import time
import json
import os
from datetime import datetime
from collections import defaultdict
import threading
from typing import Optional, Dict, Any, List


class PerformanceMonitor:
    """线程安全的性能监控器"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.metrics = {
            "llm_calls": [],
            "http_requests": [],
            "playwright_ops": [],
            "module_times": [],
        }
        self.start_time = None
        self.target_url = None
        self._initialized = True

    def start_audit(self, target_url: str):
        """开始审计任务"""
        self.start_time = time.time()
        self.target_url = target_url
        print(f"\n{'='*70}")
        print(f"[性能监控] 开始审计: {target_url}")
        print(f"{'='*70}\n")

    def record_llm(self, operation: str, duration: float, success: bool = True,
                   error: Optional[str] = None, model: Optional[str] = None):
        """记录 LLM 调用"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "duration_seconds": round(duration, 2),
            "success": success,
            "error": error,
            "model": model,
        }
        with self._lock:
            self.metrics["llm_calls"].append(record)

        # 实时打印
        status = "✅" if success else "❌"
        model_str = f" ({model})" if model else ""
        print(f"  [LLM] {status} {operation}{model_str}: {duration:.2f} 秒")

        # 警告慢调用
        if duration > 10:
            print(f"  [LLM] ⚠️ 慢调用警告: {operation} 耗时 {duration:.2f} 秒")

    def record_http(self, method: str, url: str, duration: float,
                   status_code: Optional[int] = None, success: bool = True,
                   error: Optional[str] = None):
        """记录 HTTP 请求"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "url": url[:200],  # 截断长 URL
            "duration_seconds": round(duration, 2),
            "status_code": status_code,
            "success": success,
            "error": error,
        }
        with self._lock:
            self.metrics["http_requests"].append(record)

        # 只打印慢请求 (> 3 秒)
        if duration > 3:
            status = "✅" if success else "❌"
            print(f"  [HTTP] {status} {method} {url[:60]}... : {duration:.2f} 秒")

    def record_playwright(self, operation: str, duration: float, success: bool = True):
        """记录 Playwright 操作"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "duration_seconds": round(duration, 2),
            "success": success,
        }
        with self._lock:
            self.metrics["playwright_ops"].append(record)

        # 只打印慢操作 (> 5 秒)
        if duration > 5:
            status = "✅" if success else "❌"
            print(f"  [Playwright] {status} {operation}: {duration:.2f} 秒")

    def record_module(self, module_name: str, duration: float):
        """记录模块执行时间"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "duration_seconds": round(duration, 2),
        }
        with self._lock:
            self.metrics["module_times"].append(record)

        print(f"\n[模块] {module_name} 完成: {duration:.2f} 秒 ({duration/60:.1f} 分钟)\n")

    def save_report(self, output_file: str = "/tmp/performance_report.json"):
        """保存性能报告"""
        total_time = time.time() - self.start_time if self.start_time else 0

        report = {
            "target_url": self.target_url or "unknown",
            "total_audit_time_seconds": round(total_time, 2),
            "generated_at": datetime.now().isoformat(),
            "metrics": self.metrics,
            "summary": self._generate_summary(),
        }

        # 确保目录存在
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"\n{'='*70}")
        print(f"[性能监控] 报告已保存: {output_file}")
        print(f"{'='*70}\n")

        self._print_summary()

    def _generate_summary(self) -> Dict[str, Any]:
        """生成摘要统计"""
        import statistics

        summary = {}

        # LLM 统计
        llm_calls = self.metrics["llm_calls"]
        if llm_calls:
            durations = [c["duration_seconds"] for c in llm_calls if c["success"]]
            if durations:
                summary["llm"] = {
                    "total_calls": len(llm_calls),
                    "successful_calls": len(durations),
                    "avg_duration": round(statistics.mean(durations), 2),
                    "median_duration": round(statistics.median(durations), 2),
                    "max_duration": round(max(durations), 2),
                    "total_time": round(sum(durations), 2),
                    "slow_calls_gt_10s": sum(1 for d in durations if d > 10),
                }

        # HTTP 统计
        http_reqs = self.metrics["http_requests"]
        if http_reqs:
            durations = [r["duration_seconds"] for r in http_reqs if r["success"]]
            if durations:
                summary["http"] = {
                    "total_requests": len(http_reqs),
                    "successful_requests": len(durations),
                    "avg_duration": round(statistics.mean(durations), 2),
                    "median_duration": round(statistics.median(durations), 2),
                    "max_duration": round(max(durations), 2),
                    "total_time": round(sum(durations), 2),
                    "slow_requests_gt_3s": sum(1 for d in durations if d > 3),
                }

        # Playwright 统计
        pw_ops = self.metrics["playwright_ops"]
        if pw_ops:
            durations = [o["duration_seconds"] for o in pw_ops if o["success"]]
            if durations:
                summary["playwright"] = {
                    "total_operations": len(pw_ops),
                    "successful_operations": len(durations),
                    "avg_duration": round(statistics.mean(durations), 2),
                    "total_time": round(sum(durations), 2),
                    "slow_operations_gt_5s": sum(1 for d in durations if d > 5),
                }

        # 模块统计
        module_times = self.metrics["module_times"]
        if module_times:
            summary["modules"] = {}
            for m in module_times:
                module_name = m["module"]
                duration = m["duration_seconds"]
                if module_name not in summary["modules"]:
                    summary["modules"][module_name] = []
                summary["modules"][module_name].append(duration)

            # 计算每个模块的平均耗时
            for module_name in summary["modules"]:
                times = summary["modules"][module_name]
                summary["modules"][module_name] = {
                    "count": len(times),
                    "avg_duration": round(statistics.mean(times), 2),
                    "total_time": round(sum(times), 2),
                }

        return summary

    def _print_summary(self):
        """打印摘要"""
        summary = self._generate_summary()

        print("\n" + "="*70)
        print("性能监控摘要")
        print("="*70)

        if "llm" in summary:
            llm = summary["llm"]
            print(f"\n【LLM 调用】")
            print(f"  总次数: {llm['total_calls']}")
            print(f"  成功次数: {llm['successful_calls']}")
            print(f"  平均耗时: {llm['avg_duration']:.2f} 秒")
            print(f"  中位数: {llm['median_duration']:.2f} 秒")
            print(f"  最大耗时: {llm['max_duration']:.2f} 秒")
            print(f"  总耗时: {llm['total_time']:.2f} 秒 ({llm['total_time']/60:.1f} 分钟)")
            print(f"  慢调用 (>10s): {llm['slow_calls_gt_10s']} 次")

        if "http" in summary:
            http = summary["http"]
            print(f"\n【HTTP 请求】")
            print(f"  总次数: {http['total_requests']}")
            print(f"  成功次数: {http['successful_requests']}")
            print(f"  平均耗时: {http['avg_duration']:.2f} 秒")
            print(f"  中位数: {http['median_duration']:.2f} 秒")
            print(f"  最大耗时: {http['max_duration']:.2f} 秒")
            print(f"  总耗时: {http['total_time']:.2f} 秒 ({http['total_time']/60:.1f} 分钟)")
            print(f"  慢请求 (>3s): {http['slow_requests_gt_3s']} 次")

        if "playwright" in summary:
            pw = summary["playwright"]
            print(f"\n【Playwright 操作】")
            print(f"  总次数: {pw['total_operations']}")
            print(f"  平均耗时: {pw['avg_duration']:.2f} 秒")
            print(f"  总耗时: {pw['total_time']:.2f} 秒 ({pw['total_time']/60:.1f} 分钟)")
            print(f"  慢操作 (>5s): {pw['slow_operations_gt_5s']} 次")

        if "modules" in summary:
            print(f"\n【模块耗时】")
            for module_name, stats in sorted(summary["modules"].items()):
                print(f"  {module_name:30s}: {stats['total_time']:7.2f} 秒 ({stats['total_time']/60:.1f} 分钟)")

        print("="*70)


# 全局访问函数
def get_perf_monitor() -> PerformanceMonitor:
    """获取全局性能监控器实例"""
    return PerformanceMonitor()
