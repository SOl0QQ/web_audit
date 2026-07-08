"""
主入口：Web 安全审计流水线

按照以下顺序依次调度各模块：
  1. 登录页识别 (LoginDetectorModule)
  2. SQL 注入检测 (SQLiDetectorModule)
  3. 文件上传功能识别 (UploadIdentifierModule)
  4. 上传安全审查 (UploadSecurityAuditModule)

使用方法:
  python -m web_audit.main --url https://target.example.com

或直接运行:
  python web_audit/main.py
"""
import argparse
import os
import sys

import time

from web_audit.core.requester import Requester
from web_audit.modules.login_detector import LoginDetectorModule
from web_audit.modules.sqli_detector import SQLiDetectorModule
from web_audit.modules.upload_auditor import UploadIdentifierModule
from web_audit.reports.reporter import Reporter


def run_pipeline(target_url: str, step: str = "all"):
    """
    完整的 Web 安全审计流水线。

    Args:
        target_url: 目标网站的起始 URL（不需要是登录页）
        step: 指定执行的模块 ("all", "login", "sqli", "upload_id", "upload_audit")
    """
    # 全局防御性修复：确保 target_url 始终带有 http:// 协议前缀
    if target_url and not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    pipeline_start_time = time.time()
    print(f"\n{'=' * 60}")
    print(f"  Web 安全审计流水线启动")
    print(f"  目标: {target_url}")
    if step != "all":
        print(f"  模式: 单独执行 [{step}]")
    print(f"{'=' * 60}\n")

    requester = Requester()
    reporter = Reporter(target_url)

    # 发起初始探测，解析可能的全局重定向 (例如 http://test3 -> https://test3/main/)
    print(f"  [System] 正在探测目标连通性与重定向...")
    # 允许 requests 自动追踪所有的重定向链 (allow_redirects=True 是默认的)
    init_resp = requester.get(target_url, allow_redirects=True)
    
    if init_resp and init_resp.history:
        # history 包含了所有的重定向过程，init_resp.url 是最终落地页
        print(f"  [System] 检测到目标发生了 {len(init_resp.history)} 次重定向:")
        for i, resp in enumerate(init_resp.history, 1):
            print(f"           {i}. [{resp.status_code}] {resp.url} -> {resp.headers.get('Location', 'Unknown')}")
        print(f"  [System] 最终目标确定为: {init_resp.url}")
        
        target_url = init_resp.url
        # 更新 reporter 的基础 URL
        reporter.target_url = target_url
    elif init_resp and init_resp.url != target_url:
        print(f"  [System] 目标发生重定向: {target_url} -> {init_resp.url}")
        target_url = init_resp.url
        reporter.target_url = target_url

    # 跨模块共享状态
    analysis_url = target_url
    login_page_url = None
    landing_page_url = None
    is_authenticated = False
    upload_id_result = None

    try:
        # ── Step 1: 登录页识别 ─────────────────────────────
        if step in ["all", "login"]:
            print("\n[Step 1/4] 登录页面识别")
            print("-" * 40)
            login_module = LoginDetectorModule(requester)
            t0 = time.time()
            login_result = login_module.run(target_url)
            login_result['execution_time_seconds'] = round(time.time() - t0, 2)
            reporter.add_result(login_result)

            if login_result["findings"]:
                login_page_url = login_result["findings"][0].get("login_page_url")
            
            analysis_url = login_page_url or target_url

        # ── Step 2: SQL 注入检测 ───────────────────────────
        if step in ["all", "sqli"]:
            print(f"\n[Step 2/4] SQL 注入漏洞检测（目标: {analysis_url}）")
            print("-" * 40)
            sqli_module = SQLiDetectorModule(requester)
            t0 = time.time()
            sqli_result = sqli_module.run(analysis_url)
            sqli_result['execution_time_seconds'] = round(time.time() - t0, 2)
            reporter.add_result(sqli_result)

            for finding in sqli_result.get("findings", []):
                if finding.get("is_bypassed"):
                    landing_page_url = finding.get("landing_page_url")
                    is_authenticated = True
                    break

        upload_scan_url = landing_page_url if landing_page_url else analysis_url
        
        # 針對 AJAX/API 登入：如果著陸頁其實是後端 API (例如 checklogin.php)，爬蟲會找不到任何連結
        # 我們將爬蟲起點強制切換回網站根目錄或原始目標網址
        if upload_scan_url:
            lower_url = upload_scan_url.lower()
            if any(kw in lower_url for kw in ["checklogin", "ajax", "api", "login.php", "login_action"]):
                import urllib.parse
                # Ensure we join with a slash to get the root of the target_url, or just use target_url
                # Safe parsing: ensure target_url has scheme before parsing so netloc isn't empty
                safe_target = target_url if "://" in target_url else "http://" + target_url
                parsed_target = urllib.parse.urlparse(safe_target)
                upload_scan_url = f"{parsed_target.scheme}://{parsed_target.netloc}/"
                print(f"  [System] 檢測到登錄著陸頁為 API/Action 端點 ({landing_page_url})，將上傳掃描起點修正為: {upload_scan_url}")
            elif "?" in upload_scan_url and "Login" in upload_scan_url:
                import urllib.parse
                safe_target = target_url if "://" in target_url else "http://" + target_url
                parsed_target = urllib.parse.urlparse(safe_target)
                upload_scan_url = f"{parsed_target.scheme}://{parsed_target.netloc}/"

        # ── Step 3: 文件上传功能识别 ───────────────────────
        if step in ["all", "upload_id"]:
            print(f"\n[Step 3/4] 文件上传功能识别（目标: {upload_scan_url}）")
            print("-" * 40)
            upload_id_module = UploadIdentifierModule(requester)
            t0 = time.time()
            upload_id_result = upload_id_module.run(
                upload_scan_url,
                context={"is_authenticated": is_authenticated}
            )
            upload_id_result['execution_time_seconds'] = round(time.time() - t0, 2)
            reporter.add_result(upload_id_result)

        # ── Step 4: 综合文件上传漏洞检测与验证 ────────
        if step in ["all", "upload_audit", "upload_exploit"]:
            print("\n[Step 4/4] 综合文件上传漏洞检测与验证")
            print("-" * 40)
            from web_audit.modules.unified_upload_auditor import UnifiedUploadAuditModule
            unified_upload_module = UnifiedUploadAuditModule(requester)
            
            if upload_id_result and upload_id_result["findings"]:
                t0 = time.time()
                audit_result = unified_upload_module.run(
                    upload_scan_url,
                    context={"upload_forms": upload_id_result["findings"]}
                )
                audit_result['execution_time_seconds'] = round(time.time() - t0, 2)
                reporter.add_result(audit_result)
            elif step in ["upload_audit", "upload_exploit"]:
                # 单独运行时，构造一个基础的上传端点用于测试
                print(f"  审查端点: {target_url} (单独运行)")
                t0 = time.time()
                dummy_form = {
                    "action_url": target_url,
                    "file_input_names": ["file"]
                }
                audit_result = unified_upload_module.run(
                    target_url,
                    context={"upload_forms": [dummy_form]}
                )
                audit_result['execution_time_seconds'] = round(time.time() - t0, 2)
                reporter.add_result(audit_result)
            else:
                print("  未发现上传端点，跳过安全审查与漏洞验证。")

    finally:
        requester.close()

    # ── 生成报告 ───────────────────────────────────────────
    reporter.total_time = time.time() - pipeline_start_time
    reporter.print_summary()
    report_path = reporter.generate()
    print(f"\n完整报告路径: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Web 安全审计流水线 (基于 LangChain)"
    )
    
    # ... [其余原有逻辑] ...
    
    parser.add_argument(
        "--url",
        type=str,
        help="目标网站起始 URL（如 https://example.com）",
        required=False,
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="包含多个目标 URL 的文本文件路径（每行一个）",
        required=False,
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=5,
        help="批量扫描时的并发线程数 (默认: 5)",
        required=False,
    )
    parser.add_argument(
        "--step",
        type=str,
        choices=["all", "login", "sqli", "upload_id", "upload_audit", "upload_exploit"],
        default="all",
        help="指定要单独运行的模块 (all, login, sqli, upload_id, upload_audit, upload_exploit)"
    )
    args = parser.parse_args()

    # 收集扫描目标
    targets = []
    target_env = args.url or os.getenv("AUDIT_TARGET_URL", "")
    
    if args.file:
        if not os.path.exists(args.file):
            print(f"错误：指定的文件不存在: {args.file}")
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # 过滤空行和注释
                if line and not line.startswith('#'):
                    # 防御性修复: 确保目标格式合法，补充 scheme 如果缺失
                    if not line.startswith("http://") and not line.startswith("https://"):
                        line = "http://" + line
                    targets.append(line)
    elif target_env:
        if not target_env.startswith("http://") and not target_env.startswith("https://"):
            target_env = "http://" + target_env
        targets.append(target_env)

    if not targets:
        print("错误：请通过 --url、-f/--file 参数或 AUDIT_TARGET_URL 环境变量指定至少一个目标 URL。")
        sys.exit(1)

    print(f"\n[System] 共加载了 {len(targets)} 个扫描目标，准备开始并发扫描 (并发数: {args.threads})...\n")
    
    import concurrent.futures
    import threading

    def scan_task(url: str, index: int, total: int):
        try:
            print(f"\n>>> [{index}/{total}] [Thread-{threading.get_ident()}] 正在启动扫描任务: {url}")
            run_pipeline(url, step=args.step)
        except Exception as e:
            print(f"\n[Error] 扫描目标 {url} 发生未捕获的严重异常，已强制跳过。错误详情: {e}")
            import traceback
            traceback.print_exc()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_task, t, i, len(targets)) for i, t in enumerate(targets, 1)]
        concurrent.futures.wait(futures)

    print(f"\n[System] 批量扫描完成！共处理了 {len(targets)} 个目标。")


if __name__ == "__main__":
    main()
