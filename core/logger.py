"""
核心：线程安全的日志缓冲代理

为了在异步流水线中解决多个测试链同时 print 导致的日志交织问题，
我们劫持 sys.stdout。通过 threading.local 为每个开启了 buffer 模式的线程
单独隔离 stdout 内容，并在任务结束后集中输出。
"""
import sys
import threading
import io

class ThreadSafeLogger:
    def __init__(self):
        self.original_stdout = sys.stdout
        self.local = threading.local()
        # 增加一个锁，用于控制多线程在向真正的屏幕集中输出时不重叠
        self.print_lock = threading.Lock()

    def write(self, data):
        if hasattr(self.local, 'buffer'):
            self.local.buffer.write(data)
        else:
            self.original_stdout.write(data)

    def flush(self):
        if hasattr(self.local, 'buffer'):
            self.local.buffer.flush()
        else:
            self.original_stdout.flush()

    def start_buffer(self):
        """当前线程开启日志缓冲"""
        self.local.buffer = io.StringIO()

    def get_buffer_and_stop(self) -> str:
        """获取当前线程的全部缓冲日志，并关闭缓冲，恢复原生输出"""
        if hasattr(self.local, 'buffer'):
            res = self.local.buffer.getvalue()
            self.local.buffer.close()
            del self.local.buffer
            return res
        return ""
        
    def dump_buffer_to_screen(self, title: str):
        """提取并带边框地整体打印当前线程的日志，确保输出不会交织"""
        log_content = self.get_buffer_and_stop()
        if not log_content.strip():
            return
            
        with self.print_lock:
            # 使用原生 stdout 输出，避免递归死循环
            self.original_stdout.write(f"\n{'='*70}\n")
            self.original_stdout.write(f" ⬇️  {title}\n")
            self.original_stdout.write(f"{'='*70}\n")
            self.original_stdout.write(log_content)
            if not log_content.endswith("\n"):
                self.original_stdout.write("\n")
            self.original_stdout.write(f"{'='*70}\n\n")
            self.original_stdout.flush()

# 全局单例
thread_safe_logger = ThreadSafeLogger()

def init_global_logger():
    """替换全局 stdout"""
    sys.stdout = thread_safe_logger
