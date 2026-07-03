"""
抽象基类：所有审计模块的接口契约

每个功能模块都必须继承此基类并实现 run() 方法，
确保系统可以通过统一接口动态调度所有模块。
"""
from abc import ABC, abstractmethod
from typing import Any, Dict
from web_audit.core.requester import Requester


class BaseModule(ABC):
    """
    审计模块抽象基类。

    Attributes:
        name (str): 模块名称（子类定义）
        requester (Requester): 共享的 HTTP 请求器实例
    """

    name: str = "base_module"

    def __init__(self, requester: Requester):
        self.requester = requester

    @abstractmethod
    def run(self, url: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行审计逻辑。

        Args:
            url: 当前分析的目标 URL
            context: 上下文信息，包含 PageParser 提取的 features 等

        Returns:
            标准化的审计结果字典，应包含：
            - module: 模块名称
            - url: 目标 URL
            - findings: 具体发现列表
            - summary: 文字摘要（供 LLM 使用）
        """
        raise NotImplementedError

    def _base_result(self, url: str) -> Dict[str, Any]:
        """返回标准结果骨架。"""
        return {
            "module": self.name,
            "url": url,
            "findings": [],
            "summary": "",
        }
