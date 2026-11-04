"""
核心：LLM 工厂

统一管理 LangChain LLM 实例的创建，支持多 Provider 切换（Google / OpenAI / Ollama）。
"""
import time
import threading
from typing import Type, Any, Dict
from pydantic import BaseModel
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables import Runnable
from langchain_core.callbacks import BaseCallbackHandler
from web_audit.config.settings import (
    LLM_PROVIDER,
    LLM_MODEL,
    LLM_TEMPERATURE,
    GOOGLE_API_KEY,
    OPENAI_API_KEY,
    OLLAMA_BASE_URL,
    LLM_TIMEOUT,
)
from web_audit.core.performance_monitor import get_perf_monitor

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LLM 请求限流器 - 防止 Ollama 过载
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 全局信号量：控制同时发往 LLM 服务端的最大并发请求数
# Ollama 默认串行处理，但多个请求会排队导致超时
# 设置为 2-3 可避免请求堆积，同时保持一定并发度
_LLM_SEMAPHORE = threading.Semaphore(2)  # 最多 2 个并发 LLM 请求


class PerformanceCallbackHandler(BaseCallbackHandler):
    """LLM 性能监控回调处理器"""

    def __init__(self):
        self._start_times = {}

    def on_llm_start(self, serialized: Dict[str, Any], prompts, **kwargs):
        """LLM 调用开始时记录"""
        run_id = kwargs.get('run_id')
        if run_id:
            self._start_times[str(run_id)] = time.time()

    def on_llm_end(self, response, **kwargs):
        """LLM 调用结束时记录性能"""
        run_id = kwargs.get('run_id')
        if run_id and str(run_id) in self._start_times:
            duration = time.time() - self._start_times[str(run_id)]
            del self._start_times[str(run_id)]

            get_perf_monitor().record_llm(
                operation="invoke",
                duration=duration,
                success=True,
                model=LLM_MODEL
            )

    def on_llm_error(self, error: Exception, **kwargs):
        """LLM 调用出错时记录"""
        run_id = kwargs.get('run_id')
        if run_id and str(run_id) in self._start_times:
            duration = time.time() - self._start_times[str(run_id)]
            del self._start_times[str(run_id)]

            get_perf_monitor().record_llm(
                operation="invoke",
                duration=duration,
                success=False,
                error=str(error),
                model=LLM_MODEL
            )


# 全局回调处理器实例
_perf_callback = PerformanceCallbackHandler()


class ThrottledLLMWrapper:
    """
    LLM 请求限流包装器

    通过信号量控制并发请求数，防止 Ollama 服务端过载。
    当并发请求达到上限时，后续请求会阻塞等待，而不是堆积在 Ollama 队列中。
    """

    def __init__(self, llm):
        self._llm = llm

    def invoke(self, *args, **kwargs):
        """带限流的 invoke 方法"""
        # 获取信号量（如果已达上限则阻塞等待）
        acquired = _LLM_SEMAPHORE.acquire(timeout=LLM_TIMEOUT)
        if not acquired:
            print(f"[LLM限流] ⚠️ 等待超时，强制继续...")

        try:
            return self._llm.invoke(*args, **kwargs)
        finally:
            # 释放信号量
            _LLM_SEMAPHORE.release()

    def with_structured_output(self, schema, method=None):
        """代理 with_structured_output 方法"""
        if method:
            return self._llm.with_structured_output(schema, method=method)
        return self._llm.with_structured_output(schema)

    def __getattr__(self, name):
        """代理其他所有方法到原始 LLM"""
        return getattr(self._llm, name)


def get_llm() -> BaseChatModel:
    """
    根据配置返回对应的 LangChain Chat LLM 实例。
    支持：google (Gemini) | openai (GPT) | ollama (本地模型)

    所有返回的 LLM 都经过 ThrottledLLMWrapper 包装，
    通过信号量控制并发请求数，防止 Ollama 服务端过载。
    """
    # 添加性能监控回调
    callbacks = [_perf_callback]

    if LLM_PROVIDER == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            model=LLM_MODEL,
            api_key=GOOGLE_API_KEY,
            temperature=LLM_TEMPERATURE,
            timeout=LLM_TIMEOUT,
            callbacks=callbacks,
        )
    elif LLM_PROVIDER == "openai":
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model=LLM_MODEL,
            api_key=OPENAI_API_KEY,
            temperature=LLM_TEMPERATURE,
            timeout=LLM_TIMEOUT,
            callbacks=callbacks,
        )
    elif LLM_PROVIDER == "ollama":
        from langchain_ollama import ChatOllama
        llm = ChatOllama(
            model=LLM_MODEL,
            base_url=OLLAMA_BASE_URL,
            temperature=LLM_TEMPERATURE,
            timeout=LLM_TIMEOUT,
            format="json",  # 強制返回 JSON 格式，對於本地模型的 Pydantic structured output 至關重要
            callbacks=callbacks,
        )
    else:
        raise ValueError(f"不支持的 LLM_PROVIDER: {LLM_PROVIDER}")

    # 包装 LLM，添加限流控制
    return ThrottledLLMWrapper(llm)


def check_llm_health() -> bool:
    """
    检查 LLM 服务端健康状态

    Returns:
        True: 服务端正常
        False: 服务端过载或不可达
    """
    if LLM_PROVIDER != "ollama":
        return True  # 云端服务不做检查

    try:
        import requests
        # 检查 Ollama API 是否可达
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if resp.status_code == 200:
            return True
        else:
            print(f"[LLM健康检查] ⚠️ Ollama 返回异常状态码: {resp.status_code}")
            return False
    except Exception as e:
        print(f"[LLM健康检查] ❌ Ollama 不可达: {e}")
        return False


def get_llm_queue_status() -> Dict[str, Any]:
    """
    获取当前 LLM 请求队列状态

    Returns:
        包含当前并发数、等待数等信息的字典
    """
    return {
        "provider": LLM_PROVIDER,
        "max_concurrent": _LLM_SEMAPHORE._value,  # 剩余可用槽位
        "semaphore_value": _LLM_SEMAPHORE._value,
    }


def get_structured_llm(schema: Type[BaseModel]) -> Runnable:
    """
    返回已綁定結構化輸出 schema 的 LLM，自動根據 Provider 選擇最相容的 method：

    - ollama  : json_mode  — 本地模型不支援 tool call，依賴底層 format='json'
    - google  : function_calling — Gemini 原生支援，最穩定
    - openai  : function_calling — GPT 原生支援
    - 其他    : function_calling — 適用 Claude 等，避免 assistant prefill 400 錯誤

    所有模組應統一使用此函式取代 llm.with_structured_output(schema)，
    以確保在切換 Provider 時無需逐一修改各模組程式碼。
    """
    llm = get_llm()
    if LLM_PROVIDER == "ollama":
        # Ollama 本地模型使用 json_mode，配合底層 format="json" 設定
        return llm.with_structured_output(schema, method="json_mode")
    else:
        # Gemini / OpenAI / Claude / 其他雲端模型使用 function_calling
        # 特別針對 Claude：避免 LangChain 自動附加 assistant prefill（`{`），
        # Claude API 明確不支援對話以 assistant 訊息結尾的請求。
        return llm.with_structured_output(schema, method="function_calling")

