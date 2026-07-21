"""
核心：LLM 工厂

统一管理 LangChain LLM 实例的创建，支持多 Provider 切换（Google / OpenAI / Ollama）。
"""
from typing import Type
from pydantic import BaseModel
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables import Runnable
from web_audit.config.settings import (
    LLM_PROVIDER,
    LLM_MODEL,
    LLM_TEMPERATURE,
    GOOGLE_API_KEY,
    OPENAI_API_KEY,
    OLLAMA_BASE_URL,
)


def get_llm() -> BaseChatModel:
    """
    根据配置返回对应的 LangChain Chat LLM 实例。
    支持：google (Gemini) | openai (GPT) | ollama (本地模型)
    """
    if LLM_PROVIDER == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=LLM_MODEL,
            api_key=GOOGLE_API_KEY,
            temperature=LLM_TEMPERATURE,
        )
    elif LLM_PROVIDER == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=LLM_MODEL,
            api_key=OPENAI_API_KEY,
            temperature=LLM_TEMPERATURE,
        )
    elif LLM_PROVIDER == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=LLM_MODEL,
            base_url=OLLAMA_BASE_URL,
            temperature=LLM_TEMPERATURE,
            format="json",  # 強制返回 JSON 格式，對於本地模型的 Pydantic structured output 至關重要
        )
    else:
        raise ValueError(f"不支持的 LLM_PROVIDER: {LLM_PROVIDER}")


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

