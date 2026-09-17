from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"

class LLMConfigError(RuntimeError):
    pass

@dataclass
class LLMConfig:
    base_url: str = DEFAULT_BASE_URL
    api_key: str = ""
    model: str = DEFAULT_MODEL
    temperature: float = 0.1
    max_tokens: int = 4000
    timeout: float = 60.0
    max_retries: int = 1

def load_config() -> LLMConfig:
    key = os.environ.get("LLM_API_KEY", "").strip() #   填充API密钥
    if not key:
        raise LLMConfigError(
            "未找到 LLM_API_KEY 环境变量。\n"
            "请先配置环境变量再运行，例如:\n"
            "  Windows CMD:\n"
            "    set LLM_API_KEY=sk-xxxx\n"
            "    set LLM_BASE_URL=https://api.deepseek.com\n"
            "    set LLM_MODEL=deepseek-chat\n"
            "  Linux / WSL (bash):\n"
            "    export LLM_API_KEY=sk-xxxx\n"
            "    export LLM_BASE_URL=https://api.deepseek.com\n"
            "    export LLM_MODEL=deepseek-chat\n"
            "  注意: 在 WSL 中 set 无效, 必须用 export; 可用 echo ${LLM_API_KEY:0:6} 验证"
        )
    return LLMConfig(
        base_url=os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL).strip(),
        api_key=key,
        model=os.environ.get("LLM_MODEL", DEFAULT_MODEL).strip(),
        temperature=float(os.environ.get("LLM_TEMPERATURE", "0.1")),
        max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "4000")),
        timeout=float(os.environ.get("LLM_TIMEOUT", "60")),
        max_retries=int(os.environ.get("LLM_MAX_RETRIES", "1")),
    )
