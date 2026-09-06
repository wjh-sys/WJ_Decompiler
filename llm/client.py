from __future__ import annotations

import time
from typing import Any, cast
from .config import LLMConfig

class LLMError(RuntimeError):
    pass

class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config
        try:
            import openai
        except ImportError:
            raise LLMError("未安装 openai SDK，请先执行: pip install openai")
        self._client = openai.OpenAI(
            base_url=config.base_url,
            api_key=config.api_key,
            timeout=config.timeout,
        )

    def chat(self, messages: list[dict[str, Any]]) -> str:
        last_err = None
        for attempt in range(self.config.max_retries + 1):
            try:
                resp = self._client.chat.completions.create(
                    model=self.config.model,
                    messages=cast(Any, messages),
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    response_format={"type": "json_object"},
                )
                content = (resp.choices[0].message.content or "").strip()
                if not content:
                    raise LLMError("模型返回空内容")
                return content
            except LLMError:
                raise
            except Exception as e:
                last_err = e
                if attempt < self.config.max_retries:
                    time.sleep(1.5 * (attempt + 1))
        raise LLMError(f"LLM 调用失败(已重试 {self.config.max_retries} 次): {last_err}")
