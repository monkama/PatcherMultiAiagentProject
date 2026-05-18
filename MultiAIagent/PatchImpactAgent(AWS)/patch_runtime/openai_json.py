from __future__ import annotations

import os
import time
from typing import Any


DEFAULT_OPENAI_MODEL = (
    os.environ.get("PATCH_IMPACT_OPENAI_MODEL")
    or os.environ.get("OPENAI_MODEL")
    or os.environ.get("OPENAI_MODEL_ID")
    or "gpt-4.1"
)
DEFAULT_OPENAI_BASE_URL = str(os.environ.get("OPENAI_BASE_URL") or "").strip()

_OPENAI_CLIENT: Any | None = None


def _openai_client() -> Any:
    global _OPENAI_CLIENT
    if _OPENAI_CLIENT is None:
        import openai

        api_key = str(os.environ.get("OPENAI_API_KEY") or "").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY 환경변수가 필요합니다.")

        client_args: dict[str, Any] = {"api_key": api_key}
        if DEFAULT_OPENAI_BASE_URL:
            client_args["base_url"] = DEFAULT_OPENAI_BASE_URL
        _OPENAI_CLIENT = openai.OpenAI(**client_args)
    return _OPENAI_CLIENT


def call_openai_text(
    *,
    instructions: str,
    prompt: str,
    model_name: str | None = None,
    max_retries: int = 3,
    retry_delay: int = 5,
) -> str:
    resolved_model = str(model_name or "").strip() or DEFAULT_OPENAI_MODEL
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        try:
            response = _openai_client().chat.completions.create(
                model=resolved_model,
                messages=[
                    {"role": "system", "content": instructions},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
            )
            output_text = str(response.choices[0].message.content or "").strip()
            if not output_text:
                raise RuntimeError("OpenAI 응답 텍스트가 비어 있습니다.")
            return output_text
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            message = str(exc)
            transient = any(
                token in message
                for token in ("429", "500", "502", "503", "timeout", "Timeout", "rate limit")
            )
            if transient and attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            raise

    raise RuntimeError(f"{resolved_model} 호출 실패: {last_exc}")
