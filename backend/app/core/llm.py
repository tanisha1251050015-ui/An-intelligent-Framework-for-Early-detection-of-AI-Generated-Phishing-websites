"""Secure LLM integration layer for Phase 2D."""

import os
import json
import logging
import math
from abc import ABC, abstractmethod

from app.core.prompts import SYSTEM_PROMPT, DATA_TEMPLATE

logger = logging.getLogger(__name__)

MAX_LLM_INPUT_CHARS = 10000

MAX_RISK_HINTS = 20
MAX_HINT_TYPE_CHARS = 100
MAX_HINT_EVIDENCE_CHARS = 1000
MAX_SUMMARY_CHARS = 2000
MAX_MODEL_CHARS = 100

class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        """Run analysis and return structured dict."""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI API wrapper."""
    
    def __init__(self):
        try:
            import openai
        except ImportError:
            self._client = None
            return

        api_key = os.environ.get("OPENAI_API_KEY")
        api_base = os.environ.get("OPENAI_API_BASE")
        self.model = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
        
        if not api_key:
            self._client = None
            return
            
        self._client = openai.OpenAI(
            api_key=api_key,
            base_url=api_base,
            timeout=30.0,
            max_retries=0
        )
        
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        if self._client is None:
            return {"status": "unavailable", "reason": "llm_not_configured"}
            
        try:
            import openai
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            
            raw_content = response.choices[0].message.content
            return json.loads(raw_content)
            
        except openai.APITimeoutError:
            return {"status": "unavailable", "reason": "timeout"}
        except openai.APIConnectionError:
            return {"status": "unavailable", "reason": "connection_error"}
        except openai.RateLimitError:
            return {"status": "unavailable", "reason": "rate_limit"}
        except openai.OpenAIError as e:
            return {"status": "unavailable", "reason": "provider_error"}
        except json.JSONDecodeError:
            return {"status": "unavailable", "reason": "malformed_json"}
        except Exception as e:
            return {"status": "unavailable", "reason": "unknown_error"}


def _validate_schema(data: dict) -> dict:
    """Validate LLM output schema."""
    if not isinstance(data, dict):
        return {"status": "unavailable", "reason": "invalid_schema"}
        
    if "risk_hints" not in data or not isinstance(data["risk_hints"], list):
        return {"status": "unavailable", "reason": "invalid_schema"}
        
    valid_hints = []
    for hint in data.get("risk_hints", []):
        if len(valid_hints) >= MAX_RISK_HINTS:
            break
            
        if not isinstance(hint, dict):
            continue
            
        conf = hint.get("confidence")
        if not isinstance(conf, (int, float)) or isinstance(conf, bool):
            continue
        if not math.isfinite(conf):
            continue
        if conf < 0.0 or conf > 1.0:
            continue
            
        type_str = str(hint.get("type", "unknown"))[:MAX_HINT_TYPE_CHARS]
        evidence_str = str(hint.get("evidence", ""))[:MAX_HINT_EVIDENCE_CHARS]
        
        valid_hints.append({
            "type": type_str,
            "confidence": float(conf),
            "evidence": evidence_str
        })
        
    summary_str = str(data.get("summary", ""))[:MAX_SUMMARY_CHARS]
    model_str = str(data.get("model", "advisory-llm"))[:MAX_MODEL_CHARS]
        
    return {
        "status": "completed",
        "risk_hints": valid_hints,
        "summary": summary_str,
        "model": model_str
    }


def _encode_xml(text: str) -> str:
    """Encode XML/HTML characters to prevent delimiter injection."""
    return text.replace("<", "&lt;").replace(">", "&gt;")


def analyze_webpage(url: str, html_stats: dict | None, ocr_data: dict | None) -> dict:
    """Analyze webpage content using LLM."""
    
    html_text = ""
    if html_stats and isinstance(html_stats.get("text"), str):
        html_text = html_stats["text"]
        
    ocr_text = ""
    if ocr_data and isinstance(ocr_data.get("text"), str):
        ocr_text = ocr_data["text"]
        
    # Truncate
    if len(html_text) > (MAX_LLM_INPUT_CHARS // 2):
        html_text = html_text[:(MAX_LLM_INPUT_CHARS // 2)] + "...[TRUNCATED]"
        
    if len(ocr_text) > (MAX_LLM_INPUT_CHARS // 2):
        ocr_text = ocr_text[:(MAX_LLM_INPUT_CHARS // 2)] + "...[TRUNCATED]"
        
    safe_url = _encode_xml(url)
    safe_html_text = _encode_xml(html_text)
    safe_ocr_text = _encode_xml(ocr_text)
        
    user_prompt = DATA_TEMPLATE.format(
        url=safe_url,
        html_text=safe_html_text,
        ocr_text=safe_ocr_text
    )
    
    provider = OpenAIProvider()
    result = provider.analyze(SYSTEM_PROMPT, user_prompt)
    
    if result.get("status") == "unavailable":
        return result
        
    return _validate_schema(result)
