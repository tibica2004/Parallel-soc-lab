from __future__ import annotations
import os, re, json
from langchain_openai import ChatOpenAI

OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434/v1")

ROLES = {
    "fast":      {"temperature": 0.0, "max_tokens": 2000},
    "hunt":      {"temperature": 0.1, "max_tokens": 4000},
    "hunt_b":    {"temperature": 0.7, "max_tokens": 4000},
    "critic":    {"temperature": 0.3, "max_tokens": 2000},
    "correlate": {"temperature": 0.2, "max_tokens": 4000},
}

NO_THINK = "\n\n/no_think"
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def get_llm(role: str, json_schema: dict | None = None) -> ChatOpenAI:
    cfg = ROLES[role]
    return ChatOpenAI(
        model=os.environ.get(f"MODEL_{role.upper()}", "qwen3:14b"),
        base_url=os.environ.get(f"LLM_BASE_URL_{role.upper()}") or os.environ.get("LLM_BASE_URL", OLLAMA),
        api_key="local", temperature=cfg["temperature"],
        max_tokens=cfg["max_tokens"], timeout=300,
    )


def strip_thinking(text: str) -> str:
    return _THINK_RE.sub("", text).strip()


def parse_json_response(content: str) -> dict:
    cleaned = strip_thinking(content)
    cleaned = cleaned.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    m = _JSON_RE.search(cleaned)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"neparsabil: {cleaned[:300]}")
