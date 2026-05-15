"""
AEGIS SOC — LLM Helper
Singleton Groq client + broadcast helpers for agents.
Every agent uses call_llm() for structured LLM interactions.
"""

import json
from groq import AsyncGroq
from backend.config import settings
from backend.websocket.manager import manager
from backend.database import log_agent_action

# ── Singleton Groq Client ──
_client = None


def get_client() -> AsyncGroq:
    """Get or create the singleton Groq client."""
    global _client
    if _client is None:
        _client = AsyncGroq(api_key=settings.groq_api_key)
    return _client


async def call_llm(
    prompt: str,
    system_instruction: str = "",
    temperature: float | None = None,
    response_mime_type: str = "application/json",
) -> str:
    """
    Call Groq and return the response text.
    Defaults to JSON output for structured responses.
    Set response_mime_type to "text/plain" for free-form text.
    """
    client = get_client()
    
    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    
    messages.append({"role": "user", "content": prompt})

    kwargs = {
        "model": settings.groq_model,
        "messages": messages,
        "temperature": temperature or settings.llm_temperature,
    }

    if response_mime_type == "application/json":
        kwargs["response_format"] = {"type": "json_object"}

    response = await client.chat.completions.create(**kwargs)
    return response.choices[0].message.content


async def call_llm_json(
    prompt: str,
    system_instruction: str = "",
    temperature: float | None = None,
) -> dict | list:
    """Call Gemini and parse the JSON response."""
    text = await call_llm(
        prompt=prompt,
        system_instruction=system_instruction,
        temperature=temperature,
        response_mime_type="application/json",
    )
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to extract JSON from markdown code blocks
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
            return json.loads(text)
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
            return json.loads(text)
        raise


async def call_llm_text(
    prompt: str,
    system_instruction: str = "",
    temperature: float | None = None,
) -> str:
    """Call Gemini and return plain text response."""
    return await call_llm(
        prompt=prompt,
        system_instruction=system_instruction,
        temperature=temperature,
        response_mime_type="text/plain",
    )


# ──────────────────────────────────────────────
# Agent Broadcast Helpers
# ──────────────────────────────────────────────

async def broadcast_agent(incident_id: str, agent_name: str, message: str,
                          data: dict | None = None):
    """Broadcast an agent update to dashboard AND log to database."""
    await manager.send_agent_update(incident_id, agent_name, message, data)
    await log_agent_action(incident_id, agent_name, message, data)


async def broadcast_status(incident_id: str, new_status: str):
    """Broadcast a status change to dashboard."""
    await manager.send_status_change(incident_id, new_status)


# ──────────────────────────────────────────────
# Prompt Sanitization (anti-injection)
# ──────────────────────────────────────────────

def sanitize_for_prompt(text: str) -> str:
    """
    Strip potential prompt injection patterns from external data
    before including it in an LLM prompt.
    """
    if not text:
        return ""
    # Remove common injection patterns
    dangerous_patterns = [
        "ignore previous instructions",
        "ignore all instructions",
        "disregard",
        "you are now",
        "new instructions:",
        "system prompt:",
        "ADMIN OVERRIDE",
        "<|im_start|>",
        "<|im_end|>",
        "```system",
    ]
    sanitized = text
    for pattern in dangerous_patterns:
        sanitized = sanitized.replace(pattern, "[REDACTED]")
        sanitized = sanitized.replace(pattern.upper(), "[REDACTED]")
    return sanitized
