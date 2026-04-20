"""Declarative pricing table for well-known cloud models.

Scope of what this is:

  - A rough per-call cost estimator so operators know whether a long
    engagement cost them $0.40 or $40 without logging in to every
    provider dashboard.
  - NOT a billing system. Prices change; some providers charge per
    request or per cached token; discounts, free tiers, and regional
    pricing are all ignored. The number here is a floor estimate,
    useful for relative comparison and sanity checks.

Resolution strategy:

  - Exact model id match first (``claude-opus-4-5-20251001``).
  - Then family prefix (``claude-opus-4-5``, ``gpt-4o``, ``gemini-2.0-flash``).
  - Local / unpriced models return ``None`` — the caller should treat
    that as "no cost recorded" rather than zero.

Prices are USD per 1 million tokens, (input, output).
"""
from __future__ import annotations

# Keep entries sorted by provider family, newest first within each family.
# Format: model-id-or-family-prefix -> (input_per_mtok, output_per_mtok)
_PRICING_TABLE: dict[str, tuple[float, float]] = {
    # --- Anthropic --- (https://www.anthropic.com/pricing)
    "claude-opus-4-7": (15.0, 75.0),
    "claude-opus-4-6": (15.0, 75.0),
    "claude-opus-4-5": (15.0, 75.0),
    "claude-opus-4": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-sonnet-4": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-haiku-4": (1.0, 5.0),
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-5-haiku": (0.80, 4.0),
    "claude-3-opus": (15.0, 75.0),
    # --- OpenAI ---
    "gpt-5.4": (2.5, 10.0),
    "gpt-5": (2.5, 10.0),
    "gpt-4.1": (2.0, 8.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.5, 10.0),
    "o4-mini": (1.10, 4.40),
    "o3-mini": (1.10, 4.40),
    "o3": (2.0, 8.0),
    # --- Google Gemini ---
    "gemini-2.5-pro": (1.25, 5.0),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-1.5-pro": (1.25, 5.0),
    "gemini-1.5-flash": (0.075, 0.30),
    # --- Groq ---
    "llama-3.3-70b": (0.59, 0.79),
    "llama-3.1-70b": (0.59, 0.79),
    "llama-3.1-8b": (0.05, 0.08),
    "mixtral-8x7b": (0.24, 0.24),
    # --- DeepSeek ---
    "deepseek-chat": (0.27, 1.10),
    "deepseek-reasoner": (0.55, 2.19),
    # --- xAI ---
    "grok-4": (5.0, 15.0),
    "grok-3": (3.0, 15.0),
    "grok-2": (2.0, 10.0),
    # --- Mistral ---
    "mistral-large": (2.0, 6.0),
    "mistral-small": (0.20, 0.60),
    # --- OpenRouter --- (pass-through; actual cost depends on route)
    # Omitted — OpenRouter invoices per model, and the header already
    # contains attribution to the downstream provider.
}


def _normalize(model: str) -> str:
    return (model or "").strip().lower()


def lookup_price(model: str) -> tuple[float, float] | None:
    """Return (input_per_mtok, output_per_mtok) or None if unpriced."""
    key = _normalize(model)
    if not key:
        return None
    if key in _PRICING_TABLE:
        return _PRICING_TABLE[key]
    # Longest-prefix match — avoids e.g. claude-haiku-4 winning over
    # claude-haiku-4-5 when both are listed.
    candidates = sorted(
        (prefix for prefix in _PRICING_TABLE if key.startswith(prefix)),
        key=len,
        reverse=True,
    )
    if candidates:
        return _PRICING_TABLE[candidates[0]]
    return None


def estimate_cost_usd(
    model: str, input_tokens: int, output_tokens: int
) -> float | None:
    """Rough USD cost for a single call. None for unpriced/local models."""
    price = lookup_price(model)
    if price is None:
        return None
    in_rate, out_rate = price
    return (input_tokens / 1_000_000.0) * in_rate + (output_tokens / 1_000_000.0) * out_rate


__all__ = ["estimate_cost_usd", "lookup_price"]
