"""Google Vertex AI adapter.

Vertex AI is Google's enterprise Gemini endpoint — same ``generateContent``
wire protocol as the consumer Gemini API, but:

  - Auth: OAuth2 Bearer token (service-account ADC via ``google-auth``) rather
    than a static ``?key=`` query param.
  - Endpoint: regional — ``https://{location}-aiplatform.googleapis.com/v1/
    projects/{project}/locations/{location}/publishers/google/models/{model}
    :generateContent``
  - No ``?key=`` query param at all; everything goes through the Authorization
    header.

Because the ``generateContent`` request/response schema is identical to the
consumer Gemini API we reuse the message-translation and tool-formatting helpers
from ``koda.adapters.gemini`` directly — no copy-paste.

Auth resolution order
---------------------
1. ``google-auth`` Application Default Credentials (ADC) via
   ``google.auth.default()``.  ADC picks up in order: ``GOOGLE_APPLICATION_
   CREDENTIALS`` env var → gcloud SDK credentials → GCE/Cloud Run metadata.
   ``google-auth`` is an *optional* dependency — imported lazily; a clear error
   is raised at chat-time if it is absent **and** no explicit token was
   supplied.
2. Explicit ``access_token`` in the config dict — useful for short-lived tokens
   generated outside Python (e.g. ``$(gcloud auth print-access-token)``).
3. If neither is available, the adapter returns an error response immediately
   rather than making a network call that will 401.

Default model
-------------
``gemini-1.5-pro-002`` — the stable GA version as of late 2024/early 2025.
Newer models (2.0 flash, 2.5 flash/pro) exist but their Vertex regional
availability varies by project tier.  Operators should override once confirmed.

Streaming
---------
Not implemented — Vertex's streaming endpoint uses a different path suffix
(``:streamGenerateContent``) and a chunked JSON envelope.  Returning a clear
error keeps the contract honest rather than silently ignoring the request.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from .base import Message, Provider, ProviderResponse, ToolCall, ToolChoice, ToolSpec

# We reuse the generateContent message/tool transforms from the consumer Gemini
# adapter verbatim — same wire shape, so no copy-paste needed.
from .gemini import (
    _format_tools as _gemini_format_tools,
)
from .gemini import (
    _synth_call_id,
)
from .gemini import (
    _tool_config as _gemini_tool_config,
)
from .gemini import (
    _translate_messages as _gemini_translate_messages,
)

_DEFAULT_LOCATION = "us-central1"
# gemini-1.5-pro-002: stable GA with broad regional availability on Vertex AI.
# Newer models (gemini-2.0-flash, gemini-2.5-*) are available but rollout
# is gated by project allowlist — override via config["model"] once confirmed.
_DEFAULT_MODEL = "gemini-1.5-pro-002"

# OAuth2 scope required for Vertex AI API calls.
_VERTEX_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def _build_endpoint(project: str, location: str, model: str) -> str:
    """Construct the non-streaming generateContent URL for Vertex AI."""
    base = f"https://{location}-aiplatform.googleapis.com"
    return (
        f"{base}/v1/projects/{project}/locations/{location}"
        f"/publishers/google/models/{model}:generateContent"
    )


def _try_adc_token() -> str | tuple[str, str]:
    """Attempt Application Default Credentials token retrieval.

    Returns the bearer token string on success.
    Raises ImportError if google-auth is not installed.
    Raises google.auth.exceptions.DefaultCredentialsError if ADC is not set up.
    Other google.auth exceptions bubble up as-is.
    """
    try:
        import google.auth  # type: ignore[import-not-found]
        import google.auth.transport.requests  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "google-auth is not installed. Install it with:\n"
            "  pip install google-auth\n"
            "or provide an explicit access_token in the provider config."
        ) from exc

    credentials, _ = google.auth.default(scopes=[_VERTEX_SCOPE])
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    return credentials.token


class VertexAIProvider(Provider):
    """Google Vertex AI — enterprise Gemini via regional aiplatform.googleapis.com."""

    supports_tools: bool = True

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._project: str = config.get("project") or ""
        self._location: str = config.get("location") or _DEFAULT_LOCATION
        self._model: str = config.get("model") or _DEFAULT_MODEL
        # Explicit static token (e.g. from gcloud auth print-access-token).
        # Takes precedence only when google-auth ADC is unavailable or fails.
        self._access_token: str = config.get("access_token") or ""
        self._timeout: float = float(config.get("timeout", 120.0))

    def get_model(self) -> str:
        return self._model

    def _get_bearer_token(self) -> str:
        """Resolve a bearer token using ADC first, explicit token as fallback.

        Raises a RuntimeError with a user-facing message if neither source
        can produce a token.
        """
        # Try ADC first — it handles token refresh automatically.
        try:
            return _try_adc_token()
        except ImportError as exc:
            # google-auth not installed; fall through to explicit token.
            if not self._access_token:
                raise RuntimeError(
                    "Vertex AI auth: google-auth is not installed and no "
                    "access_token was provided in the config.\n"
                    "Options:\n"
                    "  1. pip install google-auth  (uses Application Default Credentials)\n"
                    "  2. Set access_token in provider config (short-lived — must refresh manually)"
                ) from exc
            return self._access_token
        except Exception:  # noqa: BLE001
            # ADC available but credentials not set up — try explicit token.
            if self._access_token:
                return self._access_token
            raise

    async def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        tool_choice: ToolChoice = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        # --- pre-flight validation ---
        if not self._project:
            return ProviderResponse(
                text=(
                    "Vertex AI: no GCP project configured. "
                    "Set project in the provider config."
                ),
                stop_reason="error",
            )

        # --- auth ---
        try:
            token = self._get_bearer_token()
        except RuntimeError as exc:
            return ProviderResponse(text=str(exc), stop_reason="error")
        except Exception as exc:  # noqa: BLE001
            return ProviderResponse(
                text=f"Vertex AI auth error: {exc}",
                stop_reason="error",
            )

        # --- build payload (reuses Gemini wire shape) ---
        contents, system_text = _gemini_translate_messages(messages)
        payload: dict[str, Any] = {"contents": contents}
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}
        if tools:
            formatted = _gemini_format_tools(tools)
            if formatted:
                payload["tools"] = formatted
        tc = _gemini_tool_config(tool_choice)
        if tc is not None:
            payload["toolConfig"] = tc

        gen_cfg: dict[str, Any] = {}
        for k in ("temperature", "topP", "topK", "maxOutputTokens"):
            src_key = {"topP": "top_p", "topK": "top_k", "maxOutputTokens": "max_tokens"}.get(k, k)
            if src_key in self.config:
                gen_cfg[k] = self.config[src_key]
        if gen_cfg:
            payload["generationConfig"] = gen_cfg

        url = _build_endpoint(self._project, self._location, self._model)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

        # --- HTTP ---
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    url,
                    content=json.dumps(payload),
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            return ProviderResponse(
                text=f"vertex_ai transport error: {exc}",
                stop_reason="error",
            )

        # --- error handling ---
        if resp.status_code in (401, 403):
            excerpt = resp.text[:300].replace("\n", " ")
            action = (
                "token expired or wrong scope — run `gcloud auth application-default login` or refresh token"
                if resp.status_code == 401
                else "access denied — check IAM permissions for the GCP project"
            )
            return ProviderResponse(
                text=f"vertex_ai HTTP {resp.status_code} ({action}): {excerpt}",
                stop_reason="error",
            )

        if resp.status_code == 404:
            excerpt = resp.text[:300].replace("\n", " ")
            return ProviderResponse(
                text=(
                    f"vertex_ai HTTP 404: model '{self._model}' not found in project "
                    f"'{self._project}' / location '{self._location}'. "
                    f"Check model name and regional availability. Detail: {excerpt}"
                ),
                stop_reason="error",
            )

        if resp.status_code >= 500:
            excerpt = resp.text[:300].replace("\n", " ")
            return ProviderResponse(
                text=f"vertex_ai HTTP {resp.status_code} (server error): {excerpt}",
                stop_reason="error",
            )

        if resp.status_code >= 400:
            excerpt = resp.text[:300].replace("\n", " ")
            return ProviderResponse(
                text=f"vertex_ai HTTP {resp.status_code}: {excerpt}",
                stop_reason="error",
            )

        # --- parse response (identical shape to Gemini API) ---
        try:
            data = resp.json()
        except ValueError:
            return ProviderResponse(
                text="vertex_ai returned non-JSON response.",
                stop_reason="error",
            )

        candidates = data.get("candidates") or []
        if not candidates:
            block = data.get("promptFeedback", {}).get("blockReason", "")
            return ProviderResponse(
                text=f"vertex_ai returned no candidates (block: {block or 'unknown'}).",
                stop_reason="error" if block else "end_turn",
                raw=data,
            )

        cand = candidates[0]
        parts = (cand.get("content") or {}).get("parts") or []
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in parts:
            if "text" in part and part["text"]:
                text_parts.append(part["text"])
            fn_call = part.get("functionCall")
            if isinstance(fn_call, dict):
                name = fn_call.get("name") or ""
                args = fn_call.get("args") or {}
                if not isinstance(args, dict):
                    args = {}
                tool_calls.append(
                    ToolCall(id=_synth_call_id(name, args), name=name, arguments=args)
                )

        usage_raw = data.get("usageMetadata") or {}
        usage = {
            "prompt_tokens": usage_raw.get("promptTokenCount", 0),
            "completion_tokens": usage_raw.get("candidatesTokenCount", 0),
            "total_tokens": usage_raw.get("totalTokenCount", 0),
        }
        return ProviderResponse(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=cand.get("finishReason") or "",
            usage=usage,
            raw=data,
        )


__all__ = ["VertexAIProvider"]
