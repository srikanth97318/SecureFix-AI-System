"""Gemini API adapter. Provider errors never include credential or response text."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from securefix.config import DEFAULT_GEMINI_MODEL, DEFAULT_LLM_TIMEOUT_SECONDS
from securefix.sanitization import redact_sensitive_text


class LLMError(RuntimeError):
    """Base error for hosted LLM failures."""


class MissingAPIKeyError(LLMError):
    """Raised when the required Gemini API key is unavailable."""


class ProviderConfigurationError(LLMError):
    """Raised when the Gemini SDK or configuration is unavailable."""


class ProviderRequestError(LLMError):
    """Raised for Gemini failures with sanitized provider diagnostics."""

    category = "api_error"

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        diagnostic: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.diagnostic = diagnostic


class LLMTimeoutError(ProviderRequestError):
    """Raised when the Gemini request exceeds its configured timeout."""

    category = "timeout"


class LLMRateLimitError(ProviderRequestError):
    """Raised when Gemini rejects a request due to rate limiting."""

    category = "rate_limit"


class InvalidAPIKeyError(ProviderRequestError):
    category = "invalid_api_key"


class PermissionDeniedError(ProviderRequestError):
    category = "permission_denied"


class ModelNotFoundError(ProviderRequestError):
    category = "model_not_found"


class QuotaExceededError(ProviderRequestError):
    category = "quota_exceeded"


class NetworkConnectivityError(ProviderRequestError):
    category = "network_connectivity"


class ServiceUnavailableError(ProviderRequestError):
    category = "service_unavailable"


class MalformedLLMResponseError(LLMError):
    """Raised when Gemini returns no usable text."""


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None


class GeminiProvider:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: int = DEFAULT_LLM_TIMEOUT_SECONDS,
        client: Any | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        try:
            from dotenv import load_dotenv
        except ModuleNotFoundError:
            pass
        else:
            load_dotenv(override=False)

        resolved_key = api_key or os.getenv("GEMINI_API_KEY")
        if not resolved_key or not resolved_key.strip():
            raise MissingAPIKeyError(
                "GEMINI_API_KEY is required. Set it in the environment or in a local .env file."
            )
        resolved_key = resolved_key.strip()

        self._api_key = resolved_key
        self.model = model or os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
        self.timeout_seconds = timeout_seconds
        self._last_usage: TokenUsage | None = None
        if client is not None:
            self._client = client
            return

        try:
            from google import genai
            from google.genai import types
        except ModuleNotFoundError as exc:
            raise ProviderConfigurationError(
                "Gemini support is not installed. Install with "
                "`python -m pip install -e '.[llm]'`."
            ) from exc

        try:
            self._client = genai.Client(
                api_key=resolved_key,
                http_options=types.HttpOptions(timeout=timeout_seconds * 1000),
            )
        except Exception as exc:
            diagnostic = _sanitize_provider_diagnostic(str(exc), resolved_key)
            raise ProviderConfigurationError(
                "Unable to initialize the Gemini client; "
                f"sanitized diagnostic: {diagnostic}"
            ) from None

    def generate(self, prompt: str) -> str:
        """Return model text; callers must validate it before using it."""
        self._last_usage = None
        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "temperature": 0.1,
                },
            )
        except Exception as exc:
            raise _classify_provider_error(
                exc,
                self._api_key,
                self.timeout_seconds,
            ) from None

        response_text = getattr(response, "text", None)
        if not isinstance(response_text, str) or not response_text.strip():
            raise MalformedLLMResponseError("Gemini returned an empty or non-text response.")

        self._last_usage = _read_token_usage(getattr(response, "usage_metadata", None))
        sanitized = response_text.replace(self._api_key, "[REDACTED]")
        return redact_sensitive_text(sanitized)

    @property
    def last_usage(self) -> TokenUsage | None:
        return self._last_usage


def _read_token_usage(metadata: Any) -> TokenUsage | None:
    if metadata is None:
        return None

    def token_count(*names: str) -> int | None:
        for name in names:
            if isinstance(metadata, dict):
                value = metadata.get(name)
            else:
                value = getattr(metadata, name, None)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
        return None

    usage = TokenUsage(
        input_tokens=token_count("prompt_token_count", "input_tokens"),
        output_tokens=token_count("candidates_token_count", "output_tokens"),
        total_tokens=token_count("total_token_count", "total_tokens"),
    )
    if all(value is None for value in (usage.input_tokens, usage.output_tokens, usage.total_tokens)):
        return None
    return usage


def _classify_provider_error(
    error: Exception,
    api_key: str,
    timeout_seconds: int,
) -> ProviderRequestError:
    diagnostic = _sanitize_provider_diagnostic(str(error), api_key)
    error_name = type(error).__name__.lower()
    normalized = diagnostic.lower()
    status_code = _http_status_code(error)

    if (
        isinstance(error, TimeoutError)
        or "timeout" in error_name
        or status_code in {408, 504}
        or "deadline_exceeded" in normalized
    ):
        error_type: type[ProviderRequestError] = LLMTimeoutError
        message = f"Gemini request timed out after {timeout_seconds} seconds."
    elif (
        any(
            marker in error_name
            for marker in ("connecterror", "connectionerror", "networkerror", "gaierror")
        )
        or any(
            marker in normalized
            for marker in (
                "network is unreachable",
                "name or service not known",
                "temporary failure in name resolution",
                "failed to establish a new connection",
                "connection refused",
                "connection reset",
            )
        )
    ):
        error_type = NetworkConnectivityError
        message = "Gemini request could not connect to the API."
    elif (
        status_code == 401
        or "unauthenticated" in normalized
        or any(
            marker in normalized
            for marker in (
                "invalid api key",
                "api key not valid",
                "api key is invalid",
                "api_key_invalid",
            )
        )
    ):
        error_type = InvalidAPIKeyError
        message = "Gemini rejected the API key."
    elif status_code in {403, 429} and any(
        marker in normalized for marker in ("quota", "billing", "daily limit")
    ):
        error_type = QuotaExceededError
        message = "Gemini quota is exhausted."
    elif status_code == 403 or "permission_denied" in normalized:
        error_type = PermissionDeniedError
        message = "Gemini denied permission for this request."
    elif (
        (status_code == 404 and "model" in normalized)
        or "model_not_found" in normalized
    ):
        error_type = ModelNotFoundError
        message = "The configured Gemini model was not found or is unavailable."
    elif status_code == 503 or "unavailable" in normalized:
        error_type = ServiceUnavailableError
        message = "The Gemini service is temporarily unavailable."
    elif status_code == 429 or "ratelimit" in error_name or "rate limit" in normalized:
        error_type = LLMRateLimitError
        message = "Gemini rate limit reached. Wait before making another request."
    else:
        error_type = ProviderRequestError
        message = "Gemini request failed."

    details = error_type.category
    if status_code is not None:
        details += f" (HTTP {status_code})"
    if diagnostic:
        details += f": {diagnostic}"
    return error_type(
        f"{message} Sanitized diagnostic: {details}",
        status_code=status_code,
        diagnostic=details,
    )


def _http_status_code(error: Exception) -> int | None:
    for candidate in (getattr(error, "status_code", None), getattr(error, "code", None)):
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            return candidate
    return None


def _sanitize_provider_diagnostic(value: str, api_key: str) -> str:
    sanitized = value.replace(api_key, "[REDACTED]") if api_key else value
    sanitized = re.sub(
        r"(?i)([?&](?:key|api[_-]?key|x-goog-api-key|access_token)=)[^&\s]+",
        r"\1[REDACTED]",
        sanitized,
    )
    return redact_sensitive_text(sanitized)[:2000]
