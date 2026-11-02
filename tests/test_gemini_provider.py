from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from securefix.llm.gemini_provider import (
    GeminiProvider,
    InvalidAPIKeyError,
    LLMRateLimitError,
    LLMTimeoutError,
    MalformedLLMResponseError,
    ModelNotFoundError,
    MissingAPIKeyError,
    NetworkConnectivityError,
    PermissionDeniedError,
    ProviderRequestError,
    QuotaExceededError,
    ServiceUnavailableError,
)
from securefix.llm import connectivity


def test_provider_requires_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda **_kwargs: False)

    with pytest.raises(MissingAPIKeyError, match="GEMINI_API_KEY"):
        GeminiProvider(client=Mock())


def test_provider_uses_configured_model_and_json_response() -> None:
    generate_content = Mock(return_value=SimpleNamespace(text='{"ok": true}'))
    provider = GeminiProvider(
        api_key="test-key",
        model="gemini-test",
        client=SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)),
    )

    assert provider.generate("prompt") == '{"ok": true}'
    assert generate_content.call_args.kwargs["model"] == "gemini-test"
    assert generate_content.call_args.kwargs["config"]["response_mime_type"] == "application/json"


def test_provider_uses_model_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

    provider = GeminiProvider(api_key="test-key", client=Mock())

    assert provider.model == "gemini-3.5-flash-lite"


def test_provider_defaults_to_gemini_35_flash_lite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda **_kwargs: False)

    provider = GeminiProvider(api_key="test-key", client=Mock())

    assert provider.model == "gemini-3.5-flash-lite"


def test_provider_redacts_api_key_from_model_output() -> None:
    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(
            models=SimpleNamespace(
                generate_content=Mock(
                    return_value=SimpleNamespace(text='{"message":"test-key"}')
                )
            )
        ),
    )

    assert "test-key" not in provider.generate("prompt")


def test_provider_maps_timeout_without_leaking_provider_error() -> None:
    generate_content = Mock(side_effect=TimeoutError("test-key timeout"))
    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)),
    )

    with pytest.raises(LLMTimeoutError) as error:
        provider.generate("prompt")

    assert "test-key" not in str(error.value)


def test_provider_maps_rate_limit_without_leaking_provider_error() -> None:
    error = RuntimeError("test-key rate limit exceeded")
    error.status_code = 429
    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(
            models=SimpleNamespace(generate_content=Mock(side_effect=error))
        ),
    )

    with pytest.raises(LLMRateLimitError) as caught:
        provider.generate("prompt")

    assert "test-key" not in str(caught.value)


def test_provider_wraps_other_api_errors_without_raw_text() -> None:
    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(
            models=SimpleNamespace(
                generate_content=Mock(side_effect=RuntimeError("test-key request URL"))
            )
        ),
    )

    with pytest.raises(ProviderRequestError) as error:
        provider.generate("prompt")

    assert "test-key" not in str(error.value)
    assert "request URL" in str(error.value)
    assert error.value.diagnostic is not None
    assert error.value.category == "api_error"


@pytest.mark.parametrize(
    ("exception", "expected_type", "category", "status_code"),
    [
        (RuntimeError("API key not valid"), InvalidAPIKeyError, "invalid_api_key", 400),
        (RuntimeError("PERMISSION_DENIED"), PermissionDeniedError, "permission_denied", 403),
        (RuntimeError("models/gemini-test not found"), ModelNotFoundError, "model_not_found", 404),
        (RuntimeError("quota exceeded"), QuotaExceededError, "quota_exceeded", 429),
        (RuntimeError("billing quota exhausted"), QuotaExceededError, "quota_exceeded", 403),
        (RuntimeError("rate limit exceeded"), LLMRateLimitError, "rate_limit", 429),
        (RuntimeError("UNAVAILABLE high demand"), ServiceUnavailableError, "service_unavailable", 503),
        (RuntimeError("DEADLINE_EXCEEDED"), LLMTimeoutError, "timeout", 504),
        (ConnectionError("connection refused"), NetworkConnectivityError, "network_connectivity", None),
    ],
)
def test_provider_classifies_and_preserves_sanitized_api_diagnostics(
    exception: Exception,
    expected_type: type[ProviderRequestError],
    category: str,
    status_code: int | None,
) -> None:
    if status_code is not None:
        exception.code = status_code
    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(
            models=SimpleNamespace(generate_content=Mock(side_effect=exception))
        ),
    )

    with pytest.raises(expected_type) as caught:
        provider.generate("prompt")

    assert caught.value.category == category
    assert caught.value.status_code == status_code
    assert caught.value.diagnostic
    assert str(exception) in caught.value.diagnostic


def test_provider_redacts_api_key_from_error_diagnostic() -> None:
    exception = RuntimeError(
        "request to https://example.invalid/?key=test-key failed; "
        "API key=test-key"
    )
    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(
            models=SimpleNamespace(generate_content=Mock(side_effect=exception))
        ),
    )

    with pytest.raises(ProviderRequestError) as caught:
        provider.generate("prompt")

    assert "test-key" not in str(caught.value)
    assert "key=[REDACTED]" in str(caught.value)


def test_provider_rejects_empty_response() -> None:
    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(
            models=SimpleNamespace(generate_content=Mock(return_value=SimpleNamespace(text=None)))
        ),
    )

    with pytest.raises(MalformedLLMResponseError, match="empty or non-text"):
        provider.generate("prompt")


def test_connectivity_command_makes_a_small_generation_request(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = Mock()
    provider.model = "gemini-test"
    monkeypatch.setattr(connectivity, "GeminiProvider", Mock(return_value=provider))

    assert connectivity.main() == 0

    provider.generate.assert_called_once_with(
        'Reply with exactly this JSON object: {"status":"ok"}'
    )
    assert "Gemini text generation succeeded with model gemini-test." in capsys.readouterr().out


def test_connectivity_command_displays_sanitized_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = Mock()
    provider.model = "gemini-test"
    provider.generate.side_effect = ProviderRequestError(
        "Gemini request failed. Sanitized diagnostic: api_error (HTTP 400): key=[REDACTED]"
    )
    monkeypatch.setattr(connectivity, "GeminiProvider", Mock(return_value=provider))

    assert connectivity.main() == 1

    output = capsys.readouterr().out
    assert "with model gemini-test" in output
    assert "api_error (HTTP 400)" in output
    assert "test-key" not in output
