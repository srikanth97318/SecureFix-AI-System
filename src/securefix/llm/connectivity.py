"""Small live Gemini request for verifying local API configuration."""

from __future__ import annotations

from securefix.llm.gemini_provider import GeminiProvider, LLMError


def main() -> int:
    provider: GeminiProvider | None = None
    try:
        provider = GeminiProvider()
        provider.generate('Reply with exactly this JSON object: {"status":"ok"}')
    except LLMError as exc:
        model = f" with model {provider.model}" if provider is not None else ""
        print(f"Gemini connectivity test failed{model}: {exc}")
        return 1

    print(f"Gemini text generation succeeded with model {provider.model}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
