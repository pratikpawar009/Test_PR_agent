from __future__ import annotations

import os

from openai import AzureOpenAI, OpenAI


def _env_non_empty(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def _client() -> OpenAI | AzureOpenAI:
    azure_key = _env_non_empty("AZURE_OPENAI_API_KEY")
    azure_endpoint = _env_non_empty("AZURE_OPENAI_ENDPOINT")
    azure_api_version = _env_non_empty("AZURE_API_VERSION")
    if azure_key and azure_endpoint and azure_api_version:
        return AzureOpenAI(
            api_key=azure_key,
            azure_endpoint=azure_endpoint,
            api_version=azure_api_version,
        )

    api_key = _env_non_empty("OPENAI_API_KEY")
    if api_key:
        return OpenAI(api_key=api_key)

    raise RuntimeError(
        "No LLM credentials found. Set Azure vars "
        "(AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_API_VERSION) "
        "or OPENAI_API_KEY."
    )


def _model_name() -> str:
    azure_deployment = _env_non_empty("AZURE_DEPLOYMENT_NAME")
    if azure_deployment:
        return azure_deployment
    return _env_non_empty("OPENAI_MODEL") or "gpt-4o-mini"


def ask_llm(prompt: str) -> str:
    client = _client()
    response = client.chat.completions.create(
        model=_model_name(),
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a strict and practical senior software engineer reviewing PR diffs. "
                    "Return only valid JSON when requested."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )
    content = response.choices[0].message.content
    if not content:
        return ""
    return content.strip()
