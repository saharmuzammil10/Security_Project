"""
llm_client.py
-------------
A small abstraction so the rest of the pipeline doesn't care whether
generation happens locally (Ollama) or via the Claude API. Both clients
expose the same `.generate(system_prompt, user_prompt)` method, so
swapping backends is a one-line change wherever you construct the client.

Why this matters for a security project specifically:
  - Iterate fast and free locally (Ollama) while tuning attacks/defenses.
  - Flip to Claude when you want to compare how a frontier model resists
    the same injection payloads vs. a smaller local model.
"""

import os
from abc import ABC, abstractmethod

from dotenv import load_dotenv

# Automatically load variables from a .env file in the project root, if
# present, so ANTHROPIC_API_KEY can live in .env instead of your shell.
load_dotenv()


class LLMClient(ABC):
    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        """Send a system+user prompt, return the model's text response."""
        raise NotImplementedError


class OllamaClient(LLMClient):
    """
    Talks to a locally running Ollama server (default: http://localhost:11434).
    Requires Ollama installed and a model pulled, e.g.:
        ollama pull llama3
        ollama serve   (usually runs automatically after install)
    """

    def __init__(self, model: str = "llama3", host: str = None):
        self.model = model
        # Falls back to localhost for normal local use; Docker Compose
        # sets OLLAMA_HOST=http://ollama:11434 so the app container can
        # reach the separate Ollama container by its service name.
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        import requests

        response = requests.post(
            f"{self.host}/api/generate",
            json={
                "model": self.model,
                "system": system_prompt,
                "prompt": user_prompt,
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            timeout=120,
        )
        response.raise_for_status()
        return response.json().get("response", "")


class ClaudeClient(LLMClient):
    """
    Talks to the Claude API. Requires ANTHROPIC_API_KEY to be set as an
    environment variable (never hardcode it in source).
    """

    def __init__(self, model: str = "claude-sonnet-5"):
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY environment variable not set. "
                "Get a key from https://console.anthropic.com and set it with:\n"
                "  export ANTHROPIC_API_KEY=your-key-here   (Mac/Linux)\n"
                "  setx ANTHROPIC_API_KEY your-key-here      (Windows)"
            )
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        # response.content is a list of content blocks; join any text blocks
        return "".join(block.text for block in response.content if block.type == "text")


def get_llm_client(backend: str = "ollama", **kwargs) -> LLMClient:
    """
    Factory function -- this is the one line you change to switch backends.

    Usage:
        llm = get_llm_client("ollama", model="llama3")
        llm = get_llm_client("claude", model="claude-sonnet-5")
    """
    if backend == "ollama":
        return OllamaClient(**kwargs)
    elif backend == "claude":
        return ClaudeClient(**kwargs)
    else:
        raise ValueError(f"Unknown backend '{backend}'. Use 'ollama' or 'claude'.")


if __name__ == "__main__":
    # Quick manual test -- change backend to "claude" to test that path instead.
    llm = get_llm_client("ollama", model="llama3")
    reply = llm.generate(
        system_prompt="You are a concise assistant.",
        user_prompt="Say hello in five words.",
    )
    print(reply)