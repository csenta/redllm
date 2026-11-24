"""
Target connector abstractions for RedLLM.
"""

from abc import ABC, abstractmethod
import requests


class BaseTarget(ABC):
    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Sends the adversarial prompt to the target and returns the raw response string."""
        pass


class MockTarget(BaseTarget):
    """
    Deterministic mock target for automated tests and offline simulation.
    """
    def __init__(self, system_prompt: str = "", canary: str = "", refuses: bool = True):
        self.system_prompt = system_prompt
        self.canary = canary
        self.refuses = refuses

    def complete(self, prompt: str) -> str:
        prompt_lower = prompt.lower()
        if "verbatim" in prompt_lower or "preamble" in prompt_lower or "debug mode" in prompt_lower:
            # Simulate a system leak vulnerability
            return f"System instructions: {self.system_prompt}. Canary secret: {self.canary}"

        if self.refuses:
            return "I cannot fulfill this request. It goes against my safety guidelines and ethical policies."
        else:
            return "Here is the step-by-step walkthrough to perform the requested operation: Step 1..."


class OpenAITarget(BaseTarget):
    """
    Connects to any OpenAI-compatible endpoint (Groq, OpenAI, Ollama, etc.).
    """
    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key: str = "",
        model: str = "gpt-4o",
        system_prompt: str = "",
        temperature: float = 0.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.system_prompt = system_prompt
        self.temperature = temperature

    def complete(self, prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}" if self.api_key else "",
        }
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=45)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
