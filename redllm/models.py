"""
Data models for RedLLM adversarial testing framework.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "LLM01_Prompt_Injection"
    SYSTEM_LEAK = "LLM06_Sensitive_Information_Disclosure"
    ROLEPLAY_JAILBREAK = "LLM01_Roleplay_Bypass"
    OBFUSCATION_EVASION = "LLM01_Encoding_Evasion"
    REFUSAL_SUPPRESSION = "LLM01_Refusal_Suppression"


@dataclass
class AttackPayload:
    name: str
    category: AttackCategory
    base_prompt: str
    mutated_prompt: str
    technique: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    payload: AttackPayload
    target_response: str
    is_jailbreak: bool
    confidence_score: float  # 0.0 to 1.0
    reason: str


@dataclass
class AuditReport:
    target_name: str
    total_attacks: int
    successful_jailbreaks: int
    evasion_rate: float
    results: list[TestResult] = field(default_factory=list)
