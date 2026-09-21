"""Response inspection heuristics and classifier assistance.

Inspects tool outputs for:
- Prompt injection patterns
- Hidden instructions
- Exfiltration tokens / Base64 / Hex payloads
- Suspicious external URLs
"""

from typing import Any, Dict, List, Optional
import re


class ResponseInspector:
    """Inspector for tool execution outputs."""

    def __init__(self):
        # Known suspicious injection patterns
        self.injection_patterns = [
            r"(?i)ignore previous instructions",
            r"(?i)system prompt override",
            r"(?i)send .* to https?://",
            r"(?i)base64decode\(",
        ]

    def inspect_content(self, content: Any) -> float:
        """Inspect response content and return a risk score (0-100).

        [TODO Day 10: Full regex suite, payload decoders, and secondary LLM classifier]
        """
        text = str(content)
        for pattern in self.injection_patterns:
            if re.search(pattern, text):
                return 85.0
        return 0.0
