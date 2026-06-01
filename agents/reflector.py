"""Reflector Agent: analyzes failures and recommends mutations."""

import json
from prompts import REFLECTOR_PROMPT
from llm import LLMClient


class ReflectorAgent:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    def reflect(
        self,
        vuln_type: str,
        payload: str,
        execution_result: dict,
        history: list,
        iteration: int,
    ) -> dict:
        """Analyze why a payload failed and recommend next steps."""
        history_str = json.dumps(history[-5:], indent=2, default=str) if history else "None"
        result_str = json.dumps(execution_result, indent=2, default=str)

        analysis = self.llm.generate_json(
            REFLECTOR_PROMPT,
            f"vuln_type: {vuln_type}\n"
            f"payload: {payload}\n"
            f"execution_result: {result_str}\n"
            f"history: {history_str}\n"
            f"iteration: {iteration}",
        )

        # Ensure required fields
        analysis.setdefault("analysis", "No analysis available")
        analysis.setdefault("detected_filters", [])
        analysis.setdefault("injection_context", "unknown")
        analysis.setdefault("recommended_mutations", [])
        analysis.setdefault("confidence", 0.5)
        analysis.setdefault("should_continue", iteration < 15)

        return analysis
