"""Orchestrator Agent: coordinates multi-target parallel attacks."""

import json
from prompts import ORCHESTRATOR_PROMPT
from llm import LLMClient
from tools.memory import AttackMemory
from tools.waf_detector import WAFResult


class OrchestratorAgent:
    def __init__(self, llm: LLMClient, memory: AttackMemory = None):
        self.llm = llm
        self.memory = memory

    def plan_attack(
        self,
        recon_results: list[dict],
        waf_result: WAFResult = None,
        history: list = None,
    ) -> dict:
        """Plan the attack strategy across multiple targets.

        Returns a plan with multiple attack targets for parallel execution.
        """
        targets_str = json.dumps(recon_results, indent=2, default=str)
        history_str = json.dumps(history[-5:], indent=2, default=str) if history else "None"

        # Memory insights
        memory_insights = "None"
        if self.memory:
            stats = self.memory.get_stats()
            memory_insights = json.dumps(stats)

        waf_info = "none"
        if waf_result and waf_result.detected:
            waf_info = f"{waf_result.waf_name} (confidence={waf_result.confidence:.2f}, strategies={waf_result.bypass_strategies})"

        result = self.llm.generate_json(
            ORCHESTRATOR_PROMPT,
            f"phase: planning\n"
            f"targets: {targets_str}\n"
            f"waf_info: {waf_info}\n"
            f"memory_insights: {memory_insights}\n"
            f"history: {history_str}",
        )

        # Ensure we have a valid plan
        if "targets_to_attack" not in result:
            # Default: attack all discovered injection points
            result["targets_to_attack"] = self._extract_targets(recon_results)

        return result

    def merge_results(self, attack_results: list[dict]) -> dict:
        """Merge results from parallel attack branches."""
        successes = [r for r in attack_results if r.get("success")]
        failures = [r for r in attack_results if not r.get("success")]

        summary = {
            "total_attacks": len(attack_results),
            "successes": len(successes),
            "failures": len(failures),
            "successful_payloads": [
                {"payload": r.get("payload"), "evidence": r.get("evidence"), "endpoint": r.get("endpoint")}
                for r in successes
            ],
            "best_fitness": max((r.get("fitness", 0) for r in attack_results), default=0),
        }
        return summary

    def _extract_targets(self, recon_results: list[dict]) -> list[dict]:
        """Extract attack targets from recon data."""
        targets = []
        for recon in recon_results:
            for point in recon.get("injection_points", []):
                targets.append({
                    "endpoint": recon.get("endpoint", "/"),
                    "param": point.get("name", "q"),
                    "method": recon.get("method", "GET"),
                    "vuln_type": self._guess_vuln_type(point),
                })
        return targets or [{"endpoint": "/", "param": "q", "method": "GET", "vuln_type": "sqli"}]

    def _guess_vuln_type(self, injection_point: dict) -> str:
        context = injection_point.get("context", "")
        if "login" in context or "search" in context:
            return "sqli"
        if "comment" in context or "input" in context:
            return "xss"
        return "sqli"
