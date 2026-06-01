"""Mutator Agent: evolves payloads using GA engine + LLM + rule-based strategies.

Three-layer mutation:
  1. Genetic Algorithm (population-based, fitness-driven)
  2. LLM creative mutations (prompted by reflection analysis)
  3. Rule-based deterministic mutations (fast, predictable)
"""

import json
from prompts import MUTATOR_PROMPT
from llm import LLMClient
from tools.payload_mutator import GeneticEngine, Individual, PayloadMutator
from tools.waf_detector import WAFResult


class MutatorAgent:
    def __init__(self, llm: LLMClient, ga_config=None):
        self.llm = llm
        self.ga_config = ga_config
        self.ga_engine: GeneticEngine | None = None

    def initialize_ga(
        self,
        seed_payloads: list,
        vuln_type: str = "sqli",
        waf_result: WAFResult | None = None,
    ) -> list[Individual]:
        """Initialize the GA population from seed payloads (strings or dicts with payload+family)."""
        cfg = self.ga_config
        self.ga_engine = GeneticEngine(
            population_size=cfg.population_size if cfg else 12,
            elite_count=cfg.elite_count if cfg else 2,
            tournament_size=cfg.tournament_size if cfg else 3,
            crossover_rate=cfg.crossover_rate if cfg else 0.7,
            base_mutation_rate=cfg.base_mutation_rate if cfg else 0.15,
            vuln_type=vuln_type,
        )
        return self.ga_engine.initialize(seed_payloads)

    def evolve_generation(
        self,
        evaluated_population: list[Individual],
    ) -> list[Individual]:
        """Run one GA generation cycle."""
        if not self.ga_engine:
            return evaluated_population
        return self.ga_engine.evolve(evaluated_population)

    def mutate(
        self,
        original_payload: str,
        reflection: dict,
        vuln_type: str,
        waf_result: WAFResult | None = None,
        ga_best_fitness: float = 0.0,
        count: int = 4,
    ) -> list[dict]:
        """Generate mutated payloads using all three layers."""
        # Layer 1: LLM creative mutations
        llm_mutations = self._llm_mutate(
            original_payload, reflection, vuln_type, waf_result, ga_best_fitness, count
        )

        # Layer 2: Rule-based mutations
        rule_mutations = self._rule_mutate(original_payload, vuln_type)

        # Combine and deduplicate
        all_mutations = llm_mutations + rule_mutations
        seen = set()
        unique = []
        for m in all_mutations:
            p = m.get("payload", "")
            if p and p not in seen and p != original_payload:
                seen.add(p)
                unique.append(m)

        return unique[:count * 2]

    def _llm_mutate(
        self,
        payload: str,
        reflection: dict,
        vuln_type: str,
        waf_result: WAFResult | None,
        ga_best_fitness: float,
        count: int,
    ) -> list[dict]:
        """LLM-driven creative mutations informed by reflection + WAF."""
        filters = reflection.get("detected_filters", [])
        strategies = reflection.get("recommended_mutations", [])
        filters_str = ", ".join(filters) if filters else "none detected"
        strategies_str = ", ".join(strategies) if strategies else "explore freely"
        waf_strategies = ", ".join(waf_result.bypass_strategies) if waf_result and waf_result.detected else "none"

        result = self.llm.generate_json(
            MUTATOR_PROMPT,
            f"original_payload: {payload}\n"
            f"reflection: {json.dumps(reflection, default=str)}\n"
            f"filters: {filters_str}\n"
            f"waf_strategies: {waf_strategies}\n"
            f"vuln_type: {vuln_type}\n"
            f"ga_best_fitness: {ga_best_fitness}\n"
            f"count: {count}",
        )
        return result.get("mutated_payloads", [])

    def _rule_mutate(self, payload: str, vuln_type: str) -> list[dict]:
        """Deterministic rule-based mutations + semantic transforms."""
        mutations = []
        if vuln_type == "sqli":
            for m in PayloadMutator.mutate_sqli(payload):
                mutations.append({"payload": m, "mutation_applied": "rule_sqli", "reasoning": "deterministic"})
            # Semantic equivalent transforms
            from tools.payload_mutator import SemanticTransformer
            for m in SemanticTransformer.transform_sqli(payload):
                mutations.append({"payload": m, "mutation_applied": "semantic_sqli", "reasoning": "semantic equivalent"})
        elif vuln_type == "xss":
            for m in PayloadMutator.mutate_xss(payload):
                mutations.append({"payload": m, "mutation_applied": "rule_xss", "reasoning": "deterministic"})
            from tools.payload_mutator import SemanticTransformer
            for m in SemanticTransformer.transform_xss(payload):
                mutations.append({"payload": m, "mutation_applied": "semantic_xss", "reasoning": "semantic equivalent"})
        elif vuln_type == "cmdi":
            from tools.payload_mutator import SemanticTransformer
            for m in SemanticTransformer.transform_cmdi(payload):
                mutations.append({"payload": m, "mutation_applied": "semantic_cmdi", "reasoning": "semantic equivalent"})
        return mutations
