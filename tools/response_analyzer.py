"""
BypassEvo v4.0 — AI Response Analyzer

Deep LLM-driven analysis of HTTP responses to understand:
1. WHY a payload was blocked (exact rule reasoning)
2. WHAT signals exist in the response (partial success indicators)
3. HOW to adapt the next payload based on response patterns
4. WHAT the WAF "learned" from our attempts (adaptive WAF detection)

This replaces the simple is_blocked/passed binary classification with
a rich, structured understanding of each response.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from llm import LLMClient


@dataclass
class ResponseInsight:
    """Structured insight from analyzing a single HTTP response."""
    # Classification
    classification: str = "blocked"  # blocked | passed | partial | no_effect | error
    confidence: float = 0.0

    # WAF behavior analysis
    waf_rule_triggered: str = ""       # Which rule likely triggered
    detection_mechanism: str = ""      # keyword | regex | semantic | behavioral | ml
    evasion_proximity: float = 0.0     # How close to bypassing (0=far, 1=almost)

    # Response signals
    sql_error_leaked: bool = False     # SQL error visible despite block
    content_anomaly: bool = False      # Response differs from standard block page
    timing_anomaly: bool = False       # Response time suggests processing
    partial_execution: bool = False    # Backend partially processed the payload

    # Adaptation signals
    waf_adapting: bool = False         # WAF seems to be learning/adapting
    new_rule_detected: bool = False    # A new blocking rule appeared
    rule_relaxed: bool = False         # A previously strict rule seems relaxed

    # Actionable recommendations
    mutation_hints: list = field(default_factory=list)  # Specific mutations to try
    avoid_patterns: list = field(default_factory=list)  # Patterns to avoid
    exploit_signals: list = field(default_factory=list)  # Signals suggesting exploitation path

    # Raw analysis
    analysis_text: str = ""
    response_fingerprint: str = ""     # Hash-like fingerprint of response characteristics


@dataclass
class FailurePattern:
    """A learned pattern from multiple failures."""
    pattern_type: str = ""          # keyword_block | encoding_detect | semantic_block | rate_limit
    trigger_signature: str = ""     # What consistently triggers this pattern
    confidence: float = 0.0
    occurrences: int = 0
    first_seen_iteration: int = 0
    last_seen_iteration: int = 0
    # What we learned
    waf_decodes_before_match: bool = False
    waf_normalizes_case: bool = False
    waf_tracks_context: bool = False
    # Bypass strategies that might work
    potential_bypasses: list = field(default_factory=list)
    # Strategies confirmed to NOT work
    failed_bypasses: list = field(default_factory=list)


RESPONSE_ANALYSIS_PROMPT = """You are an elite WAF security researcher performing DEEP RESPONSE ANALYSIS.
Your job is to extract maximum intelligence from a single HTTP response — understanding not just
WHETHER a payload was blocked, but WHY, HOW CLOSE it was to succeeding, and WHAT TO TRY NEXT.

═══════════════════════════════════════════════════════════════════
RESPONSE DATA
═══════════════════════════════════════════════════════════════════
Payload sent: {payload}
HTTP status code: {status_code}
Response time: {response_time:.3f}s (baseline: {baseline_time:.3f}s)
Response body (first 600 chars):
{response_body}

Response headers (relevant):
{response_headers}

═══════════════════════════════════════════════════════════════════
CONTEXT
═══════════════════════════════════════════════════════════════════
WAF: {waf_name}
Bypass technique used: {technique}
Previous responses for comparison:
{previous_responses}

Known WAF rules (inferred from past analysis):
{inferred_rules}

═══════════════════════════════════════════════════════════════════
ANALYSIS FRAMEWORK — Think step by step
═══════════════════════════════════════════════════════════════════

1. CLASSIFICATION: Is this blocked/passed/partial/no_effect/error?
   - blocked: WAF explicitly rejected (403, custom block page)
   - passed: WAF allowed through (200 with different content than baseline)
   - partial: WAF blocked but leaked information (SQL error in 403 body)
   - no_effect: Payload went through but had no injection effect (200, same as baseline)
   - error: Server error unrelated to injection (500 from app crash)

2. EVASION PROXIMITY: How close was this to bypassing?
   - 0.0-0.2: Standard block, nothing interesting
   - 0.2-0.4: Different block page or timing — different rule triggered
   - 0.4-0.6: Partial signals — some processing happened before block
   - 0.6-0.8: Very close — SQL error leaked, or response time anomaly
   - 0.8-1.0: Almost bypassed — content changed, or intermittent block

3. DETECTION MECHANISM: How did the WAF detect this?
   - keyword: Simple keyword matching (UNION, SELECT, etc.)
   - regex: Pattern matching (e.g., \\bUNION\\s+SELECT\\b)
   - semantic: Understanding SQL syntax structure
   - behavioral: Rate-based or session-based detection
   - ml: Machine learning / anomaly detection

4. MUTATION HINTS: Based on this specific response, what should we try next?
   - Be SPECIFIC: "encode the 'U' in UNION as %55" not "try encoding"
   - Reference the EXACT part of the payload that likely triggered the block
   - Consider what the response tells us about the WAF's parsing depth

5. WAF ADAPTATION: Is the WAF learning from our attempts?
   - Same payload blocked differently than before?
   - Block page changed?
   - Response time increased (deeper inspection)?

Respond with JSON:
{{
    "classification": "blocked|passed|partial|no_effect|error",
    "confidence": 0.0-1.0,
    "evasion_proximity": 0.0-1.0,
    "detection_mechanism": "keyword|regex|semantic|behavioral|ml",
    "waf_rule_triggered": "description of the specific rule",
    "sql_error_leaked": false,
    "content_anomaly": false,
    "timing_anomaly": false,
    "partial_execution": false,
    "waf_adapting": false,
    "mutation_hints": [
        {{
            "action": "specific mutation to try",
            "target": "which part of the payload to modify",
            "reasoning": "why this should work based on the response"
        }}
    ],
    "avoid_patterns": ["patterns that definitely trigger this WAF"],
    "exploit_signals": ["any signals suggesting exploitation is possible"],
    "analysis": "your detailed reasoning about this response"
}}"""


FAILURE_PATTERN_PROMPT = """You are a WAF behavior analyst. Analyze multiple blocked responses to identify
SYSTEMATIC FAILURE PATTERNS — recurring reasons why payloads are being blocked.

═══════════════════════════════════════════════════════════════════
BLOCKED RESPONSES (last {count} attempts)
═══════════════════════════════════════════════════════════════════
{blocked_responses}

═══════════════════════════════════════════════════════════════════
PASSED RESPONSES (for comparison)
═══════════════════════════════════════════════════════════════════
{passed_responses}

═══════════════════════════════════════════════════════════════════
KNOWN RULES
═══════════════════════════════════════════════════════════════════
{known_rules}

═══════════════════════════════════════════════════════════════════
YOUR TASK
═══════════════════════════════════════════════════════════════════

Identify FAILURE PATTERNS by comparing blocked vs passed payloads:
1. What do ALL blocked payloads have in common that passed ones don't?
2. Is the WAF doing case-insensitive matching? (test: same keyword, different case)
3. Is the WAF decoding before matching? (test: encoded vs plain)
4. Is the WAF tracking context? (test: same keyword in different positions)
5. Are there any "almost passed" payloads that suggest a specific weakness?

For each pattern found, suggest CONCRETE bypass strategies that exploit the gap
between what's blocked and what's passed.

Respond with JSON:
{{
    "patterns": [
        {{
            "pattern_type": "keyword_block|encoding_detect|semantic_block|context_aware|rate_limit",
            "trigger_signature": "what consistently triggers this block",
            "confidence": 0.0-1.0,
            "evidence": "specific examples from the data",
            "waf_decodes_before_match": true/false,
            "waf_normalizes_case": true/false,
            "waf_tracks_context": true/false,
            "potential_bypasses": [
                {{
                    "technique": "specific technique",
                    "payload_example": "concrete example payload",
                    "reasoning": "why this exploits the pattern's weakness"
                }}
            ],
            "failed_bypasses": ["techniques that definitely don't work"]
        }}
    ],
    "overall_analysis": "summary of WAF behavior model",
    "recommended_next_steps": ["ordered list of what to try next"],
    "waf_sophistication": "basic|intermediate|advanced|ml_based"
}}"""


class ResponseAnalyzer:
    """AI-driven deep response analysis engine.

    Replaces simple binary classification with rich, structured understanding
    of each HTTP response. Learns from patterns across multiple responses.
    """

    def __init__(self, llm: LLMClient, max_history: int = 50):
        self.llm = llm
        self.max_history = max_history
        self._response_history: list[dict] = []
        self._failure_patterns: list[FailurePattern] = []
        self._response_fingerprints: dict[str, int] = {}  # fingerprint -> count

    def analyze_response(
        self,
        payload: str,
        status_code: int,
        response_body: str,
        response_time: float,
        response_headers: dict = None,
        technique: str = "",
        waf_name: str = "unknown",
        baseline_time: float = 0.1,
        inferred_rules: list = None,
    ) -> ResponseInsight:
        """Deep analysis of a single HTTP response using LLM.

        This is the core v4.0 innovation: instead of just checking status codes,
        we ask the LLM to reason about the response like a security researcher.
        """
        insight = ResponseInsight()

        # Quick pre-filter: obvious cases don't need LLM
        if status_code == 200 and response_time < baseline_time * 1.5:
            # Likely passed or no effect — still analyze for content
            pass
        elif status_code in (403, 406, 503):
            # Likely blocked — but analyze for partial signals
            pass

        # Build context from recent responses
        prev_responses = self._format_previous_responses(last_n=3)

        # Format inferred rules
        rules_text = "None inferred yet."
        if inferred_rules:
            rules_lines = []
            for r in inferred_rules[:5]:
                kws = r.get("trigger_keywords", [])[:5]
                rules_lines.append(f"  - {r.get('rule_type', '?')}: triggers=[{', '.join(kws)}]")
            rules_text = "\n".join(rules_lines)

        # Format headers
        headers_text = "None captured."
        if response_headers:
            relevant_headers = {k: v for k, v in response_headers.items()
                                if k.lower() in ("server", "x-powered-by", "x-waf", "x-blocked-by",
                                                  "content-type", "x-request-id", "cf-ray")}
            if relevant_headers:
                headers_text = json.dumps(relevant_headers, indent=2)

        prompt = RESPONSE_ANALYSIS_PROMPT.format(
            payload=payload[:200],
            status_code=status_code,
            response_time=response_time,
            baseline_time=baseline_time,
            response_body=response_body[:600],
            response_headers=headers_text,
            waf_name=waf_name,
            technique=technique or "unknown",
            previous_responses=prev_responses,
            inferred_rules=rules_text,
        )

        try:
            result = self.llm.generate_json(prompt, "Analyze this response now.")

            if isinstance(result, dict) and "classification" in result:
                insight.classification = result.get("classification", "blocked")
                insight.confidence = result.get("confidence", 0.5)
                insight.evasion_proximity = result.get("evasion_proximity", 0.0)
                insight.detection_mechanism = result.get("detection_mechanism", "unknown")
                insight.waf_rule_triggered = result.get("waf_rule_triggered", "")
                insight.sql_error_leaked = result.get("sql_error_leaked", False)
                insight.content_anomaly = result.get("content_anomaly", False)
                insight.timing_anomaly = result.get("timing_anomaly", False)
                insight.partial_execution = result.get("partial_execution", False)
                insight.waf_adapting = result.get("waf_adapting", False)
                insight.mutation_hints = result.get("mutation_hints", [])
                insight.avoid_patterns = result.get("avoid_patterns", [])
                insight.exploit_signals = result.get("exploit_signals", [])
                insight.analysis_text = result.get("analysis", "")
        except Exception:
            # Fallback: basic classification without LLM
            insight = self._basic_classify(status_code, response_body, response_time, baseline_time)

        # Generate response fingerprint
        insight.response_fingerprint = self._fingerprint_response(status_code, response_body, response_time)

        # Track in history
        self._response_history.append({
            "payload": payload[:100],
            "status_code": status_code,
            "response_time": response_time,
            "technique": technique,
            "classification": insight.classification,
            "evasion_proximity": insight.evasion_proximity,
            "fingerprint": insight.response_fingerprint,
        })
        if len(self._response_history) > self.max_history:
            self._response_history = self._response_history[-self.max_history:]

        # Track fingerprint frequency
        fp = insight.response_fingerprint
        self._response_fingerprints[fp] = self._response_fingerprints.get(fp, 0) + 1

        # Detect WAF adaptation
        if self._detect_waf_adaptation():
            insight.waf_adapting = True

        return insight

    def extract_failure_patterns(
        self,
        bypass_history: list[dict],
        waf_name: str = "unknown",
        inferred_rules: list = None,
    ) -> list[FailurePattern]:
        """Analyze multiple failures to extract systematic patterns.

        This is called periodically (every N blocked payloads) to update
        our understanding of the WAF's behavior model.
        """
        blocked = [h for h in bypass_history if h.get("status_code") in (403, 406, 503)]
        passed = [h for h in bypass_history if h.get("status_code") not in (403, 406, 503, 0)]

        if len(blocked) < 3:
            return self._failure_patterns  # Not enough data

        # Format blocked responses for LLM
        blocked_text = []
        for h in blocked[-15:]:
            tech = h.get("technique") or h.get("family") or "unknown"
            blocked_text.append(
                f"  [{tech}] {h.get('payload', '')[:80]} → {h.get('status_code', 403)}"
            )

        # Format passed responses
        passed_text = []
        for h in passed[-5:]:
            tech = h.get("technique") or h.get("family") or "unknown"
            passed_text.append(
                f"  [{tech}] {h.get('payload', '')[:80]} → {h.get('status_code', 200)}"
            )

        # Format known rules
        rules_text = "None."
        if inferred_rules:
            rules_lines = []
            for r in inferred_rules[:5]:
                kws = r.get("trigger_keywords", [])[:5]
                rules_lines.append(f"  - {r.get('rule_type', '?')}: [{', '.join(kws)}]")
            rules_text = "\n".join(rules_lines)

        prompt = FAILURE_PATTERN_PROMPT.format(
            count=len(blocked_text),
            blocked_responses="\n".join(blocked_text),
            passed_responses="\n".join(passed_text) if passed_text else "None yet.",
            known_rules=rules_text,
        )

        try:
            result = self.llm.generate_json(prompt, "Identify failure patterns now.")

            if isinstance(result, dict) and "patterns" in result:
                patterns = []
                for p in result["patterns"]:
                    if isinstance(p, dict) and p.get("pattern_type"):
                        fp = FailurePattern(
                            pattern_type=p.get("pattern_type", ""),
                            trigger_signature=p.get("trigger_signature", ""),
                            confidence=p.get("confidence", 0.5),
                            waf_decodes_before_match=p.get("waf_decodes_before_match", False),
                            waf_normalizes_case=p.get("waf_normalizes_case", False),
                            waf_tracks_context=p.get("waf_tracks_context", False),
                            potential_bypasses=p.get("potential_bypasses", []),
                            failed_bypasses=p.get("failed_bypasses", []),
                        )
                        patterns.append(fp)
                self._failure_patterns = patterns
                return patterns
        except Exception:
            pass

        return self._failure_patterns

    def get_mutation_guidance(self) -> dict:
        """Synthesize all learned patterns into actionable mutation guidance.

        Returns a structured dict that the GA engine can use to guide mutations.
        """
        guidance = {
            "avoid": [],          # Patterns to avoid (confirmed triggers)
            "try": [],            # Specific mutations to try (from hints)
            "promising_families": [],  # Families showing progress
            "dead_families": [],  # Families confirmed to not work
            "waf_model": {},      # Our understanding of the WAF
        }

        # From failure patterns
        for fp in self._failure_patterns:
            if fp.confidence > 0.6:
                guidance["avoid"].append(fp.trigger_signature)
                for bypass in fp.potential_bypasses:
                    if isinstance(bypass, dict):
                        guidance["try"].append(bypass)
                for failed in fp.failed_bypasses:
                    guidance["dead_families"].append(failed)

            # Build WAF model
            if fp.waf_decodes_before_match:
                guidance["waf_model"]["decodes_url"] = True
            if fp.waf_normalizes_case:
                guidance["waf_model"]["normalizes_case"] = True
            if fp.waf_tracks_context:
                guidance["waf_model"]["tracks_context"] = True

        # From recent response insights
        for resp in self._response_history[-10:]:
            if resp.get("evasion_proximity", 0) > 0.5:
                guidance["promising_families"].append(resp.get("technique", ""))

        # Deduplicate
        guidance["promising_families"] = list(set(f for f in guidance["promising_families"] if f))
        guidance["dead_families"] = list(set(guidance["dead_families"]))

        return guidance

    def _basic_classify(self, status_code: int, body: str, resp_time: float, baseline_time: float) -> ResponseInsight:
        """Fallback classification without LLM."""
        insight = ResponseInsight()

        if status_code in (403, 406, 503):
            insight.classification = "blocked"
            insight.confidence = 0.9
            # Check for SQL error in block page
            sql_patterns = [
                r"you have an error in your sql",
                r"mysql_fetch", r"pg_query", r"ora-\d{5}",
                r"xpath.*error", r"syntax error",
            ]
            body_lower = body.lower()
            for pat in sql_patterns:
                if re.search(pat, body_lower):
                    insight.sql_error_leaked = True
                    insight.classification = "partial"
                    insight.evasion_proximity = 0.6
                    break
        elif status_code == 200:
            insight.classification = "passed"
            insight.confidence = 0.7
        elif status_code == 500:
            insight.classification = "error"
            insight.confidence = 0.8
            insight.partial_execution = True
        else:
            insight.classification = "blocked"
            insight.confidence = 0.5

        # Timing analysis
        if resp_time > baseline_time * 3:
            insight.timing_anomaly = True
            insight.evasion_proximity = max(insight.evasion_proximity, 0.4)

        return insight

    def _fingerprint_response(self, status_code: int, body: str, resp_time: float) -> str:
        """Create a fingerprint for response deduplication and pattern detection."""
        # Fingerprint based on: status code + body length bucket + time bucket
        len_bucket = len(body) // 100 * 100  # Round to nearest 100
        time_bucket = round(resp_time, 1)
        return f"{status_code}:{len_bucket}:{time_bucket}"

    def _detect_waf_adaptation(self) -> bool:
        """Detect if the WAF is adapting to our attempts.

        Signs of adaptation:
        - Same payload gets different responses over time
        - Block page changes
        - Response time increases (deeper inspection)
        - New fingerprints appearing for similar payloads
        """
        if len(self._response_history) < 5:
            return False

        recent = self._response_history[-5:]
        older = self._response_history[-10:-5] if len(self._response_history) >= 10 else []

        if not older:
            return False

        # Check if response fingerprints are changing
        recent_fps = set(r.get("fingerprint", "") for r in recent)
        older_fps = set(r.get("fingerprint", "") for r in older)

        # New fingerprints appearing = WAF changing behavior
        new_fps = recent_fps - older_fps
        if len(new_fps) > 2:
            return True

        # Average response time increasing = deeper inspection
        recent_times = [r.get("response_time", 0) for r in recent]
        older_times = [r.get("response_time", 0) for r in older]
        if recent_times and older_times:
            avg_recent = sum(recent_times) / len(recent_times)
            avg_older = sum(older_times) / len(older_times)
            if avg_recent > avg_older * 1.5:
                return True

        return False

    def _format_previous_responses(self, last_n: int = 3) -> str:
        """Format recent response history for LLM context."""
        if not self._response_history:
            return "No previous responses."

        lines = []
        for r in self._response_history[-last_n:]:
            lines.append(
                f"  [{r.get('technique', '?')}] {r.get('payload', '')[:60]} → "
                f"{r.get('status_code', '?')} ({r.get('classification', '?')}, "
                f"proximity={r.get('evasion_proximity', 0):.2f})"
            )
        return "\n".join(lines)
