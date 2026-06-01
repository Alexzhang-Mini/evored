"""Online WAF bypass technique research via DuckDuckGo search.

Searches for known bypass techniques for a given WAF, parses results into
structured data, and feeds them into the bypass generation pipeline.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from config import WebSearchConfig

logger = logging.getLogger("bypassevo.web_search")


@dataclass
class SearchResult:
    """A single parsed search result."""
    title: str
    url: str
    snippet: str
    technique: str = ""        # Extracted bypass technique name
    payload_example: str = ""  # Example payload if found in snippet
    source: str = ""           # "exploit-db" | "github" | "blog" | "other"


@dataclass
class SearchResponse:
    """Aggregated search response for a WAF bypass query."""
    waf_name: str
    query: str
    results: list[SearchResult] = field(default_factory=list)
    techniques_summary: str = ""   # LLM-summarized techniques
    search_time: float = 0.0
    error: str = ""


# Known technique keywords to extract from search snippets
_TECHNIQUE_PATTERNS = [
    # SQL injection bypass
    (r"(?i)(union\s+select|comment\s+injection|case\s+variation|inline\s+comment)", "sql_comment_injection"),
    (r"(?i)(double\s+url\s+encode|url\s+encod|percent\s+encod)", "url_encoding"),
    (r"(?i)(unicode|fullwidth|homoglyph|utf-?8)", "unicode_bypass"),
    (r"(?i)(chunked|transfer.encoding)", "chunked_encoding"),
    (r"(?i)(request\s+smuggl|cl.te|te.cl)", "request_smuggling"),
    (r"(?i)(parameter\s+pollution|hpp|duplicate\s+param)", "parameter_pollution"),
    (r"(?i)(content.type\s+manipulat|multipart|application/json)", "content_type_manipulation"),
    (r"(?i)(http\s+method|get\s+to\s+post|put|patch|options)", "http_method_switch"),
    (r"(?i)(null\s+byte|%00|null\s+inject)", "null_byte_injection"),
    (r"(?i)(whitespace|tab|%09|%0a|%0d|%0c|form.feed)", "whitespace_alternative"),
    (r"(?i)(base64|b64\s+encod)", "base64_encoding"),
    (r"(?i)(case\s+variat|upper|lower|mixed\s+case)", "case_variation"),
    (r"(?i)(bypass|evad|circumvent|waf)", "general_bypass"),
]

# Source classification patterns
_SOURCE_PATTERNS = [
    (r"exploit-db\.com|exploitdb", "exploit-db"),
    (r"github\.com", "github"),
    (r"owasp\.org", "owasp"),
    (r"portswigger\.net", "portswigger"),
    (r"medium\.com|infosec", "blog"),
    (r"cve|nvd\.nist", "cve"),
]


def _classify_source(url: str) -> str:
    """Classify the source type from URL."""
    for pattern, source in _SOURCE_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return source
    return "other"


def _extract_techniques(text: str) -> list[str]:
    """Extract bypass technique names from text."""
    found = []
    for pattern, name in _TECHNIQUE_PATTERNS:
        if re.search(pattern, text):
            found.append(name)
    return list(set(found)) or ["unknown"]


def _extract_payload_example(text: str) -> str:
    """Try to extract a payload example from snippet text."""
    # Look for common SQL injection patterns
    sql_patterns = [
        r"(?:UNION|union)\s+(?:SELECT|select)\s+[^\s<]{5,60}",
        r"(?:OR|or)\s+(?:1|'1')\s*=\s*(?:1|'1')",
        r"(?:AND|and)\s+(?:1|'1')\s*=\s*(?:1|'1')",
        r"'(?:\s*(?:OR|AND)\s+[^']{3,40})",
        r"<script[^>]*>[^<]{5,60}</script>",
        r"(?:SELECT|select)\s+[^;]{5,60}(?:FROM|from)",
    ]
    for pattern in sql_patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(0).strip()
    return ""


def _build_queries(waf_name: str, vuln_type: str, trigger_segments: list[str] = None) -> list[str]:
    """Build search queries for known bypass techniques."""
    queries = []
    waf_lower = waf_name.lower() if waf_name else ""

    # Primary: specific WAF name + vuln type
    if waf_lower and waf_lower not in ("unknown", "none", ""):
        queries.append(f"{waf_name} WAF bypass {vuln_type} techniques 2024 2025")
        queries.append(f"{waf_name} bypass payload {vuln_type} exploit")
    else:
        # Generic WAF bypass
        queries.append(f"WAF bypass {vuln_type} techniques 2024 2025")
        queries.append(f"web application firewall bypass {vuln_type} payload")

    # Trigger-segment specific query
    if trigger_segments:
        segment_text = " ".join(trigger_segments[:3])[:80]
        if segment_text.strip():
            queries.append(f"WAF bypass {segment_text} {vuln_type}")

    return queries


class WAFBypassSearcher:
    """Search for known WAF bypass techniques online."""

    def __init__(self, config: WebSearchConfig):
        self.config = config
        self._cache: dict[str, SearchResponse] = {}
        self._available: Optional[bool] = None

    def _check_available(self) -> bool:
        """Check if ddgs is importable."""
        if self._available is None:
            try:
                from ddgs import DDGS
                self._available = True
            except ImportError:
                logger.warning("ddgs not installed: pip install ddgs")
                self._available = False
        return self._available

    def search(
        self,
        waf_name: str,
        vuln_type: str = "sqli",
        trigger_segments: list[str] = None,
        session_id: str = "",
    ) -> SearchResponse:
        """Search for known bypass techniques for a specific WAF.

        Args:
            waf_name: Name of the detected WAF (e.g., "Cloudflare", "ModSecurity")
            vuln_type: Vulnerability type (sqli, xss, cmdi)
            trigger_segments: Payload segments that triggered the WAF
            session_id: Current session ID for caching

        Returns:
            SearchResponse with parsed results and technique summary
        """
        if not self.config.enabled:
            return SearchResponse(waf_name=waf_name, query="", error="search disabled")

        if not self._check_available():
            return SearchResponse(waf_name=waf_name, query="", error="duckduckgo-search not installed")

        # Check cache (same WAF + vuln_type within session)
        cache_key = f"{waf_name.lower()}:{vuln_type}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached.search_time < self.config.cache_ttl:
                logger.info(f"[WEB-SEARCH] Cache hit for {cache_key}")
                return cached

        queries = _build_queries(waf_name, vuln_type, trigger_segments)
        all_results: list[SearchResult] = []
        seen_urls: set[str] = set()

        start = time.time()
        try:
            from ddgs import DDGS

            with DDGS() as ddgs:
                for query in queries:
                    try:
                        hits = ddgs.text(
                            query,
                            max_results=self.config.max_results,
                            region=self.config.search_locale,
                        )
                        for hit in hits:
                            url = hit.get("href", "")
                            if url in seen_urls:
                                continue
                            seen_urls.add(url)

                            title = hit.get("title", "")
                            snippet = hit.get("body", "")
                            combined_text = f"{title} {snippet}"
                            techniques = _extract_techniques(combined_text)
                            payload = _extract_payload_example(snippet)

                            result = SearchResult(
                                title=title,
                                url=url,
                                snippet=snippet[:300],
                                technique=techniques[0] if techniques else "",
                                payload_example=payload,
                                source=_classify_source(url),
                            )
                            all_results.append(result)
                    except Exception as e:
                        logger.warning(f"[WEB-SEARCH] Query failed: {query[:50]}... — {e}")
                        continue

        except Exception as e:
            elapsed = time.time() - start
            logger.error(f"[WEB-SEARCH] Search error: {e}")
            return SearchResponse(
                waf_name=waf_name,
                query=queries[0] if queries else "",
                search_time=elapsed,
                error=str(e),
            )

        elapsed = time.time() - start

        # Build technique summary
        technique_set: dict[str, int] = {}
        for r in all_results:
            tech = r.technique
            if tech:
                technique_set[tech] = technique_set.get(tech, 0) + 1
        summary_parts = [f"{t}({c})" for t, c in sorted(technique_set.items(), key=lambda x: -x[1])]
        techniques_summary = ", ".join(summary_parts[:8]) if summary_parts else "no specific techniques found"

        response = SearchResponse(
            waf_name=waf_name,
            query=queries[0] if queries else "",
            results=all_results,
            techniques_summary=techniques_summary,
            search_time=elapsed,
        )

        # Cache result
        self._cache[cache_key] = response
        logger.info(f"[WEB-SEARCH] Found {len(all_results)} results for {waf_name}/{vuln_type} in {elapsed:.1f}s")
        return response


def format_search_results_for_prompt(resp: SearchResponse) -> str:
    """Format search results into a string suitable for LLM prompt injection."""
    if not resp.results:
        if resp.error:
            return f"[Web Search: unavailable — {resp.error}]"
        return "[Web Search: no results found]"

    lines = [f"[Online Research — {resp.waf_name} WAF bypass techniques]"]
    lines.append(f"Techniques found: {resp.techniques_summary}")
    lines.append(f"Sources: {len(resp.results)} results from {resp.search_time:.1f}s search")
    lines.append("")

    for i, r in enumerate(resp.results[:6], 1):
        lines.append(f"{i}. [{r.source}] {r.title}")
        lines.append(f"   URL: {r.url}")
        if r.technique:
            lines.append(f"   Technique: {r.technique}")
        if r.payload_example:
            lines.append(f"   Example: {r.payload_example}")
        if r.snippet:
            lines.append(f"   Summary: {r.snippet[:200]}")
        lines.append("")

    return "\n".join(lines)
