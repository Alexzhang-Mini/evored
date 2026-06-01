"""BypassEvo FastAPI Backend — REST + WebSocket for real-time attack streaming."""

import sys
import os
import re
import uuid
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    BypassEvoConfig, LLMConfig, TargetConfig, AgentConfig,
    GAConfig, MemoryConfig, ProxyConfig, FastTestConfig, WebSearchConfig,
)
from graph import build_graph, create_initial_state
from backend.models import AttackRequest
from backend.ws_manager import manager


# ── Lifespan ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="BypassEvo API", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Attack state (in-memory, single session) ────────────────────────────

def _default_ga_stats():
    return {"generation": 0, "best_fitness": 0, "avg_fitness": 0, "worst_fitness": 0, "mutation_rate": 0, "population_size": 0}

def _default_ga_history():
    return [{"generation": 0, "best_fitness": 0, "avg_fitness": 0, "worst_fitness": 0, "best_payload": "", "population_size": 0}]

def _default_memory_stats():
    return {"total_entries": 0, "successes": 0, "failures": 0, "success_rate": 0, "session_id": "", "chromadb": False}

def _default_rate_limit_status():
    return {"current_delay": 0, "base_delay": 0, "backoff_level": 0, "consecutive_blocks": 0, "max_consecutive_blocks": 10, "is_backing_off": False}

def _default_injection_fingerprint():
    return {"is_injectable": False, "quote_type": "unknown", "closure_char": "", "comment_style": "--", "dbms_hint": "unknown", "confidence": 0}

def _fresh_attack_state():
    return {
        "running": False,
        "completed": False,
        "success": False,
        "logs": [],
        "evolution_tree": {},
        "history": [],
        "current_phase": "idle",
        "stage": "idle",
        "iteration": 0,
        "ga_stats": _default_ga_stats(),
        "ga_history": _default_ga_history(),
        "population": [],
        "waf_result": {"detected": False, "waf_name": "", "confidence": 0, "indicators": [], "bypass_strategies": []},
        "memory_stats": _default_memory_stats(),
        "final_result": None,
        # Two-stage pipeline
        "bypass_success": False,
        "bypass_payload": "",
        "bypass_technique": "",
        "bypass_techniques": [],
        "bypass_history": [],
        "block_analysis": None,
        "block_history": [],
        "report": "",
        # Rate limit status
        "rate_limit_status": _default_rate_limit_status(),
        # Injection fingerprint (from recon)
        "injection_fingerprint": _default_injection_fingerprint(),
        # Connection error tracking
        "connection_errors": 0,
        # Baseline response for fitness evaluation
        "baseline_snippet": "",
        # Smart stopping
        "consecutive_server_errors": 0,
        "consecutive_very_low": 0,
        "stop_reason": "",
        "paused": False,
        # Strategy rotation tracking
        "consecutive_low_fitness": 0,
        "current_strategy": "error",
        # Recon deep analysis
        "recon_report": "",
        "current_analysis": "",
        "recommended_strategy": "unknown",
        # Extracted data from successful exploit
        "extracted_data": "",
        # Attack context (for report generation)
        "vuln_type": "sqli",
        "target_url": "",
        "endpoint": "",
        # Hypothesis-driven bypass
        "hypotheses": [],
        "hypothesis_history": [],
        "inferred_rules": [],
        "reasoning_chain": {},
    }

_attack_state = _fresh_attack_state()

# Control flags for stop/pause — asyncio.Event for cross-thread signaling
_stop_event = asyncio.Event()
_resume_event = asyncio.Event()
_should_pause = False
# Lock to prevent concurrent start_attack
_attack_lock = asyncio.Lock()

PRESETS = {
    # SQL Injection scenarios
    "SQLi_GET_Param": {"endpoint": "/search", "param": "id", "method": "GET", "vuln_type": "sqli"},
    "SQLi_POST_Login": {"endpoint": "/login", "param": "username", "method": "POST", "vuln_type": "sqli"},
    "SQLi_POST_Search": {"endpoint": "/search", "param": "q", "method": "POST", "vuln_type": "sqli"},
    "SQLi_JSON_API": {"endpoint": "/api/query", "param": "filter", "method": "POST", "vuln_type": "sqli"},
    # XSS scenarios
    "XSS_Reflected_GET": {"endpoint": "/search", "param": "q", "method": "GET", "vuln_type": "xss"},
    "XSS_Stored_POST": {"endpoint": "/comment", "param": "content", "method": "POST", "vuln_type": "xss"},
    "XSS_DOM_Fragment": {"endpoint": "/page", "param": "name", "method": "GET", "vuln_type": "xss"},
    # Command Injection scenarios
    "CMDi_POST_Exec": {"endpoint": "/ping", "param": "host", "method": "POST", "vuln_type": "cmdi"},
    "CMDi_GET_Lookup": {"endpoint": "/lookup", "param": "domain", "method": "GET", "vuln_type": "cmdi"},
}


# ── REST endpoints ──────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.0", "ws_clients": manager.active_count}


@app.get("/api/presets")
async def get_presets():
    return [{"name": k, **v} for k, v in PRESETS.items()]


@app.get("/api/state")
async def get_state():
    """Return current attack state (polled by frontend on connect)."""
    return _attack_state


@app.post("/api/attack")
async def start_attack(req: AttackRequest):
    """Start an attack — streams results over WebSocket."""
    async with _attack_lock:
        if _attack_state["running"]:
            return {"error": "Attack already running"}

        config = _build_config(req)

        # Reset state using fresh template
        _attack_state.update(_fresh_attack_state())
        _attack_state["running"] = True
        _attack_state["vuln_type"] = req.vuln_type
        _attack_state["target_url"] = config.target.base_url
        _attack_state["endpoint"] = req.endpoint

    # Run attack in background (lock released)
    asyncio.create_task(_run_attack(config, req))

    return {"status": "started"}


@app.post("/api/reset")
async def reset():
    """Reset attack state."""
    _attack_state.update(_fresh_attack_state())
    await manager.broadcast({"type": "state", "data": _attack_state})
    return {"status": "reset"}


@app.post("/api/stop")
async def stop_attack():
    """Signal the running attack to stop."""
    if not _attack_state["running"]:
        return {"error": "No attack running"}
    _stop_event.set()
    _attack_state["logs"].append("[SYSTEM] Stop requested by user...")
    await manager.broadcast({"type": "state", "data": _build_broadcast_state()})
    return {"status": "stopping"}


@app.post("/api/pause")
async def pause_attack():
    """Signal the running attack to pause."""
    global _should_pause
    if not _attack_state["running"]:
        return {"error": "No attack running"}
    _should_pause = True
    _resume_event.clear()
    _attack_state["logs"].append("[SYSTEM] Pause requested by user...")
    _attack_state["paused"] = True
    await manager.broadcast({"type": "state", "data": _build_broadcast_state()})
    return {"status": "pausing"}


@app.post("/api/resume")
async def resume_attack():
    """Resume a paused attack."""
    global _should_pause
    if not _attack_state["paused"]:
        return {"error": "Attack not paused"}
    _should_pause = False
    _resume_event.set()
    _attack_state["paused"] = False
    _attack_state["logs"].append("[SYSTEM] Resuming attack...")
    await manager.broadcast({"type": "state", "data": _build_broadcast_state()})
    return {"status": "resumed"}


class ParseRequestInput(BaseModel):
    raw_request: str


@app.post("/api/parse-request")
async def parse_raw_request(req: ParseRequestInput):
    """Parse a raw HTTP request (Burp/ZAP format) or bare URL into structured fields.

    Handles:
    - Standard HTTP request lines: GET /path HTTP/1.1
    - Bare URLs: http://host/path?query#fragment
    - Fragments (#) are auto-stripped with a warning
    """
    try:
        lines = req.raw_request.strip().split("\n")
        if not lines:
            return {"error": "Empty request"}

        # Parse request line: METHOD /path HTTP/1.1
        first_line = lines[0].strip()
        parts = first_line.split()

        # Detect bare URL and convert to GET request
        if len(parts) == 1 and re.match(r'^https?://', parts[0], re.IGNORECASE):
            first_line = f"GET {parts[0]} HTTP/1.1"
            parts = first_line.split()

        if len(parts) < 2:
            return {"error": f"Invalid request line: {first_line}. Expected format: GET /path HTTP/1.1 or a full URL like http://host/path"}

        method = parts[0].upper()
        path = parts[1]

        # Strip fragment (#...) from path — HTTP requests never send fragments
        fragment_stripped = False
        if "#" in path:
            path = path.split("#")[0]
            fragment_stripped = True

        # Parse headers
        headers = {}
        body = ""
        header_end = False
        for line in lines[1:]:
            stripped = line.strip()
            if not stripped and not header_end:
                header_end = True
                continue
            if header_end:
                body += line + "\n"
            elif ":" in stripped:
                key, val = stripped.split(":", 1)
                headers[key.strip()] = val.strip()

        body = body.strip()

        # Extract host from headers
        host = headers.get("Host", headers.get("host", ""))
        scheme = "https" if "443" in host else "http"
        base_url = f"{scheme}://{host}" if host else ""

        # Parse query params from path
        endpoint = path
        params = {}
        if "?" in path:
            endpoint, query_str = path.split("?", 1)
            for pair in query_str.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v

        # Parse body params if POST
        body_params = {}
        if method == "POST" and body:
            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            if "application/x-www-form-urlencoded" in content_type:
                for pair in body.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        body_params[k] = v
            elif "application/json" in content_type:
                import json as _json
                try:
                    body_params = _json.loads(body)
                except Exception:
                    pass

        # Guess main param (first one, or 'id'/'q' if present)
        all_params = {**params, **body_params}
        main_param = "q"
        for candidate in ["id", "q", "search", "user", "name"]:
            if candidate in all_params:
                main_param = candidate
                break
        if not main_param and all_params:
            main_param = list(all_params.keys())[0]

        # Clean base_url — strip trailing slash and path
        if base_url:
            from urllib.parse import urlparse as _urlparse
            _p = _urlparse(base_url)
            base_url = f"{_p.scheme}://{_p.netloc}"

        # Normalize endpoint — ensure leading slash
        if endpoint and not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        extra = {k: v for k, v in all_params.items() if k != main_param}

        result = {
            "method": method,
            "base_url": base_url,
            "endpoint": endpoint,
            "param": main_param,
            "params": all_params,
            "headers": headers,
            "body": body,
            "extra_params": extra,
            "cookie": headers.get("Cookie", headers.get("cookie", "")),
            "preview": {
                "full_url": f"{base_url}{endpoint}",
                "param_count": len(all_params),
                "has_body": bool(body),
                "header_count": len(headers),
            },
        }
        if fragment_stripped:
            result["warning"] = "Fragment (#) was automatically stripped from URL"
        return result
    except Exception as e:
        return {"error": f"Failed to parse request: {str(e)}"}


class ManualTestRequest(BaseModel):
    payload: str
    endpoint: str = "/search"
    param: str = "q"
    method: str = "GET"
    base_url: str = "http://192.168.1.100"
    timeout: int = 10
    php_sessid: str = ""
    extra_params: dict = {}


class EnrichKBRequest(BaseModel):
    pattern: str
    dbms: str = "generic"
    category: str = "syntax"
    confidence: float = 0.80
    description: str = ""


@app.post("/api/test-payload")
async def test_payload(req: ManualTestRequest):
    """Execute a single payload against the target for quick verification."""
    from tools.scanner import Scanner, ScanResult
    from agents.executor import ExecutorAgent
    import time as _time

    try:
        scanner = Scanner(req.base_url, req.timeout, php_sessid=req.php_sessid)
        executor = ExecutorAgent(scanner)

        start = _time.time()
        result = executor.execute(
            payload=req.payload,
            endpoint=req.endpoint,
            param=req.param,
            method=req.method,
            data=req.extra_params if req.extra_params else None,
        )
        elapsed = _time.time() - start

        # Also run scanner analysis on the response
        scan_result = ScanResult(
            url="", method=req.method,
            status_code=result.get("response_code", 0),
            response_text=result.get("response_snippet", ""),
            response_time=result.get("response_time", elapsed),
            headers={}, payload=req.payload,
        )
        is_blocked = scanner.is_blocked(scan_result)

        # Run KB matching on response
        from tools.sql_error_kb import get_kb
        kb = get_kb()
        response_text = result.get("response_snippet", "")
        kb_matches = kb.match(response_text)
        highlighted_preview, matched_keywords = kb.highlight_matches(response_text, max_preview=2000)
        smart_suggestions = kb.smart_extract(response_text)

        return {
            "success": result.get("success", False),
            "blocked": is_blocked,
            "status_code": result.get("response_code", 0),
            "response_time": result.get("response_time", elapsed),
            "evidence": result.get("evidence", ""),
            "indicators": result.get("indicators", []),
            "response_snippet": response_text[:2000],
            "response_preview_highlighted": highlighted_preview,
            "confidence": result.get("confidence", 0),
            "kb_matches": [{"description": d, "confidence": c, "dbms": db} for d, c, db in kb_matches],
            "matched_keywords": matched_keywords,
            "smart_suggestions": smart_suggestions,
        }
    except Exception as e:
        return {
            "success": False,
            "blocked": False,
            "status_code": 0,
            "response_time": 0,
            "evidence": f"Error: {str(e)}",
            "indicators": [],
            "response_snippet": "",
            "confidence": 0,
        }


@app.post("/api/enrich-kb")
async def enrich_kb(req: EnrichKBRequest):
    """Add a user-enriched pattern to the SQL Error Knowledge Base."""
    from tools.sql_error_kb import get_kb
    kb = get_kb()
    ok = kb.add_pattern(
        pattern=req.pattern,
        dbms=req.dbms,
        category=req.category,
        confidence=req.confidence,
        description=req.description,
    )
    if ok:
        return {"status": "added", "stats": kb.get_stats()}
    return {"error": "Invalid regex pattern"}


@app.get("/api/kb-stats")
async def kb_stats():
    """Return SQL Error KB statistics."""
    from tools.sql_error_kb import get_kb
    return get_kb().get_stats()


@app.post("/api/memory-cleanup")
async def memory_cleanup():
    """Clean up old low-value entries from attack memory to maintain RAG quality."""
    from tools.memory import AttackMemory
    try:
        mem = AttackMemory(persist_dir="./bypassevo_chroma_db")
        result = mem.cleanup_stale(keep_last_n_sessions=10, max_entries=5000)
        return {"status": "ok", **result}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── WebSocket ───────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # Send current state on connect
    try:
        await websocket.send_json({"type": "state", "data": _attack_state})
    except Exception:
        pass
    try:
        while True:
            # Keep alive — client can send ping/pong
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


# ── Internal ────────────────────────────────────────────────────────────

def _build_config(req: AttackRequest) -> BypassEvoConfig:
    from config import WAFAnalyzerConfig, RateLimitConfig
    llm_cfg = LLMConfig(**(req.llm.model_dump() if req.llm else {}))
    target_cfg = TargetConfig(**(req.target.model_dump() if req.target else {}))
    ga_cfg = GAConfig(**(req.ga.model_dump() if req.ga else {}))
    proxy_cfg = ProxyConfig(**(req.proxy.model_dump() if req.proxy else {}))
    waf_analyzer_cfg = WAFAnalyzerConfig(**(req.waf_analyzer.model_dump() if req.waf_analyzer else {}))
    rate_limit_cfg = RateLimitConfig(**(req.rate_limit.model_dump() if req.rate_limit else {}))
    bypass_rl = RateLimitConfig(**(req.bypass_rate_limit.model_dump())) if req.bypass_rate_limit else None
    exploit_rl = RateLimitConfig(**(req.exploit_rate_limit.model_dump())) if req.exploit_rate_limit else None
    fast_test_cfg = FastTestConfig(**(req.fast_test.model_dump())) if req.fast_test else FastTestConfig()
    web_search_cfg = WebSearchConfig(**(req.web_search.model_dump())) if req.web_search else WebSearchConfig()
    return BypassEvoConfig(
        llm=llm_cfg, target=target_cfg,
        agent=AgentConfig(max_iterations=req.max_iterations),
        ga=ga_cfg,
        memory=MemoryConfig(enabled=req.memory_enabled),
        proxy=proxy_cfg,
        waf_analyzer=waf_analyzer_cfg,
        rate_limit=rate_limit_cfg,
        bypass_rate_limit=bypass_rl,
        exploit_rate_limit=exploit_rl,
        web_search=web_search_cfg,
        fast_test=fast_test_cfg,
    )


async def _run_attack(config: BypassEvoConfig, req: AttackRequest):
    """Execute the LangGraph attack loop and broadcast state via WebSocket.

    Runs the blocking graph.stream() in a thread so that time.sleep() in
    scanner/llm doesn't freeze the event loop (WS broadcasts, stop/pause).
    Steps are passed from the worker thread to the async loop via a queue.
    """
    global _should_pause
    _stop_event.clear()
    _resume_event.set()
    _should_pause = False

    _SENTINEL = object()  # Marks end of stream

    try:
        graph = build_graph(config)
        initial_state = create_initial_state(
            target_url=config.target.base_url,
            endpoint=req.endpoint,
            param=req.param,
            method=req.method,
            vuln_type=req.vuln_type,
            max_iterations=req.max_iterations,
            extra_params=config.target.extra_params,
        )

        # Queue bridges blocking graph iterator to async loop
        step_queue: asyncio.Queue = asyncio.Queue()

        def _producer():
            """Run in thread — feeds graph steps into the async queue."""
            try:
                for step in graph.stream(initial_state, stream_mode="values"):
                    loop.call_soon_threadsafe(step_queue.put_nowait, step)
            except Exception as e:
                loop.call_soon_threadsafe(step_queue.put_nowait, e)
            finally:
                loop.call_soon_threadsafe(step_queue.put_nowait, _SENTINEL)

        loop = asyncio.get_running_loop()
        graph_task = asyncio.create_task(asyncio.to_thread(_producer))

        step_count = 0
        try:
            while True:
                # Wait for next step with timeout so stop/pause are checked
                try:
                    step = await asyncio.wait_for(step_queue.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    # No step yet — check stop/pause
                    if _stop_event.is_set():
                        _attack_state["logs"].append("[SYSTEM] Attack stopped by user.")
                        _attack_state["stop_reason"] = "user_stop"
                        _attack_state["completed"] = True
                        break
                    if _should_pause:
                        _attack_state["paused"] = True
                        _attack_state["logs"].append("[SYSTEM] Attack paused.")
                        await manager.broadcast({"type": "state", "data": _build_broadcast_state()})
                        done, _ = await asyncio.wait(
                            [asyncio.create_task(_stop_event.wait()),
                             asyncio.create_task(_resume_event.wait())],
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if _stop_event.is_set():
                            _attack_state["logs"].append("[SYSTEM] Attack stopped while paused.")
                            _attack_state["stop_reason"] = "user_stop"
                            _attack_state["completed"] = True
                            break
                        _attack_state["paused"] = False
                        _attack_state["logs"].append("[SYSTEM] Attack resumed.")
                        await manager.broadcast({"type": "state", "data": _build_broadcast_state()})
                    continue

                # Handle sentinel or exception from producer
                if step is _SENTINEL:
                    break
                if isinstance(step, Exception):
                    raise step

                # Process the step
                step_count += 1
                _sync_state(step)

                # Check stop signal
                if _stop_event.is_set():
                    _attack_state["logs"].append("[SYSTEM] Attack stopped by user.")
                    _attack_state["stop_reason"] = "user_stop"
                    _attack_state["completed"] = True
                    break

                # Check pause signal
                if _should_pause or step.get("paused"):
                    _attack_state["paused"] = True
                    _attack_state["logs"].append("[SYSTEM] Attack paused.")
                    await manager.broadcast({"type": "state", "data": _build_broadcast_state()})
                    done, _ = await asyncio.wait(
                        [asyncio.create_task(_stop_event.wait()),
                         asyncio.create_task(_resume_event.wait())],
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if _stop_event.is_set():
                        _attack_state["logs"].append("[SYSTEM] Attack stopped while paused.")
                        _attack_state["stop_reason"] = "user_stop"
                        _attack_state["completed"] = True
                        break
                    _attack_state["paused"] = False
                    _attack_state["logs"].append("[SYSTEM] Attack resumed.")

                # Broadcast state
                await manager.broadcast({"type": "state", "data": _build_broadcast_state()})

                if step.get("phase") == "done" or step.get("success"):
                    break
                if step_count > req.max_iterations * 10:
                    _attack_state["logs"].append("[SYSTEM] Safety limit reached.")
                    break
        finally:
            # Cancel the producer thread if still running (user stopped / error)
            if not graph_task.done():
                graph_task.cancel()

    except Exception as e:
        import traceback
        _attack_state["logs"].append(f"[ERROR] {str(e)}")
        tb = traceback.format_exc()
        if len(tb) > 500:
            _attack_state["logs"].append(f"[ERROR-TRACE] {tb[:300]}...{tb[-200:]}")
        else:
            _attack_state["logs"].append(f"[ERROR-TRACE] {tb}")
        _attack_state["completed"] = True
    finally:
        _attack_state["running"] = False
        _should_pause = False

    # Final broadcast
    await manager.broadcast({"type": "state", "data": _build_broadcast_state()})


def _build_broadcast_state() -> dict:
    """Build a copy of _attack_state for broadcasting, with log truncation.

    Truncates logs to the last 200 entries to prevent unbounded growth
    in WebSocket messages over long-running attacks.
    """
    state = dict(_attack_state)
    logs = state.get("logs", [])
    if len(logs) > 200:
        state["logs"] = ["[SYSTEM] ... (earlier logs truncated) ..."] + logs[-200:]
    return state


def _sync_state(result: dict):
    """Sync LangGraph step output to _attack_state."""
    # Key remapping: graph state key -> frontend state key
    _remap = {"log": "logs", "phase": "current_phase"}
    for key in ["log", "history", "evolution_tree", "iteration", "phase",
                 "ga_stats", "ga_history", "population", "waf_result", "memory_stats",
                 "stage", "bypass_success", "bypass_payload", "bypass_technique",
                 "bypass_techniques", "bypass_history", "block_analysis", "block_history",
                 "report", "vuln_type", "target_url", "endpoint", "rate_limit_status",
                 "injection_fingerprint", "connection_errors", "baseline_snippet",
                 "consecutive_server_errors", "consecutive_very_low",
                 "stop_reason", "paused",
                 "consecutive_low_fitness", "current_strategy",
                 "recon_report", "current_analysis", "recommended_strategy",
                 "extracted_data",
                 "hypotheses", "hypothesis_history", "inferred_rules",
                 "reasoning_chain", "web_search_results", "strategy_plan"]:
        if key in result:
            _attack_state[_remap.get(key, key)] = result[key]
    if result.get("success"):
        _attack_state["success"] = True
        _attack_state["completed"] = True
        exec_result = result.get("execution_result") or {}
        _attack_state["final_result"] = {
            "success": exec_result.get("success", True),
            "evidence": exec_result.get("evidence", "Vulnerability confirmed"),
            "payload": exec_result.get("payload", ""),
            "response_code": exec_result.get("response_code"),
            "response_snippet": exec_result.get("response_snippet", ""),
            "response_time": exec_result.get("response_time", 0),
        }
    if result.get("phase") == "done":
        _attack_state["completed"] = True
        # Auto-generate report
        if not _attack_state.get("report"):
            try:
                from tools.waf_report import generate_report
                _attack_state["report"] = generate_report(
                    waf_result=_attack_state.get("waf_result", {}),
                    bypass_techniques=_attack_state.get("bypass_techniques", []),
                    exploit_result=_attack_state.get("final_result", {}),
                    history=_attack_state.get("history", []),
                    ga_stats=_attack_state.get("ga_stats", {}),
                    vuln_type=_attack_state.get("vuln_type", result.get("vuln_type", "sqli")),
                    target_url=_attack_state.get("target_url", result.get("target_url", "")),
                    endpoint=_attack_state.get("endpoint", result.get("endpoint", "")),
                )
            except Exception:
                pass
