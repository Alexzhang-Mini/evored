# BypassEvo v3.0 — AI-Driven WAF Bypass Research & Exploit Framework

Autonomous two-stage attack pipeline: **WAF Bypass** (discover evasion techniques) then **Exploit** (confirm vulnerabilities through the bypass).

## Architecture — Two-Stage Pipeline

```
                        ┌─────────────────────────────────────────────┐
                        │           Stage 1: WAF Bypass               │
                        │                                             │
  recon ──→ waf_detect ─┤  bypass_generate ──→ bypass_execute ──┐    │
                        │       ▲                    │          │    │
                        │       │           ┌────────┘          │    │
                        │       │           ▼                   │    │
                        │  ga_bypass_evolve ◄── block_analyze   │    │
                        │       │           (binary search +    │    │
                        │       │            LLM inference)     │    │
                        │       └───────────────────────────────┘    │
                        │                        │                    │
                        │              bypass_success?                │
                        └────────────────────────┼────────────────────┘
                                                 │
                        ┌────────────────────────▼────────────────────┐
                        │           Stage 2: Exploit                  │
                        │                                             │
                        │  exploit_generate ──→ exploit_execute ──┐   │
                        │       ▲                    │           │   │
                        │       │                    │           │   │
                        │  ga_exploit_evolve ◄───────┘           │   │
                        │       │                                │   │
                        │       └── exploit_success? ──→ DONE    │   │
                        └─────────────────────────────────────────────┘
```

**Stage 1** focuses purely on WAF evasion — finding payloads that pass the WAF without triggering blocks. Uses binary search to pinpoint trigger segments, LLM inference to reverse-engineer rules, and GA evolution to discover novel bypasses.

**Stage 2** takes a confirmed bypass payload and optimizes it for actual exploitation (SQLi extraction, XSS execution, command injection). Only entered after bypass verification (anti-false-positive re-testing).

## Rate Limit System

Per-stage rate limiting with exponential backoff and smart jitter:

| Feature | Description |
|---|---|
| **Exponential Backoff** | On 429/block: `delay * multiplier^level`, capped at `max_backoff` |
| **Smart Jitter** | Uniform (legacy) or Gaussian distribution `[base*0.6, base*1.4]` |
| **Per-Stage Config** | Bypass stage can be aggressive, Exploit stage conservative |
| **Real-time Visualization** | Current delay, backoff level, consecutive blocks shown in UI |
| **Config Persistence** | Settings saved to localStorage, restored on reload |

## Quick Start

> 详细使用指南见 [docs/USAGE.md](docs/USAGE.md)

### Docker (Recommended)

```bash
cd evored
docker-compose up -d
```

This starts:
- **Frontend** at `http://localhost:3000` (Next.js cyberpunk UI)
- **Backend** at `http://localhost:8000` (FastAPI + LangGraph)
- **DVWA** at `http://localhost:8080` (target)
- **Coraza WAF** at ports 9081/9083/9085 (Paranoia Levels 1/3/5)

### Manual Setup

```bash
# Backend
cd evored
pip install -r requirements.txt
uvicorn backend.app:app --host 0.0.0.0 --port 8000

# Frontend
cd evored/frontend
npm install
npm run dev
```

### DVWA Setup

1. Open `http://localhost:8080` → Login (admin/password)
2. Create/Reset Database → Set Security to **Low**
3. Copy `PHPSESSID` from browser cookies (F12 → Application → Cookies)

### LLM Setup

**Ollama (local):**
```bash
ollama pull qwen2.5:7b
```

**Or any OpenAI-compatible API:**
- DeepSeek: `https://api.deepseek.com/v1`
- LM Studio: `http://localhost:1234/v1`

## WAF Bypass Analysis Engine

The `WAFBlockAnalyzer` (`tools/waf_analyzer.py`) runs a 4-step pipeline:

1. **Verify Block** — Confirm the payload is actually blocked (not a network error)
2. **Binary Search** — Recursively split the payload to find the minimal trigger segment
3. **Boundary Probes** — Test 15+ encoding variations around triggers:
   - Case variations, comment injection
   - URL/double-URL encoding
   - Unicode fullwidth, overlong UTF-8
   - JS escape sequences, HTML entities
   - Base64, hex, mixed encoding
   - Null bytes, whitespace alternatives
4. **LLM Rule Inference** — Analyze probe results to reverse-engineer the WAF rule

Output: structured `BlockAnalysis` with trigger segments, rule type, blind spots, and suggested bypasses — fed directly into the GA for targeted evolution.

## Agents

| Agent | Stage | Role |
|---|---|---|
| **Generator** | Both | Creates payloads from seed knowledge + RAG memory |
| **Executor** | Both | Sends HTTP requests, detects SQL errors / XSS reflection |
| **Reflector** | Both | Analyzes failures, identifies filters, fingerprints DBMS |
| **Mutator** | Both | Three-layer evolution: GA engine + LLM creative + rule-based |
| **WAFBlockAnalyzer** | Stage 1 | Binary search + LLM rule inference on blocked payloads |

## Genetic Algorithm

Each payload is an `Individual` with fitness scoring:

- **Bypass fitness**: 0.6 base (WAF passed) + 0.4 * exploit indicators
- **Exploit fitness**: Based on SQL error detection, XSS reflection, response anomalies
- **Anti-false-positive**: Bypassed payloads re-tested N times before confirmation

GA operators: crossover, tournament selection, WAF-aware mutation weights.

## Docker Services

| Service | Port | Description |
|---|---|---|
| `frontend` | 3000 | Next.js 14 cyberpunk dashboard |
| `backend` | 8000 | FastAPI + LangGraph engine |
| `dvwa` | 8080 | Damn Vulnerable Web Application |
| `coraza-pl1` | 9081 | Coraza WAF — Paranoia Level 1 |
| `coraza-pl3` | 9083 | Coraza WAF — Paranoia Level 3 |
| `coraza-pl5` | 9085 | Coraza WAF — Paranoia Level 5 |

## Project Structure

```
evored/
├── graph.py                # LangGraph two-stage state machine
├── config.py               # All configuration dataclasses
├── prompts.py              # System prompts for all agents + stages
├── llm.py                  # OpenAI-compatible API client
├── agents/
│   ├── orchestrator.py     # Multi-target attack coordination
│   ├── generator.py        # Payload generation + RAG enrichment
│   ├── executor.py         # Scanner wrapper
│   ├── reflector.py        # Failure analysis
│   └── mutator.py          # Three-layer mutation (GA + LLM + rules)
├── tools/
│   ├── scanner.py          # HTTP scanner + rate limiting + backoff
│   ├── waf_analyzer.py     # Binary search + LLM rule inference
│   ├── waf_detector.py     # WAF fingerprinting (8 WAFs)
│   ├── waf_report.py       # Markdown report generator
│   ├── payload_mutator.py  # GA engine + deterministic mutations
│   ├── memory.py           # ChromaDB RAG memory
│   └── proxy_bridge.py     # Burp/ZAP integration
├── backend/
│   ├── app.py              # FastAPI REST + WebSocket
│   ├── models.py           # Pydantic request/response models
│   └── ws_manager.py       # WebSocket connection manager
├── frontend/
│   └── src/
│       ├── app/page.tsx    # Main page with state management
│       ├── components/
│       │   ├── Sidebar.tsx           # Configuration panel
│       │   └── tabs/
│       │       ├── AttackConsole.tsx  # Main attack dashboard
│       │       ├── EvolutionLab.tsx   # GA visualization
│       │       └── IntelCenter.tsx    # Intel + bypass techniques
│       └── lib/
│           ├── types.ts    # TypeScript interfaces
│           └── api.ts      # API + WebSocket client
├── docker-compose.yml      # Full stack: backend + frontend + DVWA + Coraza
├── waf-config/             # Coraza WAF configurations (PL1/3/5)
└── requirements.txt
```

## DVWA Attack Presets

| Preset | Endpoint | Param | Method | Vuln |
|---|---|---|---|---|
| DVWA SQLi GET | `/vulnerabilities/sqli` | `id` | GET | SQLi |
| DVWA SQLi POST | `/vulnerabilities/sqli` | `id` | POST | SQLi |
| DVWA XSS Reflected | `/vulnerabilities/xss_r` | `name` | GET | XSS |
| DVWA XSS Stored | `/vulnerabilities/xss_s` | `txtName` | POST | XSS |
| DVWA CMDi | `/vulnerabilities/exec` | `ip` | POST | CMDi |
| Juice Shop Search | `/rest/products/search` | `q` | GET | SQLi |
