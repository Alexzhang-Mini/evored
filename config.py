"""BypassEvo Configuration."""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMConfig:
    # Unified OpenAI-compatible API (works with Ollama /v1, vLLM, LM Studio, DeepSeek, etc.)
    api_base: str = "https://api.deepseek.com"
    api_key: str = ""  # Set via env var BYPASSEVO_API_KEY or pass in request
    model: str = "deepseek-chat"
    temperature: float = 0.7
    max_tokens: int = 9999
    max_parallel_llm_calls: int = 3  # Concurrency limit for async LLM calls

    def __post_init__(self):
        if not self.api_key:
            self.api_key = os.environ.get("BYPASSEVO_API_KEY", "")


@dataclass
class TargetConfig:
    base_url: str = "http://192.168.1.100"
    timeout: int = 10
    php_sessid: str = ""
    security_level: str = "low"
    extra_params: dict = field(default_factory=dict)  # Extra POST params (e.g., {"_token": "xxx", "password": "123"})


@dataclass
class RateLimitConfig:
    """Anti-ban and rate limiting settings."""
    request_delay: float = 1.0        # Seconds between each HTTP request
    delay_jitter: float = 0.5         # Random jitter added to delay (0-N seconds)
    backoff_on_429: float = 30.0      # Seconds to wait when rate-limited (429)
    backoff_on_block: float = 5.0     # Seconds to wait when WAF blocks IP
    max_consecutive_blocks: int = 10  # Pause after N consecutive blocks
    block_pause: float = 60.0         # Seconds to pause on consecutive block limit
    verify_bypass_attempts: int = 3   # Times to re-test a "bypassed" payload (anti-false-positive)
    # Exponential backoff
    backoff_multiplier: float = 2.0   # Multiply delay by this on each consecutive block/429
    max_backoff: float = 120.0        # Maximum backoff delay in seconds
    # Jitter distribution: "uniform" (legacy) or "normal" (gaussian)
    jitter_distribution: str = "uniform"


@dataclass
class GAConfig:
    """Genetic Algorithm parameters."""
    population_size: int = 12
    elite_count: int = 2
    tournament_size: int = 3
    crossover_rate: float = 0.7
    base_mutation_rate: float = 0.15
    max_generations: int = 10


@dataclass
class MemoryConfig:
    """ChromaDB RAG memory settings."""
    persist_dir: str = "./bypassevo_chroma_db"
    enabled: bool = True


@dataclass
class ProxyConfig:
    """Burp/ZAP integration settings."""
    source: str = "auto"        # auto | burp | zap | burp_xml | none
    burp_url: str = "http://127.0.0.1:1337"
    zap_url: str = "http://127.0.0.1:8080"
    zap_api_key: str = ""
    burp_xml_path: str = ""     # Path to Burp XML export


@dataclass
class AgentConfig:
    max_iterations: int = 15
    max_reflections: int = 5
    mutation_rate: float = 0.3
    population_size: int = 12


@dataclass
class WAFAnalyzerConfig:
    """WAF block analyzer settings."""
    binary_search_max_depth: int = 6
    boundary_probe_limit: int = 20
    enabled: bool = True


@dataclass
class FastTestConfig:
    """Fast Test Mode — reduces delays and skips heavy analysis for quick iteration."""
    enabled: bool = False
    bypass_delay: float = 0.2          # Override request_delay for bypass stage
    exploit_delay: float = 0.5         # Override request_delay for exploit stage
    skip_binary_search: bool = True    # Skip WAF binary search analysis
    quick_verify_count: int = 1        # Bypass verification attempts (vs normal 3)
    lightweight_recon: bool = True     # Skip deep_recon, use basic probe only
    skip_analyzer_first_n: int = 3     # Skip block_analyze for first N blocked payloads


@dataclass
class StealthConfig:
    """Behavioral stealth settings for evading WAF behavioral analysis."""
    enabled: bool = True
    # Mix normal requests between attack payloads
    decoy_ratio: float = 0.3          # Send 1 normal request per ~3 attack requests
    decoy_params: list = field(default_factory=lambda: ["test", "1", "hello", "page1"])
    # Randomize User-Agent per session
    rotate_user_agent: bool = True
    # Add random Referer headers
    random_referer: bool = True
    # Randomize request order (don't send payloads in predictable sequence)
    shuffle_payloads: bool = True


@dataclass
class WebSearchConfig:
    """Online search for known WAF bypass techniques."""
    enabled: bool = True
    max_results: int = 5            # Max search results per query
    timeout: int = 10               # Search request timeout (seconds)
    search_locale: str = "en-us"    # Search language/locale
    cache_ttl: int = 3600           # Cache results for N seconds (same WAF+session)


@dataclass
class BypassEvoConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    target: TargetConfig = field(default_factory=TargetConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    ga: GAConfig = field(default_factory=GAConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    waf_analyzer: WAFAnalyzerConfig = field(default_factory=WAFAnalyzerConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    # Per-stage overrides (None = use global rate_limit)
    bypass_rate_limit: RateLimitConfig | None = None
    exploit_rate_limit: RateLimitConfig | None = None
    web_search: WebSearchConfig = field(default_factory=WebSearchConfig)
    fast_test: FastTestConfig = field(default_factory=FastTestConfig)
    stealth: StealthConfig = field(default_factory=StealthConfig)
