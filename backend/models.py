"""Pydantic models for API request/response."""

from pydantic import BaseModel, Field
from typing import Optional


class LLMConfigRequest(BaseModel):
    api_base: str = "https://api.deepseek.com"
    api_key: str = ""
    model: str = "deepseek-chat"
    temperature: float = 0.7
    max_tokens: int = 9999


class TargetConfigRequest(BaseModel):
    base_url: str = "http://192.168.1.100"
    timeout: int = 10
    php_sessid: str = ""
    security_level: str = "low"
    extra_params: dict = {}


class GAConfigRequest(BaseModel):
    population_size: int = 12
    elite_count: int = 2
    tournament_size: int = 3
    crossover_rate: float = 0.7
    base_mutation_rate: float = 0.15
    max_generations: int = 10


class ProxyConfigRequest(BaseModel):
    source: str = "none"
    burp_url: str = "http://127.0.0.1:1337"
    zap_url: str = "http://127.0.0.1:8080"
    zap_api_key: str = ""
    burp_xml_path: str = ""


class WAFAnalyzerConfigRequest(BaseModel):
    binary_search_max_depth: int = 6
    boundary_probe_limit: int = 20
    enabled: bool = True


class RateLimitConfigRequest(BaseModel):
    request_delay: float = 1.0
    delay_jitter: float = 0.5
    backoff_on_429: float = 30.0
    backoff_on_block: float = 5.0
    max_consecutive_blocks: int = 10
    block_pause: float = 60.0
    verify_bypass_attempts: int = 3
    backoff_multiplier: float = 2.0
    max_backoff: float = 120.0
    jitter_distribution: str = "uniform"


class FastTestConfigRequest(BaseModel):
    enabled: bool = False
    bypass_delay: float = 0.2
    exploit_delay: float = 0.5
    skip_binary_search: bool = True
    quick_verify_count: int = 1
    lightweight_recon: bool = True
    skip_analyzer_first_n: int = 3


class WebSearchConfigRequest(BaseModel):
    enabled: bool = True
    max_results: int = 5
    timeout: int = 10
    search_locale: str = "en-us"
    cache_ttl: int = 3600


class AttackRequest(BaseModel):
    endpoint: str = "/search"
    param: str = "q"
    method: str = "GET"
    vuln_type: str = "sqli"
    max_iterations: int = 20
    llm: Optional[LLMConfigRequest] = None
    target: Optional[TargetConfigRequest] = None
    ga: Optional[GAConfigRequest] = None
    proxy: Optional[ProxyConfigRequest] = None
    waf_analyzer: Optional[WAFAnalyzerConfigRequest] = None
    rate_limit: Optional[RateLimitConfigRequest] = None
    bypass_rate_limit: Optional[RateLimitConfigRequest] = None
    exploit_rate_limit: Optional[RateLimitConfigRequest] = None
    fast_test: Optional[FastTestConfigRequest] = None
    web_search: Optional[WebSearchConfigRequest] = None
    memory_enabled: bool = True


class PresetInfo(BaseModel):
    name: str
    endpoint: str
    param: str
    method: str
    vuln_type: str
