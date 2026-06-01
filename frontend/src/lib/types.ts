export interface RateLimitStatus {
  current_delay: number;
  base_delay: number;
  backoff_level: number;
  consecutive_blocks: number;
  max_consecutive_blocks: number;
  is_backing_off: boolean;
}

export interface InjectionFingerprint {
  is_injectable: boolean;
  quote_type: string;
  closure_char: string;
  comment_style: string;
  dbms_hint: string;
  confidence: number;
  connection_error?: boolean;
  error_detail?: string;
  // Deep recon fields — read from top-level AttackState instead
  // (recon_report, recommended_strategy are synced at top level by backend)
  sql_error_evidence?: string[];
  data_leak_evidence?: { pattern: string; confidence: number }[];
}

export interface Hypothesis {
  mechanism: string;
  description?: string;
  detection_analysis?: string;
  blind_spot?: string;
  reasoning?: string;
  confidence?: number;
  seed_payloads?: string[];
  mutation_strategy?: string;
  success_criteria?: string;
  status?: string;
  test_count?: number;
  best_fitness?: number;
  bypass_count?: number;
}

export interface AttackState {
  running: boolean;
  completed: boolean;
  success: boolean;
  logs: string[];
  evolution_tree: Record<string, string[]>;
  history: HistoryEntry[];
  current_phase: string;
  stage: "idle" | "bypass" | "exploit";
  iteration: number;
  ga_stats: GAStats;
  ga_history: GAStats[];
  population: PopulationEntry[];
  waf_result: WAFResult;
  memory_stats: MemoryStats;
  final_result: ExecutionResult | null;
  // Vuln type (synced from backend)
  vuln_type?: string;
  // Two-stage pipeline
  bypass_success: boolean;
  bypass_payload: string;
  bypass_technique: string;
  bypass_techniques: BypassTechnique[];
  bypass_history?: { payload: string; technique?: string; status_code?: number }[];
  block_analysis: BlockAnalysis | null;
  block_history: BlockAnalysis[];
  report: string;
  // Rate limit status
  rate_limit_status?: RateLimitStatus;
  // Injection fingerprint (from recon)
  injection_fingerprint?: InjectionFingerprint;
  // Connection error tracking
  connection_errors?: number;
  // Baseline response
  baseline_snippet?: string;
  // LLM reasoning chain for hypothesis generation
  reasoning_chain?: {
    waf_detection_method?: string;
    parsing_behavior?: string;
    matching_strategy?: string;
    identified_blind_spots?: string[];
    exploitation_approach?: string;
  };
  // Smart stopping
  consecutive_server_errors?: number;
  consecutive_very_low?: number;
  stop_reason?: string;
  paused?: boolean;
  // Strategy rotation tracking
  consecutive_low_fitness?: number;
  current_strategy?: string;
  // Recon deep analysis
  recon_report?: string;
  current_analysis?: string;
  recommended_strategy?: string;
  // Extracted data from successful exploit
  extracted_data?: string;
  // Hypothesis-driven bypass
  hypotheses?: Hypothesis[];
  hypothesis_history?: HypothesisHistoryEntry[];
  inferred_rules?: InferredRule[];
}

export interface HypothesisHistoryEntry {
  iteration: number;
  hypotheses_snapshot: {
    mechanism: string;
    status: string;
    best_fitness: number;
    test_count: number;
  }[];
}

export interface InferredRule {
  rule_type: string;
  trigger_keywords?: string[];
  confidence?: number;
  evidence?: string;
  suggested_bypasses?: { technique: string; reasoning: string }[];
  failed_families?: Record<string, number>;
  total_blocked?: number;
  waf_name?: string;
}

export interface HistoryEntry {
  payload: string;
  result: "success" | "failure" | "blocked" | "bypass" | "bypass_success";
  evidence: string;
  fitness: number;
  iteration: number;
  indicators?: string[];
  technique?: string;
  bypass_technique?: string;
}

export interface BypassTechnique {
  payload: string;
  technique: string;
  waf_name: string;
  rule_type?: string;
  trigger_pattern?: string;
  fitness?: number;
  iteration?: number;
}

export interface BlockAnalysis {
  payload: string;
  is_blocked: boolean;
  trigger_segments?: { text: string; start: number; end: number; confidence: number }[];
  rule_inference?: {
    rule_type: string;
    trigger_pattern: string;
    suggested_bypasses: { technique: string; payload_variant: string; reasoning: string }[];
    reasoning: string;
    confidence: number;
  };
  probe_results?: { variation: string; payload: string; blocked: boolean }[];
  analysis_summary?: string;
}

export interface GAStats {
  generation?: number;
  best_fitness?: number;
  avg_fitness?: number;
  worst_fitness?: number;
  mutation_rate?: number;
  best_payload?: string;
  population_size?: number;
}

export interface PopulationEntry {
  payload: string;
  fitness: number;
  generation?: number;
  id?: string;
  parent_id?: string;
  mutations_applied?: string[];
  response_time?: number;
  response_code?: number;
  response_snippet?: string;
  indicators?: string[];
  hypothesis_id?: string;
}

export interface WAFResult {
  detected: boolean;
  waf_name: string;
  confidence: number;
  indicators: string[];
  bypass_strategies: string[];
}

export interface MemoryStats {
  total_entries: number;
  successes: number;
  failures: number;
  success_rate: number;
  session_id: string;
  chromadb: boolean;
}

export interface ExecutionResult {
  success: boolean;
  evidence: string;
  payload?: string;
  response_code?: number;
  response_snippet?: string;
  response_time?: number;
}

export interface Preset {
  name: string;
  endpoint: string;
  param: string;
  method: string;
  vuln_type: string;
}

interface RateLimitConfig {
  request_delay: number;
  delay_jitter: number;
  backoff_on_429: number;
  backoff_on_block: number;
  max_consecutive_blocks: number;
  block_pause: number;
  verify_bypass_attempts: number;
  backoff_multiplier: number;
  max_backoff: number;
  jitter_distribution: string;
}

export interface AttackConfig {
  endpoint: string;
  param: string;
  method: string;
  vuln_type: string;
  max_iterations: number;
  llm?: {
    api_base: string;
    api_key: string;
    model: string;
    temperature: number;
    max_tokens: number;
  };
  target?: {
    base_url: string;
    timeout: number;
    php_sessid: string;
    security_level: string;
    extra_params?: Record<string, string>;
  };
  ga?: {
    population_size: number;
    elite_count: number;
    tournament_size: number;
    crossover_rate: number;
    base_mutation_rate: number;
    max_generations: number;
  };
  proxy?: {
    source: string;
    burp_url: string;
    zap_url: string;
    zap_api_key: string;
    burp_xml_path: string;
  };
  waf_analyzer?: {
    binary_search_max_depth: number;
    boundary_probe_limit: number;
    enabled: boolean;
  };
  rate_limit?: RateLimitConfig;
  bypass_rate_limit?: RateLimitConfig;
  exploit_rate_limit?: RateLimitConfig;
  memory_enabled: boolean;
  fast_test?: {
    enabled: boolean;
    bypass_delay: number;
    exploit_delay: number;
    skip_binary_search: boolean;
    quick_verify_count: number;
    lightweight_recon: boolean;
    skip_analyzer_first_n: number;
  };
  web_search?: {
    enabled: boolean;
    max_results: number;
    timeout: number;
    search_locale: string;
    cache_ttl: number;
  };
}

export type WSMessage = {
  type: "state";
  data: AttackState;
};
