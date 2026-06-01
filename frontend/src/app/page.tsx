"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { motion } from "framer-motion";
import { Zap, Dna, Shield, PanelLeftClose, PanelLeft } from "lucide-react";

import MatrixRain from "@/components/MatrixRain";
import ParticleField from "@/components/ParticleField";
import NeonTitle from "@/components/NeonTitle";
import Sidebar from "@/components/Sidebar";
import AttackConsole from "@/components/tabs/AttackConsole";
import EvolutionLab from "@/components/tabs/EvolutionLab";
import IntelCenter from "@/components/tabs/IntelCenter";

import { fetchState, fetchPresets, startAttack, resetAttack, stopAttack, pauseAttack, resumeAttack, createWSConnection } from "@/lib/api";
import type { AttackState, AttackConfig, Preset, WSMessage } from "@/lib/types";
import { t, type Lang } from "@/lib/i18n";

const DEFAULT_STATE: AttackState = {
  running: false,
  completed: false,
  success: false,
  logs: [],
  evolution_tree: {},
  history: [],
  current_phase: "idle",
  stage: "idle",
  iteration: 0,
  ga_stats: { generation: 0, best_fitness: 0, avg_fitness: 0, worst_fitness: 0, mutation_rate: 0, population_size: 0 },
  ga_history: [{ generation: 0, best_fitness: 0, avg_fitness: 0, worst_fitness: 0, best_payload: "", population_size: 0 }],
  population: [],
  waf_result: { detected: false, waf_name: "", confidence: 0, indicators: [], bypass_strategies: [] },
  memory_stats: { total_entries: 0, successes: 0, failures: 0, success_rate: 0, session_id: "", chromadb: false },
  final_result: null,
  bypass_success: false,
  bypass_payload: "",
  bypass_technique: "",
  bypass_techniques: [],
  bypass_history: [],
  block_analysis: null,
  block_history: [],
  report: "",
  rate_limit_status: { current_delay: 0, base_delay: 0, backoff_level: 0, consecutive_blocks: 0, max_consecutive_blocks: 10, is_backing_off: false },
  injection_fingerprint: { is_injectable: false, quote_type: "unknown", closure_char: "", comment_style: "--", dbms_hint: "unknown", confidence: 0 },
  connection_errors: 0,
  consecutive_server_errors: 0,
  consecutive_very_low: 0,
  stop_reason: "",
  paused: false,
  consecutive_low_fitness: 0,
  current_strategy: "error",
  hypotheses: [],
  hypothesis_history: [],
  inferred_rules: [],
};

const DEFAULT_CONFIG: AttackConfig = {
  endpoint: "/search",
  param: "q",
  method: "GET",
  vuln_type: "sqli",
  max_iterations: 20,
  llm: {
    api_base: "https://api.deepseek.com",
    api_key: "",
    model: "deepseek-chat",
    temperature: 0.7,
    max_tokens: 9999,
  },
  target: {
    base_url: "http://192.168.1.100",
    timeout: 10,
    php_sessid: "",
    security_level: "low",
    extra_params: {},
  },
  ga: {
    population_size: 12,
    elite_count: 2,
    tournament_size: 3,
    crossover_rate: 0.7,
    base_mutation_rate: 0.15,
    max_generations: 10,
  },
  proxy: {
    source: "none",
    burp_url: "http://127.0.0.1:1337",
    zap_url: "http://127.0.0.1:8080",
    zap_api_key: "",
    burp_xml_path: "",
  },
  rate_limit: {
    request_delay: 1.0,
    delay_jitter: 0.5,
    backoff_on_429: 30.0,
    backoff_on_block: 5.0,
    max_consecutive_blocks: 10,
    block_pause: 60.0,
    verify_bypass_attempts: 3,
    backoff_multiplier: 2.0,
    max_backoff: 120.0,
    jitter_distribution: "uniform",
  },
  memory_enabled: true,
  web_search: {
    enabled: true,
    max_results: 5,
    timeout: 10,
    search_locale: "en-us",
    cache_ttl: 3600,
  },
};

type Tab = "attack" | "evolution" | "intel";

const TAB_IDS: Tab[] = ["attack", "evolution", "intel"];
const TAB_ICONS = { attack: Zap, evolution: Dna, intel: Shield };
const TAB_KEYS: Record<Tab, string> = {
  attack: "tab.attack",
  evolution: "tab.evolution",
  intel: "tab.intel",
};

const STORAGE_KEY = "bypassevo_config";

function loadSavedConfig(): AttackConfig {
  if (typeof window === "undefined") return DEFAULT_CONFIG;
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      // Deep merge with defaults to handle new fields added in future versions
      return {
        ...DEFAULT_CONFIG,
        ...parsed,
        rate_limit: { ...DEFAULT_CONFIG.rate_limit, ...parsed.rate_limit },
        bypass_rate_limit: parsed.bypass_rate_limit ? { ...DEFAULT_CONFIG.rate_limit, ...parsed.bypass_rate_limit } : undefined,
        exploit_rate_limit: parsed.exploit_rate_limit ? { ...DEFAULT_CONFIG.rate_limit, ...parsed.exploit_rate_limit } : undefined,
        web_search: { ...DEFAULT_CONFIG.web_search, ...parsed.web_search },
      };
    }
  } catch {}
  return DEFAULT_CONFIG;
}

export default function Home() {
  const [state, setState] = useState<AttackState>(DEFAULT_STATE);
  const [config, setConfig] = useState<AttackConfig>(DEFAULT_CONFIG);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("attack");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [bgEnabled, setBgEnabled] = useState(false);
  const [lang, setLang] = useState<Lang>("zh");
  const wsRef = useRef<WebSocket | null>(null);
  const wsCleanupRef = useRef<(() => void) | null>(null);
  const configLoaded = useRef(false);

  // Initialize — load saved config and language from localStorage
  useEffect(() => {
    const saved = loadSavedConfig();
    setConfig(saved);
    configLoaded.current = true;
    fetchState().then(setState).catch(() => {});
    fetchPresets().then(setPresets).catch(() => {});
    // Read persisted language preference after hydration
    try {
      const savedLang = localStorage.getItem("bypassevo_lang");
      if (savedLang === "zh" || savedLang === "en") setLang(savedLang);
    } catch {}
  }, []);

  // Persist config to localStorage on change
  useEffect(() => {
    if (!configLoaded.current) return;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    } catch {}
  }, [config]);

  // Persist language to localStorage
  useEffect(() => {
    try {
      localStorage.setItem("bypassevo_lang", lang);
    } catch {}
  }, [lang]);

  // WebSocket connection
  useEffect(() => {
    const { ws, cleanup } = createWSConnection((msg: WSMessage) => {
      if (msg.type === "state") {
        setState(msg.data);
      }
    });
    wsRef.current = ws;
    wsCleanupRef.current = cleanup;
    return () => {
      cleanup();
    };
  }, []);

  const handleStart = useCallback(async () => {
    setActiveTab("attack");
    try {
      const res = await startAttack(config);
      if ("error" in res) {
        console.warn("Start attack failed:", res.error);
      }
    } catch (e) {
      console.error("Start attack error:", e);
    }
  }, [config]);

  const handleStep = useCallback(async () => {
    setActiveTab("attack");
    await startAttack(config);
  }, [config]);

  const handleReset = useCallback(async () => {
    await resetAttack();
    setState(DEFAULT_STATE);
  }, []);

  const handleStop = useCallback(async () => {
    await stopAttack();
  }, []);

  const handlePause = useCallback(async () => {
    await pauseAttack();
  }, []);

  const handleResume = useCallback(async () => {
    await resumeAttack();
  }, []);

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Background effects */}
      {bgEnabled && (
        <>
          <MatrixRain />
          <ParticleField />
        </>
      )}

      {/* Main content */}
      <div className="relative z-10 min-h-screen flex flex-col">
        {/* Header */}
        <header className="flex items-center justify-between px-6 py-4 border-b border-cyber-border/30">
          <div className="flex items-center gap-4">
            <motion.button
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="text-cyber-dim hover:text-cyber-neon transition-colors"
            >
              {sidebarOpen ? <PanelLeftClose size={20} /> : <PanelLeft size={20} />}
            </motion.button>
            <NeonTitle lang={lang} />
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setBgEnabled(!bgEnabled)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                bgEnabled
                  ? "bg-cyber-neon/10 border border-cyber-neon/20 text-cyber-neon"
                  : "glass text-cyber-dim"
              }`}
            >
              {bgEnabled ? t("header.fxOn", lang) : t("header.fxOff", lang)}
            </button>
            <div className="text-cyber-dim/30 text-[10px] font-mono">
              {t("header.version", lang)}
            </div>
          </div>
        </header>

        {/* Body */}
        <div className="flex-1 flex overflow-hidden">
          {/* Sidebar */}
          <motion.aside
            className="border-r border-cyber-border/30 flex-shrink-0 relative"
            animate={{ width: sidebarOpen ? 320 : 0, opacity: sidebarOpen ? 1 : 0 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
            style={{ minWidth: 0 }}
          >
            <div className="h-full overflow-y-auto scroll-smooth" style={{ scrollbarGutter: "stable" }}>
              <div className="p-3 w-[320px]">
                <Sidebar
                  config={config}
                  onChange={setConfig}
                  presets={presets}
                  lang={lang}
                  onLangChange={setLang}
                />
              </div>
            </div>
            {/* Fade indicator at bottom — more content below */}
            {sidebarOpen && (
              <div className="absolute bottom-0 left-0 right-0 h-8 bg-gradient-to-t from-[#050505] to-transparent pointer-events-none z-10" />
            )}
          </motion.aside>

          {/* Main panel */}
          <main className="flex-1 flex flex-col overflow-hidden">
            {/* Tab bar */}
            <div className="flex items-center gap-1 px-6 py-3 border-b border-cyber-border/20">
              {TAB_IDS.map((id) => {
                const Icon = TAB_ICONS[id];
                return (
                  <motion.button
                    key={id}
                    onClick={() => setActiveTab(id)}
                    className={`relative flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold font-mono transition-all ${
                      activeTab === id
                        ? "bg-cyber-neon/10 text-cyber-neon border border-cyber-neon/20"
                        : "text-cyber-dim hover:text-white/70 hover:bg-white/[0.03]"
                    }`}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <Icon size={16} />
                    {t(TAB_KEYS[id] as any, lang)}
                    {activeTab === id && (
                      <motion.div
                        className="absolute bottom-0 left-1/2 w-8 h-0.5 bg-cyber-neon rounded-full"
                        layoutId="tab-indicator"
                        style={{ x: "-50%" }}
                      />
                    )}
                  </motion.button>
                );
              })}
              <div className="flex-1" />
              {state.running && (
                <motion.div
                  className="flex items-center gap-2 text-cyber-neon text-xs font-mono"
                  animate={{ opacity: [1, 0.5, 1] }}
                  transition={{ duration: 1.5, repeat: Infinity }}
                >
                  <span className="w-2 h-2 rounded-full bg-cyber-neon" />
                  {t("tab.streaming", lang)}
                </motion.div>
              )}
            </div>

            {/* Tab content */}
            <div className="flex-1 overflow-y-auto p-6">
              {activeTab === "attack" && (
                <AttackConsole
                  state={state}
                  config={config}
                  lang={lang}
                  onStart={handleStart}
                  onStep={handleStep}
                  onReset={handleReset}
                  onStop={handleStop}
                  onPause={handlePause}
                  onResume={handleResume}
                />
              )}
              {activeTab === "evolution" && <EvolutionLab state={state} lang={lang} />}
              {activeTab === "intel" && <IntelCenter state={state} lang={lang} />}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
