"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain, Target, Dna, Key, Plug, ChevronDown, Globe, Timer, ShieldCheck,
  ClipboardPaste, Loader2, Zap,
} from "lucide-react";
import type { AttackConfig, Preset } from "@/lib/types";
import { t, type Lang } from "@/lib/i18n";
import { parseRawRequest } from "@/lib/api";
import { parseSmartUrl, cleanRawInput } from "@/lib/utils";

interface Props {
  config: AttackConfig;
  onChange: (config: AttackConfig) => void;
  presets: Preset[];
  lang: Lang;
  onLangChange: (lang: Lang) => void;
}

function Section({
  icon: Icon,
  title,
  children,
  defaultOpen = false,
}: {
  icon: any;
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="glass !rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-3 py-2 text-cyber-neon text-xs font-bold hover:bg-white/[0.02] transition-colors"
      >
        <Icon size={14} />
        <span className="flex-1 text-left">{title}</span>
        <motion.div animate={{ rotate: open ? 180 : 0 }} transition={{ duration: 0.2 }}>
          <ChevronDown size={12} className="text-cyber-dim" />
        </motion.div>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-3 pb-3 space-y-2.5">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function SectionI18n({
  icon: Icon,
  titleKey,
  lang,
  children,
  defaultOpen = false,
}: {
  icon: any;
  titleKey: string;
  lang: Lang;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="glass !rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-3 py-2 text-cyber-neon text-xs font-bold hover:bg-white/[0.02] transition-colors"
      >
        <Icon size={14} />
        <span className="flex-1 text-left">{t(titleKey as any, lang)}</span>
        <motion.div animate={{ rotate: open ? 180 : 0 }} transition={{ duration: 0.2 }}>
          <ChevronDown size={12} className="text-cyber-dim" />
        </motion.div>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-3 pb-3 space-y-2.5">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function Field({
  label,
  children,
  help,
}: {
  label: string;
  children: React.ReactNode;
  help?: string;
}) {
  return (
    <div>
      <label className="text-cyber-dim text-[11px] block mb-0.5">{label}</label>
      {children}
      {help && <div className="text-cyber-dim/40 text-[9px] mt-0.5">{help}</div>}
    </div>
  );
}

const inputCls =
  "w-full bg-black/40 border border-cyber-border rounded-lg px-2.5 py-1.5 text-white/90 text-xs font-mono focus:border-cyber-neon/40 focus:outline-none focus:ring-1 focus:ring-cyber-neon/20 transition-colors placeholder:text-cyber-dim/30";
const selectCls =
  "w-full bg-black/40 border border-cyber-border rounded-lg px-2.5 py-1.5 text-white/90 text-xs font-mono focus:border-cyber-neon/40 focus:outline-none appearance-none cursor-pointer";

/** Safe parseInt — returns fallback (default 0) for empty/invalid input. */
function safeInt(value: string, fallback: number = 0): number {
  const n = parseInt(value, 10);
  return Number.isNaN(n) ? fallback : n;
}

/** Safe parseFloat — returns fallback (default 0) for empty/invalid input. */
function safeFloat(value: string, fallback: number = 0): number {
  const n = parseFloat(value);
  return Number.isNaN(n) ? fallback : n;
}

function ImportRequestButton({
  config,
  onChange,
  lang,
}: {
  config: AttackConfig;
  onChange: (config: AttackConfig) => void;
  lang: Lang;
}) {
  const [open, setOpen] = useState(false);
  const [rawText, setRawText] = useState("");
  const [parsing, setParsing] = useState(false);
  const [status, setStatus] = useState<"idle" | "ok" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const [preview, setPreview] = useState<Record<string, any> | null>(null);
  const [fragmentStripped, setFragmentStripped] = useState(false);

  const handleParse = async () => {
    if (!rawText.trim()) return;
    setParsing(true);
    setStatus("idle");
    setErrorMsg("");
    setPreview(null);
    setFragmentStripped(false);
    try {
      // Pre-process: strip fragments, convert bare URLs to GET requests
      const { cleaned, fragment_stripped } = cleanRawInput(rawText);
      setFragmentStripped(fragment_stripped);
      const result = await parseRawRequest(cleaned);
      if (result.error) {
        setStatus("error");
        setErrorMsg(result.error);
        return;
      }
      // Show preview
      setPreview(result);
    } catch (e: any) {
      setStatus("error");
      setErrorMsg(e?.message || "Network error");
    } finally {
      setParsing(false);
    }
  };

  const handleApply = () => {
    if (!preview) return;
    // Build target patch
    const targetPatch: Record<string, any> = {};
    if (preview.base_url) targetPatch.base_url = preview.base_url;
    if (preview.extra_params && Object.keys(preview.extra_params).length > 0) {
      targetPatch.extra_params = preview.extra_params;
    }
    if (preview.cookie) {
      const match = preview.cookie.match(/PHPSESSID=([^;]+)/i);
      if (match) targetPatch.php_sessid = match[1];
    }
    // Build top-level patch
    const topPatch: Record<string, any> = {};
    if (preview.endpoint) topPatch.endpoint = preview.endpoint;
    if (preview.param) topPatch.param = preview.param;
    if (preview.method) topPatch.method = preview.method;
    // Single onChange call — avoids stale closure overwriting
    onChange({
      ...config,
      ...topPatch,
      target: {
        base_url: "http://192.168.1.100",
        timeout: 10,
        php_sessid: "",
        security_level: "low",
        ...config.target,
        ...targetPatch,
      },
    });
    setStatus("ok");
    setPreview(null);
  };

  return (
    <div className="border-t border-cyber-border/30 pt-3 mt-2">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 text-cyber-purple text-xs font-mono font-bold hover:text-cyber-neon transition-colors"
      >
        <ClipboardPaste size={14} />
        {t("sidebar.importRequest", lang)}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden mt-2"
          >
            <div className="text-cyber-dim/50 text-[10px] mb-2">
              {t("sidebar.importRequestHelp", lang)}
            </div>
            <textarea
              className={`${inputCls} min-h-[100px] resize-y font-mono text-[11px]`}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder={`GET /vulnerabilities/sqli/?id=1 HTTP/1.1\nHost: 192.168.1.100\nCookie: PHPSESSID=abc123\nUser-Agent: Mozilla/5.0\n\n`}
            />
            <div className="flex items-center gap-2 mt-2">
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                onClick={handleParse}
                disabled={parsing || !rawText.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-purple/15 border border-cyber-purple/30 text-cyber-purple text-xs font-mono font-bold disabled:opacity-40 hover:bg-cyber-purple/25 transition-all"
              >
                {parsing ? <Loader2 size={12} className="animate-spin" /> : <ClipboardPaste size={12} />}
                {parsing ? t("sidebar.importParsing", lang) : t("sidebar.importRequest", lang)}
              </motion.button>
              {status === "ok" && (
                <span className="text-green-400 text-[10px] font-mono">{t("sidebar.importParsed", lang)}</span>
              )}
              {status === "error" && (
                <span className="text-red-400 text-[10px] font-mono">{errorMsg || t("sidebar.importError", lang)}</span>
              )}
            </div>
            {/* Fragment stripped warning */}
            {(fragmentStripped || preview?.warning) && (
              <p className="text-yellow-400 text-[10px] font-mono mt-1">
                ⚠ {t("sidebar.fragmentStripped", lang)}
              </p>
            )}
            {/* Preview parsed results */}
            {preview && (
              <div className="mt-2 p-2 rounded-lg bg-black/30 border border-cyber-border/30 text-[10px] font-mono space-y-1">
                <div className="text-cyber-neon font-bold mb-1">{t("generic.preview", lang)}</div>
                <div><span className="text-cyber-dim">{t("sidebar.method", lang)}:</span> <span className="text-white/80">{preview.method}</span></div>
                <div><span className="text-cyber-dim">URL:</span> <span className="text-white/80">{preview.base_url}{preview.endpoint}</span></div>
                <div><span className="text-cyber-dim">{t("sidebar.parameter", lang)}:</span> <span className="text-yellow-400">{preview.param}</span></div>
                {preview.extra_params && Object.keys(preview.extra_params).length > 0 && (
                  <div><span className="text-cyber-dim">{t("sidebar.extraParams", lang)}:</span> <span className="text-white/80">{Object.keys(preview.extra_params).join(", ")}</span></div>
                )}
                {preview.cookie && (
                  <div><span className="text-cyber-dim">Cookie:</span> <span className="text-cyber-purple">{preview.cookie.substring(0, 40)}...</span></div>
                )}
                <button
                  onClick={handleApply}
                  className="mt-1 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-500/15 border border-green-500/30 text-green-400 text-xs font-mono font-bold hover:bg-green-500/25 transition-all w-full justify-center"
                >
                  {t("sidebar.applyToConfig", lang)}
                </button>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function Sidebar({ config, onChange, presets, lang, onLangChange }: Props) {
  const [fragmentWarning, setFragmentWarning] = useState(false);

  const update = (patch: Partial<AttackConfig>) => {
    onChange({ ...config, ...patch });
  };

  const updateLLM = (patch: Partial<NonNullable<AttackConfig["llm"]>>) => {
    onChange({
      ...config,
      llm: {
        api_base: "https://api.deepseek.com",
        api_key: "",
        model: "deepseek-chat",
        temperature: 0.7,
        max_tokens: 9999,
        ...config.llm,
        ...patch,
      },
    });
  };

  const updateTarget = (patch: Partial<NonNullable<AttackConfig["target"]>>) => {
    onChange({
      ...config,
      target: {
        base_url: "http://192.168.1.100",
        timeout: 10,
        php_sessid: "",
        security_level: "low",
        ...config.target,
        ...patch,
      },
    });
  };

  const updateGA = (patch: Partial<NonNullable<AttackConfig["ga"]>>) => {
    onChange({
      ...config,
      ga: {
        population_size: 12,
        elite_count: 2,
        tournament_size: 3,
        crossover_rate: 0.7,
        base_mutation_rate: 0.15,
        max_generations: 10,
        ...config.ga,
        ...patch,
      },
    });
  };

  const updateProxy = (patch: Partial<NonNullable<AttackConfig["proxy"]>>) => {
    onChange({
      ...config,
      proxy: {
        source: "none",
        burp_url: "http://127.0.0.1:1337",
        zap_url: "http://127.0.0.1:8080",
        zap_api_key: "",
        burp_xml_path: "",
        ...config.proxy,
        ...patch,
      },
    });
  };

  const updateRateLimit = (patch: Partial<NonNullable<AttackConfig["rate_limit"]>>) => {
    onChange({
      ...config,
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
        ...config.rate_limit,
        ...patch,
      },
    });
  };

  const updateBypassRL = (patch: Partial<NonNullable<AttackConfig["bypass_rate_limit"]>>) => {
    const base = config.rate_limit || {
      request_delay: 1.0, delay_jitter: 0.5, backoff_on_429: 30.0, backoff_on_block: 5.0,
      max_consecutive_blocks: 10, block_pause: 60.0, verify_bypass_attempts: 3,
      backoff_multiplier: 2.0, max_backoff: 120.0, jitter_distribution: "uniform",
    };
    onChange({
      ...config,
      bypass_rate_limit: { ...base, ...config.bypass_rate_limit, ...patch },
    });
  };

  const updateExploitRL = (patch: Partial<NonNullable<AttackConfig["exploit_rate_limit"]>>) => {
    const base = config.rate_limit || {
      request_delay: 1.0, delay_jitter: 0.5, backoff_on_429: 30.0, backoff_on_block: 5.0,
      max_consecutive_blocks: 10, block_pause: 60.0, verify_bypass_attempts: 3,
      backoff_multiplier: 2.0, max_backoff: 120.0, jitter_distribution: "uniform",
    };
    onChange({
      ...config,
      exploit_rate_limit: { ...base, ...config.exploit_rate_limit, ...patch },
    });
  };

  const clearBypassRL = () => onChange({ ...config, bypass_rate_limit: undefined });
  const clearExploitRL = () => onChange({ ...config, exploit_rate_limit: undefined });

  const updateFastTest = (patch: Partial<NonNullable<AttackConfig["fast_test"]>>) => {
    onChange({
      ...config,
      fast_test: {
        enabled: false,
        bypass_delay: 0.2,
        exploit_delay: 0.5,
        skip_binary_search: true,
        quick_verify_count: 1,
        lightweight_recon: true,
        skip_analyzer_first_n: 3,
        ...config.fast_test,
        ...patch,
      },
    });
  };

  const updateWebSearch = (patch: Partial<NonNullable<AttackConfig["web_search"]>>) => {
    onChange({
      ...config,
      web_search: {
        enabled: true,
        max_results: 5,
        timeout: 10,
        search_locale: "en-us",
        cache_ttl: 3600,
        ...config.web_search,
        ...patch,
      },
    });
  };

  const applyPreset = (name: string) => {
    const p = presets.find((pr) => pr.name === name);
    if (p) {
      update({
        endpoint: p.endpoint,
        param: p.param,
        method: p.method,
        vuln_type: p.vuln_type,
      });
    }
  };

  return (
    <div className="space-y-2">
      {/* Language toggle — compact */}
      <div className="flex gap-1.5">
        {(["zh", "en"] as const).map((l) => (
          <button
            key={l}
            onClick={() => onLangChange(l)}
            className={`flex-1 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
              lang === l
                ? "bg-cyber-neon/10 border border-cyber-neon/30 text-cyber-neon"
                : "glass text-cyber-dim hover:text-white/70"
            }`}
          >
            {l === "zh" ? "中文" : "EN"}
          </button>
        ))}
      </div>

      {/* LLM Config */}
      <SectionI18n icon={Brain} titleKey="sidebar.llmConfig" lang={lang} defaultOpen>
        <Field label={t("sidebar.apiBase", lang)} help="Ollama: http://localhost:11434/v1">
          <input
            className={inputCls}
            value={config.llm?.api_base || ""}
            onChange={(e) => updateLLM({ api_base: e.target.value })}
            placeholder="https://api.deepseek.com/anthropic"
          />
        </Field>
        <Field label={t("sidebar.apiKey", lang)}>
          <input
            className={inputCls}
            type="password"
            value={config.llm?.api_key || ""}
            onChange={(e) => updateLLM({ api_key: e.target.value })}
            placeholder="sk-..."
          />
        </Field>
        <Field label={t("sidebar.model", lang)}>
          <input
            className={inputCls}
            value={config.llm?.model || ""}
            onChange={(e) => updateLLM({ model: e.target.value })}
            placeholder="deepseek-v4-flash"
          />
        </Field>
        <Field label={`${t("sidebar.temperature", lang)}: ${config.llm?.temperature ?? 0.7}`}>
          <input
            type="range"
            min="0"
            max="1.5"
            step="0.1"
            value={config.llm?.temperature ?? 0.7}
            onChange={(e) => updateLLM({ temperature: safeFloat(e.target.value) })}
            className="w-full accent-cyber-neon"
          />
        </Field>
      </SectionI18n>

      {/* Target Config */}
      <SectionI18n icon={Target} titleKey="sidebar.targetConfig" lang={lang} defaultOpen>
        <Field label={t("sidebar.targetUrl", lang)} help={t("sidebar.targetUrlHelp", lang)}>
          <input
            className={inputCls}
            value={config.target?.base_url || ""}
            onChange={(e) => {
              const val = e.target.value;
              const result = parseSmartUrl(val);
              setFragmentWarning(result.fragment_stripped);
              if (result.endpoint) {
                // Full URL pasted — auto-fill endpoint, param, and base_url
                const mergedTarget = {
                  timeout: 10,
                  php_sessid: "",
                  security_level: "low",
                  ...config.target,
                  base_url: result.base_url,
                };
                onChange({
                  ...config,
                  endpoint: result.endpoint,
                  param: result.param || config.param,
                  target: mergedTarget,
                });
              } else {
                updateTarget({ base_url: result.base_url });
              }
            }}
            placeholder="http://192.168.1.100 | http://192.168.1.100/sqli/?id=1"
          />
        </Field>
        {fragmentWarning && (
          <p className="text-xs text-yellow-400 mt-1">
            {t("sidebar.fragmentStrippedShort", lang)}
          </p>
        )}
        <Field label={t("sidebar.preset", lang)}>
          <select
            className={selectCls}
            onChange={(e) => applyPreset(e.target.value)}
            defaultValue=""
          >
            <option value="" disabled>
              {t("sidebar.selectPreset", lang)}
            </option>
            {presets.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t("sidebar.endpoint", lang)}>
            <input
              className={inputCls}
              value={config.endpoint}
              onChange={(e) => update({ endpoint: e.target.value })}
            />
          </Field>
          <Field label={t("sidebar.parameter", lang)}>
            <input
              className={inputCls}
              value={config.param}
              onChange={(e) => update({ param: e.target.value })}
            />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t("sidebar.method", lang)}>
            <select
              className={selectCls}
              value={config.method}
              onChange={(e) => update({ method: e.target.value })}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </Field>
          <Field label={t("sidebar.vulnType", lang)}>
            <select
              className={selectCls}
              value={config.vuln_type}
              onChange={(e) => update({ vuln_type: e.target.value })}
            >
              <option value="sqli">SQL Injection</option>
              <option value="xss">XSS</option>
              <option value="cmdi">Command Injection</option>
            </select>
          </Field>
        </div>
        <Field label={t("sidebar.extraParams", lang)} help='JSON: {"_token": "xxx", "password": "123"}'>
          <textarea
            className={`${inputCls} min-h-[60px] resize-y`}
            value={config.target?.extra_params ? JSON.stringify(config.target.extra_params, null, 2) : ""}
            onChange={(e) => {
              const val = e.target.value.trim();
              if (!val) {
                updateTarget({ extra_params: {} });
                return;
              }
              try {
                const parsed = JSON.parse(val);
                if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
                  updateTarget({ extra_params: parsed });
                }
              } catch {
                // Invalid JSON while typing — don't update
              }
            }}
            onBlur={(e) => {
              // Normalize on blur
              const val = e.target.value.trim();
              if (val) {
                try {
                  const parsed = JSON.parse(val);
                  e.target.value = JSON.stringify(parsed, null, 2);
                } catch {}
              }
            }}
            placeholder='{"_token": "xxx", "password": "123"}'
          />
        </Field>
        {/* Import Full Request */}
        <ImportRequestButton config={config} onChange={onChange} lang={lang} />
      </SectionI18n>

      {/* Auth */}
      <SectionI18n icon={Key} titleKey="sidebar.authentication" lang={lang}>
        <Field label={t("sidebar.sessionId", lang)}>
          <input
            className={inputCls}
            type="password"
            value={config.target?.php_sessid || ""}
            onChange={(e) => updateTarget({ php_sessid: e.target.value })}
          />
          <p className="text-[10px] text-orange-400/70 mt-1 font-mono">
            {t("ac.dvwaHint", lang)}
          </p>
        </Field>
        <Field label={t("sidebar.securityLevel", lang)}>
          <select
            className={selectCls}
            value={config.target?.security_level || "low"}
            onChange={(e) => updateTarget({ security_level: e.target.value })}
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="impossible">Impossible</option>
          </select>
        </Field>
      </SectionI18n>

      {/* GA Engine */}
      <SectionI18n icon={Dna} titleKey="sidebar.gaEngine" lang={lang}>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t("sidebar.populationSize", lang)}>
            <input
              type="number"
              className={inputCls}
              min={6}
              max={20}
              value={config.ga?.population_size ?? 12}
              onChange={(e) => updateGA({ population_size: safeInt(e.target.value) })}
            />
          </Field>
          <Field label={t("sidebar.maxGenerations", lang)}>
            <input
              type="number"
              className={inputCls}
              min={3}
              max={30}
              value={config.ga?.max_generations ?? 10}
              onChange={(e) => updateGA({ max_generations: safeInt(e.target.value) })}
            />
          </Field>
        </div>
        <Field label={`${t("sidebar.crossoverRate", lang)}: ${config.ga?.crossover_rate ?? 0.7}`}>
          <input
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={config.ga?.crossover_rate ?? 0.7}
            onChange={(e) => updateGA({ crossover_rate: safeFloat(e.target.value) })}
            className="w-full accent-cyber-purple"
          />
        </Field>
        <Field label={`${t("sidebar.mutationRate", lang)}: ${config.ga?.base_mutation_rate ?? 0.15}`}>
          <input
            type="range"
            min="0"
            max="0.5"
            step="0.01"
            value={config.ga?.base_mutation_rate ?? 0.15}
            onChange={(e) => updateGA({ base_mutation_rate: safeFloat(e.target.value) })}
            className="w-full accent-cyber-red"
          />
        </Field>
      </SectionI18n>

      {/* Integrations */}
      <SectionI18n icon={Plug} titleKey="sidebar.integrations" lang={lang}>
        <Field label={t("sidebar.proxySource", lang)}>
          <select
            className={selectCls}
            value={config.proxy?.source || "none"}
            onChange={(e) => updateProxy({ source: e.target.value })}
          >
            <option value="none">None</option>
            <option value="auto">Auto-detect</option>
            <option value="burp">Burp Suite</option>
            <option value="zap">OWASP ZAP</option>
            <option value="burp_xml">Burp XML Export</option>
          </select>
        </Field>
        {config.proxy?.source === "burp_xml" && (
          <Field label={t("sidebar.burpXmlPath", lang)}>
            <input
              className={inputCls}
              value={config.proxy?.burp_xml_path || ""}
              onChange={(e) => updateProxy({ burp_xml_path: e.target.value })}
            />
          </Field>
        )}
        <Field label={t("sidebar.maxIterations", lang)}>
          <input
            type="number"
            className={inputCls}
            min={3}
            max={30}
            value={config.max_iterations}
            onChange={(e) => update({ max_iterations: safeInt(e.target.value) })}
          />
        </Field>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.memory_enabled}
            onChange={(e) => update({ memory_enabled: e.target.checked })}
            className="accent-cyber-neon"
          />
          <span className="text-cyber-dim text-sm">{t("sidebar.enableRag", lang)}</span>
        </label>
      </SectionI18n>

      {/* Online WAF Research */}
      <SectionI18n icon={Globe} titleKey="sidebar.webSearch" lang={lang}>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.web_search?.enabled ?? true}
            onChange={(e) => updateWebSearch({ enabled: e.target.checked })}
            className="accent-cyber-neon"
          />
          <span className="text-cyber-dim text-sm">{t("sidebar.webSearchEnable", lang)}</span>
        </label>
        {config.web_search?.enabled && (
          <div className="grid grid-cols-2 gap-2 mt-2">
            <Field label={t("sidebar.webSearchMaxResults", lang)}>
              <input
                type="number"
                className={inputCls}
                min={1}
                max={10}
                value={config.web_search?.max_results ?? 5}
                onChange={(e) => updateWebSearch({ max_results: safeInt(e.target.value) })}
              />
            </Field>
            <Field label={t("sidebar.webSearchTimeout", lang)}>
              <input
                type="number"
                className={inputCls}
                min={5}
                max={30}
                value={config.web_search?.timeout ?? 10}
                onChange={(e) => updateWebSearch({ timeout: safeInt(e.target.value) })}
              />
            </Field>
          </div>
        )}
      </SectionI18n>

      {/* Fast Test Mode */}
      <SectionI18n icon={Zap} titleKey="sidebar.fastTest" lang={lang}>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.fast_test?.enabled ?? false}
            onChange={(e) => updateFastTest({ enabled: e.target.checked })}
            className="accent-yellow-400"
          />
          <span className="text-yellow-400 text-sm font-bold">{t("sidebar.fastTest", lang)}</span>
        </label>
        <p className="text-cyber-dim/50 text-[10px]">{t("sidebar.fastTestDesc", lang)}</p>
        {config.fast_test?.enabled && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            className="space-y-2 mt-2"
          >
            <div className="text-yellow-400/70 text-[10px] font-mono border border-yellow-400/20 rounded-lg px-2 py-1.5 bg-yellow-400/5">
              {t("sidebar.fastTestWarning", lang)}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Field label={t("sidebar.bypassDelay", lang)}>
                <input
                  type="number"
                  className={inputCls}
                  min={0}
                  max={5}
                  step={0.1}
                  value={config.fast_test?.bypass_delay ?? 0.2}
                  onChange={(e) => updateFastTest({ bypass_delay: safeFloat(e.target.value) })}
                />
              </Field>
              <Field label={t("sidebar.exploitDelay", lang)}>
                <input
                  type="number"
                  className={inputCls}
                  min={0}
                  max={5}
                  step={0.1}
                  value={config.fast_test?.exploit_delay ?? 0.5}
                  onChange={(e) => updateFastTest({ exploit_delay: safeFloat(e.target.value) })}
                />
              </Field>
            </div>
            <Field label={t("sidebar.skipAnalysis", lang)}>
              <input
                type="number"
                className={inputCls}
                min={0}
                max={10}
                value={config.fast_test?.skip_analyzer_first_n ?? 3}
                onChange={(e) => updateFastTest({ skip_analyzer_first_n: safeInt(e.target.value) })}
              />
            </Field>
            <Field label={t("sidebar.quickVerify", lang)}>
              <input
                type="number"
                className={inputCls}
                min={1}
                max={3}
                value={config.fast_test?.quick_verify_count ?? 1}
                onChange={(e) => updateFastTest({ quick_verify_count: safeInt(e.target.value) })}
              />
            </Field>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={config.fast_test?.lightweight_recon ?? true}
                onChange={(e) => updateFastTest({ lightweight_recon: e.target.checked })}
                className="accent-yellow-400"
              />
              <span className="text-cyber-dim text-xs">{t("sidebar.lightweightRecon", lang)}</span>
            </label>
            {/* Usage recommendations */}
            <div className="mt-2 pt-2 border-t border-cyber-border/20 space-y-1.5">
              <div className="text-cyber-neon text-[10px] font-bold">
                {lang === "zh" ? "使用建议:" : "Usage Tips:"}
              </div>
              <div className="text-cyber-dim/60 text-[10px] space-y-0.5">
                <div>{lang === "zh" ? "开: 快速验证目标是否存在漏洞" : "ON: Quick target validation"}</div>
                <div>{lang === "zh" ? "开: 初次测试不熟悉的 WAF" : "ON: First test against unfamiliar WAF"}</div>
                <div>{lang === "zh" ? "关: 正式渗透测试 / 需要高精度绕过" : "OFF: Formal pentest / high-precision bypass needed"}</div>
                <div>{lang === "zh" ? "关: WAF 已确认存在，需要深度分析规则" : "OFF: WAF confirmed, need deep rule analysis"}</div>
              </div>
            </div>
          </motion.div>
        )}
      </SectionI18n>

      {/* Rate Limit & Anti-Ban */}
      <SectionI18n icon={Timer} titleKey="sidebar.rateLimit" lang={lang}>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t("sidebar.requestDelay", lang)}>
            <input
              type="number"
              className={inputCls}
              min={0}
              max={30}
              step={0.5}
              value={config.rate_limit?.request_delay ?? 1.0}
              onChange={(e) => updateRateLimit({ request_delay: safeFloat(e.target.value) })}
            />
          </Field>
          <Field label={t("sidebar.delayJitter", lang)}>
            <input
              type="number"
              className={inputCls}
              min={0}
              max={10}
              step={0.1}
              value={config.rate_limit?.delay_jitter ?? 0.5}
              onChange={(e) => updateRateLimit({ delay_jitter: safeFloat(e.target.value) })}
            />
          </Field>
        </div>
        <Field label={t("sidebar.jitterDist", lang)}>
          <select
            className={selectCls}
            value={config.rate_limit?.jitter_distribution ?? "uniform"}
            onChange={(e) => updateRateLimit({ jitter_distribution: e.target.value })}
          >
            <option value="uniform">Uniform (legacy)</option>
            <option value="normal">Normal (gaussian)</option>
          </select>
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t("sidebar.backoff429", lang)}>
            <input
              type="number"
              className={inputCls}
              min={5}
              max={300}
              step={5}
              value={config.rate_limit?.backoff_on_429 ?? 30.0}
              onChange={(e) => updateRateLimit({ backoff_on_429: safeFloat(e.target.value) })}
            />
          </Field>
          <Field label={t("sidebar.blockPause", lang)}>
            <input
              type="number"
              className={inputCls}
              min={10}
              max={600}
              step={10}
              value={config.rate_limit?.block_pause ?? 60.0}
              onChange={(e) => updateRateLimit({ block_pause: safeFloat(e.target.value) })}
            />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t("sidebar.backoffMultiplier", lang)}>
            <input
              type="number"
              className={inputCls}
              min={1}
              max={10}
              step={0.5}
              value={config.rate_limit?.backoff_multiplier ?? 2.0}
              onChange={(e) => updateRateLimit({ backoff_multiplier: safeFloat(e.target.value) })}
            />
          </Field>
          <Field label={t("sidebar.maxBackoff", lang)}>
            <input
              type="number"
              className={inputCls}
              min={10}
              max={600}
              step={10}
              value={config.rate_limit?.max_backoff ?? 120.0}
              onChange={(e) => updateRateLimit({ max_backoff: safeFloat(e.target.value) })}
            />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t("sidebar.maxConsecutiveBlocks", lang)}>
            <input
              type="number"
              className={inputCls}
              min={3}
              max={50}
              value={config.rate_limit?.max_consecutive_blocks ?? 10}
              onChange={(e) => updateRateLimit({ max_consecutive_blocks: safeInt(e.target.value) })}
            />
          </Field>
          <Field label={t("sidebar.verifyBypass", lang)}>
            <input
              type="number"
              className={inputCls}
              min={1}
              max={10}
              value={config.rate_limit?.verify_bypass_attempts ?? 3}
              onChange={(e) => updateRateLimit({ verify_bypass_attempts: safeInt(e.target.value) })}
            />
          </Field>
        </div>

        {/* Per-Stage Overrides */}
        <div className="border-t border-cyber-border/30 pt-3 mt-3">
          <div className="text-cyber-dim text-xs font-bold mb-2">{t("sidebar.perStage", lang)}</div>

          {/* Bypass Stage */}
          <div className="mb-3">
            <label className="flex items-center gap-2 cursor-pointer mb-2">
              <input
                type="checkbox"
                checked={!!config.bypass_rate_limit}
                onChange={(e) => {
                  if (e.target.checked) updateBypassRL({});
                  else clearBypassRL();
                }}
                className="accent-yellow-400"
              />
              <span className="text-yellow-400 text-xs font-mono">{t("sidebar.customBypass", lang)}</span>
            </label>
            {config.bypass_rate_limit && (
              <div className="grid grid-cols-2 gap-2 ml-4">
                <Field label={t("sidebar.requestDelay", lang)}>
                  <input type="number" className={inputCls} min={0} max={30} step={0.5}
                    value={config.bypass_rate_limit.request_delay}
                    onChange={(e) => updateBypassRL({ request_delay: safeFloat(e.target.value) })} />
                </Field>
                <Field label={t("sidebar.backoff429", lang)}>
                  <input type="number" className={inputCls} min={5} max={300} step={5}
                    value={config.bypass_rate_limit.backoff_on_429}
                    onChange={(e) => updateBypassRL({ backoff_on_429: safeFloat(e.target.value) })} />
                </Field>
              </div>
            )}
          </div>

          {/* Exploit Stage */}
          <div>
            <label className="flex items-center gap-2 cursor-pointer mb-2">
              <input
                type="checkbox"
                checked={!!config.exploit_rate_limit}
                onChange={(e) => {
                  if (e.target.checked) updateExploitRL({});
                  else clearExploitRL();
                }}
                className="accent-cyber-red"
              />
              <span className="text-cyber-red text-xs font-mono">{t("sidebar.customExploit", lang)}</span>
            </label>
            {config.exploit_rate_limit && (
              <div className="grid grid-cols-2 gap-2 ml-4">
                <Field label={t("sidebar.requestDelay", lang)}>
                  <input type="number" className={inputCls} min={0} max={30} step={0.5}
                    value={config.exploit_rate_limit.request_delay}
                    onChange={(e) => updateExploitRL({ request_delay: safeFloat(e.target.value) })} />
                </Field>
                <Field label={t("sidebar.backoff429", lang)}>
                  <input type="number" className={inputCls} min={5} max={300} step={5}
                    value={config.exploit_rate_limit.backoff_on_429}
                    onChange={(e) => updateExploitRL({ backoff_on_429: safeFloat(e.target.value) })} />
                </Field>
              </div>
            )}
          </div>
        </div>

        <div className="text-cyber-dim/40 text-[10px] mt-1 space-y-0.5">
          <p>{t("sidebar.rateLimitHelp.exponential", lang)}</p>
          <p>{t("sidebar.rateLimitHelp.jitter", lang)}</p>
          <p>{t("sidebar.rateLimitHelp.perStage", lang)}</p>
        </div>
      </SectionI18n>

      {/* Version — bottom padding for fade gradient */}
      <div className="text-center text-cyber-dim/20 text-[9px] font-mono pt-1 pb-4">
        {t("sidebar.version", lang)}
      </div>
    </div>
  );
}
