"use client";

import { useRef, useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Play, SkipForward, RotateCcw, Target, Zap, Shield, Crosshair, Timer, AlertTriangle, ChevronDown, ChevronRight, Beaker, Send, Loader2, Brain, RefreshCw, Square, Pause, PlayCircle, BookPlus } from "lucide-react";
import GlassCard from "@/components/GlassCard";
import StatusBadge from "@/components/StatusBadge";
import type { AttackState, AttackConfig } from "@/lib/types";
import type { ManualTestResult } from "@/lib/api";
import { testPayload, enrichKB } from "@/lib/api";
import { getLogColor, truncate } from "@/lib/utils";
import { t, type Lang } from "@/lib/i18n";

interface Props {
  state: AttackState;
  config: AttackConfig;
  lang: Lang;
  onStart: () => void;
  onStep: () => void;
  onReset: () => void;
  onStop?: () => void;
  onPause?: () => void;
  onResume?: () => void;
}

// Log line classification for visual differentiation
type LogCategory = "data" | "success" | "llm" | "blocked" | "error" | "info";

function classifyLogLine(line: string): LogCategory {
  if (line.includes("[EXPLOIT-VERIFY] LLM confirmed data extraction")) return "data";
  if (line.includes("VULNERABILITY CONFIRMED")) return "success";
  if (line.includes("[EXPLOIT-VERIFY]") || line.includes("[HYPOTHESIS]")) return "llm";
  if (line.includes("BLOCKED") || line.includes("[BYPASS-EXEC] BLOCKED")) return "blocked";
  if (line.includes("[ERROR]") || line.includes("VERIFY FAILED")) return "error";
  return "info";
}

const logCategoryStyles: Record<LogCategory, string> = {
  data: "bg-emerald-500/20 border-l-4 border-emerald-400 text-emerald-300 font-bold pl-3 py-1 rounded-r",
  success: "bg-green-500/15 border-l-4 border-green-400 text-green-300 font-bold pl-3 py-1 rounded-r",
  llm: "bg-purple-500/10 border-l-4 border-purple-400 text-purple-300 pl-3 py-0.5 rounded-r",
  blocked: "bg-orange-500/10 border-l-4 border-orange-400 text-orange-300 pl-3 py-0.5 rounded-r",
  error: "bg-red-900/20 border-l-4 border-red-600 text-red-400 pl-3 py-0.5 rounded-r",
  info: "",
};

function LogLine({ line, index, lang }: { line: string; index: number; lang: Lang }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetail = line.includes("Response:") || line.includes("BLOCKED") || line.includes("PASSED WAF") || line.includes("Trigger") || line.includes("Rule:") || line.includes("Suggested:") || line.includes("Indicators:") || line.includes("Evidence:") || line.includes("Low fitness") || line.includes("LOW FITNESS") || line.includes("Partial signal") || line.includes("VULNERABILITY CONFIRMED") || line.includes("EXPLOIT-EXEC") || line.includes("BYPASS-EXEC") || line.includes("login_page") || line.includes("Login page detected") || line.includes("EXPLOIT-PAYLOAD VERIFY") || line.includes("EXPLOIT-STAGE VERIFY") || line.includes("STRATEGY ROTATION");

  const category = classifyLogLine(line);
  const categoryStyle = logCategoryStyles[category];

  // Parse structured data from log line
  const getStatusBadge = () => {
    if (line.includes("BLOCKED") || line.includes("FALSE POSITIVE")) return { text: "BLOCKED", icon: "🛡️", color: "bg-red-500/15 text-red-400 border-red-500/40" };
    if (line.includes("PASSED WAF") && line.includes("exploit-payload-check OK")) return { text: "PASSED", icon: "⚡", color: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40" };
    if (line.includes("PASSED WAF")) return { text: "PASSED (需验证)", icon: "⚡", color: "bg-amber-500/15 text-amber-400 border-amber-500/40" };
    if (line.includes("RATE LIMITED")) return { text: "429", icon: "⏳", color: "bg-orange-500/15 text-orange-400 border-orange-500/40" };
    if (line.includes("CONFIRMED") || line.includes("VULNERABILITY CONFIRMED")) return { text: "SUCCESS", icon: "✅", color: "bg-emerald-500/20 text-emerald-300 border-emerald-400/50 font-extrabold" };
    if (line.includes("LOW FITNESS") || line.includes("Low fitness")) return { text: "LOW FITNESS", icon: "📉", color: "bg-amber-500/15 text-amber-400 border-amber-500/40" };
    if (line.includes("Partial signal")) return { text: "PARTIAL", icon: "🔍", color: "bg-blue-500/15 text-blue-400 border-blue-500/40" };
    if (line.includes("STRATEGY ROTATION")) return { text: "ROTATE", icon: "🔄", color: "bg-purple-500/15 text-purple-400 border-purple-500/40" };
    if (line.includes("EXPLOIT-STAGE VERIFY FAILED") || line.includes("EXPLOIT-PAYLOAD VERIFY FAILED")) return { text: "UNRELIABLE", icon: "❌", color: "bg-red-600/15 text-red-400 border-red-600/40" };
    if (line.includes("login_page") || line.includes("Login page detected")) return { text: "LOGIN PAGE", icon: "🔑", color: "bg-orange-500/15 text-orange-400 border-orange-500/40" };
    return null;
  };

  // Extract strategy tag
  const getStrategyTag = () => {
    const match = line.match(/Strategy=(\S+)/);
    if (match) return match[1];
    if (line.includes("[ERROR-BASED]")) return "ERROR-BASED";
    if (line.includes("[UNION]")) return "UNION";
    if (line.includes("[TIME-BLIND]")) return "TIME-BLIND";
    if (line.includes("[BOOLEAN-BLIND]")) return "BOOLEAN-BLIND";
    return null;
  };

  const statusBadge = getStatusBadge();
  const strategyTag = getStrategyTag();

  // Color map for strategy tags
  const strategyColors: Record<string, string> = {
    "ERROR-BASED": "bg-red-500/15 text-red-400 border-red-500/30",
    "UNION": "bg-purple-500/15 text-purple-400 border-purple-500/30",
    "TIME-BLIND": "bg-blue-500/15 text-blue-400 border-blue-500/30",
    "BOOLEAN-BLIND": "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    "PROBE": "bg-gray-500/15 text-gray-400 border-gray-500/30",
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.2 }}
      className="group"
    >
      <div className={`log-line ${categoryStyle || getLogColor(line)} flex items-start gap-2`}>
        {hasDetail && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="mt-0.5 text-cyber-dim/50 hover:text-cyber-neon transition-colors flex-shrink-0"
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        )}
        <span className="flex-1">{line}</span>
        {strategyTag && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono font-bold flex-shrink-0 ${strategyColors[strategyTag] || strategyColors["PROBE"]}`}>
            {strategyTag}
          </span>
        )}
        {statusBadge && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono font-bold flex-shrink-0 inline-flex items-center gap-1 ${statusBadge.color}`}>
            <span className="text-xs">{statusBadge.icon}</span>
            {statusBadge.text}
          </span>
        )}
      </div>
      {hasDetail && expanded && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          className="ml-6 mt-1 mb-2 overflow-hidden"
        >
          <div className="glass !p-3 !rounded-lg text-xs font-mono space-y-1.5">
            {line.includes("BLOCKED") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.status", lang)} </span>
                <span className="text-red-400 font-bold">{t("ac.detail.wafIntercepted", lang)}</span>
              </div>
            )}
            {line.includes("EXPLOIT-PAYLOAD VERIFY FAILED") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.analysis", lang)} </span>
                <span className="text-red-400 font-bold">
                  {lang === "zh"
                    ? "Exploit Payload 被 WAF 拦截 — 绕过技术不适用于实际攻击载荷"
                    : "Exploit payload blocked by WAF — bypass technique doesn't work for actual attack payloads"
                  }
                </span>
              </div>
            )}
            {line.includes("EXPLOIT-STAGE VERIFY FAILED") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.analysis", lang)} </span>
                <span className="text-red-400 font-bold">
                  {lang === "zh"
                    ? "Exploit 阶段验证失败 — Payload 在重复测试中不稳定"
                    : "Exploit-stage verification failed — payload unreliable under repeated testing"
                  }
                </span>
              </div>
            )}
            {line.includes("PASSED WAF") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.status", lang)} </span>
                <span className="text-emerald-400 font-bold">{t("ac.detail.payloadBypassed", lang)}</span>
              </div>
            )}
            {line.includes("Trigger") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.analysis", lang)} </span>
                <span className="text-yellow-400">{line.split("Trigger")[1]?.trim()}</span>
              </div>
            )}
            {line.includes("Rule:") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.wafRule", lang)} </span>
                <span className="text-cyber-purple">{line.split("Rule:")[1]?.trim()}</span>
              </div>
            )}
            {line.includes("Suggested:") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.bypassSuggestion", lang)} </span>
                <span className="text-cyber-neon">{line.split("Suggested:")[1]?.trim()}</span>
              </div>
            )}
            {line.includes("Indicators:") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.detectionSignals", lang)} </span>
                <span className="text-yellow-400">{line.split("Indicators:")[1]?.trim()}</span>
              </div>
            )}
            {line.includes("Evidence:") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.evidence", lang)} </span>
                <span className="text-white/80 break-all">{line.split("Evidence:")[1]?.trim()}</span>
              </div>
            )}
            {line.includes("Response:") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.responseBody", lang)} </span>
                <pre className="text-white/70 bg-black/40 rounded p-2 mt-1 overflow-x-auto max-h-40 text-[10px] whitespace-pre-wrap break-all">
                  {line.split("Response:")[1]?.trim()}
                </pre>
              </div>
            )}
            {line.includes("Low fitness") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.analysis", lang)} </span>
                <span className="text-amber-400">{t("ac.detail.lowFitnessDesc", lang)}</span>
              </div>
            )}
            {line.includes("Partial signal") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.analysis", lang)} </span>
                <span className="text-blue-400">{t("ac.detail.partialSignalDesc", lang)}</span>
              </div>
            )}
            {line.includes("VULNERABILITY CONFIRMED") && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.result", lang)} </span>
                <span className="text-green-400 font-bold">{t("ac.detail.exploitSuccess", lang)}</span>
              </div>
            )}
            {(line.includes("login_page") || line.includes("Login page detected")) && (
              <div>
                <span className="text-cyber-dim">{t("ac.detail.status", lang)} </span>
                <span className="text-orange-400 font-bold">{t("ac.loginPageDetected", lang)}</span>
                <div className="text-orange-300/70 text-[10px] mt-1">{t("ac.loginPageHint", lang)}</div>
              </div>
            )}
            {/* Request vs Response comparison for BYPASS-EXEC and EXPLOIT-EXEC lines */}
            {(line.includes("BYPASS-EXEC] Testing") || line.includes("EXPLOIT-EXEC] Testing") || line.includes("BYPASS-EXEC] Payload:") || line.includes("EXPLOIT-EXEC] Payload:")) && (() => {
              const payloadMatch = line.match(/(?:Testing #\d+: |Payload: )(.+)/);
              const payload = payloadMatch?.[1] || "";
              const responseMatch = line.includes("Response:") ? line.split("Response:")[1]?.trim() : null;
              if (!payload && !responseMatch) return null;
              return (
                <div className="mt-2 pt-2 border-t border-cyber-border/30">
                  <div className="text-cyber-purple text-[10px] font-bold uppercase tracking-wider mb-1.5">{t("manual.reqVsResp", lang)}</div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <div className="text-cyber-dim text-[9px] uppercase tracking-wider mb-0.5">{t("manual.reqPayload", lang)}</div>
                      <pre className="text-yellow-400/80 bg-black/50 rounded p-1.5 overflow-x-auto max-h-24 text-[9px] font-mono break-all">
                        {payload || "N/A"}
                      </pre>
                    </div>
                    <div>
                      <div className="text-cyber-dim text-[9px] uppercase tracking-wider mb-0.5">{t("manual.respBody", lang)}</div>
                      <pre className="text-white/60 bg-black/50 rounded p-1.5 overflow-x-auto max-h-24 text-[9px] font-mono break-all">
                        {responseMatch || "Expand to see response..."}
                      </pre>
                    </div>
                  </div>
                </div>
              );
            })()}
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}

function ManualTestPanel({ config, lang }: { config: AttackConfig; lang: Lang }) {
  const [payload, setPayload] = useState("");
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<ManualTestResult | null>(null);
  const [enriching, setEnriching] = useState(false);
  const [enrichDone, setEnrichDone] = useState(false);
  const [showComparison, setShowComparison] = useState(false);

  const handleTest = useCallback(async () => {
    if (!payload.trim()) return;
    setTesting(true);
    setResult(null);
    setEnrichDone(false);
    try {
      const res = await testPayload({
        payload: payload.trim(),
        endpoint: config.endpoint,
        param: config.param,
        method: config.method,
        base_url: config.target?.base_url || "http://localhost",
        timeout: config.target?.timeout || 10,
        php_sessid: config.target?.php_sessid || "",
        extra_params: config.target?.extra_params || {},
      });
      setResult(res);
    } catch {
      setResult({ success: false, blocked: false, status_code: 0, response_time: 0, evidence: "Request failed", indicators: [], response_snippet: "", confidence: 0 });
    } finally {
      setTesting(false);
    }
  }, [payload, config]);

  const handleEnrich = useCallback(async () => {
    if (!result?.evidence) return;
    setEnriching(true);
    try {
      await enrichKB({
        pattern: result.evidence.slice(0, 200),
        dbms: result.kb_matches?.[0]?.dbms || "generic",
        category: "syntax",
        confidence: result.confidence || 0.80,
        description: `Manual test: ${result.evidence.slice(0, 100)}`,
      });
      setEnrichDone(true);
    } catch {
      // ignore
    } finally {
      setEnriching(false);
    }
  }, [result]);

  return (
    <GlassCard glowColor="neon">
      <h4 className="text-cyber-neon font-bold text-sm mb-3 flex items-center gap-2">
        <Beaker size={16} /> {t("manual.title", lang)}
      </h4>
      <div className="flex gap-2 mb-3">
        <input
          type="text"
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
          placeholder={t("manual.placeholder", lang)}
          className="flex-1 bg-black/40 border border-cyber-border/50 rounded-lg px-3 py-2 text-xs font-mono text-white/90 placeholder:text-cyber-dim/40 focus:border-cyber-neon/50 focus:outline-none"
          onKeyDown={(e) => e.key === "Enter" && handleTest()}
        />
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={handleTest}
          disabled={testing || !payload.trim()}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyber-neon/10 border border-cyber-neon/30 text-cyber-neon text-xs font-mono font-bold disabled:opacity-40 hover:bg-cyber-neon/20 transition-all"
        >
          {testing ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
          {testing ? t("manual.testing", lang) : t("manual.test", lang)}
        </motion.button>
      </div>
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: -5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-2 text-xs font-mono"
          >
            <div className="flex items-center gap-2">
              {result.blocked ? (
                <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-bold">{t("manual.blocked", lang)}</span>
              ) : result.success ? (
                <span className="px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30 font-bold">{t("manual.passed", lang)}</span>
              ) : result.status_code === 0 ? (
                <span className="px-2 py-0.5 rounded bg-gray-500/20 text-gray-400 border border-gray-500/30 font-bold">{t("manual.error", lang)}</span>
              ) : (
                <span className="px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 font-bold">STATUS {result.status_code}</span>
              )}
              <span className="text-cyber-dim">|</span>
              <span className="text-white/70">HTTP {result.status_code}</span>
              <span className="text-cyber-dim">|</span>
              <span className="text-white/70">{result.response_time.toFixed(2)}s</span>
            </div>
            {result.evidence && (
              <div className="text-cyber-dim break-all">
                <span className="text-cyber-purple">Evidence:</span> {result.evidence}
              </div>
            )}
            {result.indicators && result.indicators.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {result.indicators.map((ind, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded bg-cyber-purple/10 text-cyber-purple border border-cyber-purple/20 text-[10px]">
                    {ind}
                  </span>
                ))}
              </div>
            )}
            {/* Response preview — use highlighted version if available */}
            {(result.response_preview_highlighted || result.response_snippet) && (
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-cyber-purple text-[10px] font-bold">{t("manual.responsePreview", lang)}</span>
                  {result.matched_keywords && result.matched_keywords.length > 0 && (
                    <span className="text-green-400 text-[10px]">{result.matched_keywords.length} {t("manual.kbMatchCount", lang)}</span>
                  )}
                </div>
                <pre className="text-white/60 bg-black/40 rounded p-2 overflow-x-auto max-h-32 text-[10px] whitespace-pre-wrap break-all">
                  {result.response_preview_highlighted || result.response_snippet}
                </pre>
              </div>
            )}
            {/* Smart suggestions — auto-extracted patterns */}
            {result.smart_suggestions && result.smart_suggestions.length > 0 && (
              <div className="mt-1.5">
                <span className="text-orange-400 text-[10px] font-bold">{t("manual.autoDetected", lang)}</span>
                <div className="space-y-0.5 mt-0.5">
                  {result.smart_suggestions.slice(0, 3).map((s, i) => (
                    <div key={i} className="text-[10px] text-white/50 font-mono truncate">
                      [{s.dbms}] {s.description}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {/* Request vs Response comparison */}
            {result.response_snippet && (
              <div className="mt-2">
                <button
                  onClick={() => setShowComparison(!showComparison)}
                  className="flex items-center gap-1 text-[10px] text-cyber-purple hover:text-cyber-neon transition-colors"
                >
                  {showComparison ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                  {t("manual.reqVsResp", lang)}
                </button>
                {showComparison && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="grid grid-cols-2 gap-2 mt-1.5"
                  >
                    <div>
                      <div className="text-cyber-dim text-[9px] uppercase tracking-wider mb-0.5">{t("manual.reqPayload", lang)}</div>
                      <pre className="text-yellow-400/80 bg-black/50 rounded p-1.5 overflow-x-auto max-h-20 text-[9px] font-mono break-all">
                        {payload}
                      </pre>
                    </div>
                    <div>
                      <div className="text-cyber-dim text-[9px] uppercase tracking-wider mb-0.5">{t("manual.respBody", lang)}</div>
                      <pre className="text-white/60 bg-black/50 rounded p-1.5 overflow-x-auto max-h-20 text-[9px] font-mono break-all">
                        {result.response_snippet.slice(0, 500)}
                      </pre>
                    </div>
                  </motion.div>
                )}
              </div>
            )}
            {/* KB matches */}
            {result.kb_matches && result.kb_matches.length > 0 && (
              <div className="mt-1.5">
                <span className="text-cyber-purple text-[10px] font-bold">{t("manual.kbMatches", lang)}</span>
                <div className="flex flex-wrap gap-1 mt-0.5">
                  {result.kb_matches.map((m, i) => (
                    <span key={i} className="px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20 text-[10px] font-mono">
                      {m.description} ({(m.confidence * 100).toFixed(0)}%)
                    </span>
                  ))}
                </div>
              </div>
            )}
            {/* Enrich button — visible when success detected */}
            {result.success && !enrichDone && (
              <motion.button
                initial={{ opacity: 0, y: -3 }}
                animate={{ opacity: 1, y: 0 }}
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                onClick={handleEnrich}
                disabled={enriching}
                className="mt-2 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-purple/15 border border-cyber-purple/40 text-cyber-purple text-[10px] font-mono font-bold hover:bg-cyber-purple/25 transition-all"
              >
                {enriching ? <Loader2 size={12} className="animate-spin" /> : <BookPlus size={12} />}
                {enriching ? t("manual.adding", lang) : t("manual.addToKB", lang)}
              </motion.button>
            )}
            {enrichDone && (
              <div className="mt-1.5 text-green-400 text-[10px] font-mono">{t("manual.addedToKB", lang)}</div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </GlassCard>
  );
}

export default function AttackConsole({ state, config, lang, onStart, onStep, onReset, onStop, onPause, onResume }: Props) {
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [state.logs]);

  const status = state.running
    ? "running"
    : state.success
      ? "success"
      : state.completed
        ? "done"
        : "idle";

  const gaLine = state.ga_stats?.generation
    ? ` · Gen ${state.ga_stats.generation} · Best ${state.ga_stats.best_fitness?.toFixed(3)}`
    : "";

  const fp = state.injection_fingerprint;
  const reconCompleted = state.current_phase !== "idle" && state.stage !== "idle";
  // Don't show "no injection" if SQL errors were found (likely injectable despite probe failure)
  const hasSqlEvidence = fp?.sql_error_evidence && fp.sql_error_evidence.length > 0;
  const showNoInjection = reconCompleted && fp && !fp.is_injectable && !fp.connection_error && !hasSqlEvidence;

  return (
    <div className="space-y-5 animate-fade-in-up">
      {/* Fast Mode banner — prominent when enabled */}
      {config.fast_test?.enabled && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass !px-5 !py-3 border-l-4 border-yellow-400/60 bg-gradient-to-r from-yellow-500/10 to-transparent"
        >
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Zap size={18} className="text-yellow-400" />
              <span className="text-yellow-400 font-bold text-sm font-mono">{t("attack.fastMode", lang)}</span>
            </div>
            <span className="text-yellow-300/60 text-xs">
              {lang === "zh"
                ? "速度优先，分析较轻 — 延迟 0.2s，跳过深度探测，单次验证"
                : "Speed first, lightweight analysis — 0.2s delay, skip deep probing, single verify"
              }
            </span>
          </div>
        </motion.div>
      )}

      {/* Status bar */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <StatusBadge status={status} lang={lang} />
          {/* Stage indicator — prominent */}
          {state.stage && state.stage !== "idle" && (
            <div className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold font-mono ${
              state.stage === "bypass"
                ? "bg-yellow-500/10 border border-yellow-500/30 text-yellow-400"
                : "bg-cyber-red/10 border border-cyber-red/30 text-cyber-red"
            }`}>
              {state.stage === "bypass" ? <Shield size={16} /> : <Crosshair size={16} />}
              {state.stage === "bypass" ? t("attack.stage1", lang) : t("attack.stage2", lang)}
              {state.stage === "exploit" && state.waf_result && !state.waf_result.detected && (
                <span className="text-green-400 ml-1">(No WAF)</span>
              )}
              {state.bypass_success && state.stage === "exploit" && (
                <span className="text-cyber-neon ml-1">{t("attack.bypassed", lang)}</span>
              )}
            </div>
          )}
          {/* Fast mode indicator */}
          {config.fast_test?.enabled && (
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-yellow-500/10 border border-yellow-500/30 text-yellow-400">
              <Zap size={12} />
              {t("attack.fastMode", lang)}
            </div>
          )}
          {/* Strategy rotation indicator */}
          {state.stage === "exploit" && (state.consecutive_low_fitness ?? 0) > 0 && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono bg-orange-500/10 border border-orange-500/30 text-orange-400">
              <span className="text-orange-400 font-bold">{t("exploit.rotation", lang)}</span>
              <span className="text-cyber-dim">|</span>
              <span>{state.consecutive_low_fitness}/4 {t("exploit.lowFitness", lang)}</span>
              <span className="text-cyber-dim">|</span>
              <span className="text-cyber-neon">{t("exploit.currentStrategy", lang)}: {(state.current_strategy || "error").toUpperCase()}</span>
            </div>
          )}
          <span className="text-cyber-dim text-sm font-mono">
            {t("attack.iteration", lang)} {state.iteration}/{config.max_iterations}
            {gaLine}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={onStart}
            disabled={state.running}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyber-neon/15 to-cyber-purple/15 border border-cyber-neon/25 text-cyber-neon font-bold text-sm font-mono disabled:opacity-40 disabled:cursor-not-allowed hover:border-cyber-neon/40 transition-all"
          >
            <Play size={16} /> {t("attack.start", lang)}
          </motion.button>
          {/* Stop button — red, visible when running */}
          {state.running && !state.paused && onStop && (
            <motion.button
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={onStop}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 font-bold text-sm font-mono hover:bg-red-500/20 transition-all"
            >
              <Square size={14} /> {t("attack.stop", lang)}
            </motion.button>
          )}
          {/* Pause button — yellow, visible when running */}
          {state.running && !state.paused && onPause && (
            <motion.button
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={onPause}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 font-bold text-sm font-mono hover:bg-yellow-500/20 transition-all"
            >
              <Pause size={14} /> {t("attack.pause", lang)}
            </motion.button>
          )}
          {/* Resume button — green, visible when paused */}
          {state.paused && onResume && (
            <motion.button
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={onResume}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-green-500/10 border border-green-500/30 text-green-400 font-bold text-sm font-mono hover:bg-green-500/20 transition-all"
            >
              <PlayCircle size={14} /> {t("attack.resume", lang)}
            </motion.button>
          )}
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={onStep}
            disabled={state.running}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl glass border border-cyber-border text-cyber-dim font-mono text-sm disabled:opacity-40 hover:border-cyber-purple/30 hover:text-cyber-purple transition-all"
          >
            <SkipForward size={16} /> {t("attack.step", lang)}
          </motion.button>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={onReset}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl glass border border-cyber-border text-cyber-dim font-mono text-sm hover:border-cyber-red/30 hover:text-cyber-red transition-all"
          >
            <RotateCcw size={16} /> {t("attack.reset", lang)}
          </motion.button>
        </div>
      </div>

      {/* Target info bar */}
      <div className="glass px-4 py-3 flex items-center gap-4 flex-wrap text-sm font-mono">
        <div className="flex items-center gap-2 text-cyber-neon">
          <Target size={14} />
          <span>{t("attack.target", lang)}</span>
        </div>
        <code className="text-white/90">
          {(() => {
            const base = (config.target?.base_url || "http://localhost").replace(/\/+$/, "");
            const ep = (config.endpoint || "/").replace(/^\/+/, "/");
            // Avoid duplicate path segments
            if (ep !== "/" && base.endsWith(ep)) return base;
            return `${base}${ep}`;
          })()}
        </code>
        <span className="text-cyber-purple">{config.vuln_type.toUpperCase()}</span>
        <span className="text-cyber-dim">{config.method} ?{config.param}=</span>
      </div>

      {/* Progress bar */}
      {state.running && (
        <div className="glass px-4 py-2">
          <div className="flex items-center justify-between text-[10px] font-mono text-cyber-dim mb-1">
            <span>{t("attack.progress", lang)}</span>
            <span>{state.iteration}/{config.max_iterations} {t("attack.iteration", lang)}</span>
          </div>
          <div className="w-full h-1.5 bg-black/40 rounded-full overflow-hidden">
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-cyber-neon/60 to-cyber-purple/60"
              initial={{ width: 0 }}
              animate={{ width: `${Math.min(100, (state.iteration / Math.max(config.max_iterations, 1)) * 100)}%` }}
              transition={{ duration: 0.3 }}
            />
          </div>
          {state.current_phase && state.current_phase !== "idle" && (
            <div className="text-[9px] text-cyber-dim/50 mt-1 font-mono">
              {state.current_phase.replace(/_/g, " ").toUpperCase()}
            </div>
          )}
        </div>
      )}

      {/* Connection error banner */}
      {(state.connection_errors ?? 0) >= 4 || state.injection_fingerprint?.connection_error ? (
        <div className="glass !p-4 border-2 border-red-500/50 bg-red-500/10 rounded-xl">
          <div className="flex items-center gap-3">
            <AlertTriangle size={20} className="text-red-400" />
            <div>
              <div className="text-red-400 font-bold text-sm">{t("attack.stopReason.connectionErrors", lang)}</div>
              <div className="text-red-300/70 text-xs mt-1">
                {state.injection_fingerprint?.error_detail || t("attack.connErrorDetail", lang)}
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {/* Login page detection banner — PHPSESSID expired or missing */}
      {state.logs.some((l) => l.includes("login_page") || l.includes("Login page detected")) && (
        <motion.div
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass !p-4 border-2 border-orange-500/50 bg-orange-500/10 rounded-xl"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle size={20} className="text-orange-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="text-orange-400 font-bold text-sm">{t("ac.loginPageDetected", lang)}</div>
              <div className="text-orange-300/70 text-xs mt-1">{t("ac.loginPageHint", lang)}</div>
              <div className="mt-2 px-3 py-2 rounded-lg bg-orange-500/10 border border-orange-500/20">
                <code className="text-orange-300 text-[11px] font-mono">{t("ac.dvwaHint", lang)}</code>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Paused banner */}
      {state.paused && (
        <motion.div
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass !p-4 border-2 border-yellow-500/50 bg-yellow-500/10 rounded-xl"
        >
          <div className="flex items-center gap-3">
            <Pause size={20} className="text-yellow-400" />
            <div className="flex-1">
              <div className="text-yellow-400 font-bold text-sm">{t("attack.paused", lang)}</div>
              <div className="text-yellow-300/70 text-xs mt-1">
                {state.stop_reason === "low_fitness_stall"
                  ? t("attack.stopReason.lowFitness", lang)
                  : t("attack.pausedHint", lang)}
              </div>
              {state.stop_reason === "low_fitness_stall" && (
                <div className="text-yellow-200/50 text-[10px] mt-1.5 font-mono">
                  {lang === "zh"
                    ? "建议: 切换策略、手动测试 Payload、或调整目标配置后恢复"
                    : "Tip: Switch strategy, manually test payloads, or adjust config before resuming"}
                </div>
              )}
            </div>
            {onResume && (
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={onResume}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 font-bold text-xs font-mono hover:bg-green-500/20 transition-all flex-shrink-0"
              >
                <PlayCircle size={14} /> {t("attack.resume", lang)}
              </motion.button>
            )}
          </div>
        </motion.div>
      )}

      {/* Stop reason banner */}
      {!state.running && state.completed && state.stop_reason && !state.paused && (
        <motion.div
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          className={`glass !p-4 border-2 rounded-xl ${
            state.stop_reason === "server_errors"
              ? "border-red-500/50 bg-red-500/10"
              : state.stop_reason === "connection_errors"
                ? "border-red-500/50 bg-red-500/10"
                : state.stop_reason === "user_stop"
                  ? "border-orange-500/50 bg-orange-500/10"
                  : "border-yellow-500/50 bg-yellow-500/10"
          }`}
        >
          <div className="flex items-center gap-3">
            <AlertTriangle size={20} className={
              state.stop_reason === "server_errors" ? "text-red-400"
                : state.stop_reason === "connection_errors" ? "text-red-400"
                : state.stop_reason === "user_stop" ? "text-orange-400"
                : "text-yellow-400"
            } />
            <div>
              <div className={`font-bold text-sm ${
                state.stop_reason === "server_errors" ? "text-red-400"
                  : state.stop_reason === "connection_errors" ? "text-red-400"
                  : state.stop_reason === "user_stop" ? "text-orange-400"
                  : "text-yellow-400"
              }`}>
                {t(`attack.stopReason.${state.stop_reason === "server_errors" ? "serverErrors" : state.stop_reason === "connection_errors" ? "connectionErrors" : state.stop_reason === "user_stop" ? "userStop" : "lowFitness"}` as any, lang)}
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Injection fingerprint display — vuln-type adaptive */}
      {state.vuln_type === "sqli" && fp?.is_injectable && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-xl border border-green-500/30 bg-gradient-to-r from-green-500/10 via-emerald-500/5 to-green-500/3"
        >
          <div className="px-5 py-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-green-400 font-bold text-base">{t("vuln.sqliPoint", lang)}</span>
              <span className="ml-auto text-green-400/70 text-xs font-mono">
                {t("recon.confidence", lang)}: <span className="text-green-300 font-bold text-sm">{((fp.confidence ?? 0) * 100).toFixed(0)}%</span>
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.quote", lang)}</div>
                <div className="text-cyber-neon font-mono font-bold text-lg">{fp.quote_type || "unknown"}</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.closure", lang)}</div>
                <div className="text-yellow-400 font-mono font-bold text-lg">{fp.closure_char || "'"}</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.comment", lang)}</div>
                <div className="text-cyber-purple font-mono font-bold text-lg">{fp.comment_style || "--"}</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.dbms", lang)}</div>
                <div className="text-orange-400 font-mono font-bold text-lg">{fp.dbms_hint || "unknown"}</div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
      {state.vuln_type === "xss" && fp?.is_injectable && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-xl border border-green-500/30 bg-gradient-to-r from-green-500/10 via-emerald-500/5 to-green-500/3"
        >
          <div className="px-5 py-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-green-400 font-bold text-base">{t("vuln.xssPoint", lang)}</span>
              <span className="ml-auto text-green-400/70 text-xs font-mono">
                {t("recon.confidence", lang)}: <span className="text-green-300 font-bold text-sm">{((fp.confidence ?? 0) * 100).toFixed(0)}%</span>
              </span>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("vuln.context", lang)}</div>
                <div className="text-cyber-neon font-mono font-bold text-lg">{t("vuln.reflected", lang)}</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.confidence", lang)}</div>
                <div className="text-green-400 font-mono font-bold text-lg">{((fp.confidence ?? 0) * 100).toFixed(0)}%</div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
      {state.vuln_type === "cmdi" && fp?.is_injectable && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-xl border border-green-500/30 bg-gradient-to-r from-green-500/10 via-emerald-500/5 to-green-500/3"
        >
          <div className="px-5 py-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-green-400 font-bold text-base">{t("vuln.cmdiPoint", lang)}</span>
              <span className="ml-auto text-green-400/70 text-xs font-mono">
                {t("recon.confidence", lang)}: <span className="text-green-300 font-bold text-sm">{((fp.confidence ?? 0) * 100).toFixed(0)}%</span>
              </span>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.confidence", lang)}</div>
                <div className="text-green-400 font-mono font-bold text-lg">{((fp.confidence ?? 0) * 100).toFixed(0)}%</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("vuln.separator", lang)}</div>
                <div className="text-orange-400 font-mono font-bold text-lg">✓</div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
      {/* Fallback: show original sqli-style fingerprint when vuln_type is not set */}
      {!state.vuln_type && fp?.is_injectable && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-xl border border-green-500/30 bg-gradient-to-r from-green-500/10 via-emerald-500/5 to-green-500/3"
        >
          <div className="px-5 py-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-green-400 font-bold text-base">{t("recon.confirmed", lang)}</span>
              <span className="ml-auto text-green-400/70 text-xs font-mono">
                {t("recon.confidence", lang)}: <span className="text-green-300 font-bold text-sm">{((fp.confidence ?? 0) * 100).toFixed(0)}%</span>
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.quote", lang)}</div>
                <div className="text-cyber-neon font-mono font-bold text-lg">{fp.quote_type || "unknown"}</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.closure", lang)}</div>
                <div className="text-yellow-400 font-mono font-bold text-lg">{fp.closure_char || "'"}</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.comment", lang)}</div>
                <div className="text-cyber-purple font-mono font-bold text-lg">{fp.comment_style || "--"}</div>
              </div>
              <div className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("recon.dbms", lang)}</div>
                <div className="text-orange-400 font-mono font-bold text-lg">{fp.dbms_hint || "unknown"}</div>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* No injection point — suggestion banner */}
      {showNoInjection && (
        <motion.div
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass !p-4 border-2 border-amber-500/40 bg-amber-500/5 rounded-xl"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle size={18} className="text-amber-400 mt-0.5 flex-shrink-0" />
            <div>
              <div className="text-amber-400 font-bold text-sm mb-1">{t("recon.noInjection", lang)}</div>
              <div className="text-amber-300/70 text-xs">{t("recon.suggest", lang)}</div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Recon Report — deep analysis results */}
      {state.recon_report && reconCompleted && (
        <motion.div
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass !p-4 border border-cyber-neon/20 rounded-xl"
        >
          <div className="flex items-center gap-2 mb-3">
            <Brain size={16} className="text-cyber-neon" />
            <span className="text-cyber-neon font-bold text-sm">{t("recon.report", lang)}</span>
            {state.recommended_strategy && state.recommended_strategy !== "unknown" && (
              <span className="ml-auto px-2 py-0.5 rounded bg-cyber-purple/15 text-cyber-purple border border-cyber-purple/30 text-[10px] font-mono font-bold">
                {t("recon.recommended", lang)}: {state.recommended_strategy.toUpperCase()}
              </span>
            )}
          </div>
          <div className="text-white/80 text-xs font-mono leading-relaxed">
            {state.recon_report}
          </div>
          {/* SQL errors found */}
          {fp?.sql_error_evidence && fp.sql_error_evidence.length > 0 && (
            <div className="mt-3 pt-3 border-t border-cyber-border/30">
              <div className="text-red-400 text-[10px] font-bold uppercase tracking-wider mb-1">{t("recon.sqlErrors", lang)}</div>
              <div className="flex flex-wrap gap-1">
                {fp.sql_error_evidence.slice(0, 5).map((err, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 text-[10px] font-mono">
                    {err}
                  </span>
                ))}
              </div>
            </div>
          )}
          {/* Data leak signals */}
          {fp?.data_leak_evidence && fp.data_leak_evidence.length > 0 && (
            <div className="mt-2 pt-2 border-t border-cyber-border/30">
              <div className="text-yellow-400 text-[10px] font-bold uppercase tracking-wider mb-1">{t("recon.dataLeaks", lang)}</div>
              <div className="flex flex-wrap gap-1">
                {fp.data_leak_evidence.slice(0, 5).map((leak, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 text-[10px] font-mono">
                    {leak.pattern} ({(leak.confidence * 100).toFixed(0)}%)
                  </span>
                ))}
              </div>
            </div>
          )}
          {/* Likely injectable hint (when standard probe failed but SQL errors found) */}
          {!fp?.is_injectable && fp?.sql_error_evidence && fp.sql_error_evidence.length > 0 && (
            <div className="mt-2 pt-2 border-t border-cyber-border/30">
              <div className="flex items-center gap-2">
                <AlertTriangle size={12} className="text-amber-400" />
                <span className="text-amber-400 text-xs font-mono">{t("recon.likelyInjectable", lang)}</span>
              </div>
            </div>
          )}
        </motion.div>
      )}

      {/* Main area */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* Log panel */}
        <div className="lg:col-span-3 space-y-4">
          <GlassCard glowColor="neon" className="!p-0 overflow-hidden">
            <div className="px-5 py-3 border-b border-cyber-border flex items-center gap-2">
              <Zap size={16} className="text-cyber-neon" />
              <span className="text-cyber-neon font-bold text-sm">
                {t("attack.thoughtChain", lang)}
              </span>
              <span className="text-cyber-dim text-xs ml-auto font-mono">
                {state.logs.length} {t("attack.entries", lang)}
              </span>
            </div>
            <div
              ref={logRef}
              className="p-5 max-h-[520px] overflow-y-auto"
              style={{
                background: "rgba(0, 0, 0, 0.15)",
              }}
            >
              {state.logs.length === 0 ? (
                <div className="text-cyber-dim/40 text-sm font-mono text-center py-10">
                  {state.running ? (
                    <div className="flex items-center justify-center gap-2">
                      <Loader2 size={16} className="text-cyber-neon animate-spin" />
                      <span className="text-cyber-neon">{t("attack.initializing", lang)}</span>
                    </div>
                  ) : (
                    t("attack.waiting", lang)
                  )}
                </div>
              ) : (
                <div className="space-y-0.5">
                  {state.logs.map((line, i) => (
                    <LogLine key={i} line={line} index={i} lang={lang} />
                  ))}
                </div>
              )}
              {state.running && (
                <div className="log-line text-cyber-neon typing-cursor mt-1" />
              )}
            </div>
          </GlassCard>

          {/* Manual Payload Test — below log panel */}
          <ManualTestPanel config={config} lang={lang} />
        </div>

        {/* Side info */}
        <div className="space-y-4">
          {/* Current Analysis — real-time response understanding */}
          {state.current_analysis && (
            <GlassCard glowColor="neon">
              <h4 className="text-cyber-neon font-bold text-sm mb-3 flex items-center gap-2">
                <Brain size={16} /> {t("analysis.title", lang)}
              </h4>
              <div className="text-white/80 text-xs font-mono leading-relaxed">
                {state.current_analysis}
              </div>
            </GlassCard>
          )}

          {/* Strategy Status — shows current exploitation strategy */}
          {state.stage === "exploit" && (
            <GlassCard glowColor="purple">
              <h4 className="text-orange-400 font-bold text-sm mb-3 flex items-center gap-2">
                <RefreshCw size={16} /> {t("exploit.manualOverride", lang)}
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {["error", "union", "blind", "time"].map((s) => (
                  <span
                    key={s}
                    className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold border ${
                      (state.current_strategy || "error") === s
                        ? "bg-cyber-neon/20 border-cyber-neon/50 text-cyber-neon"
                        : "bg-black/30 border-cyber-border/30 text-cyber-dim/50"
                    }`}
                  >
                    {s.toUpperCase()}
                  </span>
                ))}
              </div>
              {state.recommended_strategy && (
                <div className="mt-2 text-[10px] text-cyber-dim font-mono">
                  {t("ac.reconRecommends", lang)} <span className="text-cyber-purple">{state.recommended_strategy.toUpperCase()}</span>
                </div>
              )}
            </GlassCard>
          )}

          {/* WAF Blind Test Indicator — shows when WAF is unknown and bypass stage active */}
          {state.stage === "bypass" && state.waf_result && !state.waf_result.detected && state.bypass_history && state.bypass_history.length > 0 && (
            <GlassCard glowColor="purple">
              <h4 className="text-orange-400 font-bold text-sm mb-3 flex items-center gap-2">
                <AlertTriangle size={16} /> {t("ac.wafBlindTest", lang)}
              </h4>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-cyber-dim">{t("ac.wafStatus", lang)}</span>
                  <span className="text-orange-400 font-bold">{t("ac.wafUnknown", lang)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cyber-dim">{t("ac.blockRate", lang)}</span>
                  <span className="text-white/70">
                    {(() => {
                      const total = state.bypass_history?.length || 0;
                      const blocked = state.bypass_history?.filter((h: any) => [403, 406, 503].includes(h.status_code)).length || 0;
                      return total > 0 ? `${Math.round(blocked * 100 / total)}%` : "N/A";
                    })()}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cyber-dim">{t("ac.attempts", lang)}</span>
                  <span className="text-white/70">{state.bypass_history?.length || 0}</span>
                </div>
                {(state.consecutive_low_fitness ?? 0) > 0 && (
                  <div className="flex justify-between items-center">
                    <span className="text-cyber-dim">{t("ac.consecutiveBlocksLabel", lang)}</span>
                    <span className={(state.consecutive_low_fitness ?? 0) >= 4 ? "text-red-400 font-bold" : "text-yellow-400"}>
                      {state.consecutive_low_fitness ?? 0}
                    </span>
                  </div>
                )}
                {/* Auto-suggestion — escalates with block count */}
                {(state.bypass_history?.length || 0) >= 6 && (() => {
                  const total = state.bypass_history?.length || 0;
                  const blocked = state.bypass_history?.filter((h: any) => [403, 406, 503].includes(h.status_code)).length || 0;
                  const blockRate = total > 0 ? Math.round(blocked * 100 / total) : 0;
                  const isHighBlock = blockRate >= 80;
                  return (
                    <div className="mt-2 pt-2 border-t border-cyber-border/30">
                      <div className={`text-${isHighBlock ? 'red' : 'amber'}-400 text-[10px] font-bold mb-1`}>
                        {isHighBlock ? `⚠️ ${t("ac.highBlockRate", lang)}` : t("ac.autoSuggestion", lang)}
                      </div>
                      {isHighBlock ? (
                        <div className="space-y-1 text-[10px] text-white/60">
                          <div>1. {t("ac.bypass.chunked", lang)}</div>
                          <div>2. {t("ac.bypass.headerPollution", lang)}</div>
                          <div>3. {t("ac.bypass.methodSwitch", lang)}</div>
                          <div>4. {t("ac.bypass.jsonContent", lang)}</div>
                          <div>5. {t("ac.bypass.caseVariation", lang)}</div>
                        </div>
                      ) : (
                        <div className="text-white/60 text-[10px]">
                          {t("ac.bypass.genericSuggestion", lang)}
                        </div>
                      )}
                    </div>
                  );
                })()}
              </div>
            </GlassCard>
          )}

          {/* Bypass success card */}
          <AnimatePresence>
            {state.bypass_success && state.bypass_payload && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
              >
                <GlassCard glowColor="purple">
                  <h4 className="text-yellow-400 font-bold text-sm mb-3 flex items-center gap-2">
                    <Shield size={16} /> {t("attack.wafBypassed", lang)}
                  </h4>
                  {/* Warning: bypass success doesn't guarantee exploit will pass */}
                  <div className="flex items-start gap-2 mb-3 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/30">
                    <AlertTriangle size={14} className="text-amber-400 flex-shrink-0 mt-0.5" />
                    <span className="text-amber-300 text-[10px] font-mono leading-relaxed">
                      {lang === "zh"
                        ? "注意: 绕过成功 ≠ 漏洞利用成功。Exploit 阶段的 Payload 仍可能被 WAF 拦截。"
                        : "Warning: Bypass success ≠ Exploit success. Exploit payloads may still be blocked by WAF."
                      }
                    </span>
                  </div>
                  <div className="text-cyber-neon text-xs font-mono mb-2">
                    {t("attack.technique", lang)}: {state.bypass_technique || "unknown"}
                  </div>
                  <pre className="text-white/90 text-xs bg-black/40 rounded-lg p-3 overflow-x-auto font-mono">
                    {state.bypass_payload}
                  </pre>
                </GlassCard>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Rate Limit Status */}
          {state.rate_limit_status && Object.keys(state.rate_limit_status).length > 0 && (
            <GlassCard glowColor="purple">
              <h4 className="text-cyber-neon font-bold text-sm mb-3 flex items-center gap-2">
                <Timer size={16} /> {t("attack.rateLimit", lang)}
              </h4>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-cyber-dim">{t("attack.currentDelay", lang)}</span>
                  <span className={state.rate_limit_status.is_backing_off ? "text-orange-400" : "text-cyber-neon"}>
                    {state.rate_limit_status.current_delay?.toFixed(1)}s
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cyber-dim">{t("attack.baseDelay", lang)}</span>
                  <span className="text-white/70">{state.rate_limit_status.base_delay?.toFixed(1)}s</span>
                </div>
                {state.rate_limit_status.is_backing_off && (
                  <div className="flex justify-between items-center">
                    <span className="text-cyber-dim flex items-center gap-1">
                      <AlertTriangle size={12} className="text-orange-400" /> {t("attack.backoffLevel", lang)}
                    </span>
                    <span className="text-orange-400 font-bold">
                      {state.rate_limit_status.backoff_level}
                    </span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-cyber-dim">{t("attack.consecutiveBlocks", lang)}</span>
                  <span className={
                    (state.rate_limit_status.consecutive_blocks ?? 0) >= (state.rate_limit_status.max_consecutive_blocks ?? 10) * 0.7
                      ? "text-orange-400" : "text-white/70"
                  }>
                    {state.rate_limit_status.consecutive_blocks ?? 0}/{state.rate_limit_status.max_consecutive_blocks ?? 10}
                  </span>
                </div>
                {/* Backoff progress bar */}
                <div className="mt-1">
                  <div className="w-full h-1.5 bg-black/40 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        state.rate_limit_status.is_backing_off ? "bg-orange-400" : "bg-cyber-neon"
                      }`}
                      style={{
                        width: `${Math.min(
                          ((state.rate_limit_status.consecutive_blocks ?? 0) / (state.rate_limit_status.max_consecutive_blocks ?? 10)) * 100,
                          100
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            </GlassCard>
          )}

          {/* Latest response */}
          <GlassCard glowColor="purple" delay={0.1}>
            <h4 className="text-cyber-neon font-bold text-sm mb-3">
              {t("attack.latestResponse", lang)}
            </h4>
            {state.history.length > 0 ? (
              (() => {
                const last = state.history[state.history.length - 1];
                const isOk = last.result === "success";
                const isBypass = last.result === "bypass" || last.result === "bypass_success";
                const isBlocked = last.result === "blocked";
                const label = isOk
                  ? t("attack.exploitSuccess", lang)
                  : isBypass
                    ? t("attack.wafBypassedLabel", lang)
                    : isBlocked
                      ? t("attack.blocked", lang)
                      : t("attack.fail", lang);
                const color = isOk ? "text-emerald-300" : isBypass ? "text-yellow-300" : isBlocked ? "text-red-400" : "text-cyber-dim";
                const bgColor = isOk ? "bg-emerald-500/10 border-emerald-400/30" : isBypass ? "bg-yellow-500/10 border-yellow-500/30" : isBlocked ? "bg-red-500/10 border-red-500/30" : "bg-black/20 border-cyber-border/30";
                return (
                  <div>
                    <div className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border ${bgColor} mb-2`}>
                      <span className="text-lg">{isOk ? "✅" : isBypass ? "⚡" : isBlocked ? "🛡️" : "❌"}</span>
                      <span className={`font-bold text-sm ${color}`}>{label}</span>
                    </div>
                    <pre className="text-white/80 text-xs block break-all max-h-32 overflow-y-auto bg-black/30 rounded p-2 whitespace-pre-wrap">
                      {last.payload}
                    </pre>
                    <div className="text-cyber-dim text-xs mt-2 font-mono">
                      fitness: {last.fitness.toFixed(3)}
                    </div>
                  </div>
                );
              })()
            ) : (
              <div className="text-cyber-dim/40 text-sm">{t("attack.noData", lang)}</div>
            )}
          </GlassCard>

          {/* Success exploit — prominent green banner */}
          <AnimatePresence>
            {state.success && state.final_result && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
              >
                <div className="relative overflow-hidden rounded-xl border border-green-500/40 bg-gradient-to-r from-green-500/12 via-emerald-500/8 to-green-500/5">
                  <div className="px-5 py-4">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-3 h-3 rounded-full bg-green-400 animate-pulse" />
                      <span className="text-green-400 font-bold text-lg">{t("ac.vulnConfirmed", lang)}</span>
                    </div>
                    {/* Extracted data — most prominent display */}
                    {state.extracted_data && (
                      <div className="mb-4 p-4 rounded-xl bg-emerald-500/15 border-2 border-emerald-400/40">
                        <div className="text-emerald-400 text-[10px] font-bold uppercase tracking-wider mb-2">{t("log.extractedValue", lang)}</div>
                        <div className="text-emerald-200 text-xl font-mono font-bold break-all">
                          {state.extracted_data}
                        </div>
                        {state.current_strategy && (
                          <div className="mt-2 text-emerald-400/70 text-xs font-mono">
                            {t("log.method", lang)}: {state.current_strategy.toUpperCase()}
                          </div>
                        )}
                      </div>
                    )}
                    {/* Payload */}
                    {state.final_result.payload && (
                      <div className="mb-3">
                        <div className="text-cyber-dim text-[10px] uppercase tracking-wider mb-1">{t("log.payload", lang)}</div>
                        <pre className="text-white/90 text-xs bg-black/40 rounded-lg p-3 overflow-x-auto font-mono">
                          {state.final_result.payload}
                        </pre>
                      </div>
                    )}
                    {/* Technical details — collapsible */}
                    {(() => {
                      const ev = state.final_result.evidence || "";
                      const snippet = state.final_result.response_snippet || "";
                      const combined = ev + " " + snippet;
                      const dbInfo: { label: string; value: string }[] = [];
                      const sqlErrMatch = combined.match(/SQL error detected \((\w+)\):\s*([^\n.]+)/i);
                      if (sqlErrMatch) dbInfo.push({ label: "DBMS", value: sqlErrMatch[1] });
                      const errTypeMatch = combined.match(/(xpath syntax error|extractvalue|updatexml|mysql_fetch|duplicate entry|you have an error in your sql syntax|syntax error at or near|ora-\d{5})/i);
                      if (errTypeMatch) dbInfo.push({ label: "SQL Error", value: errTypeMatch[1] });
                      const dbMatch = combined.match(/database\s*[=:]\s*([^\s,;|]+)/i);
                      if (dbMatch) dbInfo.push({ label: "Database", value: dbMatch[1] });
                      const verMatch = combined.match(/(mysql|postgresql|mariadb|oracle|mssql)[\s/]*[\d.]+/i) || combined.match(/version\s*[=:]\s*([^\s,;|]+)/i);
                      if (verMatch) dbInfo.push({ label: "Version", value: verMatch[0] });
                      const userMatch = combined.match(/user\s*[=:]\s*([^\s,;|]+)/i) || combined.match(/\broot@[\w.]+/i);
                      if (userMatch) dbInfo.push({ label: "User", value: userMatch[1] || userMatch[0] });
                      const hostMatch = combined.match(/@@hostname\s*[=:]\s*([^\s,;|]+)/i) || combined.match(/hostname\s*[=:]\s*([^\s,;|]+)/i);
                      if (hostMatch) dbInfo.push({ label: "Host", value: hostMatch[1] });
                      const tableMatch = combined.match(/table_name\s*[=:]\s*([^\s,;|]+)/i);
                      if (tableMatch) dbInfo.push({ label: "Table", value: tableMatch[1] });
                      const colMatch = combined.match(/column_name\s*[=:]\s*([^\s,;|]+)/i);
                      if (colMatch) dbInfo.push({ label: "Column", value: colMatch[1] });
                      const passMatch = combined.match(/password\s*[=:]\s*([^\s,;|<]+)/i);
                      if (passMatch) dbInfo.push({ label: "Password", value: passMatch[1] });
                      const firstNameMatch = combined.match(/first\s*name\s*[=:]\s*([^\s,;|<]+)/i);
                      if (firstNameMatch) dbInfo.push({ label: "First Name", value: firstNameMatch[1] });
                      const surnameMatch = combined.match(/surname\s*[=:]\s*([^\s,;|<]+)/i);
                      if (surnameMatch) dbInfo.push({ label: "Surname", value: surnameMatch[1] });
                      if (dbInfo.length === 0 && !state.extracted_data) {
                        // No structured data and no extracted_data — show raw evidence
                        return (
                          <div className="text-green-200 text-sm font-mono mb-3 p-2.5 rounded-lg bg-green-500/10 border border-green-500/20 break-all">
                            {state.final_result.evidence}
                          </div>
                        );
                      }
                      if (dbInfo.length === 0) return null;
                      return (
                        <div className="mb-3 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                          <div className="text-emerald-400 text-[10px] font-bold uppercase tracking-wider mb-1.5">{t("ac.extractedData", lang)}</div>
                          <div className="flex flex-wrap gap-2">
                            {dbInfo.map((d, i) => (
                              <span key={i} className="px-2 py-1 rounded bg-black/30 text-emerald-300 text-xs font-mono font-bold">
                                {d.label}: <span className="text-white">{d.value}</span>
                              </span>
                            ))}
                          </div>
                        </div>
                      );
                    })()}
                    {/* Extracted data grid — vuln-type adaptive */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                      <div className="bg-black/30 rounded-lg px-3 py-2">
                        <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("ac.statusLabel", lang)}</div>
                        <div className="text-green-400 font-mono font-bold">{state.final_result.response_code || "200"}</div>
                      </div>
                      <div className="bg-black/30 rounded-lg px-3 py-2">
                        <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("ac.timeLabel", lang)}</div>
                        <div className="text-cyber-neon font-mono font-bold">{(state.final_result.response_time || 0).toFixed(2)}s</div>
                      </div>
                      {state.vuln_type === "sqli" && (
                        <>
                          <div className="bg-black/30 rounded-lg px-3 py-2">
                            <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("ac.dbmsLabel", lang)}</div>
                            <div className="text-orange-400 font-mono font-bold">{state.injection_fingerprint?.dbms_hint || "unknown"}</div>
                          </div>
                          <div className="bg-black/30 rounded-lg px-3 py-2">
                            <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("ac.strategyLabel", lang)}</div>
                            <div className="text-cyber-purple font-mono font-bold">{(state.current_strategy || "error").toUpperCase()}</div>
                          </div>
                        </>
                      )}
                      {state.vuln_type === "xss" && (
                        <>
                          <div className="bg-black/30 rounded-lg px-3 py-2">
                            <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("vuln.context", lang)}</div>
                            <div className="text-orange-400 font-mono font-bold">{t("vuln.reflected", lang)}</div>
                          </div>
                          <div className="bg-black/30 rounded-lg px-3 py-2">
                            <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("vuln.event", lang)}</div>
                            <div className="text-cyber-purple font-mono font-bold">{state.extracted_data || "—"}</div>
                          </div>
                        </>
                      )}
                      {state.vuln_type === "cmdi" && (
                        <>
                          <div className="bg-black/30 rounded-lg px-3 py-2 sm:col-span-2">
                            <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("vuln.output", lang)}</div>
                            <div className="text-orange-400 font-mono font-bold truncate">{state.extracted_data || "—"}</div>
                          </div>
                        </>
                      )}
                      {!state.vuln_type && (
                        <>
                          <div className="bg-black/30 rounded-lg px-3 py-2">
                            <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("ac.dbmsLabel", lang)}</div>
                            <div className="text-orange-400 font-mono font-bold">{state.injection_fingerprint?.dbms_hint || "unknown"}</div>
                          </div>
                          <div className="bg-black/30 rounded-lg px-3 py-2">
                            <div className="text-cyber-dim text-[10px] uppercase tracking-wider">{t("ac.strategyLabel", lang)}</div>
                            <div className="text-cyber-purple font-mono font-bold">{(state.current_strategy || "error").toUpperCase()}</div>
                          </div>
                        </>
                      )}
                    </div>
                    {/* Technical details — collapsible raw evidence */}
                    {state.extracted_data && state.final_result.evidence && (
                      <details className="mt-3">
                        <summary className="text-cyber-dim text-xs cursor-pointer hover:text-white/70 transition-colors">
                          {t("log.technicalDetails", lang)}
                        </summary>
                        <div className="mt-2 text-white/60 text-xs font-mono p-2.5 rounded-lg bg-black/30 border border-cyber-border/20 break-all">
                          {state.final_result.evidence}
                        </div>
                      </details>
                    )}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
