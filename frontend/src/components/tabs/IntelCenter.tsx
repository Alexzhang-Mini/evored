"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Brain, History, AlertTriangle, CheckCircle, Search, FileText, ChevronDown, Crosshair, Loader2 } from "lucide-react";
import GlassCard from "@/components/GlassCard";
import type { AttackState } from "@/lib/types";
import { truncate } from "@/lib/utils";
import { t, type Lang } from "@/lib/i18n";

interface Props {
  state: AttackState;
  lang: Lang;
}

export default function IntelCenter({ state, lang }: Props) {
  const waf = state.waf_result;
  const mem = state.memory_stats;
  const history = state.history || [];
  const bypasses = state.bypass_techniques || [];
  const blockAnalyses = state.block_history || [];
  const hypotheses = state.hypotheses || [];
  const inferredRules = state.inferred_rules || [];
  const [showReport, setShowReport] = useState(false);
  const [expandedRuleTypes, setExpandedRuleTypes] = useState<Record<string, boolean>>({});
  const [showReasoning, setShowReasoning] = useState(false);
  const reasoningChain = (state as any).reasoning_chain || {};

  const isLoading = state.running && history.length === 0;

  // Helper: status color for hypothesis
  const getStatusColor = (status?: string) => {
    switch (status) {
      case "active": return "text-cyber-neon";
      case "refined": return "text-amber-400";
      case "discarded": return "text-cyber-dim";
      default: return "text-cyber-dim";
    }
  };

  // Helper: status label for hypothesis
  const getStatusLabel = (status?: string) => {
    switch (status) {
      case "active": return t("intel.hypothesis.active", lang);
      case "refined": return t("intel.hypothesis.refined", lang);
      case "discarded": return t("intel.hypothesis.discarded", lang);
      default: return status || "—";
    }
  };

  // Helper: group rules by rule_type
  const rulesByType = inferredRules.reduce<Record<string, typeof inferredRules>>((acc, rule) => {
    const key = rule.rule_type || "unknown";
    if (!acc[key]) acc[key] = [];
    acc[key].push(rule);
    return acc;
  }, {});

  const toggleRuleType = (type: string) => {
    setExpandedRuleTypes(prev => ({ ...prev, [type]: !prev[type] }));
  };

  return (
    <div className="space-y-5 animate-fade-in-up">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* WAF Detection */}
        <GlassCard glowColor="red">
          <div className="flex items-center gap-2 mb-4">
            <Shield size={18} className="text-cyber-neon" />
            <h4 className="text-cyber-neon font-bold text-sm">{t("intel.wafDetection", lang)}</h4>
          </div>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 size={20} className="text-cyber-neon animate-spin" />
              <span className="text-cyber-dim text-sm ml-2 font-mono">{t("intel.loading", lang)}</span>
            </div>
          ) : waf && Object.keys(waf).length > 0 ? (
            waf.detected ? (
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle size={16} className="text-cyber-red" />
                  <span className="text-cyber-red font-bold text-lg">
                    {waf.waf_name?.toUpperCase()}
                  </span>
                </div>
                <div className="text-cyber-dim text-sm mb-3">
                  {t("intel.confidence", lang)}: {(waf.confidence * 100).toFixed(0)}%
                </div>
                {waf.bypass_strategies?.length > 0 && (
                  <div>
                    <div className="text-white/70 text-xs font-bold mb-2">
                      {t("intel.knownBypass", lang)}
                    </div>
                    <div className="space-y-1">
                      {waf.bypass_strategies.slice(0, 6).map((s, i) => (
                        <div
                          key={i}
                          className="text-cyber-dim text-xs pl-3 border-l border-cyber-red/20"
                        >
                          {s}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-cyber-neon">
                <CheckCircle size={18} />
                <span className="text-sm">{t("intel.noWaf", lang)}</span>
              </div>
            )
          ) : (
            <div className="text-cyber-dim/40 text-sm">{t("intel.noData", lang)}</div>
          )}
        </GlassCard>

        {/* Memory Status */}
        <GlassCard glowColor="blue">
          <div className="flex items-center gap-2 mb-4">
            <Brain size={18} className="text-cyber-neon" />
            <h4 className="text-cyber-neon font-bold text-sm">{t("intel.memoryStatus", lang)}</h4>
          </div>
          {mem && Object.keys(mem).length > 0 ? (
            <div className="grid grid-cols-2 gap-4">
              {[
                { label: t("intel.totalEntries", lang), value: mem.total_entries ?? 0, color: "text-cyber-neon" },
                { label: t("intel.successes", lang), value: mem.successes ?? 0, color: "text-cyber-red" },
                { label: t("intel.successRate", lang), value: `${((mem.success_rate ?? 0) * 100).toFixed(0)}%`, color: "text-cyber-purple" },
                { label: t("intel.backend", lang), value: mem.chromadb ? "ChromaDB" : "In-Memory", color: mem.chromadb ? "text-cyber-neon" : "text-cyber-dim" },
              ].map(({ label, value, color }) => (
                <div key={label}>
                  <div className="text-cyber-dim text-xs">{label}</div>
                  <div className={`${color} text-xl font-mono font-bold`}>
                    {value}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-cyber-dim/40 text-sm">{t("intel.noData", lang)}</div>
          )}
        </GlassCard>
      </div>

      {/* Hypothesis Panel */}
      <GlassCard glowColor="purple" delay={0.05}>
        <div className="flex items-center gap-2 mb-4">
          <Brain size={18} className="text-cyber-purple" />
          <h4 className="text-cyber-purple font-bold text-sm">{t("intel.hypotheses", lang)}</h4>
          {hypotheses.length > 0 && (
            <span className="text-cyber-dim text-xs ml-auto font-mono">
              {hypotheses.length}
            </span>
          )}
        </div>
        {hypotheses.length > 0 ? (
          <div className="space-y-3">
            {hypotheses.map((h, i) => (
              <motion.div
                key={i}
                className="glass !p-3 !rounded-lg"
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-white/90 font-bold text-sm font-mono flex-1">
                    {h.mechanism}
                  </span>
                  <span className={`text-xs font-mono px-2 py-0.5 rounded bg-white/5 ${getStatusColor(h.status)}`}>
                    {getStatusLabel(h.status)}
                  </span>
                </div>
                {/* Confidence bar */}
                <div className="mb-2">
                  <div className="flex items-center justify-between text-xs text-cyber-dim mb-1">
                    <span>{t("intel.hypothesis.confidence", lang)}</span>
                    <span className="font-mono">{((h.confidence ?? 0) * 100).toFixed(0)}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                    <motion.div
                      className="h-full bg-cyber-purple rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${(h.confidence ?? 0) * 100}%` }}
                      transition={{ duration: 0.6, delay: i * 0.05 }}
                    />
                  </div>
                </div>
                {/* Stats row */}
                <div className="flex items-center gap-4 text-xs">
                  <span className="text-cyber-dim">
                    {t("intel.hypothesis.testCount", lang)}: <span className="text-white/80 font-mono">{h.test_count ?? 0}</span>
                  </span>
                  <span className="text-cyber-dim">
                    {t("intel.hypothesis.bestFitness", lang)}: <span className="text-white/80 font-mono">{(h.best_fitness ?? 0).toFixed(3)}</span>
                  </span>
                </div>
              </motion.div>
            ))}
          </div>
        ) : (
          <div className="text-cyber-dim/40 text-sm text-center py-4">
            {t("intel.hypothesis.noData", lang)}
          </div>
        )}
        {/* Reasoning Chain — LLM's analysis of WAF detection principles */}
        {reasoningChain && Object.keys(reasoningChain).length > 0 && (
          <div className="mt-4 pt-4 border-t border-cyber-border/20">
            <button
              onClick={() => setShowReasoning(!showReasoning)}
              className="flex items-center gap-2 text-cyber-purple/70 text-xs font-mono w-full text-left"
            >
              <motion.div animate={{ rotate: showReasoning ? 180 : 0 }}>
                <ChevronDown size={12} />
              </motion.div>
              <span>{t("intel.hypothesis.reasoning", lang)}</span>
            </button>
            <AnimatePresence>
              {showReasoning && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden"
                >
                  <div className="mt-2 space-y-2 text-xs">
                    {reasoningChain.waf_detection_method && (
                      <div>
                        <span className="text-cyber-dim">{t("intel.reasoning.detection", lang)}: </span>
                        <span className="text-white/70">{reasoningChain.waf_detection_method}</span>
                      </div>
                    )}
                    {reasoningChain.parsing_behavior && (
                      <div>
                        <span className="text-cyber-dim">{t("intel.reasoning.parsing", lang)}: </span>
                        <span className="text-white/70">{reasoningChain.parsing_behavior}</span>
                      </div>
                    )}
                    {reasoningChain.matching_strategy && (
                      <div>
                        <span className="text-cyber-dim">{t("intel.reasoning.matching", lang)}: </span>
                        <span className="text-white/70">{reasoningChain.matching_strategy}</span>
                      </div>
                    )}
                    {reasoningChain.identified_blind_spots && reasoningChain.identified_blind_spots.length > 0 && (
                      <div>
                        <span className="text-cyber-dim">{t("intel.reasoning.blindSpots", lang)}: </span>
                        <div className="mt-1 space-y-1">
                          {reasoningChain.identified_blind_spots.map((spot: string, i: number) => (
                            <div key={i} className="text-cyber-neon pl-3 border-l border-cyber-neon/20">
                              {spot}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {reasoningChain.exploitation_approach && (
                      <div>
                        <span className="text-cyber-dim">{t("intel.reasoning.approach", lang)}: </span>
                        <span className="text-white/80 font-bold">{reasoningChain.exploitation_approach}</span>
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}
      </GlassCard>

      {/* Rule Panel */}
      <GlassCard glowColor="red" delay={0.08}>
        <div className="flex items-center gap-2 mb-4">
          <Crosshair size={18} className="text-cyber-red" />
          <h4 className="text-cyber-red font-bold text-sm">{t("intel.rules", lang)}</h4>
          {inferredRules.length > 0 && (
            <span className="text-cyber-dim text-xs ml-auto font-mono">
              {inferredRules.length}
            </span>
          )}
        </div>
        {inferredRules.length > 0 ? (
          <div className="space-y-3">
            {Object.entries(rulesByType).map(([ruleType, rules]) => (
              <div key={ruleType} className="glass !p-3 !rounded-lg">
                <button
                  onClick={() => toggleRuleType(ruleType)}
                  className="w-full flex items-center gap-2 text-left"
                >
                  <span className="text-white/90 font-bold text-sm font-mono flex-1">
                    {ruleType}
                  </span>
                  <span className="text-cyber-dim text-xs font-mono">{rules.length}</span>
                  <motion.div animate={{ rotate: expandedRuleTypes[ruleType] ? 180 : 0 }}>
                    <ChevronDown size={14} className="text-cyber-dim" />
                  </motion.div>
                </button>
                <AnimatePresence>
                  {expandedRuleTypes[ruleType] && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="overflow-hidden"
                    >
                      <div className="space-y-3 mt-3">
                        {rules.map((rule, ri) => (
                          <div key={ri} className="border-l-2 border-cyber-red/20 pl-3 space-y-2">
                            {/* Trigger keywords */}
                            {rule.trigger_keywords && rule.trigger_keywords.length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                {rule.trigger_keywords.map((kw, ki) => (
                                  <span
                                    key={ki}
                                    className="text-xs px-1.5 py-0.5 rounded bg-cyber-red/10 text-cyber-red font-mono"
                                  >
                                    {kw}
                                  </span>
                                ))}
                              </div>
                            )}
                            {/* Confidence bar */}
                            {rule.confidence !== undefined && (
                              <div className="flex items-center gap-2">
                                <span className="text-cyber-dim text-xs">{t("intel.rules.confidence", lang)}</span>
                                <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                                  <div
                                    className="h-full bg-cyber-red/70 rounded-full"
                                    style={{ width: `${(rule.confidence ?? 0) * 100}%` }}
                                  />
                                </div>
                                <span className="text-cyber-dim text-xs font-mono">
                                  {((rule.confidence ?? 0) * 100).toFixed(0)}%
                                </span>
                              </div>
                            )}
                            {/* Evidence */}
                            {rule.evidence && (
                              <div className="text-cyber-dim text-xs">
                                <span className="text-white/50">{t("intel.rules.evidence", lang)}: </span>
                                {truncate(rule.evidence, 100)}
                              </div>
                            )}
                            {/* Suggested bypasses */}
                            {rule.suggested_bypasses && rule.suggested_bypasses.length > 0 && (
                              <div className="mt-1">
                                <div className="text-white/50 text-xs mb-1">{t("intel.rules.bypasses", lang)}:</div>
                                <div className="space-y-1">
                                  {rule.suggested_bypasses.map((bp, bi) => (
                                    <div key={bi} className="text-xs pl-2 border-l border-cyber-neon/20">
                                      <span className="text-cyber-neon font-mono">{bp.technique}</span>
                                      {bp.reasoning && (
                                        <span className="text-cyber-dim ml-2">— {truncate(bp.reasoning, 80)}</span>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-cyber-dim/40 text-sm text-center py-4">
            {t("intel.rules.noData", lang)}
          </div>
        )}
      </GlassCard>

      {/* Discovered Bypass Techniques */}
      {bypasses.length > 0 && (
        <GlassCard glowColor="neon" delay={0.05}>
          <div className="flex items-center gap-2 mb-4">
            <Shield size={18} className="text-yellow-400" />
            <h4 className="text-yellow-400 font-bold text-sm">{t("intel.discoveredBypass", lang)}</h4>
            <span className="text-cyber-dim text-xs ml-auto font-mono">
              {bypasses.length} {t("intel.techniques", lang)}
            </span>
          </div>
          <div className="space-y-3">
            {bypasses.map((b, i) => (
              <motion.div
                key={i}
                className="glass !p-3 !rounded-lg"
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-yellow-400 font-bold text-sm font-mono">
                    {b.technique && b.technique !== "unknown" ? b.technique : t("intel.wafBypass", lang)}
                  </span>
                  {b.waf_name && (
                    <span className="text-cyber-dim text-xs px-2 py-0.5 rounded bg-white/5">
                      vs {b.waf_name}
                    </span>
                  )}
                  {b.fitness !== undefined && (
                    <span className="text-cyber-neon text-xs font-mono ml-auto">
                      fitness={b.fitness.toFixed(3)}
                    </span>
                  )}
                </div>
                <pre className="text-white/80 text-xs bg-black/40 rounded p-2 overflow-x-auto font-mono">
                  {b.payload}
                </pre>
                {b.rule_type && (
                  <div className="text-cyber-dim text-xs mt-2">
                    {t("intel.rule", lang)} {b.rule_type} | {t("intel.trigger", lang)} <code className="text-cyber-purple">{b.trigger_pattern}</code>
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </GlassCard>
      )}

      {/* Block Analysis */}
      {blockAnalyses.length > 0 && (
        <GlassCard glowColor="purple" delay={0.1}>
          <div className="flex items-center gap-2 mb-4">
            <Search size={18} className="text-cyber-purple" />
            <h4 className="text-cyber-purple font-bold text-sm">{t("intel.blockAnalysis", lang)}</h4>
            <span className="text-cyber-dim text-xs ml-auto font-mono">
              {blockAnalyses.length} {t("intel.analyses", lang)}
            </span>
          </div>
          <div className="space-y-3">
            {blockAnalyses.slice(-3).reverse().map((analysis, i) => (
              <motion.div
                key={i}
                className="glass !p-3 !rounded-lg"
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <div className="text-white/70 text-xs mb-2">
                  {analysis.analysis_summary || t("intel.noSummary", lang)}
                </div>
                {analysis.trigger_segments && analysis.trigger_segments.length > 0 && (
                  <div className="mb-2">
                    <div className="text-cyber-dim text-xs font-bold mb-1">{t("intel.triggerSegments", lang)}</div>
                    {analysis.trigger_segments.map((seg, j) => (
                      <code key={j} className="text-cyber-red text-xs bg-cyber-red/10 px-2 py-0.5 rounded mr-2">
                        {seg.text} ({(seg.confidence * 100).toFixed(0)}%)
                      </code>
                    ))}
                  </div>
                )}
                {analysis.rule_inference && (
                  <div>
                    <div className="text-cyber-dim text-xs">
                      Rule: <span className="text-cyber-purple">{analysis.rule_inference.rule_type}</span>
                      {analysis.rule_inference.confidence > 0 && (
                        <span className="ml-2">({(analysis.rule_inference.confidence * 100).toFixed(0)}% confidence)</span>
                      )}
                    </div>
                    {analysis.rule_inference.suggested_bypasses?.length > 0 && (
                      <div className="mt-1">
                        <span className="text-cyber-dim text-xs">{t("intel.suggested", lang)} </span>
                        {analysis.rule_inference.suggested_bypasses.slice(0, 3).map((b, j) => (
                          <span key={j} className="text-cyber-neon text-xs mr-2">
                            {b.technique}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </GlassCard>
      )}

      {/* Attack History */}
      <GlassCard glowColor="neon" delay={0.15}>
        <div className="flex items-center gap-2 mb-4">
          <History size={18} className="text-cyber-neon" />
          <h4 className="text-cyber-neon font-bold text-sm">{t("intel.attackHistory", lang)}</h4>
          <span className="text-cyber-dim text-xs ml-auto font-mono">
            {history.length} {t("intel.entries", lang)}
          </span>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 size={20} className="text-cyber-neon animate-spin" />
            <span className="text-cyber-dim text-sm ml-2 font-mono">{t("intel.loading", lang)}</span>
          </div>
        ) : history.length > 0 ? (
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {[...history].reverse().slice(0, 20).map((h, i) => {
              const isOk = h.result === "success";
              const isBypass = h.result === "bypass" || h.result === "bypass_success";
              const isBlocked = h.result === "blocked";
              const icon = isOk ? "✓" : isBypass ? "⚡" : isBlocked ? "🛡" : "✗";
              const color = isOk
                ? "text-cyber-red"
                : isBypass
                  ? "text-yellow-400"
                  : isBlocked
                    ? "text-orange-400"
                    : "text-cyber-dim";
              return (
                <motion.div
                  key={i}
                  className="glass !p-3 !rounded-lg flex items-center gap-3"
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                >
                  <span className={`font-bold text-sm ${color}`}>{icon}</span>
                  <code className="text-white/80 text-xs flex-1 break-all max-h-16 overflow-y-auto">
                    {h.payload}
                  </code>
                  {h.technique && (
                    <span className="text-cyber-purple text-xs font-mono">
                      {h.technique}
                    </span>
                  )}
                  <span className="text-cyber-dim text-xs font-mono">
                    f={h.fitness.toFixed(3)}
                  </span>
                  <span className="text-cyber-dim/40 text-xs font-mono">
                    iter={h.iteration}
                  </span>
                </motion.div>
              );
            })}
          </div>
        ) : (
          <div className="text-cyber-dim/40 text-sm text-center py-8">
            {t("intel.noHistory", lang)}
          </div>
        )}
      </GlassCard>

      {/* Report */}
      {state.report && (
        <GlassCard glowColor="red" delay={0.2}>
          <button
            onClick={() => setShowReport(!showReport)}
            className="w-full flex items-center gap-2 text-cyber-red font-bold text-sm"
          >
            <FileText size={18} />
            <span className="flex-1 text-left">{t("intel.report", lang)}</span>
            <motion.div animate={{ rotate: showReport ? 180 : 0 }}>
              <ChevronDown size={14} />
            </motion.div>
          </button>
          <AnimatePresence>
            {showReport && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                <pre className="text-white/80 text-xs bg-black/40 rounded-lg p-4 mt-3 overflow-x-auto font-mono whitespace-pre-wrap max-h-[600px] overflow-y-auto">
                  {state.report}
                </pre>
              </motion.div>
            )}
          </AnimatePresence>
        </GlassCard>
      )}
    </div>
  );
}
