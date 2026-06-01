"use client";

import { useMemo } from "react";
import { motion } from "framer-motion";
import { Dna, TrendingUp, BarChart3, GitBranch, Trophy, Loader2 } from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, Legend,
} from "recharts";
import GlassCard from "@/components/GlassCard";
import type { AttackState, HypothesisHistoryEntry } from "@/lib/types";
import { truncate } from "@/lib/utils";
import { t, type Lang } from "@/lib/i18n";

const HYPOTHESIS_PALETTE = [
  "#00ff88", "#ff6b6b", "#4ecdc4", "#ffd93d",
  "#6c5ce7", "#a29bfe", "#fd79a8", "#00b894",
];

interface Props {
  state: AttackState;
  lang: Lang;
}

const CustomTooltip = ({ active, payload, label, gaHistory, lang }: any) => {
  if (!active || !payload?.length) return null;
  // Find the matching generation's best payload
  const genData = gaHistory?.find((h: any) => (h.generation ?? 0) === label);
  const bestPayload = genData?.best_payload || "";
  return (
    <div className="glass !rounded-lg px-3 py-2 text-xs font-mono max-w-xs">
      <div className="text-cyber-dim mb-1 font-bold">Gen {label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.color }}>
          {p.name}: {p.value?.toFixed(4)}
        </div>
      ))}
      {bestPayload && (
        <div className="mt-1.5 pt-1.5 border-t border-cyber-border/30">
          <div className="text-cyber-dim text-[9px] uppercase tracking-wider mb-0.5">{t("evo.bestPayload", lang)}</div>
          <div className="text-cyber-neon text-[10px] break-all leading-relaxed">{bestPayload.length > 80 ? bestPayload.slice(0, 80) + "..." : bestPayload}</div>
        </div>
      )}
      {genData?.best_fitness !== undefined && genData.best_fitness > 0 && (
        <div className="mt-1 text-[9px] text-cyber-dim">
          {genData.best_fitness >= 0.8 ? t("evo.strongSignal", lang) : genData.best_fitness >= 0.5 ? t("evo.partialSignal", lang) : genData.best_fitness >= 0.3 ? t("evo.weakSignal", lang) : t("evo.noSignal", lang)}
        </div>
      )}
    </div>
  );
};

export default function EvolutionLab({ state, lang }: Props) {
  const ga = state.ga_stats || {};
  const gaHist = state.ga_history || [];
  const pop = state.population || [];

  // Ensure we always have at least gen 0 data point for the chart
  // Always include gen 0 (baseline) — only filter out intermediate all-zero entries
  const meaningfulHist = useMemo(() =>
    gaHist.length <= 2
      ? gaHist
      : gaHist.filter((h, i) =>
          i === 0 || (h.best_fitness ?? 0) > 0 || (h.avg_fitness ?? 0) > 0
        ),
    [gaHist]
  );

  const chartData = useMemo(() =>
    meaningfulHist.length > 0
      ? meaningfulHist.map((h, i) => ({
          gen: h.generation ?? i,
          best: h.best_fitness ?? 0,
          avg: h.avg_fitness ?? 0,
          worst: h.worst_fitness ?? 0,
        }))
      : [{ gen: 0, best: 0, avg: 0, worst: 0 }],
    [meaningfulHist]
  );

  // Fitness distribution bins
  const bins = useMemo(() => {
    const b = Array.from({ length: 10 }, (_, i) => ({
      range: `${(i * 0.1).toFixed(1)}`,
      count: 0,
    }));
    pop.forEach((p) => {
      const idx = Math.min(9, Math.floor((p.fitness || 0) * 10));
      b[idx].count++;
    });
    return b;
  }, [pop]);

  const sortedPop = useMemo(
    () => [...pop].sort((a, b) => (b.fitness || 0) - (a.fitness || 0)),
    [pop]
  );

  const isLoading = state.running && gaHist.length === 0;
  const hasRealData = gaHist.length > 0;  // Show chart from gen 0, even with zero fitness

  return (
    <div className="space-y-5 animate-fade-in-up">
      {/* GA description */}
      <div className="glass px-5 py-3 border-l-2 border-cyber-purple/50">
        <span className="text-cyber-purple font-bold">{t("evo.title", lang)}</span>
        <span className="text-cyber-dim text-sm ml-2">
          {t("evo.desc", lang)}
        </span>
      </div>

      {/* Metrics row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: t("evo.generation", lang), value: ga.generation ?? 0, icon: Dna },
          { label: t("evo.bestFitness", lang), value: (ga.best_fitness ?? 0).toFixed(3), icon: Trophy },
          { label: t("evo.avgFitness", lang), value: (ga.avg_fitness ?? 0).toFixed(3), icon: TrendingUp },
          { label: t("evo.mutationRate", lang), value: (ga.mutation_rate ?? 0).toFixed(3), icon: GitBranch },
          { label: t("evo.population", lang), value: pop.length, icon: BarChart3 },
        ].map(({ label, value, icon: Icon }, i) => (
          <motion.div
            key={label}
            className="glass p-4 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
          >
            <Icon size={18} className="text-cyber-purple/60 mx-auto mb-2" />
            <div className="text-cyber-neon font-mono text-2xl font-bold">
              {value}
            </div>
            <div className="text-cyber-dim text-xs mt-1">{label}</div>
          </motion.div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Fitness evolution chart */}
        <div className="lg:col-span-2">
          <GlassCard glowColor="purple">
            <h4 className="text-cyber-purple font-bold text-sm mb-4">
              {t("evo.fitnessEvolution", lang)}
            </h4>
            {isLoading ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 size={24} className="text-cyber-purple animate-spin" />
                <span className="text-cyber-dim text-sm ml-2 font-mono">Loading...</span>
              </div>
            ) : hasRealData || pop.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="gradBest" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00ff9d" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00ff9d" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradAvg" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ff00ff" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#ff00ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#141414" />
                  <XAxis dataKey="gen" stroke="#374151" tick={{ fontSize: 11 }} />
                  <YAxis domain={[0, 1]} stroke="#374151" tick={{ fontSize: 11 }} />
                  <Tooltip content={<CustomTooltip gaHistory={gaHist} lang={lang} />} />
                  <Area
                    type="monotone"
                    dataKey="best"
                    stroke="#00ff9d"
                    strokeWidth={2}
                    fill="url(#gradBest)"
                    name={t("evo.best", lang)}
                  />
                  <Area
                    type="monotone"
                    dataKey="avg"
                    stroke="#ff00ff"
                    strokeWidth={1.5}
                    strokeDasharray="4 4"
                    fill="url(#gradAvg)"
                    name={t("evo.avg", lang)}
                  />
                  <Line
                    type="monotone"
                    dataKey="worst"
                    stroke="#ff0044"
                    strokeWidth={1}
                    strokeDasharray="2 4"
                    dot={false}
                    name={t("evo.worst", lang)}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-cyber-dim/40 text-sm text-center py-16 font-mono">
                {t("evo.startToSee", lang)}
              </div>
            )}
            {meaningfulHist.length > 0 && meaningfulHist.length <= 3 && (
              <div className="text-cyber-dim/30 text-[10px] text-center mt-1 font-mono">
                {meaningfulHist.length} {t("evo.genCount", lang)}
              </div>
            )}
            {!hasRealData && pop.length > 0 && (
              <div className="text-cyber-dim/40 text-[10px] text-center mt-1 font-mono">
                {lang === "zh" ? "种群已初始化，等待适应度数据..." : "Population initialized, waiting for fitness data..."}
              </div>
            )}
          </GlassCard>
        </div>

        {/* Population distribution */}
        <GlassCard glowColor="purple" delay={0.1}>
          <h4 className="text-cyber-purple font-bold text-sm mb-4">
            {t("evo.populationDist", lang)}
          </h4>
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 size={24} className="text-cyber-purple animate-spin" />
              <span className="text-cyber-dim text-sm ml-2 font-mono">Loading...</span>
            </div>
          ) : pop.length > 0 && pop.some(p => (p.fitness ?? 0) > 0) ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={bins}>
                <CartesianGrid strokeDasharray="3 3" stroke="#141414" />
                <XAxis dataKey="range" stroke="#374151" tick={{ fontSize: 10 }} />
                <YAxis stroke="#374151" tick={{ fontSize: 10 }} />
                <Tooltip content={<CustomTooltip lang={lang} />} />
                <Bar
                  dataKey="count"
                  fill="#00ff9d"
                  radius={[4, 4, 0, 0]}
                  opacity={0.8}
                  name="Count"
                />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-cyber-dim/40 text-sm text-center py-16 font-mono">
              {t("evo.waitingPop", lang)}
            </div>
          )}
        </GlassCard>
      </div>

      {/* Hypothesis fitness trends chart — multi-line per hypothesis */}
      {(state.hypothesis_history ?? []).length > 0 && (() => {
        const hypHistory = state.hypothesis_history as HypothesisHistoryEntry[];
        // Collect all unique mechanism names across all snapshots
        const allMechanisms = Array.from(
          new Set(hypHistory.flatMap(entry => entry.hypotheses_snapshot.map(h => h.mechanism)))
        );
        // Find discarded hypotheses (last snapshot where status is "discarded")
        const lastSnapshot = hypHistory[hypHistory.length - 1]?.hypotheses_snapshot ?? [];
        const discardedSet = new Set(
          lastSnapshot.filter(h => h.status === "discarded").map(h => h.mechanism)
        );
        // Transform to Recharts data format
        const hypChartData = hypHistory.map(entry => {
          const point: Record<string, number> = { iteration: entry.iteration };
          entry.hypotheses_snapshot.forEach(h => {
            point[h.mechanism] = h.best_fitness;
          });
          return point;
        });
        return (
          <GlassCard glowColor="purple" delay={0.12}>
            <h4 className="text-cyber-purple font-bold text-sm mb-4">
              {t("evo.hypothesisChart", lang)}
            </h4>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={hypChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#141414" />
                <XAxis dataKey="iteration" stroke="#374151" tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 1]} stroke="#374151" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "rgba(10,10,10,0.9)", border: "1px solid #222", borderRadius: 8 }}
                  labelStyle={{ color: "#888", fontSize: 11 }}
                  itemStyle={{ fontSize: 11 }}
                />
                <Legend
                  wrapperStyle={{ fontSize: 11, color: "#888" }}
                  formatter={(value: string) => <span className="text-cyber-dim text-xs">{value}</span>}
                />
                {allMechanisms.map((mechanism, idx) => (
                  <Line
                    key={mechanism}
                    type="monotone"
                    dataKey={mechanism}
                    stroke={HYPOTHESIS_PALETTE[idx % HYPOTHESIS_PALETTE.length]}
                    strokeWidth={2}
                    dot={false}
                    connectNulls
                    strokeDasharray={discardedSet.has(mechanism) ? "5 5" : undefined}
                    opacity={discardedSet.has(mechanism) ? 0.4 : 1}
                    name={mechanism}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </GlassCard>
        );
      })()}

      {/* Evolution tree */}
      <GlassCard glowColor="purple" delay={0.15}>
        <h4 className="text-cyber-purple font-bold text-sm mb-4">
          {t("evo.evolutionTree", lang)}
        </h4>
        {Object.keys(state.evolution_tree).length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 max-h-[300px] overflow-y-auto">
            {Object.entries(state.evolution_tree).map(([parent, children]) => (
              <div key={parent} className="glass !p-3 !rounded-lg">
                <div className="text-cyber-neon text-xs font-mono font-bold mb-1">
                  {truncate(parent, 30)}
                </div>
                <div className="text-cyber-dim text-xs">↓</div>
                {children.slice(0, 3).map((child, i) => (
                  <div key={i} className="text-white/60 text-xs font-mono pl-3 mt-0.5">
                    → {truncate(child, 30)}
                  </div>
                ))}
                {children.length > 3 && (
                  <div className="text-cyber-dim/40 text-xs pl-3">
                    +{children.length - 3} more
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-cyber-dim/40 text-sm text-center py-8 font-mono">
            {t("evo.treeAppear", lang)}
          </div>
        )}
      </GlassCard>

      {/* Top payloads */}
      {sortedPop.length > 0 && (
        <GlassCard glowColor="purple" delay={0.2}>
          <h4 className="text-cyber-purple font-bold text-sm mb-4">
            {t("evo.topPayloads", lang)}
          </h4>
          <div className="space-y-3">
            {sortedPop.slice(0, 5).map((ind, i) => {
              const f = ind.fitness || 0;
              return (
                <motion.div
                  key={ind.id || i}
                  className="glass !p-3 !rounded-lg"
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-cyber-neon font-mono font-bold text-sm">
                      #{i + 1}
                    </span>
                    <code className="text-white/80 text-xs flex-1 break-all max-h-16 overflow-y-auto">
                      {ind.payload}
                    </code>
                    <span className="text-cyber-dim text-xs font-mono">
                      {f.toFixed(3)}
                    </span>
                  </div>
                  <div className="fitness-bar mt-2">
                    <div
                      className="fitness-bar-fill"
                      style={{ width: `${Math.min(100, f * 100)}%` }}
                    />
                  </div>
                </motion.div>
              );
            })}
          </div>
        </GlassCard>
      )}
    </div>
  );
}
