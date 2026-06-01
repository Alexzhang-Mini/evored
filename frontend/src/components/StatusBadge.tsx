"use client";

import { motion } from "framer-motion";
import { t, type Lang } from "@/lib/i18n";

type Status = "idle" | "running" | "success" | "done";

interface StatusBadgeProps {
  status: Status;
  lang?: Lang;
}

const statusConfig = {
  idle: { labelKey: "status.idle" as const, cls: "badge-idle", dotColor: "#6b7280" },
  running: { labelKey: "status.running" as const, cls: "badge-run", dotColor: "#00ff9d" },
  success: { labelKey: "status.success" as const, cls: "badge-success", dotColor: "#ff0044" },
  done: { labelKey: "status.done" as const, cls: "badge-done", dotColor: "#ff00ff" },
};

export default function StatusBadge({ status, lang = "en" }: StatusBadgeProps) {
  const cfg = statusConfig[status];

  return (
    <motion.div
      className={`badge ${cfg.cls}`}
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      key={status}
    >
      <motion.span
        className="inline-block w-2 h-2 rounded-full"
        style={{ backgroundColor: cfg.dotColor }}
        animate={
          status === "running"
            ? { scale: [1, 1.4, 1], opacity: [1, 0.6, 1] }
            : {}
        }
        transition={{ duration: 1.5, repeat: Infinity }}
      />
      {t(cfg.labelKey, lang)}
    </motion.div>
  );
}
