"use client";

import { motion } from "framer-motion";
import { t, type Lang } from "@/lib/i18n";

interface Props {
  lang?: Lang;
}

export default function NeonTitle({ lang = "en" }: Props) {
  return (
    <div className="select-none">
      <motion.h1
        className="neon-title text-2xl md:text-3xl relative inline-block"
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
      >
        BypassEvo
      </motion.h1>
      <motion.p
        className="text-cyber-dim/60 text-[10px] mt-0.5 font-mono tracking-wider"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3, duration: 0.4 }}
      >
        {t("neon.subtitle", lang)}
      </motion.p>
    </div>
  );
}
