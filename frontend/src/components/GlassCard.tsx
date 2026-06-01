"use client";

import { motion } from "framer-motion";
import { ReactNode } from "react";
import clsx from "clsx";

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  glowColor?: "neon" | "purple" | "red" | "blue";
  hoverable?: boolean;
  delay?: number;
}

const glowMap = {
  neon: "hover:border-[rgba(0,255,157,0.2)]",
  purple: "hover:border-[rgba(255,0,255,0.2)]",
  red: "hover:border-[rgba(255,0,68,0.2)]",
  blue: "hover:border-[rgba(59,130,246,0.2)]",
};

export default function GlassCard({
  children,
  className,
  glowColor = "neon",
  hoverable = true,
  delay = 0,
}: GlassCardProps) {
  return (
    <motion.div
      className={clsx("glass p-5", hoverable && glowMap[glowColor], className)}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}
