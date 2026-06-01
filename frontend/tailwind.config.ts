import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#050505",
          card: "#0a0a0f",
          border: "rgba(0,255,157,0.12)",
          neon: "#00ff9d",
          purple: "#ff00ff",
          red: "#ff0044",
          blue: "#3b82f6",
          dim: "#6b7280",
          grid: "#141414",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Consolas", "monospace"],
        sans: ["Noto Sans SC", "Microsoft YaHei", "sans-serif"],
      },
      animation: {
        "pulse-neon": "pulse-neon 2s ease-in-out infinite",
        glow: "glow 2s ease-in-out infinite alternate",
        scanline: "scanline 8s linear infinite",
        "matrix-fall": "matrix-fall 10s linear infinite",
        "glitch-1": "glitch-1 3s infinite",
        "glitch-2": "glitch-2 3s infinite",
        "fade-in-up": "fade-in-up 0.5s ease-out",
      },
      keyframes: {
        "pulse-neon": {
          "0%, 100%": { boxShadow: "0 0 5px rgba(0,255,157,0.2)" },
          "50%": { boxShadow: "0 0 25px rgba(0,255,157,0.6)" },
        },
        glow: {
          "0%": { textShadow: "0 0 10px #00ff9d, 0 0 20px #00ff9d" },
          "100%": { textShadow: "0 0 20px #ff00ff, 0 0 40px #ff00ff" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        "matrix-fall": {
          "0%": { transform: "translateY(-100%)", opacity: "1" },
          "100%": { transform: "translateY(100vh)", opacity: "0" },
        },
        "glitch-1": {
          "0%, 100%": { clipPath: "inset(0 0 0 0)" },
          "20%": { clipPath: "inset(20% 0 60% 0)" },
          "40%": { clipPath: "inset(40% 0 20% 0)" },
          "60%": { clipPath: "inset(60% 0 10% 0)" },
          "80%": { clipPath: "inset(10% 0 80% 0)" },
        },
        "glitch-2": {
          "0%, 100%": { clipPath: "inset(0 0 0 0)" },
          "20%": { clipPath: "inset(60% 0 10% 0)" },
          "40%": { clipPath: "inset(10% 0 70% 0)" },
          "60%": { clipPath: "inset(30% 0 40% 0)" },
          "80%": { clipPath: "inset(70% 0 5% 0)" },
        },
        "fade-in-up": {
          "0%": { opacity: "0", transform: "translateY(20px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      backdropBlur: {
        xs: "2px",
      },
    },
  },
  plugins: [],
};

export default config;
