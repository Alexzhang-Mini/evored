"use client";

import { useEffect, useRef } from "react";

const CHARS =
  "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF<>{}[]|/\\";
const FONT_SIZE = 14;
const COLUMN_GAP = 20;

export default function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId: number;
    let columns: number[] = [];
    let drops: number[] = [];

    function resize() {
      if (!canvas) return;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const numCols = Math.floor(canvas.width / COLUMN_GAP);
      columns = Array.from({ length: numCols }, () =>
        Math.floor(Math.random() * canvas!.height / FONT_SIZE)
      );
      drops = [...columns];
    }

    resize();
    window.addEventListener("resize", resize);

    function draw() {
      if (!ctx || !canvas) return;

      ctx.fillStyle = "rgba(5, 5, 5, 0.06)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      for (let i = 0; i < drops.length; i++) {
        const char = CHARS[Math.floor(Math.random() * CHARS.length)];
        const x = i * COLUMN_GAP;
        const y = drops[i] * FONT_SIZE;

        // Head character — bright neon
        ctx.fillStyle = "#00ff9d";
        ctx.shadowColor = "#00ff9d";
        ctx.shadowBlur = 8;
        ctx.font = `${FONT_SIZE}px JetBrains Mono, monospace`;
        ctx.fillText(char, x, y);
        ctx.shadowBlur = 0;

        // Trail — darker
        if (drops[i] > 1) {
          const trailChar = CHARS[Math.floor(Math.random() * CHARS.length)];
          ctx.fillStyle = "rgba(0, 255, 157, 0.15)";
          ctx.fillText(trailChar, x, y - FONT_SIZE);
        }

        drops[i]++;

        if (y > canvas.height && Math.random() > 0.98) {
          drops[i] = 0;
        }
      }

      animationId = requestAnimationFrame(draw);
    }

    draw();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 z-0 pointer-events-none opacity-40"
      style={{ mixBlendMode: "screen" }}
    />
  );
}
