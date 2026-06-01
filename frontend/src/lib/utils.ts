import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getLogColor(line: string): string {
  // Priority 1: Critical status — distinct colors
  if (line.includes("VULNERABILITY CONFIRMED")) return "log-exploit-success";
  if (line.includes("SUCCESS")) return "log-success";
  if (line.includes("BLOCKED")) return "log-blocked";
  if (line.includes("BYPASSED") || line.includes("PASSED WAF")) return "log-bypass";
  if (line.includes("RATE LIMITED")) return "log-warning";
  if (line.includes("Low fitness") || line.includes("LOW FITNESS")) return "log-low-fitness";
  if (line.includes("STRATEGY ROTATION")) return "log-warning";
  // Priority 2: Error/system
  if (line.includes("[ERROR]")) return "log-error";
  if (line.includes("CONNECTION FAILED") || line.includes("TARGET UNREACHABLE")) return "log-error";
  if (line.includes("[SYSTEM]")) return "log-system";
  // Priority 3: Stage-specific
  if (line.includes("[RECON]")) return "log-recon";
  if (line.includes("[WAF]") || line.includes("[WAF-BLIND]")) return "log-waf";
  if (line.includes("[BYPASS-GEN]") || line.includes("[BYPASS-EXEC]")) return "log-generate";
  if (line.includes("[EXPLOIT-GEN]") || line.includes("[EXPLOIT-EXEC]")) return "log-execute";
  if (line.includes("[BYPASS]")) return "log-generate";
  if (line.includes("[EXPLOIT]")) return "log-execute";
  if (line.includes("[ANALYZE]")) return "log-rag";
  if (line.includes("[GA-BYPASS]") || line.includes("[GA-EXPLOIT]") || line.includes("[GA]")) return "log-ga";
  if (line.includes("[STAGE]")) return "log-system";
  if (line.includes("[RAG]")) return "log-rag";
  return "log-default";
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 3) + "...";
}

export function formatPercent(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

/**
 * Strip fragment (#...) from a URL string.
 * Returns { url, stripped } where url has the fragment removed.
 */
export function stripFragment(raw: string): { url: string; stripped: boolean } {
  const hashIdx = raw.indexOf("#");
  if (hashIdx !== -1) {
    return { url: raw.substring(0, hashIdx), stripped: true };
  }
  return { url: raw, stripped: false };
}

/**
 * Clean raw input before sending to parse-request backend.
 * - Strips fragment (#...)
 * - Normalizes whitespace
 * - Detects bare URLs and wraps them into a proper HTTP request line
 */
export function cleanRawInput(raw: string): { cleaned: string; fragment_stripped: boolean } {
  let text = raw.trim();
  let fragment_stripped = false;

  // Split into lines for analysis
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) return { cleaned: "", fragment_stripped: false };

  const firstLine = lines[0];

  // Strip fragment from the first line (URL or request line)
  const { url: noFrag, stripped } = stripFragment(firstLine);
  if (stripped) {
    fragment_stripped = true;
    lines[0] = noFrag;
  }

  // Check if first line is a bare URL (not a HTTP request line)
  const isBareUrl = /^(https?:\/\/)/i.test(lines[0]);
  const isRequestLine = /^[A-Z]+\s+\/\S*\s+HTTP\/\d/i.test(lines[0]);

  if (isBareUrl && !isRequestLine) {
    // Convert bare URL to GET request
    lines[0] = `GET ${lines[0]} HTTP/1.1`;
  }

  // Also strip fragments from any other URL-like lines (e.g., Referer header)
  for (let i = 1; i < lines.length; i++) {
    const { url, stripped: s } = stripFragment(lines[i]);
    if (s) {
      lines[i] = url;
      fragment_stripped = true;
    }
  }

  return { cleaned: lines.join("\n"), fragment_stripped };
}

/**
 * Smart URL parser — extracts base_url, endpoint, and primary param from a full URL.
 * Handles fragments (#), query strings, and edge cases gracefully.
 */
export function parseSmartUrl(raw: string): {
  base_url: string;
  endpoint: string;
  param: string;
  extra_params: Record<string, string>;
  fragment_stripped: boolean;
} {
  const { url: cleaned, stripped: fragment_stripped } = stripFragment(raw.trim());

  // Try native URL parsing
  try {
    const parsed = new URL(cleaned);
    const base_url = `${parsed.protocol}//${parsed.host}`;
    const pathname = parsed.pathname === "/" ? "" : parsed.pathname;
    const query = parsed.search || "";

    // Extract params from query string
    const params: Record<string, string> = {};
    const searchParams = new URLSearchParams(parsed.search);
    searchParams.forEach((v, k) => {
      params[k] = v;
    });

    // Guess primary param: prefer 'id', then 'q', then first
    let param = "q";
    for (const candidate of ["id", "q", "search", "user", "name"]) {
      if (candidate in params) {
        param = candidate;
        break;
      }
    }
    if (!Object.keys(params).length) {
      param = "q";
    }

    const endpoint = pathname + query;

    const extra_params = { ...params };
    delete extra_params[param];

    return { base_url, endpoint, param, extra_params, fragment_stripped };
  } catch {
    // Not a valid URL — return as-is
    return {
      base_url: cleaned,
      endpoint: "",
      param: "q",
      extra_params: {},
      fragment_stripped,
    };
  }
}
