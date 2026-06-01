import type { AttackConfig, AttackState, Preset } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }
  return res.json();
}

export async function fetchState(): Promise<AttackState> {
  return apiFetch(`${API_BASE}/api/state`);
}

export async function fetchPresets(): Promise<Preset[]> {
  return apiFetch(`${API_BASE}/api/presets`);
}

export async function startAttack(config: AttackConfig): Promise<{ status: string } | { error: string }> {
  return apiFetch(`${API_BASE}/api/attack`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}

export async function resetAttack(): Promise<{ status: string }> {
  return apiFetch(`${API_BASE}/api/reset`, { method: "POST" });
}

export async function stopAttack(): Promise<{ status: string } | { error: string }> {
  return apiFetch(`${API_BASE}/api/stop`, { method: "POST" });
}

export async function pauseAttack(): Promise<{ status: string } | { error: string }> {
  return apiFetch(`${API_BASE}/api/pause`, { method: "POST" });
}

export async function resumeAttack(): Promise<{ status: string } | { error: string }> {
  return apiFetch(`${API_BASE}/api/resume`, { method: "POST" });
}

export async function parseRawRequest(rawRequest: string): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE}/api/parse-request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_request: rawRequest }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return { error: `Server ${res.status}: ${text || res.statusText}` };
  }
  return res.json();
}

export interface ManualTestResult {
  success: boolean;
  blocked: boolean;
  status_code: number;
  response_time: number;
  evidence: string;
  indicators: string[];
  response_snippet: string;
  response_preview_highlighted?: string;
  confidence: number;
  kb_matches?: { description: string; confidence: number; dbms: string }[];
  matched_keywords?: string[];
  smart_suggestions?: { pattern: string; description: string; confidence: number; dbms: string; matched_text: string }[];
}

export async function testPayload(params: {
  payload: string;
  endpoint: string;
  param: string;
  method: string;
  base_url: string;
  timeout: number;
  php_sessid: string;
  extra_params: Record<string, string>;
}): Promise<ManualTestResult> {
  return apiFetch<ManualTestResult>(`${API_BASE}/api/test-payload`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
}

export async function enrichKB(params: {
  pattern: string;
  dbms?: string;
  category?: string;
  confidence?: number;
  description?: string;
}): Promise<{ status: string } | { error: string }> {
  return apiFetch<{ status: string } | { error: string }>(`${API_BASE}/api/enrich-kb`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
}

export function createWSConnection(
  onMessage: (data: any) => void,
  maxRetries: number = 10,
): { ws: WebSocket; cleanup: () => void } {
  const wsUrl =
    process.env.NEXT_PUBLIC_WS_URL ||
    `ws://${typeof window !== "undefined" ? window.location.hostname : "localhost"}:8000/ws`;

  let ws: WebSocket;
  let retryCount = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let cleanedUp = false;

  function connect() {
    if (cleanedUp) return;
    ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch {}
    };

    ws.onopen = () => {
      retryCount = 0; // Reset on successful connection
    };

    ws.onclose = () => {
      if (cleanedUp) return;
      if (retryCount < maxRetries) {
        retryCount++;
        const delay = Math.min(3000 * retryCount, 30000); // Backoff: 3s, 6s, 9s, ... max 30s
        reconnectTimer = setTimeout(connect, delay);
      }
    };
  }

  connect();

  function cleanup() {
    cleanedUp = true;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
    }
  }

  return { ws: ws!, cleanup };
}
