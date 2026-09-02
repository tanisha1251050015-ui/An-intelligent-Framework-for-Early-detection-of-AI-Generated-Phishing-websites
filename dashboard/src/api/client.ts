/**
 * PIP Dashboard API client.
 *
 * Talks to the PIP Backend REST API. In development the Vite server proxies
 * /api to http://localhost:8000; set VITE_API_BASE_URL to point elsewhere.
 */

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  database: string;
  timestamp: string;
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "/api/v1";

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`);
  }
  return (await response.json()) as HealthResponse;
}

export type Classification = "safe" | "suspicious" | "malicious";

export interface InspectionResult {
  id: number;
  url: string;
  status: string;
  score: number;
  classification: Classification;
  features: Record<string, unknown>;
  reasons: string[];
  created_at: string;
  updated_at: string;
}

export async function inspectUrl(url: string): Promise<InspectionResult> {
  const response = await fetch(`${API_BASE}/inspect`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    throw new Error(`Inspection failed with status ${response.status}`);
  }
  return (await response.json()) as InspectionResult;
}
