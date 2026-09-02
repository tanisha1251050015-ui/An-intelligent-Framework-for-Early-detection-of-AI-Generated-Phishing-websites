import { FormEvent, useEffect, useState } from "react";
import {
  fetchHealth,
  inspectUrl,
  type Classification,
  type HealthResponse,
  type InspectionResult,
} from "./api/client";

type ConnectionState =
  | { phase: "loading" }
  | { phase: "ok"; health: HealthResponse }
  | { phase: "error"; message: string };

type InspectionState =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "ok"; result: InspectionResult }
  | { phase: "error"; message: string };

function classificationLabel(classification: Classification): string {
  return classification.charAt(0).toUpperCase() + classification.slice(1);
}

function InspectionPanel() {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<InspectionState>({ phase: "idle" });

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = url.trim();
    if (!target) return;

    setState({ phase: "loading" });
    try {
      const result = await inspectUrl(target);
      setState({ phase: "ok", result });
    } catch (error) {
      setState({
        phase: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return (
    <section className="card" aria-label="URL inspection">
      <h2>Inspect a URL</h2>
      <form className="inspect-form" onSubmit={handleSubmit}>
        <input
          type="url"
          placeholder="https://example.com/login"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          required
        />
        <button type="submit" disabled={state.phase === "loading"}>
          {state.phase === "loading" ? "Inspecting…" : "Inspect"}
        </button>
      </form>

      {state.phase === "ok" && (
        <div className="result">
          <div className="result-header">
            <span className={`badge ${state.result.classification}`}>
              {classificationLabel(state.result.classification)}
            </span>
            <span className="score">
              Risk score: <strong>{state.result.score}</strong>/100
            </span>
          </div>
          <p className="result-url">{state.result.url}</p>
          <ul className="reasons">
            {state.result.reasons.length > 0 ? (
              state.result.reasons.map((reason) => <li key={reason}>{reason}</li>)
            ) : (
              <li>No risk indicators found.</li>
            )}
          </ul>
          <details>
            <summary>Extracted features</summary>
            <pre>{JSON.stringify(state.result.features, null, 2)}</pre>
          </details>
        </div>
      )}

      {state.phase === "error" && (
        <p className="error">{state.message}</p>
      )}
    </section>
  );
}

export default function App() {
  const [connection, setConnection] = useState<ConnectionState>({
    phase: "loading",
  });

  useEffect(() => {
    let cancelled = false;

    fetchHealth()
      .then((health) => {
        if (!cancelled) setConnection({ phase: "ok", health });
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setConnection({
            phase: "error",
            message: error instanceof Error ? error.message : String(error),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="app">
      <header>
        <h1>PIP Dashboard</h1>
        <p className="subtitle">Phishing Intelligence Platform — Phase 1</p>
      </header>

      <section className="card" aria-label="Backend connection status">
        <h2>Backend connection</h2>
        {connection.phase === "loading" && <p>Checking backend health…</p>}

        {connection.phase === "ok" && (
          <dl className="status-grid">
            <div>
              <dt>Status</dt>
              <dd className="ok">{connection.health.status}</dd>
            </div>
            <div>
              <dt>Service</dt>
              <dd>{connection.health.service}</dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{connection.health.version}</dd>
            </div>
            <div>
              <dt>Database</dt>
              <dd>{connection.health.database}</dd>
            </div>
            <div>
              <dt>Timestamp</dt>
              <dd>{new Date(connection.health.timestamp).toLocaleString()}</dd>
            </div>
          </dl>
        )}

        {connection.phase === "error" && (
          <p className="error">
            Cannot reach the backend: {connection.message}. Start it with{" "}
            <code>uvicorn app.main:app --reload</code> in <code>backend/</code>.
          </p>
        )}
      </section>

      <InspectionPanel />

      <footer>
        <p>Version 1.0.0 — deterministic heuristic scoring (Phase 1).</p>
      </footer>
    </main>
  );
}
