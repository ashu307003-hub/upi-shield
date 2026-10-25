import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Detection = {
  id: number;
  url: string;
  brand?: string;
  score: number;
  verdict: string;
  behavioral?: Record<string, any>;
  evidence?: Record<string, any>;
  screenshot: string;
  dom: string;
  created_at?: string;
};

type Health = {
  status: string;
  database_dialect?: string;
  services?: Record<string, boolean>;
};

export default function Home() {
  const [detections, setDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("all");
  const [health, setHealth] = useState<Health | null>(null);

  const [url, setUrl] = useState("");
  const [keywords, setKeywords] = useState("upi,payment,otp,pin");
  const [captureLoading, setCaptureLoading] = useState(false);
  const [captureMessage, setCaptureMessage] = useState("");

  const [analysisUrl, setAnalysisUrl] = useState("");
  const [analysisKeywords, setAnalysisKeywords] = useState(
    "upi,payment,otp,pin"
  );
  const [analysisFile, setAnalysisFile] = useState<File | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisMessage, setAnalysisMessage] = useState("");
  const [evaluation, setEvaluation] = useState<any | null>(null);
  const [evaluationLoading, setEvaluationLoading] = useState(false);
  const [evaluationError, setEvaluationError] = useState("");

  const load = () => {
    setLoading(true);
    setError("");

    fetch(`${API}/detections`, { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw Error(`API ${r.status}`);
        return r.json();
      })
      .then(setDetections)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  async function loadEvaluation() {
  setEvaluationLoading(true);
  setEvaluationError("");

  try {
    const r = await fetch(`${API}/evaluation`, {
      credentials: "include",
    });

    if (!r.ok) {
      throw Error(`Evaluation API ${r.status}`);
    }

    const data = await r.json();
    setEvaluation(data);
  } catch (e) {
    setEvaluationError(
      e instanceof Error
        ? e.message
        : "Evaluation unavailable"
    );
  } finally {
    setEvaluationLoading(false);
  }
}

  useEffect(() => {
    load();

    fetch(`${API}/health`)
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setHealth(null));

    loadEvaluation();
  }, []);

  const filtered = useMemo(
    () =>
      detections.filter(
        (d) =>
          (verdictFilter === "all" || d.verdict === verdictFilter) &&
          `${d.url} ${d.brand ?? ""}`
            .toLowerCase()
            .includes(query.toLowerCase())
      ),
    [detections, query, verdictFilter]
  );

  const phishing = detections.filter(
    (d) => d.verdict === "phishing"
  ).length;

  const suspicious = detections.filter(
    (d) => d.verdict === "suspicious"
  ).length;

  const benign = detections.filter(
    (d) => d.verdict === "benign"
  ).length;

  /*
   * Brand intelligence
   * -------------------
   * Counts the observed brands and keeps the top five.
   */
  const brandStats = useMemo(() => {
    const counts: Record<string, number> = {};

    detections.forEach((d) => {
      const brand = d.brand?.trim().toLowerCase() || "unidentified";
      counts[brand] = (counts[brand] || 0) + 1;
    });

    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [detections]);

  /*
   * Recent detection activity
   * -------------------------
   * Shows the seven most recent observations.
   */
  const recentTrend = useMemo(() => {
    return [...detections]
      .sort((a, b) => {
        const aTime = a.created_at
          ? new Date(a.created_at).getTime()
          : 0;

        const bTime = b.created_at
          ? new Date(b.created_at).getTime()
          : 0;

        return aTime - bTime;
      })
      .slice(-7);
  }, [detections]);

  /*
   * Average risk
   */
  const averageRisk = useMemo(() => {
    if (!detections.length) return 0;

    return (
      detections.reduce(
        (sum, detection) => sum + Number(detection.score || 0),
        0
      ) / detections.length
    );
  }, [detections]);

  async function capture(e: FormEvent) {
    e.preventDefault();

    setCaptureLoading(true);
    setCaptureMessage("");

    try {
      const r = await fetch(`${API}/captures`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url,
          brand_keywords: keywords
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean),
        }),
      });

      const p = await r.json();

      if (!r.ok) {
        throw Error(
          p.detail?.message ??
          p.detail ??
          `API ${r.status}`
        );
      }

      setCaptureMessage(
        `Captured: ${p.verdict} · risk ${Number(p.score).toFixed(
          2
        )} · detection #${p.id}`
      );

      setUrl("");
      load();
    } catch (e) {
      setCaptureMessage(
        e instanceof Error ? e.message : "Capture failed"
      );
    } finally {
      setCaptureLoading(false);
    }
  }

  async function analyze(e: FormEvent) {
    e.preventDefault();

    if (!analysisFile || !analysisUrl) {
      setAnalysisMessage("Provide a URL and screenshot.");
      return;
    }

    setAnalysisLoading(true);
    setAnalysisMessage("");

    const form = new FormData();

    form.append("url", analysisUrl);
    form.append("brand_keywords", analysisKeywords);
    form.append("screenshot", analysisFile);

    try {
      const r = await fetch(`${API}/analyze-upload`, {
        method: "POST",
        credentials: "include",
        body: form,
      });

      const p = await r.json();

      if (!r.ok) {
        throw Error(
          p.detail ?? `API ${r.status}`
        );
      }

      setAnalysisMessage(
        `Analyzed: ${p.verdict} · risk ${Number(
          p.score
        ).toFixed(2)} · detection #${p.id}`
      );

      load();
    } catch (e) {
      setAnalysisMessage(
        e instanceof Error ? e.message : "Analysis failed"
      );
    } finally {
      setAnalysisLoading(false);
    }
  }

  async function inspectApk(e: FormEvent) {
    e.preventDefault();

    const input = document.getElementById(
      "apk-upload"
    ) as HTMLInputElement | null;

    if (!input?.files?.[0]) {
      setAnalysisMessage("Select an APK file first.");
      return;
    }

    const form = new FormData();
    form.append("apk", input.files[0]);

    try {
      const r = await fetch(
        `${API}/apps/inspect-upload`,
        {
          method: "POST",
          credentials: "include",
          body: form,
        }
      );

      const p = await r.json();

      setAnalysisMessage(
        r.ok
          ? `APK: ${p.filename} · DEX ${p.dex_files} · native libs ${p.native_libraries} · suspicious permission markers ${p.suspicious_permission_markers?.length ?? 0
          }`
          : p.detail ?? "APK inspection failed"
      );
    } catch (e) {
      setAnalysisMessage(
        e instanceof Error
          ? e.message
          : "APK inspection failed"
      );
    }
  }

  return (
    <>
      {/* ================================
          PAGE HEADER
          ================================ */}

      <header className="page-header">
        <div>
          <div className="eyebrow">
            SECURITY OPERATIONS / TRIAGE
          </div>

          <h1>UPI Shield</h1>

          <p>
            Detect, explain and investigate suspected
            payment-brand abuse using multiple
            independent signals.
          </p>
        </div>

        <div className="header-actions">
          <button
            className="button"
            onClick={load}
          >
            ↻ Refresh
          </button>

          <Link
            href="/graph"
            className="button primary"
          >
            Campaign graph →
          </Link>
        </div>
      </header>

      {/* ================================
          TOP STATISTICS
          ================================ */}

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">
            OBSERVATIONS
          </div>

          <div className="stat-value">
            {detections.length}
          </div>

          <div className="stat-note">
            Persisted in PostgreSQL
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            HIGH RISK
          </div>

          <div className="stat-value">
            {phishing}
          </div>

          <div className="stat-note warning">
            Phishing verdicts
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            NEEDS REVIEW
          </div>

          <div className="stat-value">
            {suspicious}
          </div>

          <div className="stat-note warning">
            Suspicious verdicts
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            PLATFORM
          </div>

          <div
            className="stat-value"
            style={{
              color: "var(--green)",
              fontSize: 20,
            }}
          >
            {health?.status === "ok"
              ? "Online"
              : health?.status === "degraded"
                ? "Degraded"
                : "Checking"}
          </div>

          <div className="stat-note">
            {health?.database_dialect === "postgresql" ? "PG" : "DB"}{" "}
            {health?.services?.database
              ? "✓"
              : "…"}{" "}
            · Neo4j{" "}
            {health?.services?.neo4j
              ? "✓"
              : "…"}
          </div>
        </div>
      </section>

      {/* ================================
          THREAT INTELLIGENCE
          ================================ */}

      <section className="dashboard-grid">
        <div className="panel intelligence-card">
          <div className="eyebrow">
            THREAT INTELLIGENCE
          </div>

          <h2>Detection posture</h2>

          <div className="metric-list">
            <div className="metric-row">
              <span>
                Phishing detections
              </span>

              <strong>{phishing}</strong>
            </div>

            <div className="metric-row">
              <span>
                Suspicious detections
              </span>

              <strong>{suspicious}</strong>
            </div>

            <div className="metric-row">
              <span>
                Benign observations
              </span>

              <strong>{benign}</strong>
            </div>

            <div className="metric-row">
              <span>
                Average risk
              </span>

              <strong>
                {averageRisk.toFixed(2)}
              </strong>
            </div>
          </div>
        </div>

        <div className="panel intelligence-card">
          <div className="eyebrow">
            ANALYST QUEUE
          </div>

          <h2>Priority breakdown</h2>

          <div className="risk-bars">
            <div className="risk-item">
              <div>
                <span>
                  Critical / Phishing
                </span>

                <strong>{phishing}</strong>
              </div>

              <div className="risk-bar">
                <span
                  style={{
                    width: `${detections.length
                        ? (phishing /
                          detections.length) *
                        100
                        : 0
                      }%`,
                  }}
                />
              </div>
            </div>

            <div className="risk-item">
              <div>
                <span>
                  Needs Review
                </span>

                <strong>{suspicious}</strong>
              </div>

              <div className="risk-bar">
                <span
                  style={{
                    width: `${detections.length
                        ? (suspicious /
                          detections.length) *
                        100
                        : 0
                      }%`,
                  }}
                />
              </div>
            </div>

            <div className="risk-item">
              <div>
                <span>Benign</span>

                <strong>{benign}</strong>
              </div>

              <div className="risk-bar">
                <span
                  style={{
                    width: `${detections.length
                        ? (benign /
                          detections.length) *
                        100
                        : 0
                      }%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ================================
          DETECTION ACTIVITY + BRANDS
          ================================ */}

      <section className="dashboard-grid intelligence-secondary">
        <div className="panel trend-card">
          <div className="eyebrow">
            DETECTION ACTIVITY
          </div>

          <h2>Recent risk activity</h2>

          <div className="trend-chart">
            {recentTrend.length === 0 ? (
              <div className="empty">
                No detection activity yet.
              </div>
            ) : (
              recentTrend.map((detection) => {
                const height = Math.max(
                  12,
                  Math.min(
                    100,
                    Number(detection.score || 0) *
                    100
                  )
                );

                return (
                  <Link
                    key={detection.id}
                    href={`/detail/${detection.id}`}
                    className={`trend-column ${detection.verdict}`}
                    title={`Detection #${detection.id
                      } · risk ${Number(
                        detection.score
                      ).toFixed(2)}`}
                  >
                    <div
                      className="trend-bar"
                      style={{
                        height: `${height}%`,
                      }}
                    />

                    <span className="trend-score">
                      {Number(
                        detection.score
                      ).toFixed(2)}
                    </span>

                    <small>
                      #{detection.id}
                    </small>
                  </Link>
                );
              })
            )}
          </div>

          <div className="trend-legend">
            <span>
              <i className="legend-risk phishing" />
              Phishing
            </span>

            <span>
              <i className="legend-risk suspicious" />
              Suspicious
            </span>

            <span>
              <i className="legend-risk benign" />
              Benign
            </span>
          </div>
        </div>

        <div className="panel brand-card">
          <div className="eyebrow">
            BRAND INTELLIGENCE
          </div>

          <h2>Most observed brands</h2>

          {brandStats.length === 0 ? (
            <div className="empty">
              No brand intelligence available.
            </div>
          ) : (
            <div className="brand-list">
              {brandStats.map(
                ([brand, count]) => {
                  const percentage =
                    detections.length
                      ? (count /
                        detections.length) *
                      100
                      : 0;

                  return (
                    <div
                      className="brand-row"
                      key={brand}
                    >
                      <div className="brand-row-header">
                        <span className="brand-name">
                          {brand ===
                            "unidentified"
                            ? "Unidentified"
                            : brand.toUpperCase()}
                        </span>

                        <strong>
                          {count}
                        </strong>
                      </div>

                      <div className="brand-progress">
                        <span
                          style={{
                            width: `${percentage}%`,
                          }}
                        />
                      </div>
                    </div>
                  );
                }
              )}
            </div>
          )}
        </div>
      </section>


      <section className="panel evaluation-panel">
  <div className="evaluation-header">
    <div>
      <div className="eyebrow">MODEL EVALUATION</div>
      <h2>Detection engine performance</h2>
      <p>
        Quantitative evaluation against the labelled RVS
        validation dataset.
      </p>
    </div>

    <button
      className="button"
      onClick={loadEvaluation}
      disabled={evaluationLoading}
    >
      {evaluationLoading
        ? "Evaluating…"
        : "Refresh metrics"}
    </button>
  </div>

  {evaluationError ? (
    <div className="error-box">
      {evaluationError}
    </div>
  ) : !evaluation ? (
    <div className="empty">
      Loading evaluation metrics…
    </div>
  ) : (
    <>
      <div className="evaluation-metrics">
        <div className="evaluation-metric">
          <span>PRECISION</span>
          <strong>
            {(Number(
              evaluation.metrics?.precision ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span>RECALL</span>
          <strong>
            {(Number(
              evaluation.metrics?.recall ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span>F1 SCORE</span>
          <strong>
            {(Number(
              evaluation.metrics?.f1 ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span>FALSE POSITIVE RATE</span>
          <strong>
            {(Number(
              evaluation.metrics?.false_positive_rate ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span>SPECIFICITY</span>
          <strong>
            {(Number(
              evaluation.metrics?.specificity ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span>AVG LATENCY</span>
          <strong>
            {Number(
              evaluation.latency?.average_ms ?? 0
            ).toFixed(1)}
            <small> ms</small>
          </strong>
        </div>
      </div>

      <div className="evaluation-bottom">
        <div className="confusion-card">
          <div className="eyebrow">
            CONFUSION MATRIX
          </div>

          <div className="confusion-matrix">
            <div className="matrix-label" />

            <div className="matrix-heading">
              Predicted Positive
            </div>

            <div className="matrix-heading">
              Predicted Negative
            </div>

            <div className="matrix-heading">
              Actual Positive
            </div>

            <div className="matrix-cell positive">
              <span>TP</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.true_positive ?? 0}
              </strong>
            </div>

            <div className="matrix-cell negative">
              <span>FN</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.false_negative ?? 0}
              </strong>
            </div>

            <div className="matrix-heading">
              Actual Negative
            </div>

            <div className="matrix-cell warning">
              <span>FP</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.false_positive ?? 0}
              </strong>
            </div>

            <div className="matrix-cell positive">
              <span>TN</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.true_negative ?? 0}
              </strong>
            </div>
          </div>
        </div>

        <div className="evaluation-summary">
          <div className="eyebrow">
            DATASET
          </div>

          <h3>
            {evaluation.dataset ?? "labels.csv"}
          </h3>

          <div className="evaluation-info">
            <div>
              <span>Samples</span>
              <strong>
                {evaluation.samples ?? 0}
              </strong>
            </div>

            <div>
              <span>Evaluated</span>
              <strong>
                {evaluation.evaluated ?? 0}
              </strong>
            </div>

            <div>
              <span>Errors</span>
              <strong>
                {evaluation.errors_count ?? 0}
              </strong>
            </div>

            <div>
              <span>Latency range</span>
              <strong>
                {Number(
                  evaluation.latency?.minimum_ms ?? 0
                ).toFixed(1)}
                –
                {Number(
                  evaluation.latency?.maximum_ms ?? 0
                ).toFixed(1)}
                ms
              </strong>
            </div>
          </div>
        </div>
      </div>

      <div className="evaluation-note">
        <strong>Evaluation note:</strong>{" "}
        Metrics are calculated from the currently
        labelled dataset. Synthetic development
        samples should not be presented as real-world
        detection performance.
      </div>
    </>
  )}
</section>

      {/* ================================
          AUTHORIZED CRAWL
          ================================ */}

      <section className="panel analyzer-panel">
        <div className="eyebrow">
          AUTHORIZED CRAWL
        </div>

        <h2>
          Capture and score a test target
        </h2>

        <p>
          Only crawl domains explicitly
          present in{" "}
          <code>CRAWL_ALLOWLIST</code>.
          Use your local training page or
          another authorized target.
        </p>

        <form
          className="analyzer-form"
          onSubmit={capture}
        >
          <label>
            Target URL

            <input
              className="input"
              type="url"
              required
              placeholder="http://127.0.0.1:8765/upi-payment-simulation.html"
              value={url}
              onChange={(e) =>
                setUrl(e.target.value)
              }
            />
          </label>

          <label>
            Brand keywords

            <input
              className="input"
              value={keywords}
              onChange={(e) =>
                setKeywords(e.target.value)
              }
            />
          </label>

          <div />

          <button
            className="button primary"
            disabled={captureLoading}
          >
            {captureLoading
              ? "Capturing…"
              : "Capture + detect →"}
          </button>
        </form>

        {captureMessage && (
          <div className="success-box">
            {captureMessage}
          </div>
        )}
      </section>

      {/* ================================
          SCREENSHOT ANALYSIS
          ================================ */}

      <section className="panel analyzer-panel">
        <div className="eyebrow">
          ANALYST EVIDENCE
        </div>

        <h2>
          Analyze an uploaded screenshot
        </h2>

        <p>
          Useful when the analyst has a
          screenshot but must not crawl the
          submitted URL.
        </p>

        <form
          className="analyzer-form"
          onSubmit={analyze}
        >
          <label>
            Website URL

            <input
              className="input"
              type="url"
              required
              value={analysisUrl}
              onChange={(e) =>
                setAnalysisUrl(e.target.value)
              }
            />
          </label>

          <label>
            Brand keywords

            <input
              className="input"
              value={analysisKeywords}
              onChange={(e) =>
                setAnalysisKeywords(
                  e.target.value
                )
              }
            />
          </label>

          <label>
            Screenshot

            <input
              id="screenshot-upload"
              className="input file-input"
              type="file"
              accept="image/png,image/jpeg,image/webp"
              onChange={(e) =>
                setAnalysisFile(
                  e.target.files?.[0] ?? null
                )
              }
            />
          </label>

          <button
            className="button primary"
            disabled={analysisLoading}
          >
            {analysisLoading
              ? "Analyzing…"
              : "Analyze screenshot →"}
          </button>
        </form>

        {analysisMessage && (
          <div className="success-box">
            {analysisMessage}
          </div>
        )}
      </section>

      {/* ================================
          APK INTELLIGENCE
          ================================ */}

      <section className="panel analyzer-panel">
        <div className="eyebrow">
          APP INTELLIGENCE
        </div>

        <h2>
          Static APK inspection
        </h2>

        <p>
          Upload an APK for safe metadata
          inspection only. The file is never
          executed.
        </p>

        <form
          className="analyzer-form"
          onSubmit={inspectApk}
        >
          <label>
            APK file

            <input
              id="apk-upload"
              className="input file-input"
              type="file"
              accept=".apk"
            />
          </label>

          <div />
          <div />

          <button className="button primary">
            Inspect safely →
          </button>
        </form>
      </section>

      {/* ================================
          RECENT DETECTIONS
          ================================ */}

      <section className="toolbar">
        <div>
          <h2>Recent detections</h2>

          <span className="stat-label">
            {filtered.length} records
          </span>
        </div>

        <div className="filters">
          <input
            className="input"
            placeholder="Search URL or brand…"
            value={query}
            onChange={(e) =>
              setQuery(e.target.value)
            }
          />

          <select
            className="select"
            value={verdictFilter}
            onChange={(e) =>
              setVerdictFilter(
                e.target.value
              )
            }
          >
            <option value="all">
              All verdicts
            </option>

            <option value="phishing">
              Phishing
            </option>

            <option value="suspicious">
              Suspicious
            </option>

            <option value="benign">
              Benign
            </option>
          </select>
        </div>
      </section>

      <section className="panel table-wrap">
        {loading ? (
          <div className="empty">
            Loading detection telemetry…
          </div>
        ) : error ? (
          <div className="error-box">
            {error}
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            No detections yet. Run the local
            simulation capture above.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>TARGET</th>
                <th>BRAND</th>
                <th>RISK</th>
                <th>VERDICT</th>
                <th>EVIDENCE</th>
              </tr>
            </thead>

            <tbody>
              {filtered.map((d) => (
                <tr key={d.id}>
                  <td className="url-cell">
                    <Link
                      href={`/detail/${d.id}`}
                    >
                      {d.url}
                    </Link>

                    <small>
                      {d.created_at
                        ? new Date(
                          d.created_at
                        ).toLocaleString()
                        : ""}
                    </small>
                  </td>

                  <td>
                    {d.brand ??
                      "Unidentified"}
                  </td>

                  <td className="score">
                    {Number(
                      d.score
                    ).toFixed(2)}
                  </td>

                  <td>
                    <span
                      className={`badge ${d.verdict}`}
                    >
                      {d.verdict}
                    </span>
                  </td>

                  <td>
                    <Link
                      href={`/detail/${d.id}`}
                      className="stat-label"
                    >
                      Investigate →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}