import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { verdictLabel } from "../lib/presentation";

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

type ReportSection =
  | "all"
  | "summary"
  | "checks"
  | "brands"
  | "evaluation"
  | "connections";

function isReportSection(value: string): value is ReportSection {
  return [
    "all",
    "summary",
    "checks",
    "brands",
    "evaluation",
    "connections",
  ].includes(value);
}

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
  const [reportSection, setReportSection] = useState<ReportSection>("all");
  const [reportLoading, setReportLoading] = useState(false);
  const [reportMessage, setReportMessage] = useState<{
    text: string;
    kind: "success" | "error";
  } | null>(null);

  const load = () => {
    setLoading(true);
    setError("");

    fetch(`${API}/detections`, { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw Error(`API ${r.status}`);
        return r.json();
      })
      .then(setDetections)
      .catch(() =>
        setError("We couldn’t load your website checks. Refresh the page and try again.")
      )
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
      "We couldn’t load the test results. Please try again."
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
        `Check complete: ${verdictLabel(p.verdict)} · risk score ${(
          Number(p.score) * 100
        ).toFixed(0)}% · check #${p.id}`
      );

      setUrl("");
      load();
    } catch (e) {
      setCaptureMessage(
        e instanceof Error
          ? e.message
          : "We couldn’t check this website. Please try again."
      );
    } finally {
      setCaptureLoading(false);
    }
  }

  async function analyze(e: FormEvent) {
    e.preventDefault();

    if (!analysisFile || !analysisUrl) {
      setAnalysisMessage("Add the website address and choose a screenshot.");
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
        `Screenshot checked: ${verdictLabel(p.verdict)} · risk score ${(
          Number(p.score) * 100
        ).toFixed(0)}% · check #${p.id}`
      );

      load();
    } catch (e) {
      setAnalysisMessage(
        e instanceof Error
          ? e.message
          : "We couldn’t check this screenshot. Please try again."
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
      setAnalysisMessage("Choose an Android app file first.");
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
          ? `App file checked: ${p.filename}. Found ${p.dex_files} code files, ${p.native_libraries} additional components, and ${p.suspicious_permission_markers?.length ?? 0} permission warnings.`
          : p.detail ?? "We couldn’t check this app file."
      );
    } catch (e) {
      setAnalysisMessage(
        e instanceof Error
          ? e.message
          : "We couldn’t check this app file. Please try again."
      );
    }
  }

  async function downloadReport() {
    setReportLoading(true);
    setReportMessage(null);

    try {
      const response = await fetch(
        `${API}/reports?section=${reportSection}`,
        { credentials: "include" }
      );

      if (response.status === 401) {
        throw new Error("Please sign in again to download a report.");
      }
      if (response.status === 503) {
        throw new Error("Test results are not available right now.");
      }
      if (!response.ok) {
        throw new Error("We couldn’t create that report. Please try again.");
      }
      if (!response.headers.get("content-type")?.includes("application/pdf")) {
        throw new Error("We couldn’t create that report. Please try again.");
      }

      const report = await response.blob();
      if (!report.size) {
        throw new Error("The report is empty. Please try again.");
      }

      const downloadUrl = window.URL.createObjectURL(report);
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = `upi-shield-${reportSection}-${new Date()
        .toISOString()
        .slice(0, 10)}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(downloadUrl), 1000);

      setReportMessage({
        text: "Your report has been downloaded.",
        kind: "success",
      });
    } catch (error) {
      const message =
        error instanceof Error && error.name === "TypeError"
          ? "We couldn’t connect to create the report. Check your connection and try again."
          : error instanceof Error
            ? error.message
            : "We couldn’t create that report. Please try again.";
      setReportMessage({ text: message, kind: "error" });
    } finally {
      setReportLoading(false);
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
            WEBSITE CHECKS
          </div>

          <h1>Check a website</h1>

          <p>
            Check a website or app file for warning signs. We’ll show you what
            we found and why it may need attention.
          </p>
        </div>

        <div className="header-actions">
          <button
            className="button"
            onClick={load}
          >
            ↻ Refresh checks
          </button>

          <Link
            href="/graph"
            className="button primary"
          >
            Website connections →
          </Link>
        </div>
      </header>

      <div className="report-actions">
        <label className="report-select" htmlFor="report-section">
          <span>Download a report</span>
          <select
            className="select"
            id="report-section"
            value={reportSection}
            onChange={(event) => {
              const section = event.target.value;
              if (isReportSection(section)) setReportSection(section);
            }}
          >
            <option value="all">Everything</option>
            <option value="summary">Overview</option>
            <option value="checks">Website checks</option>
            <option value="brands">Brand results</option>
            <option value="evaluation">Test results</option>
            <option value="connections">Website connections</option>
          </select>
        </label>
        <button
          className="button primary"
          disabled={reportLoading}
          onClick={downloadReport}
        >
          {reportLoading
            ? "Preparing report…"
            : reportSection === "all"
              ? "Download full report"
              : "Download section report"}
        </button>
        <p className="report-hint">
          For one website, open its check result to download its detailed report.
        </p>
        {reportMessage && (
          <p
            className={`report-message ${reportMessage.kind}`}
            role={reportMessage.kind === "error" ? "alert" : "status"}
          >
            {reportMessage.text}
          </p>
        )}
      </div>

      {/* ================================
          TOP STATISTICS
          ================================ */}

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">
            WEBSITES CHECKED
          </div>

          <div className="stat-value">
            {detections.length}
          </div>

          <div className="stat-note">
            Saved checks
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            LIKELY SCAMS
          </div>

          <div className="stat-value">
            {phishing}
          </div>

          <div className="stat-note warning">
            May be pretending to be a trusted service
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            NEEDS A CLOSER LOOK
          </div>

          <div className="stat-value">
            {suspicious}
          </div>

          <div className="stat-note warning">
            Some warning signs found
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-label">
            SYSTEM STATUS
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
                ? "Partly available"
                : "Checking"}
          </div>

          <div className="stat-note">
            Saved data{" "}
            {health?.services?.database
              ? "✓"
              : "…"}{" "}
            · Website links{" "}
            {health?.services?.neo4j
              ? "✓"
              : "…"}
          </div>
        </div>
      </section>

      {/* ================================
          CHECK RESULTS
          ================================ */}

      <section className="dashboard-grid">
        <div className="panel intelligence-card">
          <div className="eyebrow">
            CHECK RESULTS
          </div>

          <h2>What we found</h2>

          <div className="metric-list">
            <div className="metric-row">
              <span>
                Likely scams
              </span>

              <strong>{phishing}</strong>
            </div>

            <div className="metric-row">
              <span>
                Needs a closer look
              </span>

              <strong>{suspicious}</strong>
            </div>

            <div className="metric-row">
              <span>
                No clear warning signs
              </span>

              <strong>{benign}</strong>
            </div>

            <div className="metric-row">
              <span>
                Average risk score
              </span>

              <strong>
                {(averageRisk * 100).toFixed(0)}%
              </strong>
            </div>
          </div>
        </div>

        <div className="panel intelligence-card">
          <div className="eyebrow">
            CHECK SUMMARY
          </div>

          <h2>Checks by result</h2>

          <div className="risk-bars">
            <div className="risk-item">
              <div>
                <span>
                  Likely a scam
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
                  Needs a closer look
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
                <span>No clear warning signs</span>

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
            RECENT CHECKS
          </div>

          <h2>Recent check results</h2>

          <div className="trend-chart">
            {recentTrend.length === 0 ? (
              <div className="empty">
                No websites have been checked yet.
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
                    title={`Check #${detection.id} · risk score ${(
                      Number(detection.score) * 100
                    ).toFixed(0)}%`}
                  >
                    <div
                      className="trend-bar"
                      style={{
                        height: `${height}%`,
                      }}
                    />

                    <span className="trend-score">
                      {(Number(detection.score) * 100).toFixed(0)}%
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
              Likely a scam
            </span>

            <span>
              <i className="legend-risk suspicious" />
              Needs a closer look
            </span>

            <span>
              <i className="legend-risk benign" />
              No clear warning signs
            </span>
          </div>
        </div>

        <div className="panel brand-card">
          <div className="eyebrow">
            BRANDS SEEN
          </div>

          <h2>Most common brands</h2>

          {brandStats.length === 0 ? (
            <div className="empty">
              No brands found yet.
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
      <div className="eyebrow">TEST RESULTS</div>
      <h2>How well do the checks work?</h2>
      <p>
        These percentages show how the checks performed on a set of websites
        with known results. They may differ from real-world results.
      </p>
    </div>

    <button
      className="button"
      onClick={loadEvaluation}
      disabled={evaluationLoading}
    >
      {evaluationLoading
        ? "Evaluating…"
        : "Refresh test results"}
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
          <span title="How often a warning was correct">Accurate warnings</span>
          <strong>
            {(Number(
              evaluation.metrics?.precision ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span title="How many known scam sites were found">Scams found</span>
          <strong>
            {(Number(
              evaluation.metrics?.recall ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span title="A combined measure of correct warnings and scams found">Overall score</span>
          <strong>
            {(Number(
              evaluation.metrics?.f1 ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span title="How often a safe site was flagged by mistake">False alarms</span>
          <strong>
            {(Number(
              evaluation.metrics?.false_positive_rate ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span title="How often a safe site was correctly recognized">Safe sites recognized</span>
          <strong>
            {(Number(
              evaluation.metrics?.specificity ?? 0
            ) * 100).toFixed(1)}%
          </strong>
        </div>

        <div className="evaluation-metric">
          <span title="Average time taken to check a website">Time to check</span>
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
            CHECK RESULTS TABLE
          </div>

          <div className="confusion-matrix">
            <div className="matrix-label" />

            <div className="matrix-heading">
              Marked as a scam
            </div>

            <div className="matrix-heading">
              Marked as safe
            </div>

            <div className="matrix-heading">
              Known scam
            </div>

            <div className="matrix-cell positive">
              <span>Correct warning</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.true_positive ?? 0}
              </strong>
            </div>

            <div className="matrix-cell negative">
              <span>Missed scam</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.false_negative ?? 0}
              </strong>
            </div>

            <div className="matrix-heading">
              Known safe
            </div>

            <div className="matrix-cell warning">
              <span>False alarm</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.false_positive ?? 0}
              </strong>
            </div>

            <div className="matrix-cell positive">
              <span>Correctly marked safe</span>
              <strong>
                {evaluation.confusion_matrix
                  ?.true_negative ?? 0}
              </strong>
            </div>
          </div>
        </div>

        <div className="evaluation-summary">
          <div className="eyebrow">
            TEST SET
          </div>

          <h3>Website test set</h3>

          <div className="evaluation-info">
            <div>
              <span>Websites in test</span>
              <strong>
                {evaluation.samples ?? 0}
              </strong>
            </div>

            <div>
              <span>Checked</span>
              <strong>
                {evaluation.evaluated ?? 0}
              </strong>
            </div>

            <div>
              <span>Could not check</span>
              <strong>
                {evaluation.errors_count ?? 0}
              </strong>
            </div>

            <div>
              <span>Check time range</span>
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
        <strong>Please note:</strong>{" "}
        These results come from the included test set. They are not a promise
        that every scam or safe website will be identified correctly.
      </div>
    </>
  )}
</section>

      {/* ================================
          CHECK A WEBSITE
          ================================ */}

      <section className="panel analyzer-panel">
        <div className="eyebrow">
          APPROVED WEBSITE CHECK
        </div>

        <h2>
          Check a website address
        </h2>

        <p>
          Only websites approved by your administrator can be checked. Use a
          practice website or another site you have permission to test.
        </p>

        <form
          className="analyzer-form"
          onSubmit={capture}
        >
          <label>
            Website address

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
            Brand names or payment words

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
              ? "Checking…"
              : "Check website →"}
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
          CHECK A SCREENSHOT
        </div>

        <h2>
          Check a website screenshot
        </h2>

        <p>
          Use this when you have a screenshot but can’t open the website here.
        </p>

        <form
          className="analyzer-form"
          onSubmit={analyze}
        >
          <label>
            Website address

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
            Brand names or payment words

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
              : "Check screenshot →"}
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
          CHECK AN ANDROID APP FILE
        </div>

        <h2>
          Check an Android app file (.apk)
        </h2>

        <p>
          We check basic file details and warning signs. The app is not
          installed or opened.
        </p>

        <form
          className="analyzer-form"
          onSubmit={inspectApk}
        >
          <label>
            Android app file (.apk)

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
            Check app file →
          </button>
        </form>
      </section>

      {/* ================================
          RECENT DETECTIONS
          ================================ */}

      <section className="toolbar">
        <div>
          <h2>Recent website checks</h2>

          <span className="stat-label">
            {filtered.length} checks
          </span>
          <p className="profile-muted">
            A higher risk score means more warning signs were found. It is not
            proof that a website is a scam.
          </p>
        </div>

        <div className="filters">
          <input
            className="input"
            placeholder="Search website or brand…"
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
              All results
            </option>

            <option value="phishing">
              Likely a scam
            </option>

            <option value="suspicious">
              Needs a closer look
            </option>

            <option value="benign">
              No clear warning signs
            </option>
          </select>
        </div>
      </section>

      <section className="panel table-wrap">
        {loading ? (
          <div className="empty">
            Loading website checks…
          </div>
        ) : error ? (
          <div className="error-box">
            {error}
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            No website checks yet. Check a website or screenshot above to get started.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>WEBSITE</th>
                <th>BRAND</th>
                <th>RISK SCORE</th>
                <th>RESULT</th>
                <th>DETAILS</th>
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
                    {(Number(d.score) * 100).toFixed(0)}%
                  </td>

                  <td>
                    <span
                      className={`badge ${d.verdict}`}
                    >
                      {verdictLabel(d.verdict)}
                    </span>
                  </td>

                  <td>
                    <Link
                      href={`/detail/${d.id}`}
                      className="stat-label"
                    >
                      See why →
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