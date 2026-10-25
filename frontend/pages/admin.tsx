import Head from "next/head";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useAuth } from "./_app";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type AdminUser = {
  id: number;
  full_name: string;
  email: string;
  mobile_number: string;
  email_verified: boolean;
  created_at: string | null;
  last_login_at: string | null;
  login_count: number;
};

type AdminEvent = {
  id: number;
  event_type: string;
  created_at: string | null;
  user_email: string | null;
  user_name: string | null;
  details: Record<string, unknown>;
};

type Detection = {
  id: number;
  url: string;
  brand: string | null;
  score: number;
  verdict: string;
  created_at: string | null;
  screenshot_url: string;
  evidence: Record<string, unknown>;
};

type Overview = {
  generated_at: string;
  activity_retention_days: number;
  accounts: {
    total: number;
    verified: number;
    pending_email_confirmation: number;
    registrations_in_retention_window: number;
  };
  visits: {
    page_views_in_retention_window: number;
    page_views_last_30_days: number;
    tracked_unique_visitors: boolean;
    by_page: Array<{ path: string; views: number }>;
  };
  logins_in_retention_window: number;
  detections_stored: number;
  feature_usage: Array<{ feature: string; uses: number }>;
};

function formatDate(value: string | null) {
  return value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(new Date(value))
    : "—";
}

function formatFeature(value: string) {
  return value.replaceAll("_", " ");
}

export default function Admin() {
  const { isAdmin } = useAuth();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [events, setEvents] = useState<AdminEvent[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isAdmin) return;
    let active = true;
    Promise.all([
      fetch(`${API}/admin/overview`, { credentials: "include" }),
      fetch(`${API}/admin/users?limit=100`, { credentials: "include" }),
      fetch(`${API}/admin/activity?limit=100`, { credentials: "include" }),
    ])
      .then(async ([overviewResponse, usersResponse, activityResponse]) => {
        const responses = [overviewResponse, usersResponse, activityResponse];
        const payloads = await Promise.all(responses.map((response) => response.json()));
        const failed = responses.findIndex((response) => !response.ok);
        if (failed !== -1) {
          const detail = payloads[failed]?.detail;
          throw new Error(
            typeof detail === "string"
              ? detail
              : `Admin data request failed (${responses[failed].status})`
          );
        }
        return payloads;
      })
      .then(([overviewData, userData, activityData]) => {
        if (!active) return;
        setOverview(overviewData as Overview);
        setUsers(userData.users ?? []);
        setEvents(activityData.events ?? []);
        setDetections(activityData.detections ?? []);
      })
      .catch((loadError: unknown) => {
        if (!active) return;
        setError(
          loadError instanceof Error
            ? loadError.message
            : "Could not load admin data"
        );
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [isAdmin]);

  if (!isAdmin) {
    return (
      <section className="admin-access-denied">
        <div className="eyebrow">RESTRICTED WORKSPACE</div>
        <h1>Admin access required</h1>
        <p>
          This account is not on the configured admin email allowlist.
          Contact your workspace administrator.
        </p>
        <Link href="/" className="button primary">Back to dashboard</Link>
      </section>
    );
  }

  return (
    <>
      <Head>
        <title>Admin overview · UPI Shield</title>
      </Head>
      <div className="admin-page">
        <header className="page-header">
          <div>
            <div className="eyebrow">WORKSPACE / ADMINISTRATION</div>
            <h1>Admin overview</h1>
            <p>Account growth, aggregate site visits, analyst activity, and stored evidence.</p>
          </div>
          <div className="admin-retention-badge">
            <span className="status-dot" />
            Activity logs retained for {overview?.activity_retention_days ?? 180} days
          </div>
        </header>

        {error && <div className="login-error" role="alert">{error}</div>}
        {loading && <div className="panel admin-loading">Loading workspace activity…</div>}

        {!loading && overview && (
          <>
            <section className="admin-metrics-grid" aria-label="Workspace metrics">
              <article className="admin-metric">
                <span className="admin-metric-icon">◎</span>
                <span className="admin-metric-label">REGISTERED ACCOUNTS</span>
                <strong>{overview.accounts.total}</strong>
                <small>{overview.accounts.verified} verified · {overview.accounts.pending_email_confirmation} pending</small>
              </article>
              <article className="admin-metric">
                <span className="admin-metric-icon">↗</span>
                <span className="admin-metric-label">SITE PAGE VIEWS</span>
                <strong>{overview.visits.page_views_in_retention_window}</strong>
                <small>{overview.visits.page_views_last_30_days} in the last 30 days · aggregate only</small>
              </article>
              <article className="admin-metric">
                <span className="admin-metric-icon">⌁</span>
                <span className="admin-metric-label">SUCCESSFUL SIGN-INS</span>
                <strong>{overview.logins_in_retention_window}</strong>
                <small>Within the activity retention period</small>
              </article>
              <article className="admin-metric">
                <span className="admin-metric-icon">◈</span>
                <span className="admin-metric-label">ANALYSIS RESULTS</span>
                <strong>{overview.detections_stored}</strong>
                <small>URLs, score results, and evidence records</small>
              </article>
            </section>

            <section className="admin-columns">
              <article className="panel admin-section">
                <div className="admin-section-heading">
                  <div>
                    <div className="eyebrow">ANALYST ACCESS</div>
                    <h2>Registered accounts</h2>
                  </div>
                  <span className="admin-count">{users.length} shown</span>
                </div>
                <div className="admin-table-wrap">
                  <table className="admin-table">
                    <thead>
                      <tr>
                        <th>Analyst</th>
                        <th>Mobile</th>
                        <th>Account</th>
                        <th>Sign-ins</th>
                        <th>Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((user) => (
                        <tr key={user.id}>
                          <td>
                            <strong>{user.full_name}</strong>
                            <small>{user.email}</small>
                          </td>
                          <td>{user.mobile_number}</td>
                          <td>
                            <span className={`admin-status ${user.email_verified ? "verified" : "pending"}`}>
                              {user.email_verified ? "Verified" : "Pending"}
                            </span>
                          </td>
                          <td>{user.login_count}</td>
                          <td>{formatDate(user.last_login_at)}</td>
                        </tr>
                      ))}
                      {!users.length && (
                        <tr><td colSpan={5} className="admin-empty-cell">No accounts registered yet.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </article>

              <article className="panel admin-section">
                <div className="admin-section-heading">
                  <div>
                    <div className="eyebrow">ANALYTICS</div>
                    <h2>Page views</h2>
                  </div>
                  <span className="admin-count">180 days</span>
                </div>
                <p className="admin-privacy-note">
                  Aggregate page counts only. Anonymous visitors are not fingerprinted and IP addresses are not recorded.
                </p>
                <div className="admin-page-list">
                  {overview.visits.by_page.map((page) => (
                    <div className="admin-page-row" key={page.path}>
                      <span>{page.path}</span>
                      <strong>{page.views}</strong>
                    </div>
                  ))}
                  {!overview.visits.by_page.length && (
                    <div className="admin-empty-cell">No page views recorded yet.</div>
                  )}
                </div>
                <div className="admin-feature-list">
                  <div className="eyebrow">FEATURE USE</div>
                  {overview.feature_usage.map((feature) => (
                    <div className="admin-page-row" key={feature.feature}>
                      <span>{formatFeature(feature.feature)}</span>
                      <strong>{feature.uses}</strong>
                    </div>
                  ))}
                  {!overview.feature_usage.length && (
                    <div className="admin-empty-cell">No feature runs recorded yet.</div>
                  )}
                </div>
              </article>
            </section>

            <section className="panel admin-section">
              <div className="admin-section-heading">
                <div>
                  <div className="eyebrow">PERSISTED EVIDENCE</div>
                  <h2>Recent analysis results</h2>
                </div>
                <span className="admin-count">{detections.length} recent</span>
              </div>
              <div className="admin-evidence-grid">
                {detections.map((detection) => (
                  <article className="admin-evidence-card" key={detection.id}>
                    <a
                      className="admin-evidence-image"
                      href={`${API}${detection.screenshot_url}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      <img
                        src={`${API}${detection.screenshot_url}`}
                        crossOrigin="use-credentials"
                        alt={`Captured evidence for ${detection.url}`}
                      />
                    </a>
                    <div className="admin-evidence-info">
                      <span className={`admin-status ${detection.verdict === "phishing" ? "pending" : "verified"}`}>
                        {detection.verdict}
                      </span>
                      <strong>Risk {Number(detection.score).toFixed(2)}</strong>
                      <a href={detection.url} target="_blank" rel="noreferrer">
                        {detection.url}
                      </a>
                      <small>{formatDate(detection.created_at)} · #{detection.id}</small>
                      <details className="admin-evidence-details">
                        <summary>Analysis details</summary>
                        <pre>{JSON.stringify(detection.evidence, null, 2)}</pre>
                      </details>
                    </div>
                  </article>
                ))}
                {!detections.length && (
                  <div className="admin-empty-cell">No captured detection evidence yet.</div>
                )}
              </div>
            </section>

            <section className="panel admin-section">
              <div className="admin-section-heading">
                <div>
                  <div className="eyebrow">AUDIT TRAIL</div>
                  <h2>Recent account and feature activity</h2>
                </div>
                <span className="admin-count">{events.length} recent</span>
              </div>
              <div className="admin-event-list">
                {events.map((event) => (
                  <article className="admin-event-row" key={event.id}>
                    <span className="admin-event-marker" />
                    <div>
                      <strong>{formatFeature(event.event_type)}</strong>
                      <span>
                        {event.user_name
                          ? `${event.user_name} · ${event.user_email}`
                          : event.event_type === "page_view"
                            ? "Anonymous aggregate page view"
                            : "Unlinked event"}
                      </span>
                      {!!event.details.url && (
                        <a href={String(event.details.url)} target="_blank" rel="noreferrer">
                          {String(event.details.url)}
                        </a>
                      )}
                      {!!Object.keys(event.details).length && (
                        <details className="admin-evidence-details">
                          <summary>Event details</summary>
                          <pre>{JSON.stringify(event.details, null, 2)}</pre>
                        </details>
                      )}
                    </div>
                    <time>{formatDate(event.created_at)}</time>
                  </article>
                ))}
                {!events.length && (
                  <div className="admin-empty-cell">No recent activity recorded.</div>
                )}
              </div>
            </section>
          </>
        )}
      </div>
    </>
  );
}
