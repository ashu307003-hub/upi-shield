import Head from "next/head";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useAuth } from "./_app";
import { verdictLabel } from "../lib/presentation";

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
  const labels: Record<string, string> = {
    email_verified: "Email confirmed",
    login: "Signed in",
    logout: "Signed out",
    page_view: "Viewed a page",
  };
  const label = labels[value] ?? value.replaceAll("_", " ");
  return label.charAt(0).toUpperCase() + label.slice(1);
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
          "We couldn’t load the admin information. Refresh the page and try again."
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
        <div className="eyebrow">ADMIN AREA</div>
        <h1>You can’t open this page</h1>
        <p>
          This page is only available to approved admin accounts. Contact the
          person who manages your account if you need access.
        </p>
        <Link href="/" className="button primary">Back to website checks</Link>
      </section>
    );
  }

  return (
    <>
      <Head>
        <title>Admin tools · UPI Shield</title>
      </Head>
      <div className="admin-page">
        <header className="page-header">
          <div>
            <div className="eyebrow">ADMIN AREA</div>
            <h1>Admin tools</h1>
            <p>See account totals, sign-ins, website checks, and recent activity.</p>
          </div>
          <div className="admin-retention-badge">
            <span className="status-dot" />
            Activity is saved for {overview?.activity_retention_days ?? 180} days
          </div>
        </header>

        {error && <div className="login-error" role="alert">{error}</div>}
        {loading && <div className="panel admin-loading">Loading account and website activity…</div>}

        {!loading && overview && (
          <>
            <section className="admin-metrics-grid" aria-label="Account and activity totals">
              <article className="admin-metric">
                <span className="admin-metric-icon">◎</span>
                <span className="admin-metric-label">ACCOUNTS</span>
                <strong>{overview.accounts.total}</strong>
                <small>{overview.accounts.verified} email confirmed · {overview.accounts.pending_email_confirmation} waiting for confirmation</small>
              </article>
              <article className="admin-metric">
                <span className="admin-metric-icon">↗</span>
                <span className="admin-metric-label">PAGES VIEWED</span>
                <strong>{overview.visits.page_views_in_retention_window}</strong>
                <small>{overview.visits.page_views_last_30_days} in the last 30 days · counts only</small>
              </article>
              <article className="admin-metric">
                <span className="admin-metric-icon">⌁</span>
                <span className="admin-metric-label">SIGN-INS</span>
                <strong>{overview.logins_in_retention_window}</strong>
                <small>During the period activity is saved</small>
              </article>
              <article className="admin-metric">
                <span className="admin-metric-icon">◈</span>
                <span className="admin-metric-label">WEBSITE CHECKS</span>
                <strong>{overview.detections_stored}</strong>
                <small>Saved results and screenshots</small>
              </article>
            </section>

            <section className="admin-columns">
              <article className="panel admin-section">
                <div className="admin-section-heading">
                  <div>
                    <div className="eyebrow">PEOPLE</div>
                    <h2>Accounts</h2>
                  </div>
                  <span className="admin-count">{users.length} shown</span>
                </div>
                <div className="admin-table-wrap">
                  <table className="admin-table">
                    <thead>
                      <tr>
                        <th>Name and email</th>
                        <th>Phone</th>
                        <th>Email status</th>
                        <th>Sign-ins</th>
                        <th>Last sign-in</th>
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
                              {user.email_verified ? "Confirmed" : "Not confirmed"}
                            </span>
                          </td>
                          <td>{user.login_count}</td>
                          <td>{formatDate(user.last_login_at)}</td>
                        </tr>
                      ))}
                      {!users.length && (
                        <tr>                        <td colSpan={5} className="admin-empty-cell">No accounts yet.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </article>

              <article className="panel admin-section">
                <div className="admin-section-heading">
                  <div>
                    <div className="eyebrow">SITE ACTIVITY</div>
                    <h2>Pages people visited</h2>
                  </div>
                  <span className="admin-count">180 days</span>
                </div>
                <p className="admin-privacy-note">
                  We count page visits only. We do not identify visitors or save their IP addresses here.
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
                  <div className="eyebrow">TOOLS USED</div>
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
                    <div className="eyebrow">SAVED RESULTS</div>
                    <h2>Recent website checks</h2>
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
                        alt={`Website screenshot for ${detection.url}`}
                      />
                    </a>
                    <div className="admin-evidence-info">
                      <span className={`admin-status ${detection.verdict === "phishing" ? "pending" : "verified"}`}>
                        {verdictLabel(detection.verdict)}
                      </span>
                      <strong>Risk score: {(Number(detection.score) * 100).toFixed(0)}%</strong>
                      <a href={detection.url} target="_blank" rel="noreferrer">
                        {detection.url}
                      </a>
                      <small>{formatDate(detection.created_at)} · #{detection.id}</small>
                      <details className="admin-evidence-details">
                        <summary>More check details</summary>
                        <pre>{JSON.stringify(detection.evidence, null, 2)}</pre>
                      </details>
                    </div>
                  </article>
                ))}
                {!detections.length && (
                  <div className="admin-empty-cell">No website check screenshots yet.</div>
                )}
              </div>
            </section>

            <section className="panel admin-section">
              <div className="admin-section-heading">
                <div>
                  <div className="eyebrow">RECENT ACTIVITY</div>
                  <h2>Recent account and tool activity</h2>
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
                            ? "Page visit (counts only)"
                              : "Activity not linked to an account"}
                      </span>
                      {!!event.details.url && (
                        <a href={String(event.details.url)} target="_blank" rel="noreferrer">
                          {String(event.details.url)}
                        </a>
                      )}
                      {!!Object.keys(event.details).length && (
                        <details className="admin-evidence-details">
                          <summary>More activity details</summary>
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
