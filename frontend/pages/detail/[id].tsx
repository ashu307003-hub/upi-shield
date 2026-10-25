import Link from "next/link";
import { useRouter } from "next/router";
import { useEffect, useMemo, useState } from "react";

const API =
  process.env.NEXT_PUBLIC_API_URL ??
  "http://localhost:8000";

type Detection = {
  id: number;
  url: string;
  brand?: string;
  score: number;
  verdict: string;
  behavioral: Record<string, any>;
  evidence: Record<string, any>;
  screenshot: string;
  dom: string;
  created_at?: string;
};

type GraphNode = {
  id?: string | number;
  element_id?: string;
  type?: string;
  label?: string;
  name?: string;
  properties?: Record<string, any>;
};

type GraphLink = {
  source?: string | number;
  target?: string | number;
  type?: string;
  label?: string;
};

type Campaign = {
  cluster_id?: string;
  size?: number;
  confidence?: number;
  confidence_percent?: number;
  confidence_level?: string;
  evidence?: string[];
  node_types?: string[];
  internal_relationships?: number;
  members?: any[];
  nodes?: any[];
};

function percent(value: unknown) {
  const n = Number(value ?? 0);

  return `${(n * 100).toFixed(1)}%`;
}

function score(value: unknown) {
  return Number(value ?? 0).toFixed(2);
}

function boolLabel(value: unknown) {
  return value ? "Detected" : "None";
}

function riskClass(verdict: string) {
  if (verdict === "phishing") {
    return "risk-critical";
  }

  if (verdict === "suspicious") {
    return "risk-warning";
  }

  return "risk-safe";
}

function signalWidth(value: unknown) {
  const n = Math.max(
    0,
    Math.min(100, Number(value ?? 0) * 100)
  );

  return `${n}%`;
}

function normalizeText(value: unknown) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function nodeDisplayName(node: GraphNode) {
  return (
    node.name ??
    node.label ??
    node.properties?.name ??
    node.properties?.domain ??
    node.properties?.value ??
    node.element_id ??
    node.id ??
    "Unknown"
  );
}

function nodeDisplayType(node: GraphNode) {
  return (
    node.type ??
    node.properties?.type ??
    "Infrastructure"
  );
}

function campaignContainsHostname(
  campaign: Campaign,
  hostname: string
) {
  const target = normalizeText(hostname);

  if (!target) {
    return false;
  }

  const values: string[] = [];

  const collect = (value: any) => {
    if (value == null) {
      return;
    }

    if (
      typeof value === "string" ||
      typeof value === "number"
    ) {
      values.push(String(value));
      return;
    }

    if (Array.isArray(value)) {
      value.forEach(collect);
      return;
    }

    if (typeof value === "object") {
      Object.entries(value).forEach(
        ([key, child]) => {
          if (
            [
              "domain",
              "hostname",
              "name",
              "label",
              "value",
              "url",
              "target",
              "source",
            ].includes(key.toLowerCase())
          ) {
            collect(child);
          } else if (
            typeof child === "object"
          ) {
            collect(child);
          }
        }
      );
    }
  };

  collect(campaign.members);
  collect(campaign.nodes);
  collect(campaign.evidence);

  return values.some((value) =>
    normalizeText(value).includes(target)
  );
}

export default function Detail() {
  const router = useRouter();

  const [d, setD] =
    useState<Detection | null>(null);

  const [err, setErr] = useState("");

  const [graphNodes, setGraphNodes] =
    useState<GraphNode[]>([]);

  const [graphLinks, setGraphLinks] =
    useState<GraphLink[]>([]);

  const [campaigns, setCampaigns] =
    useState<Campaign[]>([]);

  const [graphLoading, setGraphLoading] =
    useState(false);

  async function loadGraphIntelligence() {
    setGraphLoading(true);

    try {
      const [graphResponse, campaignResponse] =
        await Promise.all([
          fetch(`${API}/graph`, {
            credentials: "include",
          }),
          fetch(`${API}/graph/clusters`, {
            credentials: "include",
          }),
        ]);

      if (graphResponse.ok) {
        const graph =
          await graphResponse.json();

        setGraphNodes(
          Array.isArray(graph.nodes)
            ? graph.nodes
            : []
        );

        setGraphLinks(
          Array.isArray(graph.links)
            ? graph.links
            : []
        );
      } else {
        setGraphNodes([]);
        setGraphLinks([]);
      }

      if (campaignResponse.ok) {
        const campaignData =
          await campaignResponse.json();

        setCampaigns(
          Array.isArray(
            campaignData.clusters
          )
            ? campaignData.clusters
            : []
        );
      } else {
        setCampaigns([]);
      }
    } catch {
      setGraphNodes([]);
      setGraphLinks([]);
      setCampaigns([]);
    } finally {
      setGraphLoading(false);
    }
  }

  useEffect(() => {
    if (!router.query.id) {
      return;
    }

    loadGraphIntelligence();

    fetch(
      `${API}/detections/${router.query.id}`,
      {
        credentials: "include",
      }
    )
      .then(async (r) => {
        const p = await r.json();

        if (!r.ok) {
          throw Error(
            p.detail ??
              "Failed to load detection"
          );
        }

        return p;
      })
      .then(setD)
      .catch((e) =>
        setErr(
          e instanceof Error
            ? e.message
            : "Failed to load detection"
        )
      );
  }, [router.query.id]);

  const shot = d?.screenshot
    ?.split(/[\\/]/)
    .pop();

  const visual =
    d?.evidence?.visual ?? {};

  const components =
    d?.evidence?.components ?? {};

  const domainIntel =
    d?.evidence?.domain_intel ?? {};

  const lexical =
    domainIntel?.lexical ?? {};

  const dns =
    domainIntel?.dns ?? {};

  const behavioral =
    d?.behavioral ?? {};

  const reasons =
    d?.evidence?.reasons ?? [];

  const riskPercent = d
    ? Math.round(Number(d.score) * 100)
    : 0;

  const riskStyle = useMemo(() => {
    if (!d) {
      return {};
    }

    return {
      width: `${Math.max(
        0,
        Math.min(100, riskPercent)
      )}%`,
    };
  }, [d, riskPercent]);

  const hostname =
    normalizeText(
      domainIntel?.hostname
    ) ||
    (() => {
      try {
        return normalizeText(
          new URL(d?.url ?? "").hostname
        );
      } catch {
        return "";
      }
    })();

  const relatedGraphNodes = useMemo(() => {
    if (!hostname) {
      return [];
    }

    const directMatches =
      graphNodes.filter((node) => {
        const name = normalizeText(
          nodeDisplayName(node)
        );

        const domain =
          normalizeText(
            node.properties?.domain
          );

        const nodeHostname =
          normalizeText(
            node.properties?.hostname
          );

        return (
          name === hostname ||
          domain === hostname ||
          nodeHostname === hostname
        );
      });

    if (directMatches.length) {
      const ids = new Set<string>();

      directMatches.forEach((node) => {
        if (node.id != null) {
          ids.add(String(node.id));
        }

        if (node.element_id) {
          ids.add(node.element_id);
        }
      });

      const relatedIds = new Set(ids);

      graphLinks.forEach((link) => {
        const source =
          link.source != null
            ? String(link.source)
            : "";

        const target =
          link.target != null
            ? String(link.target)
            : "";

        if (ids.has(source)) {
          relatedIds.add(target);
        }

        if (ids.has(target)) {
          relatedIds.add(source);
        }
      });

      return graphNodes.filter((node) => {
        const id =
          node.id != null
            ? String(node.id)
            : "";

        const elementId =
          node.element_id ?? "";

        return (
          relatedIds.has(id) ||
          relatedIds.has(elementId)
        );
      });
    }

    return [];
  }, [
    graphNodes,
    graphLinks,
    hostname,
  ]);

  const relatedCampaigns = useMemo(() => {
    if (!hostname) {
      return [];
    }

    return campaigns.filter(
      (campaign) =>
        campaignContainsHostname(
          campaign,
          hostname
        )
    );
  }, [campaigns, hostname]);

  return (
    <>
      {/* =====================================================
          HEADER
      ====================================================== */}

      <header className="page-header">
        <div>
          <div className="eyebrow">
            INVESTIGATION / EVIDENCE
          </div>

          <h1>
            Detection #{router.query.id}
          </h1>

          <p className="investigation-url">
            {d?.url ??
              "Loading observation…"}
          </p>
        </div>

        <div className="header-actions">
          <Link
            href="/"
            className="button"
          >
            ← Back to queue
          </Link>

          {d && (
            <a
              className="button primary"
              href={`${API}/detections/${d.id}/report`}
              target="_blank"
              rel="noreferrer"
            >
              Generate evidence report
            </a>
          )}
        </div>
      </header>

      {err ? (
        <div className="error-box">
          {err}
        </div>
      ) : !d ? (
        <div className="empty">
          Loading investigation evidence…
        </div>
      ) : (
        <>
          {/* =====================================================
              INVESTIGATION SUMMARY
          ====================================================== */}

          <section className="investigation-summary">
            <div
              className={`investigation-verdict ${riskClass(
                d.verdict
              )}`}
            >
              <div className="eyebrow">
                FINAL ASSESSMENT
              </div>

              <div className="assessment-row">
                <div>
                  <div className="assessment-verdict">
                    {d.verdict.toUpperCase()}
                  </div>

                  <div className="assessment-subtitle">
                    Multi-signal detection assessment
                  </div>
                </div>

                <div className="assessment-score">
                  <strong>
                    {d.score.toFixed(2)}
                  </strong>

                  <span>
                    {riskPercent}% risk
                  </span>
                </div>
              </div>

              <div className="risk-track">
                <span
                  style={riskStyle}
                />
              </div>
            </div>

            <div className="investigation-facts">
              <div className="investigation-fact">
                <span>BRAND</span>

                <strong>
                  {d.brand ??
                    "Unidentified"}
                </strong>
              </div>

              <div className="investigation-fact">
                <span>PHASH DISTANCE</span>

                <strong>
                  {String(
                    d.evidence
                      ?.phash_distance ??
                      "—"
                  )}
                </strong>
              </div>

              <div className="investigation-fact">
                <span>OBSERVED</span>

                <strong>
                  {d.created_at
                    ? new Date(
                        d.created_at
                      ).toLocaleString()
                    : "—"}
                </strong>
              </div>

              <div className="investigation-fact">
                <span>SCHEME</span>

                <strong>
                  {domainIntel?.scheme ??
                    "—"}
                </strong>
              </div>
            </div>
          </section>

          {/* =====================================================
              SCREENSHOT + VISUAL ENGINE
          ====================================================== */}

          <div className="detail-grid investigation-main-grid">
            <section className="panel detail-card evidence-image-card">
              <div className="section-heading">
                <div>
                  <div className="eyebrow">
                    CAPTURED EVIDENCE
                  </div>

                  <h2>
                    Rendered page
                  </h2>
                </div>

                <span className="evidence-chip">
                  Screenshot
                </span>
              </div>

              {shot ? (
                <div className="screenshot-frame">
                  <img
                    src={`${API}/artifacts/${shot}`}
                    crossOrigin="use-credentials"
                    alt="Captured website evidence"
                  />
                </div>
              ) : (
                <div className="capture-placeholder">
                  No screenshot available
                </div>
              )}
            </section>

            <section className="panel detail-card">
              <div className="section-heading">
                <div>
                  <div className="eyebrow">
                    VISUAL INTELLIGENCE
                  </div>

                  <h2>
                    Similarity analysis
                  </h2>
                </div>
              </div>

              <div className="visual-score-block">
                <div>
                  <span>
                    Combined similarity
                  </span>

                  <strong>
                    {percent(
                      visual.visual_similarity ??
                        components.visual_similarity
                    )}
                  </strong>
                </div>

                <div className="signal-progress large">
                  <span
                    style={{
                      width: signalWidth(
                        visual.visual_similarity ??
                          components.visual_similarity
                      ),
                    }}
                  />
                </div>
              </div>

              <div className="signal">
                <span>
                  Image embedding
                </span>

                <strong>
                  {percent(
                    visual.embedding_similarity
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  pHash similarity
                </span>

                <strong>
                  {percent(
                    visual.phash_similarity
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Layout similarity
                </span>

                <strong>
                  {percent(
                    visual.layout_similarity
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  OCR brand match
                </span>

                <strong>
                  {percent(
                    visual.ocr_brand_match
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Reference images
                </span>

                <strong>
                  {visual.reference_count ??
                    0}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Detected brand
                </span>

                <strong>
                  {visual.brand ??
                    d.brand ??
                    "Unidentified"}
                </strong>
              </div>

              {visual.ocr_text ? (
                <div className="ocr-box">
                  <div className="eyebrow">
                    OCR OUTPUT
                  </div>

                  <div className="ocr-content">
                    {visual.ocr_text}
                  </div>
                </div>
              ) : (
                <div className="muted-note">
                  No OCR text extracted from
                  the captured page.
                </div>
              )}
            </section>
          </div>

          {/* =====================================================
              RISK SIGNALS
          ====================================================== */}

          <section className="panel investigation-section">
            <div className="section-heading">
              <div>
                <div className="eyebrow">
                  RISK ENGINE
                </div>

                <h2>
                  Signal contribution
                </h2>
              </div>

              <span className="evidence-chip">
                Explainable scoring
              </span>
            </div>

            <div className="signal-grid">
              <div className="signal-card">
                <div className="signal-card-header">
                  <span>
                    Visual similarity
                  </span>

                  <strong>
                    {score(
                      components.visual_similarity
                    )}
                  </strong>
                </div>

                <div className="signal-progress">
                  <span
                    style={{
                      width: signalWidth(
                        components.visual_similarity
                      ),
                    }}
                  />
                </div>
              </div>

              <div className="signal-card">
                <div className="signal-card-header">
                  <span>
                    Behavioral score
                  </span>

                  <strong>
                    {score(
                      components.behavioral_score
                    )}
                  </strong>
                </div>

                <div className="signal-progress">
                  <span
                    style={{
                      width: signalWidth(
                        components.behavioral_score
                      ),
                    }}
                  />
                </div>
              </div>

              <div className="signal-card">
                <div className="signal-card-header">
                  <span>
                    Domain score
                  </span>

                  <strong>
                    {score(
                      components.domain_score
                    )}
                  </strong>
                </div>

                <div className="signal-progress">
                  <span
                    style={{
                      width: signalWidth(
                        components.domain_score
                      ),
                    }}
                  />
                </div>
              </div>

              <div className="signal-card">
                <div className="signal-card-header">
                  <span>
                    Final risk
                  </span>

                  <strong>
                    {d.score.toFixed(2)}
                  </strong>
                </div>

                <div className="signal-progress">
                  <span
                    style={riskStyle}
                  />
                </div>
              </div>
            </div>
          </section>

          {/* =====================================================
              BEHAVIORAL + REASONS
          ====================================================== */}

          <div className="detail-grid">
            <section className="panel detail-card">
              <div className="section-heading">
                <div>
                  <div className="eyebrow">
                    BEHAVIORAL ANALYSIS
                  </div>

                  <h2>
                    Page behavior
                  </h2>
                </div>
              </div>

              <div className="behavior-grid">
                <div className="behavior-item">
                  <span>
                    External form action
                  </span>

                  <strong
                    className={
                      behavioral.external_form_action
                        ? "indicator-danger"
                        : "indicator-safe"
                    }
                  >
                    {boolLabel(
                      behavioral.external_form_action
                    )}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Suspicious redirect
                  </span>

                  <strong
                    className={
                      behavioral.suspicious_redirect
                        ? "indicator-danger"
                        : "indicator-safe"
                    }
                  >
                    {boolLabel(
                      behavioral.suspicious_redirect
                    )}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Sensitive inputs
                  </span>

                  <strong
                    className={
                      behavioral.sensitive_inputs
                        ?.length
                        ? "indicator-danger"
                        : "indicator-safe"
                    }
                  >
                    {behavioral
                      .sensitive_inputs
                      ?.length ?? 0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    External form posts
                  </span>

                  <strong
                    className={
                      behavioral.external_form_posts
                        ?.length
                        ? "indicator-danger"
                        : "indicator-safe"
                    }
                  >
                    {behavioral
                      .external_form_posts
                      ?.length ?? 0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Iframes
                  </span>

                  <strong>
                    {behavioral.iframe_count ??
                      0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Scripts
                  </span>

                  <strong>
                    {behavioral.script_count ??
                      0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    External resources
                  </span>

                  <strong>
                    {behavioral.external_resources
                      ?.length ?? 0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Brand keywords
                  </span>

                  <strong>
                    {behavioral.brand_keyword_count ??
                      0}
                  </strong>
                </div>
              </div>

              {behavioral.sensitive_inputs
                ?.length ? (
                <div className="indicator-list">
                  <div className="eyebrow">
                    SENSITIVE INPUTS
                  </div>

                  {behavioral.sensitive_inputs.map(
                    (
                      item: string,
                      index: number
                    ) => (
                      <div
                        className="indicator-row danger"
                        key={index}
                      >
                        {item}
                      </div>
                    )
                  )}
                </div>
              ) : null}

              {behavioral.external_form_posts
                ?.length ? (
                <div className="indicator-list">
                  <div className="eyebrow">
                    EXTERNAL FORM DESTINATIONS
                  </div>

                  {behavioral.external_form_posts.map(
                    (
                      item: string,
                      index: number
                    ) => (
                      <div
                        className="indicator-row"
                        key={index}
                      >
                        {item}
                      </div>
                    )
                  )}
                </div>
              ) : null}
            </section>

            <section className="panel detail-card">
              <div className="section-heading">
                <div>
                  <div className="eyebrow">
                    DETECTION EXPLANATION
                  </div>

                  <h2>
                    Why this was flagged
                  </h2>
                </div>
              </div>

              {reasons.length ? (
                <div className="reason-list">
                  {reasons.map(
                    (
                      reason: string,
                      index: number
                    ) => (
                      <div
                        className="reason-item"
                        key={index}
                      >
                        <span>
                          {index + 1}
                        </span>

                        <p>
                          {reason}
                        </p>
                      </div>
                    )
                  )}
                </div>
              ) : (
                <div className="empty">
                  No detection reasons
                  recorded.
                </div>
              )}

              <div className="investigation-action">
                <a
                  className="button primary"
                  href={`${API}/detections/${d.id}/report`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Generate evidence report →
                </a>
              </div>
            </section>
          </div>

          {/* =====================================================
              DOMAIN INTELLIGENCE
          ====================================================== */}

          <section className="panel investigation-section">
            <div className="section-heading">
              <div>
                <div className="eyebrow">
                  DOMAIN INTELLIGENCE
                </div>

                <h2>
                  Infrastructure indicators
                </h2>
              </div>
            </div>

            <div className="intel-grid">
              <div className="intel-item">
                <span>
                  Hostname
                </span>

                <strong>
                  {domainIntel.hostname ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Scheme
                </span>

                <strong>
                  {domainIntel.scheme ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  DNS addresses
                </span>

                <strong>
                  {dns.addresses?.length
                    ? dns.addresses.join(
                        ", "
                      )
                    : "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  DNS count
                </span>

                <strong>
                  {dns.count ?? 0}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  HTTPS
                </span>

                <strong>
                  {lexical.uses_https
                    ? "Yes"
                    : "No"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  URL length
                </span>

                <strong>
                  {lexical.url_length ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Hostname length
                </span>

                <strong>
                  {lexical.hostname_length ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Subdomain count
                </span>

                <strong>
                  {lexical.subdomain_count ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Digit count
                </span>

                <strong>
                  {lexical.digit_count ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Hyphen count
                </span>

                <strong>
                  {lexical.hyphen_count ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Suspicious term hits
                </span>

                <strong>
                  {lexical.suspicious_term_hits ??
                    0}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Punycode
                </span>

                <strong>
                  {lexical.has_punycode
                    ? "Detected"
                    : "None"}
                </strong>
              </div>
            </div>
          </section>

          {/* =====================================================
              INFRASTRUCTURE + CAMPAIGN INTELLIGENCE
          ====================================================== */}

          <section className="panel investigation-section">
            <div className="section-heading">
              <div>
                <div className="eyebrow">
                  INFRASTRUCTURE INTELLIGENCE
                </div>

                <h2>
                  Campaign relationships
                </h2>

                <p className="section-description">
                  Related infrastructure is derived
                  from the current graph snapshot.
                  Linkage confidence is heuristic and
                  does not prove common ownership.
                </p>
              </div>

              <Link
                href="/graph"
                className="button"
              >
                Open campaign graph →
              </Link>
            </div>

            {graphLoading ? (
              <div className="empty">
                Loading infrastructure
                relationships…
              </div>
            ) : (
              <>
                <div className="infrastructure-summary">
                  <div className="infra-stat">
                    <span>
                      GRAPH NODES
                    </span>

                    <strong>
                      {graphNodes.length}
                    </strong>
                  </div>

                  <div className="infra-stat">
                    <span>
                      RELATIONSHIPS
                    </span>

                    <strong>
                      {graphLinks.length}
                    </strong>
                  </div>

                  <div className="infra-stat">
                    <span>
                      RELATED CAMPAIGNS
                    </span>

                    <strong>
                      {relatedCampaigns.length}
                    </strong>
                  </div>

                  <div className="infra-stat">
                    <span>
                      CURRENT HOST
                    </span>

                    <strong>
                      {hostname ||
                        "Unknown"}
                    </strong>
                  </div>
                </div>

                {relatedGraphNodes.length >
                0 ? (
                  <div className="related-infrastructure">
                    <div className="eyebrow">
                      RELATED INFRASTRUCTURE
                    </div>

                    <div className="infrastructure-node-grid">
                      {relatedGraphNodes
                        .slice(0, 12)
                        .map(
                          (
                            node,
                            index
                          ) => (
                            <div
                              className="infrastructure-node"
                              key={
                                node.element_id ??
                                node.id ??
                                index
                              }
                            >
                              <span>
                                {nodeDisplayType(
                                  node
                                )}
                              </span>

                              <strong>
                                {nodeDisplayName(
                                  node
                                )}
                              </strong>
                            </div>
                          )
                        )}
                    </div>

                    {relatedGraphNodes.length >
                      12 && (
                      <div className="muted-note">
                        Showing the first 12
                        related infrastructure
                        nodes.
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="muted-note">
                    No direct infrastructure node
                    was matched to hostname{" "}
                    <strong>
                      {hostname ||
                        "unknown"}
                    </strong>{" "}
                    in the current graph snapshot.
                  </div>
                )}

                <div className="campaign-list">
                  {relatedCampaigns.length >
                  0 ? (
                    relatedCampaigns
                      .slice(0, 5)
                      .map(
                        (
                          campaign,
                          index
                        ) => {
                          const confidence =
                            Math.min(
                              100,
                              Math.max(
                                0,
                                Number(
                                  campaign.confidence_percent ??
                                    Number(
                                      campaign.confidence ??
                                        0
                                    ) *
                                      100
                                )
                              )
                            );

                          return (
                            <div
                              className="campaign-card"
                              key={
                                campaign.cluster_id ??
                                index
                              }
                            >
                              <div className="campaign-header">
                                <div>
                                  <div className="campaign-id">
                                    {campaign.cluster_id ??
                                      `CAMPAIGN-${String(
                                        index +
                                          1
                                      ).padStart(
                                        4,
                                        "0"
                                      )}`}
                                  </div>

                                  <div className="campaign-size">
                                    {campaign.size ??
                                      campaign
                                        .members
                                        ?.length ??
                                      0}{" "}
                                    infrastructure
                                    nodes
                                  </div>
                                </div>

                                <div className="campaign-confidence">
                                  <strong>
                                    {confidence.toFixed(
                                      0
                                    )}
                                    %
                                  </strong>

                                  <span>
                                    {campaign.confidence_level ??
                                      "unknown"}{" "}
                                    confidence
                                  </span>
                                </div>
                              </div>

                              <div className="campaign-progress">
                                <span
                                  style={{
                                    width: `${confidence}%`,
                                  }}
                                />
                              </div>

                              {campaign.node_types
                                ?.length ? (
                                <div className="campaign-types">
                                  {campaign.node_types.map(
                                    (
                                      type
                                    ) => (
                                      <span
                                        key={
                                          type
                                        }
                                        className="evidence-chip"
                                      >
                                        {type}
                                      </span>
                                    )
                                  )}
                                </div>
                              ) : null}

                              {campaign.evidence
                                ?.length ? (
                                <div className="campaign-evidence">
                                  <div className="eyebrow">
                                    LINKAGE EVIDENCE
                                  </div>

                                  {campaign.evidence
                                    .slice(
                                      0,
                                      6
                                    )
                                    .map(
                                      (
                                        evidence,
                                        evidenceIndex
                                      ) => (
                                        <div
                                          className="campaign-evidence-row"
                                          key={
                                            evidenceIndex
                                          }
                                        >
                                          <span>
                                            •
                                          </span>

                                          <span>
                                            {
                                              evidence
                                            }
                                          </span>
                                        </div>
                                      )
                                    )}
                                </div>
                              ) : null}

                              <div className="campaign-footer">
                                <span>
                                  Internal
                                  relationships:{" "}
                                  {campaign.internal_relationships ??
                                    0}
                                </span>

                                <Link
                                  href="/graph"
                                  className="stat-label"
                                >
                                  Investigate
                                  campaign →
                                </Link>
                              </div>
                            </div>
                          );
                        }
                      )
                  ) : (
                    <div className="campaign-empty">
                      <div className="campaign-empty-icon">
                        ◎
                      </div>

                      <div>
                        <strong>
                          No linked campaign
                        </strong>

                        <p>
                          This observation is not
                          currently associated with
                          a campaign cluster. More
                          infrastructure observations
                          may create a stronger
                          relationship over time.
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </section>

          {/* =====================================================
              RAW EVIDENCE
          ====================================================== */}

          <section className="panel investigation-section">
            <div className="section-heading">
              <div>
                <div className="eyebrow">
                  RAW EVIDENCE
                </div>

                <h2>
                  Machine-readable evidence
                </h2>
              </div>
            </div>

            <details className="raw-evidence">
              <summary>
                View visual engine output
              </summary>

              <pre>
                {JSON.stringify(
                  visual,
                  null,
                  2
                )}
              </pre>
            </details>

            <details className="raw-evidence">
              <summary>
                View domain intelligence
              </summary>

              <pre>
                {JSON.stringify(
                  domainIntel,
                  null,
                  2
                )}
              </pre>
            </details>

            <details className="raw-evidence">
              <summary>
                View behavioral telemetry
              </summary>

              <pre>
                {JSON.stringify(
                  behavioral,
                  null,
                  2
                )}
              </pre>
            </details>

            <details className="raw-evidence">
              <summary>
                View graph relationship snapshot
              </summary>

              <pre>
                {JSON.stringify(
                  {
                    hostname,
                    related_nodes:
                      relatedGraphNodes,
                    related_campaigns:
                      relatedCampaigns,
                  },
                  null,
                  2
                )}
              </pre>
            </details>
          </section>
        </>
      )}
    </>
  );
}