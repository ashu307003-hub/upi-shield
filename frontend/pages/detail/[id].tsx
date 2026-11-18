import Link from "next/link";
import { useRouter } from "next/router";
import { useEffect, useMemo, useState } from "react";
import {
  connectionReasonLabel,
  verdictLabel,
} from "../../lib/presentation";

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
  return `${(Number(value ?? 0) * 100).toFixed(0)}%`;
}

function boolLabel(value: unknown) {
  return value ? "Yes" : "No";
}

function readableReason(reason: string) {
  const labels: Record<string, string> = {
    "Strong visual similarity to a known payment/financial brand":
      "This page looks a lot like a known payment or finance brand.",
    "Moderate visual similarity to a known payment/financial brand":
      "This page looks somewhat like a known payment or finance brand.",
    "Strong image embedding similarity detected":
      "Images on this page closely match a known example.",
    "Strong page layout similarity detected":
      "The page layout closely matches a known example.",
    "Brand text detected through OCR":
      "This page uses text from a known brand.",
    "Punycode hostname":
      "The website address uses characters that could make it look like another address.",
    "URL contains @":
      "The website address contains an unusual @ symbol.",
    "Multiple payment/security terms in URL":
      "The website address includes several payment or security words.",
    "Digit-heavy hostname":
      "The website address contains many numbers.",
    "Domain registered within 30 days":
      "This website was created recently.",
    "DNS resolution failed":
      "We couldn’t find the server for this website.",
    "Form submits data to an external origin":
      "A form on this page sends information to another website.",
    "Suspicious redirect behavior detected":
      "This page may send visitors to another website unexpectedly.",
    "Sensitive payment/authentication input detected":
      "This page asks for sensitive sign-in or payment details.",
    "Embedded iframe detected":
      "This page includes content from another website.",
    "External resources detected":
      "This page loads files from other websites.",
    "Visual resemblance was insufficient for confident brand attribution":
      "The page looks similar to a brand, but we couldn’t confirm which one.",
  };
  if (labels[reason]) return labels[reason];
  if (reason.startsWith("Threat-intelligence match detected")) {
    return "This website appears on a list of known risky websites.";
  }
  const keywordMatch = reason.match(/^(\d+) payment\/brand keywords detected$/);
  if (keywordMatch) {
    return `We found ${keywordMatch[1]} payment or brand-related words on this page.`;
  }
  return reason;
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
  const type =
    node.type ??
    node.properties?.type ??
    "Website details";
  const labels: Record<string, string> = {
    domain: "Website",
    ip: "Server address",
    cert: "Security certificate",
    certificate: "Security certificate",
    asn: "Hosting provider",
    upi: "Payment ID",
    brand: "Brand",
  };
  return labels[String(type).toLowerCase()] ?? String(type).replaceAll("_", " ");
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
            r.status === 404
              ? "We couldn’t find this website check."
              : "We couldn’t load this website check. Refresh the page and try again."
          );
        }

        return p;
      })
      .then(setD)
      .catch((e) =>
        setErr(
          e instanceof Error
            ? e.message
            : "We couldn’t load this website check. Please try again."
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
            WEBSITE CHECK DETAILS
          </div>

          <h1>
            Website check #{router.query.id}
          </h1>

          <p className="investigation-url">
            {d?.url ??
              "Loading website details…"}
          </p>
        </div>

        <div className="header-actions">
          <Link
            href="/"
            className="button"
          >
            ← Back to website checks
          </Link>

          {d && (
            <a
              className="button primary"
              href={`${API}/detections/${d.id}/report`}
              target="_blank"
              rel="noreferrer"
            >
              Download report
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
          Loading check details…
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
                CHECK RESULT
              </div>

              <div className="assessment-row">
                <div>
                  <div className="assessment-verdict">
                    {verdictLabel(d.verdict)}
                  </div>

                  <div className="assessment-subtitle">
                    Based on several checks of this website.
                  </div>
                </div>

                <div className="assessment-score">
                  <strong>
                    {riskPercent}%
                  </strong>

                  <span>
                    risk score
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
                <span title="A smaller number means the images are more alike.">IMAGE COMPARISON</span>

                <strong>
                  {String(
                    d.evidence
                      ?.phash_distance ??
                      "—"
                  )}
                </strong>
              </div>

              <div className="investigation-fact">
                <span>CHECKED</span>

                <strong>
                  {d.created_at
                    ? new Date(
                        d.created_at
                      ).toLocaleString()
                    : "—"}
                </strong>
              </div>

              <div className="investigation-fact">
                <span>CONNECTION TYPE</span>

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
                    WEBSITE SCREENSHOT
                  </div>

                  <h2>
                    Page we checked
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
                    alt="Website screenshot from this check"
                  />
                </div>
              ) : (
                <div className="capture-placeholder">
                  No screenshot was saved for this check.
                </div>
              )}
            </section>

            <section className="panel detail-card">
              <div className="section-heading">
                <div>
                  <div className="eyebrow">
                    PAGE APPEARANCE
                  </div>

                  <h2>
                    Does this look like a known brand?
                  </h2>
                </div>
              </div>

              <div className="visual-score-block">
                <div>
                  <span>
                    Overall visual match
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

              <p className="muted-note">
                These checks compare the page with known brand examples. A
                match is a clue, not proof.
              </p>

              <div className="signal">
                <span>
                  Image match
                </span>

                <strong>
                  {percent(
                    visual.embedding_similarity
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Known image match
                </span>

                <strong>
                  {percent(
                    visual.phash_similarity
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Layout match
                </span>

                <strong>
                  {percent(
                    visual.layout_similarity
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Brand text match
                </span>

                <strong>
                  {percent(
                    visual.ocr_brand_match
                  )}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Known examples used
                </span>

                <strong>
                  {visual.reference_count ??
                    0}
                </strong>
              </div>

              <div className="signal">
                <span>
                  Brand name found
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
                    TEXT FOUND ON PAGE
                  </div>

                  <div className="ocr-content">
                    {visual.ocr_text}
                  </div>
                </div>
              ) : (
                <div className="muted-note">
                  No readable text was found in the screenshot.
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
                  WHY THIS RESULT?
                </div>

                <h2>
                  What affected the result?
                </h2>
                <p className="section-description">
                  We look at the page, how it behaves, and its website
                  address. A risk score is a warning, not proof of a scam.
                </p>
              </div>

              <span className="evidence-chip">
                Page, behavior, and address checks
              </span>
            </div>

            <div className="signal-grid">
              <div className="signal-card">
                <div className="signal-card-header">
                  <span>
                    Page appearance
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
                    Page behavior
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
                    Website address
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
                    Overall risk
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
                    HOW THE PAGE BEHAVES
                  </div>

                  <h2>
                    Page behavior
                  </h2>
                </div>
              </div>

              <div className="behavior-grid">
                <div className="behavior-item">
                  <span>
                    Sends form details to another website
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
                    Sends visitors to another website unexpectedly
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
                    Requests for private information
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
                    Forms sent to other websites
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
                    Embedded pages
                  </span>

                  <strong>
                    {behavioral.iframe_count ??
                      0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Background code files
                  </span>

                  <strong>
                    {behavioral.script_count ??
                      0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Files loaded from other websites
                  </span>

                  <strong>
                    {behavioral.external_resources
                      ?.length ?? 0}
                  </strong>
                </div>

                <div className="behavior-item">
                  <span>
                    Payment or brand-related words
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
                    PRIVATE INFORMATION REQUESTS
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
                    WEBSITES THAT RECEIVE FORM DETAILS
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
                    REASONS FOR THIS RESULT
                  </div>

                  <h2>
                    What we noticed
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
                          {readableReason(reason)}
                        </p>
                      </div>
                    )
                  )}
                </div>
              ) : (
                <div className="empty">
                  No specific warning signs were recorded.
                </div>
              )}

              <div className="investigation-action">
                <a
                  className="button primary"
                  href={`${API}/detections/${d.id}/report`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Download report →
                </a>
              </div>
            </section>
          </div>

          {/* =====================================================
              WEBSITE ADDRESS DETAILS
          ====================================================== */}

          <section className="panel investigation-section">
            <div className="section-heading">
              <div>
                <div className="eyebrow">
                  WEBSITE DETAILS
                </div>

                <h2>
                  Details about this website
                </h2>
              </div>
            </div>

            <div className="intel-grid">
              <div className="intel-item">
                <span>
                  Website name
                </span>

                <strong>
                  {domainIntel.hostname ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Secure connection
                </span>

                <strong>
                  {lexical.uses_https ? "Yes" : "No"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Server addresses
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
                  Number of server addresses
                </span>

                <strong>
                  {dns.count ?? 0}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Website address length
                </span>

                <strong>
                  {lexical.url_length ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Website name length
                </span>

                <strong>
                  {lexical.hostname_length ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Extra address sections
                </span>

                <strong>
                  {lexical.subdomain_count ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Numbers in the address
                </span>

                <strong>
                  {lexical.digit_count ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Dashes in the address
                </span>

                <strong>
                  {lexical.hyphen_count ??
                    "—"}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Risky words found
                </span>

                <strong>
                  {lexical.suspicious_term_hits ??
                    0}
                </strong>
              </div>

              <div className="intel-item">
                <span>
                  Look-alike characters in address
                </span>

                <strong>
                  {lexical.has_punycode ? "Yes" : "No"}
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
                  RELATED WEBSITES
                </div>

                <h2>
                  Other sites with shared details
                </h2>

                <p className="section-description">
                  These links are estimates based on shared details. They do
                  not prove that the websites belong to the same person.
                </p>
              </div>

              <Link
                href="/graph"
                className="button"
              >
                See website connections →
              </Link>
            </div>

            {graphLoading ? (
              <div className="empty">
                Loading website connections…
              </div>
            ) : (
              <>
                <div className="infrastructure-summary">
                  <div className="infra-stat">
                    <span>
                      ITEMS IN MAP
                    </span>

                    <strong>
                      {graphNodes.length}
                    </strong>
                  </div>

                  <div className="infra-stat">
                    <span>
                      CONNECTIONS
                    </span>

                    <strong>
                      {graphLinks.length}
                    </strong>
                  </div>

                  <div className="infra-stat">
                    <span>
                      RELATED GROUPS
                    </span>

                    <strong>
                      {relatedCampaigns.length}
                    </strong>
                  </div>

                  <div className="infra-stat">
                    <span>
                      WEBSITE ADDRESS
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
                      RELATED ITEMS
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
                        Showing the first 12 related items.
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="muted-note">
                    No related item was found for{" "}
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
                                    Group {index + 1}
                                  </div>

                                  <div className="campaign-size">
                                    {campaign.size ??
                                      campaign
                                        .members
                                        ?.length ??
                                      0}{" "}
                                    connected items
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
                                    {campaign.confidence_level === "high"
                                      ? "Strong match"
                                      : campaign.confidence_level === "medium"
                                        ? "Possible match"
                                        : "Weak match"}
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
                                        {nodeDisplayType({ type })}
                                      </span>
                                    )
                                  )}
                                </div>
                              ) : null}

                              {campaign.evidence
                                ?.length ? (
                                <div className="campaign-evidence">
                                  <div className="eyebrow">
                                    WHY THESE ARE CONNECTED
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
                                            {connectionReasonLabel(evidence)}
                                          </span>
                                        </div>
                                      )
                                    )}
                                </div>
                              ) : null}

                              <div className="campaign-footer">
                                <span>
                                  Connections in this group:{" "}
                                  {campaign.internal_relationships ??
                                    0}
                                </span>

                                <Link
                                  href="/graph"
                                  className="stat-label"
                                >
                                  View connections →
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
                          No related group found
                        </strong>

                        <p>
                          We haven’t found enough shared details to connect
                          this website to a group yet. More checks may reveal
                          connections.
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </section>

          {/* =====================================================
              MORE TECHNICAL DETAILS
          ====================================================== */}

          <section className="panel investigation-section">
            <div className="section-heading">
              <div>
                <div className="eyebrow">
                  MORE TECHNICAL DETAILS
                </div>

                <h2>
                  Extra information for technical users
                </h2>
              </div>
            </div>

            <details className="raw-evidence">
              <summary>
                View page appearance data
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
                View website address data
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
                View page behavior data
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
                View connection map data
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