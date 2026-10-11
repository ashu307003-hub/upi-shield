import Link from "next/link";
import { Fragment, useEffect, useRef, useState } from "react";
import * as d3 from "d3";

const API =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Node = d3.SimulationNodeDatum & {
  id: string;
  label?: string;
  type: string;
};

type GraphLink = {
  source: string;
  target: string;
  relation?: string;
};

type Cluster = {
  cluster_id: string;
  size: number;
  nodes: string[];
  members: Node[];

  confidence: number;
  confidence_percent: number;
  confidence_level: string;

  evidence: string[];
  node_types: string[];
  internal_relationships: number;

  metrics: {
    diversity_score: number;
    size_score: number;
    density_score: number;
  };
};

type GraphResponse = {
  nodes: Node[];
  links: GraphLink[];
};

type ClusterResponse = {
  clusters: Cluster[];
  total_clusters: number;
  total_nodes: number;
  total_links: number;
};

export default function Graph() {
  const ref = useRef<SVGSVGElement>(null);

  const zoomRef =
    useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(
      null
    );

  const [graph, setGraph] = useState<GraphResponse>({
    nodes: [],
    links: [],
  });

  const [clusters, setClusters] = useState<Cluster[]>([]);

  const [selectedCluster, setSelectedCluster] =
    useState<string | null>(null);

  const [loadingClusters, setLoadingClusters] =
    useState(true);

  /*
   * Load infrastructure graph + campaign clusters.
   */
  useEffect(() => {
    Promise.all([
      fetch(`${API}/graph`).then((response) =>
        response.json()
      ),

      fetch(`${API}/graph/clusters`).then((response) =>
        response.json()
      ),
    ])
      .then(
        ([graphData, clusterData]: [
          GraphResponse,
          ClusterResponse
        ]) => {
          setGraph(graphData);
          setClusters(clusterData.clusters ?? []);
        }
      )
      .catch(() => {
        setGraph({
          nodes: [],
          links: [],
        });

        setClusters([]);
      })
      .finally(() => {
        setLoadingClusters(false);
      });
  }, []);

  /*
   * Draw the D3 infrastructure graph.
   */
  useEffect(() => {
    if (!ref.current) return;

    const svg = d3.select(ref.current);

    svg.selectAll("*").remove();

    const root = svg.append("g");

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.25, 5])
      .on("zoom", (event) => {
        root.attr(
          "transform",
          event.transform
        );
      });

    svg.call(zoom);

    zoomRef.current = zoom;

    const sourceNodes = graph.nodes.length
      ? graph.nodes
      : [
          {
            id: "No observations yet",
            type: "Info",
          } as Node,
        ];

    const nodes = sourceNodes.map((node) => ({
      ...node,
    }));

    const links = graph.links.map((link) => ({
      ...link,
    }));

    /*
     * Determine which nodes belong to the
     * selected campaign.
     */
    const selectedNodes = new Set(
      selectedCluster
        ? clusters.find(
            (cluster) =>
              cluster.cluster_id ===
              selectedCluster
          )?.nodes ?? []
        : []
    );

    const sim = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink<Node, GraphLink>(links)
          .id((node) => node.id)
          .distance(130)
      )
      .force(
        "charge",
        d3
          .forceManyBody()
          .strength(-260)
      )
      .force(
        "center",
        d3.forceCenter(390, 240)
      );

    /*
     * Relationship lines.
     */
    const lines = root
      .selectAll<
        SVGLineElement,
        GraphLink
      >("line")
      .data(links)
      .join("line")
      .attr("stroke", (link) => {
        if (!selectedCluster) {
          return "#94cba4";
        }

        const source =
          typeof link.source === "string"
            ? link.source
            : (link.source as Node).id;

        const target =
          typeof link.target === "string"
            ? link.target
            : (link.target as Node).id;

        return selectedNodes.has(source) &&
          selectedNodes.has(target)
          ? "#168d49"
          : "#d8e5dc";
      })
      .attr("stroke-width", (link) => {
        if (!selectedCluster) {
          return 2;
        }

        const source =
          typeof link.source === "string"
            ? link.source
            : (link.source as Node).id;

        const target =
          typeof link.target === "string"
            ? link.target
            : (link.target as Node).id;

        return selectedNodes.has(source) &&
          selectedNodes.has(target)
          ? 3
          : 1;
      });

    /*
     * Node groups.
     */
    const groups = root
      .selectAll<
        SVGGElement,
        Node
      >("g.node")
      .data(nodes)
      .join("g")
      .attr("class", "node");

    /*
     * Node circles.
     */
    groups
      .append("circle")
      .attr("r", (node) =>
        node.type === "Domain"
          ? 17
          : 12
      )
      .attr("fill", (node) => {
        if (!selectedCluster) {
          return node.type === "Domain"
            ? "#168d49"
            : "#a6d9b2";
        }

        return selectedNodes.has(node.id)
          ? "#168d49"
          : "#d8e5dc";
      })
      .attr("stroke", (node) =>
        selectedNodes.has(node.id)
          ? "#0b6b36"
          : "#4b9f63"
      )
      .attr("stroke-width", (node) =>
        selectedNodes.has(node.id)
          ? 3
          : 1
      );

    /*
     * Node labels.
     */
    groups
      .append("text")
      .attr("y", 28)
      .attr("text-anchor", "middle")
      .attr("font-size", 10)
      .attr("fill", (node) => {
        if (!selectedCluster) {
          return "#426951";
        }

        return selectedNodes.has(node.id)
          ? "#245c39"
          : "#9aa9a0";
      })
      .text(
        (node) =>
          node.label ?? node.id
      );

    /*
     * Drag support.
     */
    groups.call(
      d3
        .drag<SVGGElement, Node>()
        .on(
          "start",
          (event, node) => {
            if (!event.active) {
              sim
                .alphaTarget(0.2)
                .restart();
            }

            node.fx = node.x;
            node.fy = node.y;
          }
        )
        .on(
          "drag",
          (event, node) => {
            node.fx = event.x;
            node.fy = event.y;
          }
        )
        .on(
          "end",
          (event, node) => {
            if (!event.active) {
              sim.alphaTarget(0);
            }

            node.fx = null;
            node.fy = null;
          }
        ) as any
    );

    /*
     * Simulation updates.
     */
    sim.on("tick", () => {
      lines
        .attr(
          "x1",
          (link: any) =>
            link.source.x
        )
        .attr(
          "y1",
          (link: any) =>
            link.source.y
        )
        .attr(
          "x2",
          (link: any) =>
            link.target.x
        )
        .attr(
          "y2",
          (link: any) =>
            link.target.y
        );

      groups.attr(
        "transform",
        (node) =>
          `translate(${node.x},${node.y})`
      );
    });

    return () => {
      sim.stop();
    };
  }, [
    graph,
    clusters,
    selectedCluster,
  ]);

  /*
   * Zoom controls.
   */
  const zoomBy = (factor: number) => {
    if (
      ref.current &&
      zoomRef.current
    ) {
      d3
        .select(ref.current)
        .transition()
        .call(
          zoomRef.current.scaleBy,
          factor
        );
    }
  };

  /*
   * Select / deselect a campaign.
   */
  const toggleCluster = (
    clusterId: string
  ) => {
    setSelectedCluster(
      (current) =>
        current === clusterId
          ? null
          : clusterId
    );
  };

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            NETWORK INTELLIGENCE / NEO4J
          </div>

          <h1>Campaign graph</h1>

          <p>
            Domains, brands, IPs,
            certificates and payment
            identities can be connected
            as observations accumulate.
          </p>
        </div>

        <Link
          href="/"
          className="button"
        >
          ← Back to triage
        </Link>
      </header>

      {/* Campaign summary */}
      <section
        className="panel"
        style={{
          marginBottom: 16,
        }}
      >
        <div className="toolbar">
          <div>
            <h2>
              Campaign clusters
            </h2>

            <p
              style={{
                marginTop: 4,
                marginBottom: 0,
                color: "#66756c",
              }}
            >
              Graph-based infrastructure
              communities detected from
              the current observations.
            </p>
          </div>

          <div
            style={{
              display: "flex",
              gap: 18,
              alignItems: "center",
            }}
          >
            <strong>
              {clusters.length} campaign
              {clusters.length === 1
                ? ""
                : "s"}
            </strong>

            <span>
              {graph.nodes.length} nodes
            </span>

            <span>
              {graph.links.length}{" "}
              relationships
            </span>
          </div>
        </div>

        {loadingClusters ? (
          <div className="graph-help">
            Loading campaign
            clusters…
          </div>
        ) : clusters.length === 0 ? (
          <div className="graph-help">
            No campaign clusters are
            available yet.
          </div>
        ) : (
          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
              marginTop: 16,
            }}
          >
            {clusters.map((cluster) => {
              const active =
                selectedCluster ===
                cluster.cluster_id;

              return (
                <Fragment
                  key={cluster.cluster_id}
                >
                  <button
                    className="button"
                    onClick={() =>
                      toggleCluster(
                        cluster.cluster_id
                      )
                    }
                    style={{
                      border: active
                        ? "2px solid #168d49"
                        : undefined,
                      background: active
                        ? "#e8f6ed"
                        : undefined,
                    }}
                  >
                    {cluster.cluster_id}
                    {" · "}
                    {cluster.size} nodes
                  </button>

                  {active && (
                    <div
                      style={{
                        width: "100%",
                        marginTop: 12,
                        padding: 16,
                        border:
                          "1px solid #d8e8dd",
                        borderRadius: 10,
                        background:
                          "#f8fcf9",
                      }}
                    >
                      {/* Confidence header */}
                      <div
                        style={{
                          display: "flex",
                          justifyContent:
                            "space-between",
                          alignItems: "center",
                          marginBottom: 12,
                        }}
                      >
                        <div>
                          <strong>
                            Campaign confidence
                          </strong>

                          <div
                            style={{
                              marginTop: 4,
                              fontSize: 24,
                              fontWeight: 700,
                              color:
                                "#168d49",
                            }}
                          >
                            {
                              cluster.confidence_percent
                            }
                            %
                          </div>
                        </div>

                        <span
                          style={{
                            padding:
                              "5px 10px",
                            borderRadius:
                              999,
                            background:
                              "#e8f6ed",
                            color:
                              "#168d49",
                            fontSize: 12,
                            fontWeight: 600,
                            textTransform:
                              "uppercase",
                          }}
                        >
                          {
                            cluster.confidence_level
                          }
                        </span>
                      </div>

                      {/* Evidence */}
                      <div
                        style={{
                          fontSize: 13,
                          fontWeight: 600,
                          marginBottom: 8,
                        }}
                      >
                        Campaign evidence
                      </div>

                      <div
                        style={{
                          display: "grid",
                          gap: 6,
                        }}
                      >
                        {cluster.evidence.map(
                          (item) => (
                            <div
                              key={item}
                              style={{
                                fontSize: 13,
                                color:
                                  "#426951",
                              }}
                            >
                              ✓ {item}
                            </div>
                          )
                        )}
                      </div>

                      {/* Cluster statistics */}
                      <div
                        style={{
                          marginTop: 14,
                          paddingTop: 12,
                          borderTop:
                            "1px solid #d8e8dd",
                          display: "flex",
                          gap: 20,
                          flexWrap: "wrap",
                          fontSize: 12,
                          color:
                            "#66756c",
                        }}
                      >
                        <span>
                          Nodes:{" "}
                          <strong>
                            {cluster.size}
                          </strong>
                        </span>

                        <span>
                          Internal
                          relationships:{" "}
                          <strong>
                            {
                              cluster.internal_relationships
                            }
                          </strong>
                        </span>

                        <span>
                          Infrastructure
                          types:{" "}
                          <strong>
                            {
                              cluster
                                .node_types
                                .length
                            }
                          </strong>
                        </span>
                      </div>
                    </div>
                  )}
                </Fragment>
              );
            })}

            {selectedCluster && (
              <button
                className="button"
                onClick={() =>
                  setSelectedCluster(
                    null
                  )
                }
              >
                Clear selection
              </button>
            )}
          </div>
        )}
      </section>

      {/* Existing infrastructure graph */}
      <section className="panel graph-panel">
        <div className="toolbar">
          <div>
            <h2>
              Infrastructure
              relationship map
            </h2>

            {selectedCluster && (
              <p
                style={{
                  marginTop: 4,
                  color: "#168d49",
                }}
              >
                Highlighting{" "}
                {selectedCluster}
              </p>
            )}
          </div>

          <div className="graph-actions">
            <button
              className="button"
              onClick={() =>
                zoomBy(1.3)
              }
            >
              +
            </button>

            <button
              className="button"
              onClick={() =>
                zoomBy(0.75)
              }
            >
              −
            </button>

            <button
              className="button"
              onClick={() => {
                if (
                  ref.current &&
                  zoomRef.current
                ) {
                  d3
                    .select(ref.current)
                    .transition()
                    .call(
                      zoomRef.current
                        .transform,
                      d3.zoomIdentity
                    );
                }
              }}
            >
              Reset
            </button>
          </div>
        </div>

        <svg
          ref={ref}
          viewBox="0 0 780 480"
          role="img"
          aria-label="Infrastructure graph"
        />

        <div className="graph-help">
          Drag nodes and use +/− to zoom.
          Select a campaign above to
          highlight its infrastructure
          cluster.
        </div>
      </section>
    </>
  );
}