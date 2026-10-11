from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx
from community import community_louvain


def cluster_sites(
    edges: list[tuple[str, str]],
) -> list[list[str]]:
    """
    Cluster infrastructure nodes using Louvain community detection.

    This produces graph communities, not proof of common ownership.
    """

    graph = nx.Graph()

    for source, target in edges:
        if not source or not target:
            continue

        source = str(source)
        target = str(target)

        if source == target:
            continue

        graph.add_edge(source, target)

    if graph.number_of_nodes() == 0:
        return []

    if graph.number_of_edges() == 0:
        return [[node] for node in graph.nodes]

    partition = community_louvain.best_partition(
        graph,
        random_state=42,
    )

    clusters: dict[int, list[str]] = defaultdict(list)

    for node, cluster_id in partition.items():
        clusters[cluster_id].append(node)

    result = [
        sorted(nodes)
        for nodes in clusters.values()
    ]

    result.sort(
        key=lambda nodes: (-len(nodes), nodes[0])
    )

    return result


def build_cluster_graph(
    nodes: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    """
    Convert the application's graph representation
    into Louvain-compatible edges.
    """

    valid_ids = {
        str(node.get("id"))
        for node in nodes
        if node.get("id")
    }

    edges: list[tuple[str, str]] = []

    for link in links:
        source = link.get("source")
        target = link.get("target")

        if isinstance(source, dict):
            source = source.get("id")

        if isinstance(target, dict):
            target = target.get("id")

        if not source or not target:
            continue

        source = str(source)
        target = str(target)

        if (
            source in valid_ids
            and target in valid_ids
            and source != target
        ):
            edges.append((source, target))

    return edges


def cluster_graph(
    nodes: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Cluster the infrastructure graph and produce
    explainable campaign evidence.

    IMPORTANT:
    The confidence value is a heuristic association score.
    It does NOT prove that infrastructure belongs to the
    same threat actor.
    """

    edges = build_cluster_graph(
        nodes=nodes,
        links=links,
    )

    clusters = cluster_sites(edges)

    node_lookup = {
        str(node.get("id")): node
        for node in nodes
        if node.get("id")
    }

    result: list[dict[str, Any]] = []

    for index, cluster_nodes in enumerate(
        clusters,
        start=1,
    ):
        members = [
            node_lookup[node_id]
            for node_id in cluster_nodes
            if node_id in node_lookup
        ]

        node_types = [
            str(member.get("type", "")).lower()
            for member in members
        ]

        type_set = set(node_types)

        evidence: list[str] = []

        # -----------------------------------------
        # Infrastructure evidence
        # -----------------------------------------

        if "domain" in type_set:
            evidence.append(
                "Domain infrastructure is present"
            )

        if "ip" in type_set:
            evidence.append(
                "IP infrastructure relationship is present"
            )

        if "cert" in type_set:
            evidence.append(
                "TLS certificate relationship is present"
            )

        if "asn" in type_set:
            evidence.append(
                "ASN/hosting relationship is present"
            )

        if "upi" in type_set:
            evidence.append(
                "Payment identity relationship is present"
            )

        if "kit" in type_set:
            evidence.append(
                "Shared kit/fingerprint relationship is present"
            )

        if "brand" in type_set:
            evidence.append(
                "Brand association is present"
            )

        # -----------------------------------------
        # Diversity score
        # -----------------------------------------
        #
        # Different infrastructure types provide
        # stronger evidence than a cluster containing
        # only one type of node.
        #
        diversity_score = min(
            len(type_set) / 5.0,
            1.0,
        )

        # -----------------------------------------
        # Cluster size score
        # -----------------------------------------

        size_score = min(
            len(cluster_nodes) / 8.0,
            1.0,
        )

        # -----------------------------------------
        # Internal relationship score
        # -----------------------------------------

        cluster_set = set(cluster_nodes)

        internal_edges = 0

        for source, target in edges:
            if (
                source in cluster_set
                and target in cluster_set
            ):
                internal_edges += 1

        possible_edges = max(
            len(cluster_nodes)
            * (len(cluster_nodes) - 1)
            / 2,
            1,
        )

        density_score = min(
            internal_edges / possible_edges,
            1.0,
        )

        # -----------------------------------------
        # Explainable campaign confidence
        # -----------------------------------------

        confidence = (
            (diversity_score * 0.50)
            + (size_score * 0.25)
            + (density_score * 0.25)
        )

        confidence = round(
            min(
                max(confidence, 0.0),
                1.0,
            ),
            2,
        )

        # -----------------------------------------
        # Confidence interpretation
        # -----------------------------------------

        if confidence >= 0.80:
            confidence_level = "high"
        elif confidence >= 0.60:
            confidence_level = "medium"
        else:
            confidence_level = "low"

        # -----------------------------------------
        # Result
        # -----------------------------------------

        result.append(
            {
                "cluster_id": f"CAMPAIGN-{index:04d}",
                "size": len(cluster_nodes),
                "nodes": cluster_nodes,
                "members": members,

                "confidence": confidence,
                "confidence_percent": round(
                    confidence * 100
                ),
                "confidence_level": confidence_level,

                "evidence": evidence,

                "node_types": sorted(
                    type_set
                ),

                "internal_relationships": (
                    internal_edges
                ),

                "metrics": {
                    "diversity_score": round(
                        diversity_score,
                        2,
                    ),
                    "size_score": round(
                        size_score,
                        2,
                    ),
                    "density_score": round(
                        density_score,
                        2,
                    ),
                },
            }
        )

    return result