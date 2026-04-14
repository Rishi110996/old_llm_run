"""
behavior_clusterer.py
---------------------
Groups EvidenceItems into BehaviorClusters and builds cross-source
corroboration chains.  No LLM calls.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from evidence_schema import APKFacts, BehaviorCluster, EvidenceItem

# ---------------------------------------------------------------------------
# known behavior families (order matters only for display)
# ---------------------------------------------------------------------------

ALL_FAMILIES: List[str] = [
    "sms_abuse",
    "call_interception",
    "accessibility_abuse",
    "overlay_fraud",
    "c2_networking",
    "dynamic_code_loading",
    "privilege_escalation",
    "anti_analysis",
    "persistence",
    "data_exfiltration",
    "credential_theft",
    "ad_analytics_only",
    "normal_app_behavior",
]

# Families that only get an LLM review if the deterministic score is truly
# high — they produce too many false-positives otherwise.
ALWAYS_REVIEW_FAMILIES: Set[str] = {
    "sms_abuse",
    "call_interception",
    "dynamic_code_loading",
    "privilege_escalation",
    "credential_theft",
    "accessibility_abuse",
    "overlay_fraud",
}

# ---------------------------------------------------------------------------
# corroboration chain builder
# ---------------------------------------------------------------------------

# evidence kinds, ordered from highest-level (manifest) to lowest-level (yara)
_KIND_ORDER = [
    "permission",
    "basic_info",
    "component",
    "cert",
    "native_lib",
    "string",
    "class",
    "yara",
]


def _build_chains(items: List[EvidenceItem]) -> List[List[str]]:
    """
    Build corroboration chains for a list of evidence items.

    Strategy: group by distinct evidence *kind*.  A chain is a sequence of
    evidence item IDs where each step adds a different kind.
    The longest chain is the most valuable signal — it means multiple
    independent extraction methods all point at the same behavior.

    We return at most 3 chains (the longest distinct ones) to keep the
    downstream prompt concise.
    """
    by_kind: Dict[str, List[EvidenceItem]] = defaultdict(list)
    for item in items:
        by_kind[item.kind].append(item)

    # Build the single greedy max-length chain (one item per kind, ordered)
    max_chain: List[str] = []
    for kind in _KIND_ORDER:
        if kind in by_kind:
            # pick highest-strength item of this kind
            best = max(by_kind[kind], key=lambda x: x.strength)
            max_chain.append(best.id)

    if not max_chain:
        return []

    chains = [max_chain]

    # Second chain: pick the second-best item from any kind that has ≥ 2 items
    alt_chain: List[str] = []
    for kind in _KIND_ORDER:
        pool = by_kind.get(kind, [])
        if len(pool) >= 2:
            alt_chain.append(sorted(pool, key=lambda x: x.strength, reverse=True)[1].id)
        elif pool:
            alt_chain.append(pool[0].id)
    if alt_chain != max_chain and alt_chain:
        chains.append(alt_chain)

    return chains


# ---------------------------------------------------------------------------
# cluster builder
# ---------------------------------------------------------------------------

def _make_cluster(family: str, items: List[EvidenceItem]) -> BehaviorCluster:
    chains = _build_chains(items)
    max_len = max((len(c) for c in chains), default=0)
    malicious = sum(1 for i in items if i.direction == "malicious")
    benign = sum(1 for i in items if i.direction == "benign")
    ambiguous = sum(1 for i in items if i.direction == "ambiguous")
    return BehaviorCluster(
        family=family,
        evidence_items=items,
        corroboration_chains=chains,
        max_chain_length=max_len,
        malicious_item_count=malicious,
        benign_item_count=benign,
        ambiguous_item_count=ambiguous,
    )


def build_clusters(
    evidence_items: List[EvidenceItem],
    apk_facts: APKFacts,
) -> Dict[str, BehaviorCluster]:
    """
    Group evidence items into BehaviorClusters, one per active family.

    An item can belong to multiple clusters (its behavior_tags list may contain
    more than one family).

    After grouping, a synthetic `normal_app_behavior` cluster is added if no
    high-scoring malicious families are present — this gives the final LLM
    explicit "all-clear" context for clean apps.
    """
    # Step 1: distribute items to families
    family_items: Dict[str, List[EvidenceItem]] = defaultdict(list)
    for item in evidence_items:
        if not item.behavior_tags:
            # untagged but scored items go to anti_analysis as a catch-all
            if item.kind in ("native_lib", "cert"):
                family_items["anti_analysis"].append(item)
        else:
            for tag in item.behavior_tags:
                family_items[tag].append(item)

    # Step 2: detect ad/analytics-only pattern
    # If the only non-empty families are networking + analytics SDK strings,
    # and there are no malicious-direction items anywhere, label ad_analytics_only.
    all_malicious = [i for i in evidence_items if i.direction == "malicious"]
    all_benign_or_ambiguous = [i for i in evidence_items if i.direction != "malicious"]
    is_ad_only = (
        not all_malicious
        and len(all_benign_or_ambiguous) > 0
        and all(
            fam in ("c2_networking", "persistence", "anti_analysis")
            for fam in family_items
            if family_items[fam]
        )
    )
    if is_ad_only:
        family_items["ad_analytics_only"].extend(all_benign_or_ambiguous)

    # Step 3: build clusters for non-empty families
    clusters: Dict[str, BehaviorCluster] = {}
    for family in ALL_FAMILIES:
        items = family_items.get(family, [])
        if not items:
            continue
        clusters[family] = _make_cluster(family, items)

    # Step 4: add normal_app_behavior cluster if no strong malicious signal
    strong_malicious_families = [
        f for f, c in clusters.items()
        if c.malicious_item_count > 0 and f not in ("ad_analytics_only", "normal_app_behavior")
    ]
    if not strong_malicious_families:
        # Synthesize normal_app_behavior items from the permissions list so the
        # final LLM always has something to anchor a "clean" verdict to.
        synth_items = [
            i for i in evidence_items
            if i.direction == "benign" or (i.direction == "ambiguous" and i.strength < 0.40)
        ]
        if synth_items:
            clusters["normal_app_behavior"] = _make_cluster("normal_app_behavior", synth_items)
        elif not clusters:
            # APK has literally no evidence at all — still create an empty benign cluster
            clusters["normal_app_behavior"] = BehaviorCluster(
                family="normal_app_behavior",
                evidence_items=[],
                corroboration_chains=[],
                max_chain_length=0,
                malicious_item_count=0,
                benign_item_count=0,
                ambiguous_item_count=0,
            )

    return clusters
