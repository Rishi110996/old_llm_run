"""
cluster_scorer.py
-----------------
Deterministic scoring of BehaviorClusters.  No LLM calls.

Formula per cluster:
  base    = Sum(item.strength x direction_weight) / item_count
  corr    = 1.0 + 0.15 x max_chain_length     (corroboration bonus)
  benign  = benign_item_count x 0.10           (benign discount)
  score   = clamp(base x corr - benign, 0, 1)

App-level pre-score:
  Sum(cluster_score x FAMILY_WEIGHT[family]) clamped to [0, 100]
  Benign-only families contribute negative weight.
"""
from __future__ import annotations

from typing import Dict, Tuple

from evidence_schema import BehaviorCluster

# ---------------------------------------------------------------------------
# direction weights: how much a single item contributes to the family score
# ---------------------------------------------------------------------------

_DIR_WEIGHT: Dict[str, float] = {
    "malicious": 1.00,
    "ambiguous": 0.40,
    "benign":   -0.50,  # benign items actively reduce the score
}

# ---------------------------------------------------------------------------
# severity weight per family: used for the app-level aggregation
# ---------------------------------------------------------------------------

FAMILY_SEVERITY: Dict[str, float] = {
    "privilege_escalation":   0.95,
    "dynamic_code_loading":   0.90,
    "credential_theft":       0.90,
    "sms_abuse":              0.88,
    "call_interception":      0.78,
    "overlay_fraud":          0.80,
    "accessibility_abuse":    0.75,
    "data_exfiltration":      0.80,
    "c2_networking":          0.70,
    "anti_analysis":          0.60,
    "persistence":            0.40,
    "ad_analytics_only":      0.00,   # never contributes to risk
    "normal_app_behavior":   -0.20,   # actively lowers risk score
}

# Clusters that always request LLM review when score >= HIGH_IMPACT_THRESHOLD
HIGH_IMPACT_FAMILIES = {
    "sms_abuse", "dynamic_code_loading", "privilege_escalation",
    "credential_theft", "accessibility_abuse", "overlay_fraud", "call_interception",
}
# Score thresholds for LLM review
LLM_REVIEW_THRESHOLD     = 0.50   # any family at this score -> review
LOW_PRIORITY_THRESHOLD   = 0.30   # high-impact families at this score -> review


def score_cluster(cluster: BehaviorCluster) -> Tuple[float, bool]:
    """
    Returns (cluster_score: float 0..1, needs_llm_review: bool).
    """
    items = cluster.evidence_items
    if not items:
        return 0.0, False

    raw = sum(
        i.strength * _DIR_WEIGHT.get(i.direction, 0.40)
        for i in items
    ) / len(items)

    corr_bonus  = 1.0 + 0.15 * cluster.max_chain_length
    benign_disc = cluster.benign_item_count * 0.10

    score = max(0.0, min(1.0, raw * corr_bonus - benign_disc))

    # LLM review decision
    needs_review = False
    if cluster.family in ("ad_analytics_only", "normal_app_behavior"):
        needs_review = False
    elif score >= LLM_REVIEW_THRESHOLD:
        needs_review = True
    elif score >= LOW_PRIORITY_THRESHOLD and cluster.family in HIGH_IMPACT_FAMILIES:
        needs_review = True

    return round(score, 4), needs_review


def score_all_clusters(
    clusters: Dict[str, BehaviorCluster],
) -> Tuple[Dict[str, BehaviorCluster], int]:
    """
    Mutates each cluster in-place with preliminary_score and needs_llm_review.
    Returns the updated clusters dict and the integer app pre-score (0-100).
    """
    weighted_sum = 0.0
    weight_total = 0.0

    for family, cluster in clusters.items():
        score, needs_review = score_cluster(cluster)
        cluster.preliminary_score = score
        cluster.needs_llm_review  = needs_review

        w = abs(FAMILY_SEVERITY.get(family, 0.30))
        weighted_sum += score * FAMILY_SEVERITY.get(family, 0.30) * 100
        weight_total += w

    if weight_total == 0:
        app_pre_score = 5
    else:
        raw_app = weighted_sum / weight_total
        app_pre_score = max(0, min(100, int(round(raw_app))))

    return clusters, app_pre_score
