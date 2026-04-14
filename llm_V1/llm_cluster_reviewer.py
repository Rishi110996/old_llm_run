"""
llm_cluster_reviewer.py
-----------------------
Stage 4: context-aware LLM review of individual BehaviorClusters.

- All clusters flagged needs_llm_review=True are reviewed in parallel via
  concurrent.futures.ThreadPoolExecutor.
- Each prompt includes the full cross-source evidence bundle for that cluster:
  permissions, components, class source code, strings, YARA — all at once.
- Model: claude-4-sonnet for all calls (best available).
- Returns Dict[family, ClusterAssessment].
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from openai import OpenAI

from evidence_schema import APKFacts, BehaviorCluster, ClusterAssessment, EvidenceItem

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

REVIEW_MODEL = "claude-4-sonnet"
MAX_CLASS_SOURCE_PER_CLUSTER = 4_000    # bytes of decompiled source per class in prompt
MAX_STRINGS_PER_CLUSTER      = 30
MAX_WORKERS                  = 6        # parallel LLM calls

# One-line description shown to the LLM per family
FAMILY_DESCRIPTIONS: Dict[str, str] = {
    "sms_abuse":            "SMS interception, covert sending, or reading SMS inbox",
    "call_interception":    "Monitoring, recording, or redirecting phone calls",
    "accessibility_abuse":  "Misuse of AccessibilityService for gesture injection, keylogging, or overlay attacks",
    "overlay_fraud":        "Drawing windows over other apps (TYPE_PHONE/SYSTEM_OVERLAY) for credential phishing",
    "c2_networking":        "Communication with hardcoded command-and-control infrastructure",
    "dynamic_code_loading": "Loading and executing code at runtime via DexClassLoader, PathClassLoader, or reflection",
    "privilege_escalation": "Attempting to gain root/shell access via su, chmod, or Runtime.exec",
    "anti_analysis":        "Detecting emulators, debuggers, Xposed hooks; obfuscation to evade analysis",
    "persistence":          "Ensuring the app restarts automatically after reboot or update",
    "data_exfiltration":    "Copying contacts, SMS, location, credentials, or files to a remote server",
    "credential_theft":     "Stealing passwords via phishing overlays, custom keyboards, or keylogging",
    "ad_analytics_only":    "Only standard advertising and analytics SDKs — no suspicious behavior",
    "normal_app_behavior":  "Standard Android patterns consistent with a legitimate application",
}


# ---------------------------------------------------------------------------
# prompt builder
# ---------------------------------------------------------------------------

def _format_item(item: EvidenceItem, include_class_source: bool, classes: Dict[str, str]) -> str:
    parts = [
        f"  [{item.kind.upper()}] {item.value}",
        f"    direction={item.direction} | strength={item.strength:.2f} | source={item.source_location}",
        f"    reason: {item.explanation}",
        f"    benign note: {item.benign_alternatives}",
    ]
    # If this item is a class, append the decompiled source (truncated to budget)
    if item.kind == "class" and include_class_source:
        source = classes.get(item.value, "")
        if source:
            truncated = source[:MAX_CLASS_SOURCE_PER_CLUSTER]
            ellipsis = " [truncated]" if len(source) > MAX_CLASS_SOURCE_PER_CLUSTER else ""
            parts.append(f"    --- decompiled source{ellipsis} ---")
            parts.append(source[:MAX_CLASS_SOURCE_PER_CLUSTER])
            parts.append("    --- end source ---")
    return "\n".join(parts)


def build_cluster_prompt(
    cluster: BehaviorCluster,
    apk_facts: APKFacts,
    all_clusters: Dict[str, BehaviorCluster],
) -> List[Dict[str, str]]:
    """Build the messages list for one cluster review call."""

    family = cluster.family
    description = FAMILY_DESCRIPTIONS.get(family, family)
    bi = apk_facts.basic_info

    # -- Evidence section --
    evidence_lines: List[str] = []
    string_items = []
    other_items = []
    for item in cluster.evidence_items:
        if item.kind == "string":
            string_items.append(item)
        else:
            other_items.append(item)

    string_items.sort(key=lambda item: (item.strength, item.direction == "malicious"), reverse=True)

    for item in other_items:
        evidence_lines.append(_format_item(item, include_class_source=True, classes=apk_facts.classes))

    # Strings: cap count to keep prompt manageable
    for item in string_items[:MAX_STRINGS_PER_CLUSTER]:
        evidence_lines.append(_format_item(item, include_class_source=False, classes={}))
    if len(string_items) > MAX_STRINGS_PER_CLUSTER:
        evidence_lines.append(
            f"  [STRING] ... {len(string_items) - MAX_STRINGS_PER_CLUSTER} additional string items not shown"
        )

    # -- Cross-cluster signals --
    cross_lines: List[str] = []
    for other_family, other_cluster in all_clusters.items():
        if other_family == family:
            continue
        if other_cluster.preliminary_score >= 0.35:
            cross_lines.append(
                f"  {other_family}: score={other_cluster.preliminary_score:.2f} "
                f"(m={other_cluster.malicious_item_count}, "
                f"a={other_cluster.ambiguous_item_count}, "
                f"b={other_cluster.benign_item_count})"
            )

    # -- Chain summary --
    chain_summary = (
        f"Corroboration chain depth: {cluster.max_chain_length} "
        f"(distinct evidence kinds: {cluster.max_chain_length})"
    )

    user_content_parts = [
        f"BEHAVIOR FAMILY: {family}",
        f"DESCRIPTION: {description}",
        "",
        "APK IDENTITY:",
        f"  package:     {bi.get('package_name', 'unknown')}",
        f"  app_name:    {bi.get('app_name', 'unknown')}",
        f"  min_sdk:     {bi.get('min_sdk', '?')}  target_sdk: {bi.get('target_sdk', '?')}",
        "",
        "EVIDENCE FROM ALL SOURCES:",
    ]
    user_content_parts.extend(evidence_lines if evidence_lines else ["  (no evidence items)"])

    if cross_lines:
        user_content_parts += ["", "CROSS-CLUSTER SIGNALS (other active behaviors):"]
        user_content_parts.extend(cross_lines)

    user_content_parts += [
        "",
        chain_summary,
        f"PRELIMINARY DETERMINISTIC SCORE: {cluster.preliminary_score:.2f}",
        "",
        "INSTRUCTIONS:",
        "- Evaluate whether the evidence above represents legitimate, malicious, or ambiguous behavior.",
        "- Consider the benign_note for each item — do NOT mark as malicious if a clear legitimate explanation exists.",
        "- 'malicious' = clear evidence of intentional abuse with no plausible benign explanation.",
        "- 'ambiguous' = suspicious but could be legitimate depending on app purpose.",
        "- 'benign' = all evidence has clear legitimate explanations.",
        "",
        "Return ONLY valid JSON, no markdown, no extra text:",
        json.dumps({
            "verdict":    "malicious|benign|ambiguous",
            "confidence": "0.0-1.0",
            "reasoning":  "2-3 sentences citing specific evidence items",
            "iocs":       ["list of concrete IOCs: domains, IPs, class names, strings"],
            "notes":      "optional: anything the final reviewer should know",
        }, indent=2),
    ]

    system_msg = (
        "You are an expert Android malware analyst. "
        "Evaluate ONE behavior family with the provided evidence. "
        "Default to benign unless the evidence unambiguously demonstrates malicious intent. "
        "Return only valid JSON matching the specified schema."
    )

    return [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": "\n".join(user_content_parts)},
    ]


# ---------------------------------------------------------------------------
# single-cluster review
# ---------------------------------------------------------------------------

def _review_one(
    cluster: BehaviorCluster,
    apk_facts: APKFacts,
    all_clusters: Dict[str, BehaviorCluster],
    call_llm_fn,
    logger: logging.Logger,
) -> ClusterAssessment:
    messages = build_cluster_prompt(cluster, apk_facts, all_clusters)
    try:
        result = call_llm_fn(messages, REVIEW_MODEL, logger)
    except Exception as exc:
        logger.warning("[cluster_review] %s failed: %s — using deterministic fallback", cluster.family, exc)
        result = None

    if not isinstance(result, dict):
        # Fallback: derive a minimal assessment from the deterministic score
        score = cluster.preliminary_score
        if score >= 0.70:
            verdict, confidence = "malicious", round(score, 2)
        elif score >= 0.40:
            verdict, confidence = "ambiguous", round(score, 2)
        else:
            verdict, confidence = "benign", round(1.0 - score, 2)
        return ClusterAssessment(
            family=cluster.family,
            verdict=verdict,
            confidence=confidence,
            reasoning="LLM unavailable; verdict derived from deterministic pre-score.",
            iocs=[],
            skipped=True,
        )

    verdict     = str(result.get("verdict", "ambiguous")).lower()
    confidence  = float(result.get("confidence", 0.5))
    reasoning   = str(result.get("reasoning", ""))
    iocs        = [str(x) for x in result.get("iocs", []) if str(x).strip()][:50]
    notes       = str(result.get("notes", ""))

    if verdict not in ("malicious", "benign", "ambiguous"):
        verdict = "ambiguous"

    return ClusterAssessment(
        family=cluster.family,
        verdict=verdict,
        confidence=min(1.0, max(0.0, confidence)),
        reasoning=reasoning,
        iocs=iocs,
        notes=notes,
        skipped=False,
    )


# ---------------------------------------------------------------------------
# parallel review of all flagged clusters
# ---------------------------------------------------------------------------

def review_clusters(
    clusters: Dict[str, BehaviorCluster],
    apk_facts: APKFacts,
    call_llm_fn,
    logger: logging.Logger,
) -> Dict[str, ClusterAssessment]:
    """
    Reviews all clusters where needs_llm_review=True in parallel.
    Clusters that don't need review get a deterministic ClusterAssessment
    (skipped=True) without any LLM call.

    call_llm_fn must have signature:
      call_llm_fn(messages: List[Dict], model: str, logger) -> Any
    """
    assessments: Dict[str, ClusterAssessment] = {}
    to_review = {f: c for f, c in clusters.items() if c.needs_llm_review}
    skip_direct = {f: c for f, c in clusters.items() if not c.needs_llm_review}

    # --- clusters that don't need LLM review ---
    for family, cluster in skip_direct.items():
        score = cluster.preliminary_score
        if family == "normal_app_behavior":
            verdict, confidence = "benign", 0.95
        elif family == "ad_analytics_only":
            verdict, confidence = "benign", 0.90
        elif score >= 0.60:
            verdict, confidence = "malicious", round(score, 2)
        elif score >= 0.30:
            verdict, confidence = "ambiguous", round(score, 2)
        else:
            verdict, confidence = "benign", round(max(0.5, 1.0 - score), 2)
        assessments[family] = ClusterAssessment(
            family=family,
            verdict=verdict,
            confidence=confidence,
            reasoning=f"Below LLM-review threshold (score={score:.2f}); deterministic verdict.",
            iocs=[],
            skipped=True,
        )

    if not to_review:
        return assessments

    logger.info("[cluster_review] Reviewing %d cluster(s) in parallel: %s",
                len(to_review), list(to_review.keys()))

    # --- parallel LLM reviews ---
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(to_review))) as pool:
        future_to_family = {
            pool.submit(
                _review_one, cluster, apk_facts, clusters, call_llm_fn, logger
            ): family
            for family, cluster in to_review.items()
        }
        for future in as_completed(future_to_family):
            family = future_to_family[future]
            try:
                assessments[family] = future.result()
                logger.info("[cluster_review] %s → %s (conf=%.2f)",
                            family,
                            assessments[family].verdict,
                            assessments[family].confidence)
            except Exception as exc:
                logger.error("[cluster_review] %s raised unexpected error: %s", family, exc)
                assessments[family] = ClusterAssessment(
                    family=family,
                    verdict="ambiguous",
                    confidence=0.5,
                    reasoning=f"Review failed with error: {exc}",
                    iocs=[],
                    skipped=True,
                )

    return assessments
