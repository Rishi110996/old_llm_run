"""
evidence_schema.py
------------------
Dataclasses that form the backbone of the v2 pipeline.
Nothing here depends on any other local module.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_evidence_id(kind: str, value: str, source_location: str) -> str:
    """16-char hex ID — deterministic, collision-resistant enough for a single APK's evidence set."""
    raw = f"{kind}::{value}::{source_location}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# core evidence unit
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    """
    One normalized piece of evidence extracted from an APK.
    direction and strength are set by deterministic rule tables, never by the LLM.
    """
    id: str
    kind: str               # permission | basic_info | string | class | component | native_lib | yara | cert
    value: str              # the raw extracted value
    source_location: str    # "permissions" | "component:ClassName" | "class:ClassName" | "yara" | …
    direction: str          # "malicious" | "benign" | "ambiguous"
    strength: float         # 0.0 – 1.0
    behavior_tags: List[str]       # behavior family names this evidence supports
    explanation: str               # one-line reason this is relevant
    benign_alternatives: str       # legitimate reason an app might legitimately have this
    api_score: float = 0.0         # for class items: Phase-1 API-call sensitivity score


# ---------------------------------------------------------------------------
# cluster of corroborated evidence
# ---------------------------------------------------------------------------

@dataclass
class BehaviorCluster:
    """
    All evidence items grouped under one behavior family, with cross-source
    corroboration chains.

    max_chain_length = count of distinct evidence *kinds* present → number of
    independent sources that all point at the same behavior.
    e.g. permission + component + class + string → max_chain_length = 4
    """
    family: str
    evidence_items: List[EvidenceItem]
    corroboration_chains: List[List[str]]   # each chain = ordered list of evidence IDs
    max_chain_length: int
    malicious_item_count: int
    benign_item_count: int
    ambiguous_item_count: int
    preliminary_score: float = 0.0          # set by cluster_scorer
    needs_llm_review: bool = False          # set by cluster_scorer


# ---------------------------------------------------------------------------
# LLM verdict for a single cluster
# ---------------------------------------------------------------------------

@dataclass
class ClusterAssessment:
    """Output of the per-cluster LLM review (Stage 4)."""
    family: str
    verdict: str            # "malicious" | "benign" | "ambiguous"
    confidence: float       # 0.0 – 1.0
    reasoning: str
    iocs: List[str]
    notes: str = ""
    skipped: bool = False   # True when below LLM-review threshold; deterministic score used


# ---------------------------------------------------------------------------
# all raw facts from one APK (Stage 0 output)
# ---------------------------------------------------------------------------

@dataclass
class APKFacts:
    """
    Everything deterministically extracted from one APK before any LLM call.
    strings is a dict {class_name: [str, …]} so the normalizer can emit
    EvidenceItems with the correct source_location.
    """
    apk_path: str
    basic_info: Dict[str, Any]
    permissions: List[str]
    components: Dict[str, Any]              # activities/services/receivers/providers + intent filters
    certificates: List[Dict[str, Any]]
    native_libs: List[str]
    strings: Dict[str, List[str]]           # class_name → strings found in that class
    classes: Dict[str, str]                 # class_name → decompiled source (budget-selected)
    class_api_scores: Dict[str, float]      # class_name → Phase-1 sensitivity score
    class_behavior_tags: Dict[str, List[str]]  # class_name → behavior family tags
    yara_matches: List[Dict[str, Any]]
