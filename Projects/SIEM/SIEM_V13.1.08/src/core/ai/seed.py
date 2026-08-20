"""Seed a ready-to-use ticket-triage model from the bundled SOC corpus.

A fresh install has active tickets but no AI history, so the AI container looks empty. This
records the curated SOC training corpus (100+ cases grounded in documented TTPs, see
core/ai/datasets/soc_cases) into provenance, each case tagged with its domain source
(dataset:windows_v1 and friends, so each source stays under the influence cap and is
rollback-able), trains the deterministic classifier, and opts ticket_triage in at auto_triage
so auto-inference can propose. Nothing about the safety model changes: the labels are capped,
provenance-tagged sources, the classifier stays deterministic, and every action still passes
the autonomy and RBAC gates.
"""
from __future__ import annotations

from typing import List, Tuple

from core.ai.triage import CATEGORY_TICKET_TRIAGE
from core.ai import autonomy as autonomy_mod
from core.ai.datasets import soc_cases
from core.ai.features import extract_ticket_features


def build_seed_dataset() -> List[Tuple[List[str], str]]:
    """The SOC corpus as (feature_tokens, label), using the same extractor the live pipeline
    uses so training and inference see identical features."""
    return [(extract_ticket_features(case), case["label"]) for case in soc_cases.load_cases()]


def seed_triage_model(triage, autonomy, actor: str = "seed:demo",
                      ceiling: int = autonomy_mod.AUTO_TRIAGE):
    """Record the SOC corpus (once per source), train ticket_triage, and opt the category in.
    Idempotent: sources already present are not re-recorded. Returns the active model version
    (or None if training could not run)."""
    prov = triage.provenance
    present = set(prov.source_counts(CATEGORY_TICKET_TRIAGE))
    for source, cases in soc_cases.by_source().items():
        if source in present:
            continue
        for case in cases:
            prov.record(CATEGORY_TICKET_TRIAGE, extract_ticket_features(case),
                        case["label"], actor=actor, source=source)
    version = triage.train_category(CATEGORY_TICKET_TRIAGE)
    autonomy.set_ceiling(CATEGORY_TICKET_TRIAGE, ceiling, actor)
    return version
