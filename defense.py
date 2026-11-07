#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""defense.py -- Task 2: Prompt-Guard-86M input defense middleware.

Inspects user input and external text channels separately using Prompt-Guard-86M.
Flags requests where injection or jailbreak probability exceeds the threshold.
Supports --mock mode for offline testing and rapid pipeline validation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any

# Fast mirror endpoint for HF downloads in China
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")

# Pinned immutable model revisions for reproducible evaluation
MODEL_REVISIONS: dict[str, str] = {
    "BlackHillsInformationSecurity/Prompt-Guard-86M": "fda434384101d6d611ce90bce46cc3329265a15c",
    "meta-llama/Prompt-Guard-86M": "1209add6ca7d9c1d815171b8e5571587fe3e7b03",
}

DEFAULT_MODEL_ID = os.environ.get("DEFENSE_MODEL", "BlackHillsInformationSecurity/Prompt-Guard-86M")
DEFAULT_REVISION = os.environ.get(
    "DEFENSE_REVISION",
    MODEL_REVISIONS.get(DEFAULT_MODEL_ID, "fda434384101d6d611ce90bce46cc3329265a15c")
)
META_MODEL_ID = "meta-llama/Prompt-Guard-86M"
DEFAULT_THRESHOLD = float(os.environ.get("DEFENSE_THRESHOLD", "0.5"))
HF_TOKEN = os.environ.get("HF_TOKEN", "")

_PIPELINE = None
_ACTIVE_BACKEND = "uninitialized"


def _load_pipeline(
    model_id: str = DEFAULT_MODEL_ID,
    revision: str | None = None,
    token: str | None = None,
) -> Any:
    global _PIPELINE, _ACTIVE_BACKEND

    if _PIPELINE is not None:
        return _PIPELINE

    token = token or HF_TOKEN or None

    try:
        from transformers import pipeline
    except ImportError:
        _ACTIVE_BACKEND = "heuristic_fallback (transformers not installed)"
        return None

    candidates = [model_id]
    if model_id != DEFAULT_MODEL_ID:
        candidates.append(DEFAULT_MODEL_ID)
    if model_id != META_MODEL_ID:
        candidates.append(META_MODEL_ID)

    for mid in candidates:
        try:
            target_rev = revision if mid == model_id else MODEL_REVISIONS.get(mid)
            kwargs: dict[str, Any] = {
                "top_k": None,
                "truncation": True,
                "max_length": 512,
            }
            if target_rev:
                kwargs["revision"] = target_rev
            if token and mid == META_MODEL_ID:
                kwargs["token"] = token
            pipe = pipeline("text-classification", model=mid, **kwargs)
            _PIPELINE = pipe
            _ACTIVE_BACKEND = f"huggingface ({mid}@{target_rev or 'head'})"
            return _PIPELINE
        except Exception:
            continue

    _ACTIVE_BACKEND = "heuristic_fallback"
    return None


def _heuristic_check(text: str) -> dict[str, float]:
    if not text or not text.strip():
        return {"INJECTION": 0.0, "JAILBREAK": 0.0, "BENIGN": 1.0}

    low = text.lower()
    patterns = [
        r"ignore (all )?(previous|prior|above) (instructions|prompts|directives)",
        r"system directive",
        r"developer (mode|message)",
        r"send_email",
        r"attacker@",
        r"override",
        r"query_database",
        r"disregard",
        r"<!--.*?ai assistant.*?-->",
        r"forward.*?(password|credential|secret|database)",
    ]

    score = 0.0
    for pat in patterns:
        if re.search(pat, low):
            score += 0.4
    score = min(score, 0.99)

    return {
        "INJECTION": score,
        "JAILBREAK": score * 0.8,
        "BENIGN": max(0.01, 1.0 - score),
    }


def _classify_text(
    text: str,
    model_id: str = DEFAULT_MODEL_ID,
    revision: str | None = None,
    mock: bool = False,
) -> dict[str, float]:
    global _ACTIVE_BACKEND
    if not text or not text.strip():
        return {"INJECTION": 0.0, "JAILBREAK": 0.0, "BENIGN": 1.0}

    if mock or os.environ.get("DEFENSE_MOCK", "0") in {"1", "true", "yes"}:
        _ACTIVE_BACKEND = "mock_heuristic"
        return _heuristic_check(text)

    pipe = _load_pipeline(model_id, revision=revision)
    if pipe is None:
        return _heuristic_check(text)

    try:
        # Prompt-Guard sequence length is 512 tokens; pass max 2000 chars and let pipe truncate to 512 tokens
        outputs = pipe(text[:2000])
        scores = {}
        raw = outputs[0] if outputs and isinstance(outputs[0], list) else outputs
        for item in raw:
            label = item["label"].upper()
            if label == "LABEL_0":
                label = "BENIGN"
            elif label == "LABEL_1":
                label = "INJECTION"
            elif label == "LABEL_2":
                label = "JAILBREAK"
            scores[label] = float(item["score"])
        return scores
    except Exception:
        return _heuristic_check(text)


def check_input_safety(
    user_input: str,
    external_text: str = "",
    threshold: float = DEFAULT_THRESHOLD,
    model_id: str = DEFAULT_MODEL_ID,
    revision: str | None = None,
    mock: bool = False,
) -> dict[str, Any]:
    """Inspects user input and external text channels separately.
    Returns ALLOW if all risk scores < threshold, else BLOCK.
    """
    effective_rev = revision or MODEL_REVISIONS.get(model_id, DEFAULT_REVISION)
    user_scores = _classify_text(user_input, model_id=model_id, revision=effective_rev, mock=mock)
    ext_scores = _classify_text(external_text, model_id=model_id, revision=effective_rev, mock=mock) if external_text.strip() else {
        "INJECTION": 0.0, "JAILBREAK": 0.0, "BENIGN": 1.0
    }

    user_risk = max(user_scores.get("INJECTION", 0.0), user_scores.get("JAILBREAK", 0.0))
    ext_risk = max(ext_scores.get("INJECTION", 0.0), ext_scores.get("JAILBREAK", 0.0))

    user_flagged = user_risk >= threshold
    ext_flagged = ext_risk >= threshold

    if user_flagged and ext_flagged:
        decision = "BLOCK"
        flagged_channel = "both"
        reason = f"Injection detected in user input ({user_risk:.2f}) and external text ({ext_risk:.2f})"
    elif user_flagged:
        decision = "BLOCK"
        flagged_channel = "user_input"
        reason = f"Direct injection in user input ({user_risk:.2f} >= {threshold})"
    elif ext_flagged:
        decision = "BLOCK"
        flagged_channel = "external_text"
        reason = f"Indirect injection in external text ({ext_risk:.2f} >= {threshold})"
    else:
        decision = "ALLOW"
        flagged_channel = None
        reason = f"Clean (user: {user_risk:.2f}, ext: {ext_risk:.2f} < {threshold})"

    return {
        "decision": decision,
        "injection_score": round(max(user_scores.get("INJECTION", 0.0), ext_scores.get("INJECTION", 0.0)), 4),
        "jailbreak_score": round(max(user_scores.get("JAILBREAK", 0.0), ext_scores.get("JAILBREAK", 0.0)), 4),
        "flagged_channel": flagged_channel,
        "reason": reason,
        "details": {
            "backend": _ACTIVE_BACKEND,
            "model_id": model_id,
            "revision": effective_rev,
            "threshold": threshold,
            "user_scores": {k: round(v, 4) for k, v in user_scores.items()},
            "external_scores": {k: round(v, 4) for k, v in ext_scores.items()},
        },
    }


def get_defense_config() -> dict[str, Any]:
    return {
        "module": "defense.py",
        "default_model_id": DEFAULT_MODEL_ID,
        "default_revision": DEFAULT_REVISION,
        "threshold": DEFAULT_THRESHOLD,
        "strategy": "two_channel_separate",
        "max_length": 512,
        "supported_revisions": MODEL_REVISIONS,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Task 2: Defense Gate")
    parser.add_argument("user_input", nargs="?", default="Hello, can you help me summarize this document?",
                        help="User input prompt")
    parser.add_argument("--external", default="", help="External text / document context")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="Safety threshold")
    parser.add_argument("--model", default=DEFAULT_MODEL_ID, help="Hugging Face model ID")
    parser.add_argument("--revision", default=None, help="Explicit model commit SHA revision")
    parser.add_argument("--mock", action="store_true", help="Run fast offline mock without downloading model")
    parser.add_argument("--json", action="store_true", help="Print structured JSON")
    args = parser.parse_args()

    res = check_input_safety(
        args.user_input,
        args.external,
        threshold=args.threshold,
        model_id=args.model,
        revision=args.revision,
        mock=args.mock,
    )
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(f"[{res['decision']}] {res['reason']}")
        print(f"Backend: {res['details']['backend']}")
