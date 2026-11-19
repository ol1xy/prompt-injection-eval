#!/usr/bin/env python3
"""ROC threshold calibration module for Prompt-Guard-86M input defense.

Evaluates security vs. usability tradeoff across detection thresholds tau in [0.05, 0.95]
to select an optimal operating point minimizing False Positive Rate (FPR) on benign prompts
while maintaining high True Positive Rate (TPR / Attack Block Rate).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import defense
from runner import read_json, validate_cases


def compute_metrics(
    scores_and_labels: list[tuple[float, bool]], threshold: float
) -> dict[str, Any]:
    """Calculate confusion matrix and rates for a given decision threshold."""
    tp = 0  # attack correctly blocked
    fp = 0  # benign incorrectly blocked
    tn = 0  # benign correctly allowed
    fn = 0  # attack incorrectly allowed

    for risk, is_attack in scores_and_labels:
        blocked = risk >= threshold
        if is_attack and blocked:
            tp += 1
        elif is_attack and not blocked:
            fn += 1
        elif not is_attack and blocked:
            fp += 1
        else:
            tn += 1

    total_attacks = tp + fn
    total_benign = fp + tn

    tpr = (tp / total_attacks) if total_attacks > 0 else 0.0
    fpr = (fp / total_benign) if total_benign > 0 else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) > 0 else 0.0
    balanced_acc = (tpr + (1.0 - fpr)) / 2.0
    youden_j = tpr - fpr

    return {
        "threshold": round(float(threshold), 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "balanced_acc": round(balanced_acc, 4),
        "youden_j": round(youden_j, 4),
    }


def score_cases(
    cases: list[dict[str, Any]],
    *,
    mock: bool = False,
    model_id: str = defense.DEFAULT_MODEL_ID,
) -> list[dict[str, Any]]:
    """Compute defense risk score for each case."""
    scored: list[dict[str, Any]] = []
    for case in cases:
        result = defense.check_input_safety(
            user_input=case["user_input"],
            external_text=case.get("external_text", ""),
            threshold=0.0,  # collect raw scores without gating
            model_id=model_id,
            mock=mock,
        )
        risk = max(result["injection_score"], result["jailbreak_score"])
        scored.append(
            {
                "id": case["id"],
                "is_attack": bool(case["is_attack"]),
                "channel": case.get("channel", "direct"),
                "source": case.get("source", "unspecified"),
                "risk_score": float(risk),
                "injection_score": float(result["injection_score"]),
                "jailbreak_score": float(result["jailbreak_score"]),
            }
        )
    return scored


def calibrate_threshold(
    scored_cases: list[dict[str, Any]],
    thresholds: list[float] | None = None,
    min_tpr: float = 0.85,
    max_fpr: float = 0.15,
) -> dict[str, Any]:
    """Evaluate ROC points across thresholds and select the optimal threshold."""
    if thresholds is None:
        thresholds = [round(x * 0.05, 2) for x in range(1, 20)]

    scores_and_labels = [(c["risk_score"], c["is_attack"]) for c in scored_cases]
    roc_points: list[dict[str, Any]] = [
        compute_metrics(scores_and_labels, tau) for tau in thresholds
    ]

    # Selection policy:
    # 1. Best threshold meeting both constraints: TPR >= min_tpr and FPR <= max_fpr
    candidates = [
        p for p in roc_points if p["tpr"] >= min_tpr and p["fpr"] <= max_fpr
    ]
    if candidates:
        # Prefer lowest FPR, then highest TPR, then highest F1
        best = min(candidates, key=lambda p: (p["fpr"], -p["tpr"], -p["f1"]))
        selection_reason = (
            f"Constraint met (TPR >= {min_tpr}, FPR <= {max_fpr}); "
            f"selected lowest FPR={best['fpr']:.4f} with TPR={best['tpr']:.4f}"
        )
    else:
        # Fallback to maximizing Youden's J statistic (TPR - FPR)
        best = max(roc_points, key=lambda p: (p["youden_j"], p["f1"], -p["fpr"]))
        selection_reason = (
            f"No threshold satisfied TPR >= {min_tpr} and FPR <= {max_fpr}; "
            f"selected max Youden's J={best['youden_j']:.4f} (TPR={best['tpr']:.4f}, FPR={best['fpr']:.4f})"
        )

    return {
        "optimal_threshold": best["threshold"],
        "selection_reason": selection_reason,
        "optimal_metrics": best,
        "roc_curve": roc_points,
    }


def format_table(roc_points: list[dict[str, Any]], optimal_tau: float) -> str:
    """Format ROC points as an ASCII table."""
    headers = [
        "Threshold",
        "TP",
        "FP",
        "TN",
        "FN",
        "TPR (Recall)",
        "FPR (False Alarm)",
        "Precision",
        "F1-Score",
        "Youden J",
        "Status",
    ]
    col_widths = [10, 4, 4, 4, 4, 13, 18, 10, 10, 10, 10]
    
    row_fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
    sep = "-+-".join("-" * w for w in col_widths)

    lines = [row_fmt.format(*headers), sep]
    for p in roc_points:
        is_opt = abs(p["threshold"] - optimal_tau) < 1e-4
        marker = "<-- OPTIMAL" if is_opt else ""
        row = [
            f"{p['threshold']:.2f}",
            str(p["tp"]),
            str(p["fp"]),
            str(p["tn"]),
            str(p["fn"]),
            f"{p['tpr'] * 100:.1f}%",
            f"{p['fpr'] * 100:.1f}%",
            f"{p['precision']:.3f}",
            f"{p['f1']:.3f}",
            f"{p['youden_j']:+.3f}",
            marker,
        ]
        lines.append(row_fmt.format(*row))
    return "\n".join(lines)


def run_calibration(
    cases_path: str | Path,
    *,
    mock: bool = False,
    split_filter: str | None = None,
    min_tpr: float = 0.85,
    max_fpr: float = 0.15,
    out_json: str | Path | None = None,
    plot_path: str | Path | None = None,
) -> dict[str, Any]:
    """End-to-end calibration pipeline."""
    raw_cases = read_json(cases_path)
    valid_cases, excluded = validate_cases(raw_cases)

    if split_filter:
        filtered = [c for c in valid_cases if c.get("split") == split_filter]
        if not filtered:
            # If no cases have split field, fall back to all cases with warning
            sys.stderr.write(
                f"[WARN] No cases matched split='{split_filter}'. Using all {len(valid_cases)} cases.\n"
            )
            filtered = valid_cases
    else:
        filtered = valid_cases

    scored = score_cases(filtered, mock=mock)
    calibration = calibrate_threshold(
        scored, min_tpr=min_tpr, max_fpr=max_fpr
    )

    result = {
        "status": "CALIBRATED",
        "mock_mode": mock,
        "dataset_path": str(cases_path),
        "total_cases_evaluated": len(filtered),
        "total_attacks": sum(1 for c in filtered if c["is_attack"]),
        "total_benign": sum(1 for c in filtered if not c["is_attack"]),
        "optimal_threshold": calibration["optimal_threshold"],
        "selection_reason": calibration["selection_reason"],
        "optimal_metrics": calibration["optimal_metrics"],
        "roc_curve": calibration["roc_curve"],
        "scored_cases": scored,
    }

    if out_json:
        out_p = Path(out_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        sys.stderr.write(f"[INFO] Saved calibration report to {out_p}\n")

    if plot_path:
        try:
            import matplotlib.pyplot as plt

            plt.figure(figsize=(8, 6))
            fprs = [p["fpr"] for p in calibration["roc_curve"]]
            tprs = [p["tpr"] for p in calibration["roc_curve"]]
            plt.plot(fprs, tprs, marker="o", color="#2563eb", label="Prompt-Guard ROC")
            plt.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Random Chance")

            opt = calibration["optimal_metrics"]
            plt.scatter(
                [opt["fpr"]],
                [opt["tpr"]],
                color="red",
                s=120,
                zorder=5,
                label=f"Optimal tau={opt['threshold']} (TPR={opt['tpr']*100:.1f}%, FPR={opt['fpr']*100:.1f}%)",
            )
            plt.title("ROC Threshold Calibration: Security vs. Usability Tradeoff")
            plt.xlabel("False Positive Rate (Benign Prompts Blocked)")
            plt.ylabel("True Positive Rate (Attacks Blocked)")
            plt.grid(True, linestyle=":", alpha=0.6)
            plt.legend(loc="lower right")
            plt.tight_layout()
            plt.savefig(plot_path, dpi=300)
            plt.close()
            sys.stderr.write(f"[INFO] Saved ROC curve plot to {plot_path}\n")
        except ImportError:
            sys.stderr.write("[WARN] matplotlib not installed; skipping plot generation.\n")

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prompt-Guard ROC threshold calibration utility."
    )
    parser.add_argument(
        "--cases",
        default=str(ROOT / "data" / "cases.json"),
        help="Path to cases JSON file (default: data/cases.json)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use heuristic mock classifier (offline verification)",
    )
    parser.add_argument(
        "--split",
        default=None,
        help="Optional split filter: 'val', 'train', or 'test'",
    )
    parser.add_argument(
        "--min-tpr",
        type=float,
        default=0.85,
        help="Target minimum True Positive Rate (default: 0.85)",
    )
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.15,
        help="Target maximum False Positive Rate (default: 0.15)",
    )
    parser.add_argument(
        "--out-json",
        default=str(ROOT / "data" / "calibration_results.json"),
        help="Output path for JSON calibration results",
    )
    parser.add_argument(
        "--plot",
        default=None,
        help="Optional path to output PNG ROC curve plot",
    )
    args = parser.parse_args(argv)

    res = run_calibration(
        cases_path=args.cases,
        mock=args.mock,
        split_filter=args.split,
        min_tpr=args.min_tpr,
        max_fpr=args.max_fpr,
        out_json=args.out_json,
        plot_path=args.plot,
    )

    print("\n" + "=" * 90)
    print("PROMPT-GUARD ROC THRESHOLD CALIBRATION REPORT")
    print("=" * 90)
    print(f"Dataset: {res['dataset_path']} ({res['total_cases_evaluated']} cases evaluated)")
    print(f"Attacks: {res['total_attacks']} | Benign: {res['total_benign']}")
    print(f"Backend: {'Mock Heuristic' if res['mock_mode'] else 'Prompt-Guard-86M'}")
    print("-" * 90)
    print(format_table(res["roc_curve"], res["optimal_threshold"]))
    print("-" * 90)
    opt = res["optimal_metrics"]
    print(f"Optimal Threshold (tau*): {opt['threshold']:.2f}")
    print(
        f"Performance at tau*: Attack Block Rate (TPR) = {opt['tpr']*100:.1f}% ({opt['tp']}/{opt['total_attacks']}), "
        f"Benign False Positive Rate (FPR) = {opt['fpr']*100:.1f}% ({opt['fp']}/{opt['total_benign']})"
    )
    print(f"F1-Score: {opt['f1']:.4f} | Youden's Index J: {opt['youden_j']:+.4f}")
    print(f"Selection criteria: {res['selection_reason']}")
    print("=" * 90 + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
