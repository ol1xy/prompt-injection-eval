"""Task 4: two-pass evaluation using only the Python standard library."""

import argparse
import hashlib
import importlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import time
from benchmark import validate_benchmark

from judge import ScoringNotConfigured, evaluate_case, validate_app_output, validate_rule

ROOT = Path(__file__).resolve().parent


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def validate_cases(cases):
    """Exclude invalid records before BOTH passes; exclude all duplicate IDs."""
    if not isinstance(cases, list):
        raise ValueError("Dataset must be a JSON array")
    ids = Counter(c.get("id") for c in cases
                  if isinstance(c, dict) and isinstance(c.get("id"), str))
    valid, excluded = [], []
    for index, case in enumerate(cases):
        errors = []
        if not isinstance(case, dict):
            errors.append("case must be an object")
        else:
            for key in ("id", "user_input", "external_text", "attack_goal"):
                if not isinstance(case.get(key), str):
                    errors.append(f"{key} must be a string")
            if isinstance(case.get("id"), str):
                if not case["id"].strip():
                    errors.append("id must not be blank")
                if ids[case["id"]] > 1:
                    errors.append("duplicate id")
            if case.get("channel") not in ("direct", "indirect"):
                errors.append("channel must be direct or indirect")
            if type(case.get("is_attack")) is not bool:
                errors.append("is_attack must be boolean")
            if case.get("is_attack") is True and not str(case.get("attack_goal", "")).strip():
                errors.append("attack cases require a nonempty goal")
            if case.get("is_attack") is False and case.get("attack_goal") != "":
                errors.append("benign attack_goal must be empty")
            if "source" in case and not isinstance(case["source"], str):
                errors.append("optional source must be a string")
        if errors:
            excluded.append({"index": index, "id": case.get("id") if isinstance(case, dict) else None,
                             "reasons": errors})
        else:
            valid.append(case)
    return valid, excluded


def _rule(case, scoring):
    overrides = scoring.get("by_case", {})
    return overrides[case["id"]] if case["id"] in overrides else scoring.get("by_goal", {}).get(case["attack_goal"])


def _record(case, pass_name, run_app, check_input_safety, scoring):
    started = time.monotonic()
    record = {"case_id": case["id"], "pass": pass_name, "is_attack": case["is_attack"],
              "channel": case["channel"], "source": case.get("source", "unspecified"),
              "attack_goal": case["attack_goal"], "decision": None,
              "attack_success": None, "status": "pending", "error": None}
    stage = "defense" if pass_name == "B" else "target"
    try:
        if pass_name == "B":
            # Deliberately pass only input strings, NEVER scoring metadata.
            safety = check_input_safety(case["user_input"], case["external_text"])
            if not isinstance(safety, dict) or safety.get("decision") not in ("ALLOW", "BLOCK"):
                raise ValueError("Defense must return decision ALLOW or BLOCK")
            record["decision"] = safety["decision"]
            record["defense_output"] = safety
            record["injection_score"] = safety.get("injection_score")
            record["jailbreak_score"] = safety.get("jailbreak_score")
            record["defense_backend"] = safety.get("details", {}).get("backend")
            if safety["decision"] == "BLOCK":
                record["status"] = "blocked"
                return record
        stage = "target"
        output = run_app(case["user_input"], case["external_text"])
        validate_app_output(output)
        record["app_output"] = output
        if not case["is_attack"]:
            record["status"] = "benign_allowed"
            return record
        stage = "judge"
        rule = _rule(case, scoring)
        record["scoring_rule"] = rule
        record["attack_success"] = evaluate_case({**case, "scoring_rule": rule}, output)
        record["status"] = "scored"
    except ScoringNotConfigured as exc:
        record.update(status="pending_scoring", error=str(exc))
    except Exception as exc:
        record.update(status=f"{stage}_error", error=f"{type(exc).__name__}: {exc}")
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return record


def _metric(records, name):
    if name == "fpr":
        selected = [r for r in records if r["pass"] == "B" and not r["is_attack"]]
        numerator = sum(r["decision"] == "BLOCK" for r in selected)
        unresolved = sum(r["decision"] not in ("ALLOW", "BLOCK") for r in selected)
    else:
        selected = [r for r in records if r["pass"] == ("A" if name == "baseline_asr" else "B") and r["is_attack"]]
        numerator = sum(r["attack_success"] is True for r in selected)
        unresolved = sum(r["status"] not in ("scored", "blocked") for r in selected)
    total = len(selected)
    return {"numerator": numerator, "denominator": total, "unresolved": unresolved,
            "rate": numerator / total if total and not unresolved else None,
            "status": "undefined" if not total else "incomplete" if unresolved else "complete"}


def run_evaluation(cases, run_app, check_input_safety, scoring, *, metadata=None):
    """Public interface for demo.py. Callables must start each case with fresh state.

    No printing or writing here. Return a JSON-serializable result dictionary.
    Incomplete metrics retain the fixed denominator and have rate=null.
    """
    if not isinstance(scoring, dict):
        raise ValueError("Scoring config must be an object")
    for key in ("by_goal", "by_case"):
        if not isinstance(scoring.get(key, {}), dict):
            raise ValueError(f"{key} must be an object")
    valid, excluded = validate_cases(cases)
    validate_benchmark(valid, excluded, scoring)
    pending = []
    for case in valid:
        if case["is_attack"]:
            try:
                validate_rule(_rule(case, scoring))
            except ValueError as exc:
                pending.append({"case_id": case["id"], "reason": str(exc)})
    records = []
    for pass_name in ("A", "B"):
        for case in valid:
            if pass_name == "A" and not case["is_attack"]:
                continue
            records.append(_record(case, pass_name, run_app, check_input_safety, scoring))
    metric_names = ("baseline_asr", "defended_asr", "fpr")
    metrics = {name: _metric(records, name) for name in metric_names}
    breakdowns = {}
    for field in ("channel", "source", "attack_goal"):
        breakdowns[field] = {
            value: {name: _metric([r for r in records if r[field] == value], name) for name in metric_names}
            for value in sorted({r[field] for r in records})
        }
    return {"schema_version": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "formal_eligible": False,
            "metadata": metadata or {}, "scoring_config": scoring,
            "dataset": {"input_count": len(cases), "valid_count": len(valid), "excluded": excluded},
            "pending_scoring": pending, "metrics": metrics, "breakdowns": breakdowns,
            "status_counts": dict(Counter(r["status"] for r in records)), "records": records,
            "metric_policy": "Fixed valid-case denominators; rate=null if unresolved. FPR uses defense decisions only.",
            "warning": "Mock results are pipeline checks only. Live results require team-confirmed rules and configuration."}


def print_summary(result):
    print(f"Mode: {result['metadata'].get('mode', 'unspecified')}")
    for name, metric in result["metrics"].items():
        rate = "N/A" if metric["rate"] is None else f"{metric['rate']:.2%}"
        print(f"{name:16} {rate:>8}  {metric['numerator']}/{metric['denominator']}"
              f"  unresolved={metric['unresolved']} ({metric['status']})")
    print(f"Excluded: {len(result['dataset']['excluded'])}; pending rules: {len(result['pending_scoring'])}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock", action="store_true", help="Explicit synthetic pipeline check; NOT a benchmark")
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--scoring", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--metadata", type=Path, help="Optional model/defense configuration JSON")
    parser.add_argument("--target-file", type=Path, help="Path to Task 1 target_app.py before repository merge")
    parser.add_argument("--check-only", action="store_true", help="Validate dataset and scoring without loading models")
    args = parser.parse_args(argv)
    live_cases = ROOT / "data/cases.json"
    cases_path = args.cases or (ROOT / "examples/cases.mock.json" if args.mock else live_cases)
    scoring_path = args.scoring or ROOT / ("examples/scoring.mock.json" if args.mock else "scoring_rules.json")
    output_path = args.output or ROOT / ("results.mock.json" if args.mock else "results.json")
    try:
        cases, scoring = read_json(cases_path), read_json(scoring_path)
        if not args.mock and scoring.get("benchmark") != {"N_attack": 15, "N_benign": 10}:
            raise ValueError("Live mode requires the confirmed 15/10 benchmark scoring profile")
        valid, excluded = validate_cases(cases)
        validate_benchmark(valid, excluded, scoring)
        if args.check_only:
            print(f"Validated {len(valid)} cases; excluded={len(excluded)}; model calls=0")
            return 2 if excluded else 0
        metadata = read_json(args.metadata) if args.metadata else {}
        if not isinstance(metadata, dict):
            raise ValueError("Metadata must be a JSON object")
        if args.mock:
            if args.target_file:
                raise ValueError("--target-file cannot be combined with --mock; mock uses its own fixtures")
            from examples.mock_modules import run_app, check_input_safety
        else:
            from benchmark import prepare_defense, ollama_metadata, dependency_versions
            from task1_integration import bind_secret_rules, load_target, prepare_target
            target_path = args.target_file
            target = load_target(target_path)
            run_app, target_config = prepare_target(target, benchmark_policy=True)
            scoring = bind_secret_rules(scoring, target)
            metadata["target_config"] = target_config
            defense = importlib.import_module("defense")
            check_input_safety = prepare_defense(defense)
            metadata["defense_config"] = defense.get_defense_config()
            metadata["dependencies"] = dependency_versions()
            metadata["ollama"] = ollama_metadata(target_config)
            target_config["model_digest"] = metadata["ollama"]["model_digest"]
        metadata.update(mode="MOCK - synthetic, not benchmark evidence" if args.mock else "LIVE - review configuration before reporting",
                        cases_path=str(cases_path.resolve()),
                        cases_sha256=hashlib.sha256(cases_path.read_bytes()).hexdigest(),
                        scoring_sha256=hashlib.sha256(scoring_path.read_bytes()).hexdigest())
        result = run_evaluation(cases, run_app, check_input_safety, scoring, metadata=metadata)
        if not args.mock:
            result["metadata"]["defense_config"] = defense.get_defense_config()
            result["formal_eligible"] = bool(
                all(m["status"] == "complete" for m in result["metrics"].values())
                and not any(r["status"].endswith("_error") for r in result["records"])
                and all(r.get("defense_backend", "").startswith("huggingface (")
                        for r in result["records"] if r["pass"] == "B")
                and metadata["ollama"]["model_digest"] and metadata["ollama"]["ollama_version"]
                and all(metadata["dependencies"].values()))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
        print_summary(result)
        print(f"Saved: {output_path.resolve()}")
        print(result["warning"])
        print(f"Formal table eligible: {result['formal_eligible']}")
        incomplete = bool(result["dataset"]["excluded"] or result["pending_scoring"] or
                          any(r["status"].endswith("_error") for r in result["records"]) or
                          any(m["status"] != "complete" for m in result["metrics"].values()))
        return 2 if incomplete or (not args.mock and not result["formal_eligible"]) else 0
    except (OSError, ValueError, ImportError, AttributeError) as exc:
        print(f"Setup error: {exc}")
        print("Try: python runner.py --mock. Live mode needs data/cases.json, target_app.py and defense.py.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
