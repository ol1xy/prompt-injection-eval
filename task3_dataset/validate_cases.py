"""Validate Task 3's JSON contract without loading any model or executing tools."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

FIELDS = {"id", "channel", "user_input", "external_text", "is_attack", "attack_goal"}
ROOT = Path(__file__).resolve().parent


def validate(dataset_path):
    with dataset_path.open(encoding="utf-8") as handle:
        cases = json.load(handle)
    if not isinstance(cases, list):
        raise ValueError("The top-level JSON value must be an array.")
    errors = []
    ids = set()
    counts = Counter()
    for index, case in enumerate(cases, 1):
        prefix = f"Case {index}"
        if not isinstance(case, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        if set(case) != FIELDS:
            errors.append(f"{prefix}: missing={sorted(FIELDS-set(case))}, extra={sorted(set(case)-FIELDS)}")
            continue
        for key in FIELDS - {"is_attack"}:
            if not isinstance(case[key], str):
                errors.append(f"{prefix}: {key} must be a string")
        if any(not isinstance(case[k], str) for k in FIELDS - {"is_attack"}):
            continue
        if type(case["is_attack"]) is not bool:
            errors.append(f"{prefix}: is_attack must be a JSON boolean")
            continue
        ident = case["id"]
        if not ident.strip() or ident in ids:
            errors.append(f"{prefix}: id must be nonempty and unique ({ident!r})")
        ids.add(ident)
        if case["channel"] not in {"direct", "indirect"}:
            errors.append(f"{ident}: invalid channel")
        if not case["user_input"].strip():
            errors.append(f"{ident}: user_input is required")
        if case["channel"] == "indirect" and not case["external_text"].strip():
            errors.append(f"{ident}: indirect cases need external_text")
        if case["is_attack"] and not case["attack_goal"].strip():
            errors.append(f"{ident}: attacks need attack_goal")
        if not case["is_attack"] and case["attack_goal"] != "":
            errors.append(f"{ident}: benign attack_goal must be an empty string")
        if case["is_attack"] and case["attack_goal"] != "send_email":
            errors.append(f"{ident}: this MVP set uses the send_email tool goal only")
        kind = "attack" if case["is_attack"] else "benign"
        counts[kind] += 1
        counts[f"{kind}_{case['channel']}"] += 1
        if case["channel"] == "indirect":
            if case["external_text"].startswith("[Retrieved document:"):
                counts[f"{kind}_document"] += 1
            elif case["external_text"].startswith("[Mock tool result:"):
                counts[f"{kind}_tool_result"] += 1
            else:
                errors.append(f"{ident}: indirect source must have a document/tool-result label")
    if not 20 <= len(cases) <= 25:
        errors.append(f"MVP requires 20-25 cases, found {len(cases)}")
    if errors:
        raise ValueError("\n".join(errors))
    return cases, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=ROOT / "data" / "cases.json")
    args = parser.parse_args()
    try:
        cases, counts = validate(args.path)
    except (OSError, ValueError) as exc:
        print(f"VALIDATION FAILED\n{exc}", file=sys.stderr)
        return 1
    print("VALIDATION PASSED")
    print(f"Total: {len(cases)}")
    for key in ["attack", "benign", "attack_direct", "attack_indirect", "attack_document",
                "attack_tool_result", "benign_direct", "benign_indirect", "benign_document", "benign_tool_result"]:
        print(f"{key}: {counts[key]}")
    print("This checks the data contract only. No model, detector, or judge was run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
