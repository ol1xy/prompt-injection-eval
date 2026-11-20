"""Validate the frozen Task 3 release and summarize either split offline."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data" / "cases.json"
EXPECTED = {
    ("evaluation", True): 10, ("evaluation", False): 58,
    ("validation", True): 5, ("validation", False): 25,
}

PUBLIC = {
    "clinc150": ("clinc/oos-eval", "828f8093932c8fe6ca7936c3d2e52903b1c523de",
                 "data/data_full.json", "verbatim"),
    "deepset": ("deepset/prompt-injections", "4f61ecb038e9c3fb77e21034b22511b523772cdd",
                "data/train-00000-of-00001-9564e8b05b4757ab.parquet", "paraphrase"),
}
ORIGINS = {
    "mfa": "nist-factors", "passwords": "nist-passwords",
    "recovery": "nist-recovery", "sessions": "nist-sessions",
    "awareness": "cisa-awareness",
}


def load_release():
    raw = DATA.read_bytes()
    rows = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(rows, list):
        raise ValueError("Expected a JSON array")
    ids, inputs = set(), set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"Row {index} must be an object")
        for key in ("id", "user_input", "external_text", "attack_goal", "category",
                    "provenance", "channel", "source", "split"):
            if not isinstance(row.get(key), str):
                raise ValueError(f"Row {index}: expected string for {key}")
        ident = row["id"]
        pair = tuple(" ".join(row[key].casefold().split()) for key in
                     ("user_input", "external_text"))
        if not ident.strip() or not pair[0] or ident in ids or pair in inputs:
            raise ValueError(f"Blank or duplicate identity/input at {ident!r}")
        ids.add(ident)
        inputs.add(pair)
        direct = row["channel"] == "direct"
        if row["channel"] not in ("direct", "indirect") or (not direct and not pair[1]):
            raise ValueError(f"Inconsistent channel/context at {ident}")
        sources = ("user",) if direct else ("document", "tool_text")
        if row["source"] not in sources or not row["category"].strip():
            raise ValueError(f"Invalid source/category at {ident}")
        attack = row.get("is_attack")
        if type(attack) is not bool or row["attack_goal"] != ("send_email" if attack else ""):
            raise ValueError(f"Invalid label/goal at {ident}")
        if (row["category"] == "attack") != attack:
            raise ValueError(f"Invalid category/label at {ident}")
        origin = row["provenance"]
        if origin in PUBLIC:
            ref = row.get("upstream", {})
            if tuple(ref.get(k) for k in ("dataset", "revision", "file", "transformation")) != PUBLIC[origin]:
                raise ValueError(f"Invalid upstream citation at {ident}")
            index = ref.get("index")
            if type(index) is not int or index < 0 or attack or not direct:
                raise ValueError(f"Invalid upstream row at {ident}")
            part = ref.get("partition")
            if origin == "clinc150":
                expected_split = {"val": "validation", "test": "evaluation"}.get(part)
                valid_label = isinstance(ref.get("label"), str) and bool(ref["label"])
                prefix = "clinc"
            else:
                expected_split = "evaluation" if part == "train" else None
                valid_label = type(ref.get("label")) is int and ref["label"] == 0
                prefix = "deepset"
            if ident != f"{prefix}_{part}_{index}" or row["split"] != expected_split or not valid_label:
                raise ValueError(f"Upstream ID, label or partition mismatch at {ident}")
        elif origin != "midterm" and ORIGINS.get(row["category"]) != origin:
            raise ValueError(f"Unknown provenance at {ident}")
    if Counter((r["split"], r["is_attack"]) for r in rows) != EXPECTED:
        raise ValueError("Split counts differ from the frozen release")
    if sum(r["provenance"] == "midterm" for r in rows) != 25:
        raise ValueError("Expected 25 course cases")
    if Counter(r["provenance"] for r in rows if r["provenance"] in PUBLIC) != {"clinc150": 12, "deepset": 6}:
        raise ValueError("Expected 12 CLINC150 and 6 deepset records")
    return rows, hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("validation", "evaluation"))
    args = parser.parse_args()
    rows, digest = load_release()
    print(f"Validated {len(rows)} cases. SHA-256 {digest}")
    for name in ([args.split] if args.split else ["validation", "evaluation"]):
        subset = [r for r in rows if r["split"] == name]
        print(f"{name}: {len(subset)} cases")
        for attack in (True, False):
            field = "source" if attack else "category"
            counts = Counter(r[field] for r in subset if r["is_attack"] == attack)
            print("  ", "attack" if attack else "benign", dict(sorted(counts.items())))


if __name__ == "__main__":
    main()
