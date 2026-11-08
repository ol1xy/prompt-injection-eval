"""Adapter for the supplied Task 1 implementation; original files stay unchanged."""

import copy
import hashlib
import importlib
import importlib.util
from pathlib import Path


def load_target(path=None):
    if path is None:
        return importlib.import_module("target_app")
    path = Path(path).resolve()
    spec = importlib.util.spec_from_file_location("pi_eval_task1_target", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot import target module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bind_secret_rules(scoring, target):
    """Resolve judge-only references without passing them to the target or defense."""
    bound = copy.deepcopy(scoring)
    for group in ("by_goal", "by_case"):
        for rule in bound.get(group, {}).values():
            if isinstance(rule, dict) and rule.get("secrets_source") == "target_app.SECRETS":
                values = getattr(target, "SECRETS", None)
                if not isinstance(values, (tuple, list)) or not values or not all(
                    isinstance(v, str) and v.strip() for v in values
                ):
                    raise ValueError("Task 1 must export a nonempty SECRETS tuple/list")
                rule["values"] = list(values)
    return bound


def prepare_target(target, *, mock=False, benchmark_policy=False):
    """Pin Task 1 run options and annotate executed calls from its verified contract.

    Use only with this Task 1 implementation, not arbitrary target applications.
    mock=True exists for offline integration tests, not for CLI live evaluation.
    """
    if benchmark_policy:
        from benchmark import POLICY
        if POLICY not in target.SYSTEM_PROMPT:
            target.SYSTEM_PROMPT += "\n\n" + POLICY
    config = dict(target.get_config())
    config["benchmark_authorization_policy"] = benchmark_policy
    config.pop("secrets", None)
    config.update(temperature=0.0, seed=42, max_steps=3, cache=False, mock=mock,
                  timeout_per_request=target.REQUEST_TIMEOUT,
                  keep_alive=target.DEFAULT_KEEP_ALIVE,
                  system_prompt_sha256=hashlib.sha256(target.SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
                  source_sha256=hashlib.sha256(Path(target.__file__).read_bytes()).hexdigest(),
                  source_path=str(Path(target.__file__).resolve()),
                  model_digest="UNVERIFIED: capture from the actual local Ollama installation",
                  tool_calls_semantics="executed mock tools; adapter annotates known tool names",
                  fresh_state_per_case=True)

    def run_app(user_input, external_text=""):
        from judge import validate_app_output
        output = target.run_app(user_input, external_text, model=config["model"],
                                temperature=0.0, seed=42, max_steps=3,
                                cache=False, mock=mock)
        validate_app_output(output)
        result = copy.deepcopy(output)
        for call in result["tool_calls"]:
            # Task 1 also logs unknown tools after dispatch returns an error string.
            # Do not annotate those as successfully executed.
            if call["name"] not in ("send_email", "query_database"):
                raise ValueError(f"Task 1 returned unsupported tool: {call['name']!r}")
            if call.get("executed") is not False:
                call["executed"] = True
        return result

    return run_app, config
