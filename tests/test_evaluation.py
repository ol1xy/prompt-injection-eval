"""Behavior tests for evaluation validity; no model downloads or network."""

import copy
import unittest

from examples.mock_modules import check_input_safety, run_app
from judge import ScoringNotConfigured, evaluate_case
from runner import ROOT, read_json, run_evaluation


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.cases = read_json(ROOT / "examples/cases.mock.json")
        self.scoring = read_json(ROOT / "examples/scoring.mock.json")

    def run_cases(self, cases=None, app=run_app, defense=check_input_safety, scoring=None):
        return run_evaluation(self.cases if cases is None else cases, app, defense,
                              self.scoring if scoring is None else scoring)

    def test_expected_two_pass_counts(self):
        result = self.run_cases()
        self.assertEqual(result["metrics"]["baseline_asr"]["rate"], 3 / 4)
        self.assertEqual(result["metrics"]["defended_asr"]["rate"], 1 / 4)
        self.assertEqual(result["metrics"]["fpr"]["rate"], 1 / 2)
        self.assertEqual(len(result["records"]), 10)
        self.assertEqual(result["metrics"]["defended_asr"]["denominator"], 4)

    def test_payload_isolation_and_block_short_circuit(self):
        app_calls, defense_calls = [], []
        original = copy.deepcopy(self.cases)
        def app(*args):
            app_calls.append(args)
            return run_app(*args)
        def defense(*args):
            defense_calls.append(args)
            return check_input_safety(*args)
        self.run_cases(app=app, defense=defense)
        self.assertEqual(len(app_calls), 7)  # A:4, B:2 attacks + 1 benign
        self.assertEqual(len(defense_calls), 6)
        self.assertTrue(all(len(a) == 2 and all(isinstance(v, str) for v in a)
                            for a in app_calls + defense_calls))
        self.assertEqual(self.cases, original)
        self.assertEqual(app_calls[:4], [(c["user_input"], c["external_text"]) for c in self.cases[:4]])

    def test_block_has_no_goal_verdict(self):
        result = self.run_cases()
        blocked = [r for r in result["records"] if r["status"] == "blocked"]
        self.assertEqual(len(blocked), 3)
        self.assertTrue(all(r["attack_success"] is None for r in blocked))

    def test_unknown_goal_is_pending_not_failed(self):
        self.cases[1]["attack_goal"] = "not_configured"
        result = self.run_cases()
        self.assertIsNone(result["metrics"]["baseline_asr"]["rate"])
        self.assertEqual(result["metrics"]["baseline_asr"]["denominator"], 4)
        self.assertEqual(result["metrics"]["baseline_asr"]["unresolved"], 1)
        self.assertEqual(result["status_counts"]["pending_scoring"], 2)

    def test_missing_model_output_is_error_not_secure(self):
        result = self.run_cases(app=lambda *args: None)
        self.assertIsNone(result["metrics"]["baseline_asr"]["rate"])
        self.assertIsNone(result["metrics"]["defended_asr"]["rate"])
        # Normal accessibility is measured at the defense boundary.
        self.assertEqual(result["metrics"]["fpr"]["rate"], 0.5)
        self.assertEqual(result["status_counts"]["target_error"], 7)

    def test_invalid_defense_decision_is_unresolved(self):
        result = self.run_cases(defense=lambda *args: {"decision": "MAYBE"})
        self.assertEqual(result["metrics"]["baseline_asr"]["rate"], 0.75)
        self.assertIsNone(result["metrics"]["defended_asr"]["rate"])
        self.assertIsNone(result["metrics"]["fpr"]["rate"])

    def test_duplicate_ids_all_excluded(self):
        self.cases.append(copy.deepcopy(self.cases[0]))
        result = self.run_cases()
        self.assertEqual(len(result["dataset"]["excluded"]), 2)
        self.assertEqual(result["metrics"]["baseline_asr"]["denominator"], 3)
        self.assertEqual(result["metrics"]["defended_asr"]["denominator"], 3)

    def test_invalid_fields_excluded_before_both_passes(self):
        self.cases[0].pop("external_text")
        self.cases[1]["is_attack"] = "true"
        result = self.run_cases()
        self.assertEqual(len(result["dataset"]["excluded"]), 2)
        self.assertEqual(result["metrics"]["baseline_asr"]["denominator"], 2)

    def test_empty_denominators_are_undefined(self):
        result = self.run_cases(cases=[])
        self.assertTrue(all(m["rate"] is None and m["status"] == "undefined"
                            for m in result["metrics"].values()))

    def test_per_case_override_and_explicit_null(self):
        self.scoring["by_case"]["mock_attack_email"] = {"type": "response_equals", "value": "never"}
        result = self.run_cases()
        self.assertEqual(result["metrics"]["baseline_asr"]["rate"], 0.5)
        self.scoring["by_case"]["mock_attack_email"] = None
        result = self.run_cases()
        self.assertIsNone(result["metrics"]["baseline_asr"]["rate"])
        # Blocked attacks still have known non-success at the defense boundary.
        self.assertEqual(result["metrics"]["defended_asr"]["rate"], 0.25)

    def test_tool_arguments_and_execution_evidence(self):
        case = {**self.cases[0], "scoring_rule": self.scoring["by_goal"]["send_email"]}
        output = run_app("MOCK_EMAIL")
        self.assertTrue(evaluate_case(case, output))
        output["tool_calls"][0]["args"]["to"] = "authorized@test.com"
        self.assertFalse(evaluate_case(case, output))
        output = run_app("MOCK_EMAIL")
        output["tool_calls"][0]["executed"] = False
        self.assertFalse(evaluate_case(case, output))
        del output["tool_calls"][0]["executed"]
        with self.assertRaises(ValueError):
            evaluate_case(case, output)

    def test_legacy_interface_and_unknown_goal(self):
        self.assertTrue(evaluate_case({**self.cases[0], "scoring_rule": {"type": "tool_call", "name": "send_email"}}, run_app("MOCK_EMAIL")))
        with self.assertRaises(ScoringNotConfigured):
            evaluate_case(self.cases[1], run_app("MOCK_LEAK"))

    def test_text_matching_is_case_sensitive(self):
        case = {**self.cases[1], "scoring_rule": {"type": "response_contains", "value": "Secret"}}
        self.assertTrue(evaluate_case(case, {"response_text": "A Secret here", "tool_calls": []}))
        self.assertFalse(evaluate_case(case, {"response_text": "a secret here", "tool_calls": []}))

    def test_invalid_rule_is_not_silently_ignored(self):
        self.scoring["by_goal"]["send_email"]["args_equal"] = {"to": "typo"}
        result = self.run_cases()
        self.assertIsNone(result["metrics"]["baseline_asr"]["rate"])
        self.assertTrue(result["pending_scoring"])

    def test_empty_response_is_valid_but_missing_response_is_not(self):
        case = self.cases[0]
        self.assertFalse(evaluate_case(case, {"response_text": "", "tool_calls": []}))
        with self.assertRaises(ValueError):
            evaluate_case(case, {"tool_calls": []})

    def test_source_breakdowns(self):
        result = self.run_cases()
        self.assertEqual(result["breakdowns"]["source"]["document"]["defended_asr"]["rate"], 1)
        self.assertEqual(result["breakdowns"]["source"]["tool_result"]["defended_asr"]["rate"], 0)


if __name__ == "__main__":
    unittest.main()
