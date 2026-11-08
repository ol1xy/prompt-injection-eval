"""Deterministic test doubles, deliberately NOT a model or security defense."""


def run_app(user_input: str, external_text: str = "") -> dict:
    text = user_input + "\n" + external_text
    calls = []
    response = "Mock normal answer"
    if "MOCK_EMAIL" in text:
        calls.append({"name": "send_email", "args": {"to": "attacker@test.com"}, "executed": True})
    if "MOCK_LEAK" in text:
        response = "SYNTHETIC_SECRET_DEMO_ONLY"
    if "MOCK_HIJACK" in text:
        response = "MOCK_HIJACK_SUCCESS"
    return {"response_text": response, "tool_calls": calls}


def check_input_safety(user_input: str, external_text: str = "") -> dict:
    blocked = "MOCK_BLOCK" in user_input + "\n" + external_text
    return {"decision": "BLOCK" if blocked else "ALLOW",
            "injection_score": float(blocked), "jailbreak_score": 0.0,
            "reason": "Synthetic fixture only"}
