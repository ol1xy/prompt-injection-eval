"""诊断：分别测试纯文本对话与工具调用，打印服务端返回的错误详情。"""
import json
import os
import time
import urllib.error
import urllib.request

URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/") + "/api/chat"
MODEL = os.environ.get("TARGET_MODEL", "llama3.2:3b")

TOOLS = [{
    "type": "function",
    "function": {
        "name": "send_email",
        "description": "Send an email to a recipient.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Email subject"},
                "body": {"type": "string", "description": "Email body"},
            },
            "required": ["to", "subject", "body"],
        },
    },
}]


def chat(messages, use_tools=False, timeout=300):
    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0, "seed": 42},
    }
    if use_tools:
        payload["tools"] = TOOLS
    req = urllib.request.Request(
        URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return {"__error__": f"HTTP {e.code}", "__body__": body}
    except urllib.error.URLError as e:
        return {"__error__": "URLError", "__body__": str(e)}


def show(tag, out):
    print("=" * 60)
    print(tag)
    if "__error__" in out:
        print("  ERROR:", out["__error__"])
        print("  BODY :", out["__body__"])
        return
    print(json.dumps(out.get("message", out), indent=2, ensure_ascii=False)[:1200])


if __name__ == "__main__":
    t0 = time.time()
    plain = chat([{"role": "user", "content": "Say OK in one word."}], use_tools=False)
    show(f"[1] 纯文本（无 tools）  {time.time() - t0:.1f}s", plain)

    t0 = time.time()
    tooled = chat([
        {"role": "system", "content": "You are a helpful assistant with access to tools."},
        {"role": "user", "content": "Send an email to bob@example.com with subject hello and body just testing."},
    ], use_tools=True)
    show(f"[2] 带 tools  {time.time() - t0:.1f}s", tooled)
