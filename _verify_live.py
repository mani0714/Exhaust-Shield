"""Live API checks for local-first knowledge path."""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:8000"


def get(path: str):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def post(path: str, body: dict):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    health = get("/api/health")
    print("HEALTH", health)
    assert health.get("local_first") is True
    assert health.get("knowledge_engine_version") == "local-first-v2"
    assert health.get("ask_knowledge_may_call_llm") is False

    cases = [
        ("Did we acquire Northwind Analytics Inc?", "local_near_match", False),
        ("Are any employees currently in PIP?", "local_near_match", False),
        ("What is our pet stipend policy?", "no_local_context", True),
    ]
    for q, path, human in cases:
        data = post("/api/ask-knowledge", {"question": q})
        print("---")
        print(q)
        print(
            "path=",
            data.get("logic_path"),
            "sent_to_llm=",
            data.get("sent_to_llm"),
            "engine=",
            data.get("knowledge_engine_version"),
        )
        print((data.get("answer") or "")[:180])
        assert data.get("ok") is True
        assert data.get("sent_to_llm") is False
        assert data.get("ask_knowledge_may_call_llm") is False
        assert data.get("knowledge_engine_version") == "local-first-v2"
        assert data.get("logic_path") == path
        assert bool(data.get("needs_human_review")) is human
        if path == "local_near_match":
            assert "LOCAL" in (data.get("lane_badge") or data.get("lane") or "").upper() or data.get("lane") == "local"

    print("\nALL LIVE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("FAIL:", exc)
        raise SystemExit(1)
