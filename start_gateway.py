"""Kill anything on :8000 and start ExhaustShield WITHOUT --reload (Windows-safe).

Orphaned uvicorn --reload workers were the root cause of the stale
local-first code path: parents die, children keep serving old gateway.py.
"""
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = 8000

_PLACEHOLDER_KEY_MARKERS = (
    "your_key_here",
    "paste_your_key",
    "your_real_key",
    "xxx",
    "changeme",
)


def _is_placeholder_key(key: str) -> bool:
    k = (key or "").strip()
    if not k:
        return True
    low = k.lower()
    if any(m in low for m in _PLACEHOLDER_KEY_MARKERS):
        return True
    # Real Groq keys are gsk_ + long token
    if low.startswith("gsk_") and len(k) < 20:
        return True
    return False


def _load_dotenv_file() -> None:
    env_path = os.path.join(ROOT, ".env")
    try:
        from dotenv import load_dotenv

        load_dotenv(env_path, override=False)
        return
    except ImportError:
        pass
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            name, value = name.strip(), value.strip().strip('"').strip("'")
            if name and name not in os.environ:
                os.environ[name] = value


def load_groq_key_file() -> None:
    """Load EXTERNAL_AI_* from .env (preferred) or groq_key.local.bat fallback."""
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"
    os.environ.setdefault("PYTHONUTF8", "1")

    _load_dotenv_file()

    path = os.path.join(ROOT, "groq_key.local.bat")
    loaded: dict[str, str] = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.lower().startswith("rem") or line.lower().startswith("@echo"):
                    continue
                m = re.match(r'(?i)set\s+"?([A-Z0-9_]+)=(.*?)"?\s*$', line)
                if not m:
                    continue
                name, value = m.group(1), m.group(2).strip().strip('"')
                if value.startswith("="):
                    value = value[1:].strip().strip('"')
                if name.startswith("EXTERNAL_AI_") and name not in os.environ:
                    loaded[name] = value
                    os.environ[name] = value

    mode = (os.environ.get("EXTERNAL_AI_MODE") or loaded.get("EXTERNAL_AI_MODE") or "simulate").lower()
    key = os.environ.get("EXTERNAL_AI_API_KEY") or loaded.get("EXTERNAL_AI_API_KEY") or ""

    if not key and mode != "live":
        os.environ.setdefault("EXTERNAL_AI_MODE", "simulate")
        print("[ExhaustShield] no .env API key — EXTERNAL_AI_MODE=simulate")

    if mode == "live" and _is_placeholder_key(key):
        print(
            "[ExhaustShield] ERROR: EXTERNAL_AI_MODE=live but EXTERNAL_AI_API_KEY is missing "
            "or still a placeholder (gsk_YOUR_KEY_HERE)."
        )
        print(
            "[ExhaustShield] Put your real Groq key in .env (see .env.example), then restart. "
            "Falling back to SIMULATE so the demo still answers."
        )
        os.environ["EXTERNAL_AI_MODE"] = "simulate"
        mode = "simulate"

    if mode == "live":
        os.environ.setdefault("EXTERNAL_AI_BASE_URL", "https://api.groq.com/openai/v1")
        os.environ.setdefault("EXTERNAL_AI_MODEL", "openai/gpt-oss-120b")
        os.environ.setdefault("EXTERNAL_AI_FALLBACK_MODEL", "openai/gpt-oss-20b")
        os.environ.setdefault("EXTERNAL_AI_LIVE_SEARCH", "1")
        retired = {
            "llama-3.3-70b-versatile": "openai/gpt-oss-120b",
            "llama-3.1-8b-instant": "openai/gpt-oss-20b",
        }
        for name in ("EXTERNAL_AI_MODEL", "EXTERNAL_AI_FALLBACK_MODEL"):
            cur = (os.environ.get(name) or "").strip()
            if cur in retired:
                os.environ[name] = retired[cur]
                print(f"[ExhaustShield] remapped retired {cur} -> {retired[cur]}")
        print("[ExhaustShield] EXTERNAL_AI_MODE=live (Groq key loaded)")
        print(f"[ExhaustShield] EXTERNAL_AI_MODEL={os.environ.get('EXTERNAL_AI_MODEL')}")
        print(
            f"[ExhaustShield] EXTERNAL_AI_FALLBACK_MODEL="
            f"{os.environ.get('EXTERNAL_AI_FALLBACK_MODEL')}"
        )
        print(f"[ExhaustShield] EXTERNAL_AI_LIVE_SEARCH={os.environ.get('EXTERNAL_AI_LIVE_SEARCH')}")
        print("[ExhaustShield] proxies cleared for Groq")
    else:
        print(f"[ExhaustShield] EXTERNAL_AI_MODE={mode}")


def _netstat_listen_pids(port: int) -> set[str]:
    try:
        out = subprocess.check_output(["netstat", "-ano"], text=True, errors="ignore")
    except Exception:
        return set()
    pids = set()
    for line in out.splitlines():
        if f":{port}" in line and "LISTENING" in line:
            parts = line.split()
            if parts and parts[-1].isdigit() and int(parts[-1]) > 0:
                pids.add(parts[-1])
    return pids


def _orphan_uvicorn_worker_pids() -> set[str]:
    """Find multiprocessing children left behind after --reload parents die."""
    try:
        detail = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
                "ForEach-Object { '{0}|{1}' -f $_.ProcessId, $_.CommandLine }",
            ],
            text=True,
            errors="ignore",
        )
    except Exception:
        return set()
    pids: set[str] = set()
    for line in detail.splitlines():
        if "multiprocessing.spawn" in line or "uvicorn" in line or "gateway:app" in line:
            pid = line.split("|", 1)[0].strip()
            if pid.isdigit():
                pids.add(pid)
    return pids


def kill_port(port: int) -> None:
    victims = _netstat_listen_pids(port) | _orphan_uvicorn_worker_pids()
    for pid in sorted(victims):
        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
        print(f"[ExhaustShield] killed PID {pid}")


def main() -> int:
    os.chdir(ROOT)
    load_groq_key_file()
    print(f"[ExhaustShield] freeing port {PORT} and orphaned reload workers...")
    kill_port(PORT)
    time.sleep(2.0)
    still = _netstat_listen_pids(PORT)
    if still:
        print(f"[ExhaustShield] ERROR: port {PORT} still held by PIDs {sorted(still)}")
        return 2
    print("[ExhaustShield] starting gateway (no --reload)...")
    print(f"[ExhaustShield] open http://127.0.0.1:{PORT}/")
    child_env = os.environ.copy()
    return subprocess.call(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "gateway:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(PORT),
        ],
        env=child_env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
