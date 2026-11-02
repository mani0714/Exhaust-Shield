@echo off
title ExhaustShield Demo
cd /d "%~dp0"

REM UTF-8 + no proxy — Groq fails often when Windows injects a broken proxy
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "http_proxy="
set "https_proxy="
set "ALL_PROXY="
set "all_proxy="
set "NO_PROXY=*"
set "no_proxy=*"

REM Live Groq credentials are loaded from .env by start_gateway.py
if exist "%~dp0.env" (
  echo Found .env — start_gateway.py will load EXTERNAL_AI_* from it.
) else (
  echo No .env found — starting in SIMULATE mode unless the key is already in the environment.
  echo To use live Groq: copy .env.example to .env and paste your key.
  echo.
)

echo Open http://127.0.0.1:8000/
echo Keep this window open during the demo. Close Cursor anytime.
echo.
python start_gateway.py
echo.
echo Server stopped.
pause
