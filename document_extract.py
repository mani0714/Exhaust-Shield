"""Extract plain text from uploaded office/docs/images for ExhaustShield chat.

Sensitive content is NOT sent to any LLM here — extraction is local only.
Outbound scrubbing (table synthetic / analysis scale) happens later in suggest_rewrite.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any


SUPPORTED_EXTENSIONS = {
    ".txt",
    ".md",
    ".csv",
    ".tsv",
    ".json",
    ".log",
    ".pdf",
    ".docx",
    ".doc",
    ".xlsx",
    ".xls",
    ".pptx",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".bmp",
    ".tif",
    ".tiff",
}


def _ext(name: str) -> str:
    n = (name or "").rsplit(".", 1)
    return f".{n[-1].lower()}" if len(n) == 2 else ""


def extract_attachment(
    filename: str, data: bytes, *, max_chars: int = 120_000
) -> dict[str, Any]:
    """Return {ok, filename, text, kind, warnings, chars}."""
    name = filename or "upload.bin"
    ext = _ext(name)
    warnings: list[str] = []
    text = ""
    kind = "unknown"

    try:
        if ext in {".txt", ".md", ".log", ".json"}:
            kind = "text"
            text = data.decode("utf-8", errors="ignore")
        elif ext in {".csv", ".tsv"}:
            kind = "table"
            text = _extract_csv(data, ext)
        elif ext == ".pdf":
            kind = "pdf"
            text, warnings = _extract_pdf(data, warnings)
        elif ext in {".docx", ".doc"}:
            kind = "word"
            text, warnings = _extract_docx(data, warnings)
        elif ext in {".xlsx", ".xls"}:
            kind = "excel"
            text, warnings = _extract_xlsx(data, warnings)
        elif ext == ".pptx":
            kind = "pptx"
            text, warnings = _extract_pptx(data, warnings)
        elif ext in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}:
            kind = "image"
            text, warnings = _extract_image(data, warnings)
        else:
            # Best-effort UTF-8
            kind = "binary_text"
            text = data.decode("utf-8", errors="ignore")
            if len(text.strip()) < 8:
                return {
                    "ok": False,
                    "filename": name,
                    "text": "",
                    "kind": kind,
                    "warnings": [f"Unsupported or empty file type: {ext or 'unknown'}"],
                    "chars": 0,
                }
    except Exception as exc:  # noqa: BLE001 — surface to UI
        return {
            "ok": False,
            "filename": name,
            "text": "",
            "kind": kind,
            "warnings": [f"Extract failed: {exc}"],
            "chars": 0,
        }

    text = (text or "").strip()
    if len(text) > max_chars:
        text = text[:max_chars] + "\n\n[…truncated for gateway size limit…]"
        warnings.append(f"Truncated to {max_chars:,} characters")

    if not text:
        warnings.append("No extractable text found (scanned PDF/image may need OCR)")
        return {
            "ok": False,
            "filename": name,
            "text": "",
            "kind": kind,
            "warnings": warnings,
            "chars": 0,
        }

    return {
        "ok": True,
        "filename": name,
        "text": text,
        "kind": kind,
        "warnings": warnings,
        "chars": len(text),
        "looks_like_dataset": _looks_tabular(text),
    }


def _looks_tabular(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 3:
        return False
    commas = sum(1 for ln in lines[:12] if ln.count(",") >= 2)
    pipes = sum(1 for ln in lines[:12] if ln.count("|") >= 2)
    tabs = sum(1 for ln in lines[:12] if ln.count("\t") >= 2)
    return max(commas, pipes, tabs) >= 3


def _extract_csv(data: bytes, ext: str) -> str:
    raw = data.decode("utf-8", errors="ignore")
    if ext == ".tsv":
        return raw
    # Normalize via csv module for quoted fields
    try:
        reader = csv.reader(io.StringIO(raw))
        rows = [",".join(cells) for cells in reader]
        return "\n".join(rows)
    except Exception:
        return raw


def _extract_pdf(data: bytes, warnings: list[str]) -> tuple[str, list[str]]:
    try:
        from pypdf import PdfReader  # type: ignore
    except ImportError:
        warnings.append("Install pypdf for PDF text extraction: pip install pypdf")
        return "", warnings
    reader = PdfReader(io.BytesIO(data))
    parts: list[str] = []
    for page in reader.pages[:40]:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            continue
    text = "\n".join(parts).strip()
    if not text:
        warnings.append("PDF had no embedded text (likely scanned) — OCR not available")
    return text, warnings


def _extract_docx(data: bytes, warnings: list[str]) -> tuple[str, list[str]]:
    try:
        from docx import Document  # type: ignore
    except ImportError:
        warnings.append("Install python-docx for Word extraction: pip install python-docx")
        return "", warnings
    try:
        doc = Document(io.BytesIO(data))
    except Exception as exc:
        warnings.append(f"Word parse error (legacy .doc may need conversion): {exc}")
        return "", warnings
    parts: list[str] = []
    for p in doc.paragraphs:
        if p.text.strip():
            parts.append(p.text)
    for table in doc.tables:
        for row in table.rows:
            cells = [c.text.strip().replace("\n", " ") for c in row.cells]
            if any(cells):
                parts.append(",".join(cells))
    return "\n".join(parts), warnings


def _extract_xlsx(data: bytes, warnings: list[str]) -> tuple[str, list[str]]:
    try:
        from openpyxl import load_workbook  # type: ignore
    except ImportError:
        warnings.append("Install openpyxl for Excel extraction: pip install openpyxl")
        return "", warnings
    try:
        wb = load_workbook(io.BytesIO(data), data_only=True, read_only=True)
    except Exception as exc:
        warnings.append(f"Excel parse error: {exc}")
        return "", warnings
    parts: list[str] = []
    for sheet in wb.worksheets[:8]:
        parts.append(f"### Sheet: {sheet.title}")
        row_i = 0
        for row in sheet.iter_rows(values_only=True):
            row_i += 1
            if row_i > 500:
                parts.append("[…sheet truncated…]")
                break
            cells = ["" if c is None else str(c).strip() for c in row]
            if any(cells):
                parts.append(",".join(cells))
    return "\n".join(parts), warnings


def _extract_pptx(data: bytes, warnings: list[str]) -> tuple[str, list[str]]:
    try:
        from pptx import Presentation  # type: ignore
    except ImportError:
        warnings.append("Install python-pptx for PowerPoint extraction: pip install python-pptx")
        return "", warnings
    try:
        prs = Presentation(io.BytesIO(data))
    except Exception as exc:
        warnings.append(f"PowerPoint parse error: {exc}")
        return "", warnings
    parts: list[str] = []
    for i, slide in enumerate(prs.slides, 1):
        parts.append(f"### Slide {i}")
        for shape in slide.shapes:
            if hasattr(shape, "text") and shape.text.strip():
                parts.append(shape.text.strip())
    return "\n".join(parts), warnings


def _extract_image(data: bytes, warnings: list[str]) -> tuple[str, list[str]]:
    """OCR when pytesseract + Tesseract are available; otherwise empty with warning."""
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        warnings.append("Install pillow for images: pip install pillow")
        return "", warnings
    try:
        img = Image.open(io.BytesIO(data))
    except Exception as exc:
        warnings.append(f"Image open failed: {exc}")
        return "", warnings
    try:
        import pytesseract  # type: ignore

        text = pytesseract.image_to_string(img) or ""
        if not text.strip():
            warnings.append("OCR returned no text")
        return text, warnings
    except Exception:
        warnings.append(
            "Image OCR unavailable (optional: pip install pytesseract + Tesseract OCR). "
            "Paste text from the image, or convert to PDF/Word."
        )
        return "", warnings


def build_prompt_with_attachments(
    user_prompt: str, attachments: list[dict[str, Any]]
) -> str:
    """Compose user ask + extracted attachment bodies for gateway analysis."""
    ask = (user_prompt or "").strip()
    blocks: list[str] = []
    for att in attachments or []:
        if not att.get("ok") or not (att.get("text") or "").strip():
            continue
        name = att.get("filename") or "attachment"
        kind = att.get("kind") or "file"
        body = (att.get("text") or "").strip()
        blocks.append(f"--- Attached ({kind}): {name} ---\n{body}")
    if not blocks:
        return ask
    if not ask:
        ask = (
            "Summarize and analyze the attached document(s). "
            "Highlight key figures, risks, and recommended next steps."
        )
    elif not re.search(r"(?i)\b(summariz|analy[sz]|review|extract|key\s+point)", ask):
        # Keep user's ask; attachments follow
        pass
    return ask + "\n\n" + "\n\n".join(blocks)
