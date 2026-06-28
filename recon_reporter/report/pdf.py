"""Optional PDF export. weasyprint is heavy (system libs), so it's NOT a dependency —
to_pdf() returns False if it isn't installed, and the CLI tells the user how to get it
(or just print the HTML report from a browser). The graceful-absence path is the default."""
from __future__ import annotations

from pathlib import Path

from ..logconf import get_logger

log = get_logger(__name__)


def available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except Exception:
        return False


def to_pdf(html_string: str, out_path: str | Path) -> bool:
    """Render HTML to a PDF file. Returns True on success, False if weasyprint is absent
    or rendering fails (caller should fall back to the HTML report)."""
    try:
        from weasyprint import HTML
    except Exception:
        log.info("weasyprint not installed; skipping PDF (use the HTML report instead)")
        return False
    try:
        HTML(string=html_string).write_pdf(str(out_path))
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("PDF rendering failed: %s", e)
        return False
