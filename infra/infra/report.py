"""Report rendering: JSON (raw) + HTML (presentable to a CTO).

The HTML report is the ACTUAL deliverable to the client. JSON is for
post-processing / piping into other tools.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)


def render_json(report: dict, output_path: str) -> None:
    """Write the report dict to disk as pretty JSON."""
    Path(output_path).write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )
    log.info(f"[REPORT] JSON written to {output_path}")


def render_html(report: dict, output_path: str, template_dir: str = "templates") -> None:
    """Render the HTML report from the Jinja2 template."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        log.error(
            "[REPORT] Jinja2 not installed. Install with: pip install jinja2"
        )
        return

    tpl_path = Path(template_dir)
    if not tpl_path.exists():
        log.error(f"[REPORT] Template directory not found: {template_dir}")
        return

    env = Environment(
        loader=FileSystemLoader(str(tpl_path)),
        autoescape=select_autoescape(["html"]),
    )

    # Filters used by template
    env.filters["humanbytes"] = _humanbytes
    env.filters["truncate_smart"] = lambda s, n=80: (
        s if len(str(s)) <= n else str(s)[: n - 1] + "…"
    )

    template = env.get_template("report.html.j2")
    html = template.render(
        report=report,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    Path(output_path).write_text(html, encoding="utf-8")
    log.info(f"[REPORT] HTML written to {output_path}")


def _humanbytes(n: int | float) -> str:
    """Format bytes into human-readable string (KB, MB, GB)."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def diff_reports(report1_path: str, report2_path: str) -> dict:
    """Compare two reports — useful for before/after audits."""
    r1 = json.loads(Path(report1_path).read_text(encoding="utf-8"))
    r2 = json.loads(Path(report2_path).read_text(encoding="utf-8"))

    devices1 = {d["ip"] for d in r1.get("devices", [])}
    devices2 = {d["ip"] for d in r2.get("devices", [])}

    saas1 = {s["domain"] for s in r1.get("saas_inventory", [])}
    saas2 = {s["domain"] for s in r2.get("saas_inventory", [])}

    return {
        "report_1": {
            "path": report1_path,
            "captured": r1.get("meta", {}).get("start", ""),
            "device_count": len(devices1),
            "saas_count": len(saas1),
        },
        "report_2": {
            "path": report2_path,
            "captured": r2.get("meta", {}).get("start", ""),
            "device_count": len(devices2),
            "saas_count": len(saas2),
        },
        "devices_added": sorted(devices2 - devices1),
        "devices_removed": sorted(devices1 - devices2),
        "saas_added": sorted(saas2 - saas1),
        "saas_removed": sorted(saas1 - saas2),
    }
