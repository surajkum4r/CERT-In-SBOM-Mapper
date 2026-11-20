"""Markdown rendering of validation results."""
from __future__ import annotations

ICON = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}


def to_markdown(result: dict, max_items: int = 50) -> str:
    s = result["summary"]
    lines = [
        f"# CERT-In {result['bom_type']} conformance report",
        "",
        f"Guideline: {result['guideline']}  ",
        f"BOM: `{result.get('serial_number') or 'n/a'}`",
        "",
        f"**Verdict: {s['verdict']}** - conformance {s['conformance_pct']}% "
        f"(every field supplied or declared a known unknown), completeness {s['completeness_pct']}% "
        f"(fields with real values), {s['items']} item(s).",
        "",
        "| present | derived | known unknown | missing | n/a |",
        "|---:|---:|---:|---:|---:|",
        f"| {s['present']} | {s['derived']} | {s['unknown']} | {s['missing']} | {s['n/a']} |",
        "",
        "## Document checks",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    lines += [f"| {c['id']} | {ICON[c['status']]} | {c['message']} |" for c in result["document_checks"]]
    lines += ["", "## Field coverage", "", "| Field | Applies to | Present | Derived | Known unknown | Missing |",
              "|---|---|---:|---:|---:|---:|"]
    for cov in result["field_coverage"].values():
        if cov["present"] + cov["derived"] + cov["unknown"] + cov["missing"] == 0:
            continue
        lines.append(f"| {cov['label']} | {cov['kind']} | {cov['present']} | {cov['derived']} | {cov['unknown']} | {cov['missing']} |")
    vs = result.get("vulnerabilities")
    if vs and vs["components"]:
        sev = vs["by_severity"]
        lines += ["", "## Vulnerabilities", "",
                  f"Coverage: {vs['components_scanned']}/{vs['components']} components checked "
                  f"({vs['coverage_pct']}%) - sources: {', '.join(vs['sources']) or 'none'}  ",
                  f"Open: {vs['open']} of {vs['total']} - **{vs['open_kev']} actively exploited (CISA KEV)**"
                  + (f", **{vs['malicious']} malicious package(s)**" if vs["malicious"] else ""), "",
                  "| critical | high | medium | low | unscored |", "|---:|---:|---:|---:|---:|",
                  f"| {sev['critical']} | {sev['high']} | {sev['medium']} | {sev['low']} | {sev['unscored'] + sev['none']} |"]
        if vs["top"]:
            lines += ["", "| Priority | ID | Severity | EPSS | Component(s) | Fix |", "|---|---|---|---:|---|---|"]
            for v in vs["top"]:
                epss = f"{float(v['epss']):.2f}" if v.get("epss") else ""
                lines.append(f"| {(v['priority'] or '').split(' - ')[0]} | {v['id']} | {v['severity'] or ''} "
                             f"{v['score'] or ''} | {epss} | {', '.join(v['components'][:3])} | {(v['fix'] or '')[:80]} |")
        if vs["coverage_gaps"]:
            lines += ["", "Components not covered by any vulnerability source:", ""]
            lines += [f"- {g['name']}: {g['reason']}" for g in vs["coverage_gaps"][:20]]
    gaps = [it for it in result["items"] if any(f["status"] == "missing" for f in it["fields"].values())]
    lines += ["", f"## Items with missing fields ({len(gaps)})", ""]
    if not gaps:
        lines.append("None - every applicable field is either supplied or declared as a known unknown.")
    for it in gaps[:max_items]:
        missing = [f["label"] for f in it["fields"].values() if f["status"] == "missing"]
        lines.append(f"- **{it['name']}** (`{it['ref']}`): {', '.join(missing)}")
    if len(gaps) > max_items:
        lines.append(f"- ... and {len(gaps) - max_items} more (see JSON report)")
    return "\n".join(lines) + "\n"
