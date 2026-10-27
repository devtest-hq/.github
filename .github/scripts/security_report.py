#!/usr/bin/env python3
"""Turn semgrep and trivy JSON into a job summary and one PR comment.

Used by .github/workflows/security-code.yml and security-image.yml. Standard
library only (runs on the runner's python3, nothing installed).

  security_report.py code  --head-semgrep F --head-trivy F
                           [--base-semgrep F --base-trivy F]
  security_report.py image --trivy F --image REF
  security_report.py comment BODY_FILE

code: with the base files, only findings the pull request ADDS are "new" (a
finding is matched by rule and place, not line number, so moved code is not
new). Without them (a push or a scheduled run), every finding is listed.

Writes the summary to $GITHUB_STEP_SUMMARY, the comment body to
$RUNNER_TEMP/security-comment.md, and "new" / "new_blocking" (new at
--fail-severity or above) to $GITHUB_OUTPUT.

Never prints a secret's value or a code line: secrets are reported by rule,
file and line only, the same rule as the sec01 weekly scan
(devtest-security/testing/normalizers.py).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections import Counter
from pathlib import Path

MARKER = "<!-- devtest-security-scan -->"
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RANK = {s: i for i, s in enumerate(reversed(SEVS))}
SEMGREP_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
CONF_CAP = {"LOW": "LOW", "MEDIUM": "MEDIUM"}
MAX_ROWS = 50


def _load(path: str | None) -> dict | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file() or not p.read_text().strip():
        return None
    return json.loads(p.read_text())


def _strip(path: str) -> str:
    """Both checkouts are scanned mounted at /src, so paths compare equal."""
    return path[len("/src/"):] if path.startswith("/src/") else path


def semgrep(report: dict | None) -> list[dict]:
    out = []
    for r in (report or {}).get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        sev = SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), "INFO")
        cap = CONF_CAP.get(str(meta.get("confidence", "")).upper())
        if cap and RANK[sev] > RANK[cap]:
            sev = cap
        path = _strip(r.get("path", ""))
        check = r.get("check_id", "")
        msg = " ".join(str(extra.get("message", "")).split())
        out.append({"tool": "semgrep", "sev": sev, "key": ("semgrep", check, path, msg),
                    "title": check.rsplit(".", 1)[-1],
                    "where": f"{path}:{(r.get('start') or {}).get('line', '?')}",
                    "detail": msg})
    return out


def trivy(report: dict | None) -> list[dict]:
    out = []
    for r in (report or {}).get("Results") or []:
        where = _strip(r.get("Target", ""))
        for v in r.get("Vulnerabilities") or []:
            vid, pkg, ver = v.get("VulnerabilityID", ""), v.get("PkgName", ""), \
                v.get("InstalledVersion", "")
            out.append({"tool": "trivy", "sev": str(v.get("Severity", "INFO")).upper(),
                        "key": ("vuln", where, vid, pkg, ver),
                        "title": f"{vid} in {pkg} {ver}".strip(), "where": where,
                        "detail": f"fixed in {v.get('FixedVersion') or '?'}"})
        for s in r.get("Secrets") or []:   # never Match / Code: they hold the value
            out.append({"tool": "trivy", "sev": str(s.get("Severity", "HIGH")).upper(),
                        "key": ("secret", where, s.get("RuleID", "")),
                        "title": f"Secret: {s.get('Title') or s.get('RuleID', '')}",
                        "where": f"{where}:{s.get('StartLine', '?')}",
                        "detail": "revoke it first, then remove it from the code"})
        for m in r.get("Misconfigurations") or []:
            if m.get("Status") not in (None, "FAIL"):
                continue
            out.append({"tool": "trivy", "sev": str(m.get("Severity", "INFO")).upper(),
                        "key": ("misconfig", where, m.get("ID", "")),
                        "title": f"{m.get('ID', '')}: {m.get('Title', '')}",
                        "where": where, "detail": m.get("Resolution", "")})
    return out


def new_only(head: list[dict], base: list[dict]) -> list[dict]:
    """Findings in head beyond those in base (multiset, matched by key)."""
    left = Counter(f["key"] for f in base)
    out = []
    for f in head:
        if left[f["key"]]:
            left[f["key"]] -= 1
        else:
            out.append(f)
    return out


def _cell(text: str, limit: int = 120) -> str:
    t = " ".join(str(text or "").split()).replace("|", "/")
    return t if len(t) <= limit else t[:limit - 1] + "…"


def table(findings: list[dict]) -> list[str]:
    rows = sorted(findings, key=lambda f: -RANK.get(f["sev"], 0))
    lines = ["| Severity | Tool | Finding | Where | Note |", "|---|---|---|---|---|"]
    for f in rows[:MAX_ROWS]:
        lines.append(f"| {f['sev']} | {f['tool']} | {_cell(f['title'])} | "
                     f"`{_cell(f['where'], 80)}` | {_cell(f['detail'])} |")
    if len(rows) > MAX_ROWS:
        lines.append(f"\n_{len(rows) - MAX_ROWS} more in the job log._")
    return lines


def counts(findings: list[dict]) -> str:
    c = Counter(f["sev"] for f in findings)
    return " · ".join(f"{c[s]} {s.lower()}" for s in SEVS[:4] if c[s]) or "none"


def _out(name: str, value) -> None:
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.write(f"{name}={value}\n")


def _summary(md: str) -> None:
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(md)
    else:
        print(md)


def report(title: str, new: list[dict], total: list[dict], diff: bool,
           fail_sev: str, notes: list[str]) -> str:
    blocking = [f for f in new if RANK.get(f["sev"], 0) >= RANK[fail_sev]]
    _out("new", len(new))
    _out("new_blocking", len(blocking))
    lines = [MARKER, f"## {title}", ""]
    if diff:
        lines.append(f"**New in this pull request:** {counts(new)}. "
                     f"In the whole branch: {counts(total)}.")
    else:
        lines.append(f"**Findings:** {counts(total)}.")
    lines += [""] + [f"> {n}" for n in notes] + ([""] if notes else [])
    shown = new if diff else total
    if shown:
        lines += table(shown) + [""]
    else:
        lines += ["Nothing to report." if not diff else
                  "This pull request adds no findings.", ""]
    lines += ["<sub>semgrep CE (p/default) and trivy (dependencies with a fix, "
              "secrets, config), MEDIUM and up. Advisory. Same tools and versions "
              "as the weekly scan on sec01. A wrong finding: say so in the PR; "
              "the security group tunes the rules.</sub>", ""]
    md = "\n".join(lines)
    _summary(md + "\n")
    Path(os.environ.get("RUNNER_TEMP", "."), "security-comment.md").write_text(md)
    return md


def post_comment(body_file: str) -> None:
    """Create or update the one comment carrying MARKER on this PR."""
    token, repo, pr = (os.environ["GH_TOKEN"], os.environ["REPO"],
                       os.environ["PR_NUMBER"])
    body = Path(body_file).read_text()
    api = f"https://api.github.com/repos/{repo}/issues"

    def call(method: str, url: str, data: dict | None = None):
        req = urllib.request.Request(
            url, method=method, data=json.dumps(data).encode() if data else None,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"null")

    existing = None
    page = 1
    while existing is None:
        batch = call("GET", f"{api}/{pr}/comments?per_page=100&page={page}")
        existing = next((c for c in batch if MARKER in (c.get("body") or "")), None)
        if len(batch) < 100:
            break
        page += 1
    if existing:
        call("PATCH", f"{api}/comments/{existing['id']}", {"body": body})
        print(f"updated comment {existing['id']}")
    else:
        c = call("POST", f"{api}/{pr}/comments", {"body": body})
        print(f"posted comment {c['id']}")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    c = sub.add_parser("code")
    c.add_argument("--head-semgrep", required=True)
    c.add_argument("--head-trivy", required=True)
    c.add_argument("--base-semgrep")
    c.add_argument("--base-trivy")
    c.add_argument("--fail-severity", default="HIGH", type=str.upper, choices=SEVS)
    i = sub.add_parser("image")
    i.add_argument("--trivy", required=True)
    i.add_argument("--image", required=True)
    i.add_argument("--fail-severity", default="HIGH", type=str.upper, choices=SEVS)
    m = sub.add_parser("comment")
    m.add_argument("body_file")
    a = ap.parse_args()

    if a.mode == "comment":
        post_comment(a.body_file)
        return 0
    if a.mode == "image":
        rep = _load(a.trivy)
        if rep is None:
            print("::error::trivy produced no output")
            return 1
        total = trivy(rep)
        report(f"Image scan: {a.image}", total, total, False, a.fail_severity,
               ["Vulnerabilities with a fixed version only: upgrade the base "
                "image or the package."])
        return 0

    hs, ht = _load(a.head_semgrep), _load(a.head_trivy)
    notes = []
    if hs is None:
        notes.append("semgrep produced no output on this branch (see the job log).")
    if ht is None:
        notes.append("trivy produced no output on this branch (see the job log).")
    total = semgrep(hs) + trivy(ht)
    diff = bool(a.base_semgrep or a.base_trivy)
    new = total
    if diff:
        bs, bt = _load(a.base_semgrep), _load(a.base_trivy)
        if bs is None or bt is None:
            notes.append("The base branch scan failed, so every finding counts as new.")
        new = new_only(total, semgrep(bs) + trivy(bt))
    report("Security scan (semgrep + trivy)", new, total, diff, a.fail_severity, notes)
    return 1 if hs is None or ht is None else 0


if __name__ == "__main__":
    sys.exit(main())
