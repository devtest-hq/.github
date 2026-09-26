#!/usr/bin/env python3
"""Turn zizmor's json-v1 output into a GitHub pull request review.

Two subcommands:
  annotate <findings.json>   emit ::warning workflow commands (fork fallback)
  review   <findings.json>   post one PR review, inline where the diff allows

Environment for `review`: GH_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, HEAD_SHA,
REVIEW_EVENT (COMMENT or REQUEST_CHANGES).
"""

import json
import os
import re
import subprocess
import sys

SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
SEV_ICON = {"High": "🔴", "Medium": "🟠", "Low": "🟡", "Informational": "🔵"}
MARKER = "<!-- zizmor-review -->"


def gh(*args, stdin=None):
    """Call gh, returning parsed JSON."""
    out = subprocess.run(
        ["gh", *args], capture_output=True, text=True, input=stdin, check=True
    ).stdout
    return json.loads(out) if out.strip() else None


def primary_location(finding):
    """zizmor emits Primary, Related and Hidden locations; anchor on Primary.

    Anchoring on all of them would post the same finding several times.
    """
    locations = finding.get("locations", [])
    for loc in locations:
        if loc.get("symbolic", {}).get("kind") == "Primary":
            return loc
    return locations[0] if locations else None


def normalise(finding):
    loc = primary_location(finding)
    if not loc:
        return None
    key = loc.get("symbolic", {}).get("key", {})
    if "Local" not in key:
        return None  # a remote input; nothing to comment on in this repo
    path = re.sub(r"^\./", "", key["Local"]["verbatim_path"])
    return {
        "ident": finding["ident"],
        "desc": finding.get("desc", ""),
        "url": finding.get("url", ""),
        "severity": finding.get("determinations", {}).get("severity", "Unknown"),
        "confidence": finding.get("determinations", {}).get("confidence", "Unknown"),
        "path": path,
        # start_point.row is 0-indexed; GitHub line numbers are 1-indexed.
        "line": loc["concrete"]["location"]["start_point"]["row"] + 1,
        "annotation": loc.get("symbolic", {}).get("annotation", ""),
        "snippet": loc.get("concrete", {}).get("feature", "").split("\n")[0].strip(),
        "fixable": bool(finding.get("fixes")),
    }


def load(path):
    with open(path) as fh:
        findings = [normalise(f) for f in json.load(fh)]
    findings = [f for f in findings if f]
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["path"], f["line"]))
    return findings


def marker_for(f):
    return f"<!-- zizmor:{f['ident']}:{f['path']}:{f['line']} -->"


def describe(f):
    icon = SEV_ICON.get(f["severity"], "⚪")
    head = f"{icon} **zizmor: `{f['ident']}`** ({f['severity']} severity, {f['confidence']} confidence)"
    body = f"{head}\n\n{f['desc']}"
    if f["annotation"]:
        body += f" — {f['annotation']}"
    if f["url"]:
        body += f"\n\n[What this means and how to fix it]({f['url']})"
    return body + f"\n\n{marker_for(f)}"


# --------------------------------------------------------------------------
# annotate
# --------------------------------------------------------------------------


def annotate(findings):
    for f in findings:
        msg = f"{f['desc']}"
        if f["annotation"]:
            msg += f" ({f['annotation']})"
        # GitHub workflow commands are newline-delimited; encode any newline.
        msg = msg.replace("\n", "%0A")
        level = "error" if f["severity"] == "High" else "warning"
        print(
            f"::{level} file={f['path']},line={f['line']},"
            f"title=zizmor: {f['ident']}::{msg}"
        )


# --------------------------------------------------------------------------
# review
# --------------------------------------------------------------------------


def diff_lines(repo, pr):
    """Map path -> set of line numbers that exist on the right side of the diff.

    A review comment can only anchor to a line inside a hunk. Findings outside
    one go in the review body instead; dropping them would let a reviewer
    believe an untouched workflow file is clean.
    """
    files = gh("api", f"repos/{repo}/pulls/{pr}/files", "--paginate") or []
    commentable = {}
    for entry in files:
        patch = entry.get("patch")
        if not patch:
            continue  # binary, or too large for GitHub to include
        lines = set()
        new_line = 0
        for raw in patch.split("\n"):
            hunk = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", raw)
            if hunk:
                new_line = int(hunk.group(1))
                continue
            if raw.startswith("-"):
                continue  # left side only
            if raw.startswith("+") or raw.startswith(" "):
                lines.add(new_line)
                new_line += 1
        commentable[entry["filename"]] = lines
    return commentable


def already_commented(repo, pr):
    comments = gh("api", f"repos/{repo}/pulls/{pr}/comments", "--paginate") or []
    reviews = gh("api", f"repos/{repo}/pulls/{pr}/reviews", "--paginate") or []
    seen = set()
    for c in comments + reviews:
        for m in re.findall(r"<!-- zizmor:[^>]+ -->", c.get("body") or ""):
            seen.add(m)
    return seen


def build_body(out_of_diff, total, suppressed):
    lines = [
        "## 🌈 zizmor — GitHub Actions security review",
        "",
        f"**{total} finding{'s' if total != 1 else ''}** in this repository's "
        "workflow files. These are security findings; please treat them as "
        "higher priority than style feedback on this pull request.",
        "",
    ]
    if out_of_diff:
        lines += [
            f"### {len(out_of_diff)} finding(s) outside this diff",
            "",
            "These are in workflow files this pull request does not touch, so "
            "they cannot be inline comments. They are pre-existing — not "
            "introduced here — but they are real:",
            "",
            "| Severity | Rule | Location |",
            "| --- | --- | --- |",
        ]
        for f in out_of_diff:
            icon = SEV_ICON.get(f["severity"], "⚪")
            rule = f"[`{f['ident']}`]({f['url']})" if f["url"] else f"`{f['ident']}`"
            # The marker is what stops this row being re-posted on the next
            # push. Inline comments carry one already; without it here, the
            # out-of-diff table was rebuilt verbatim on every push, because
            # already_commented() had nothing to match these findings against.
            lines.append(
                f"| {icon} {f['severity']} | {rule} | "
                f"`{f['path']}:{f['line']}` {marker_for(f)} |"
            )
        lines.append("")
    if suppressed:
        lines.append(
            f"_{suppressed} finding(s) already commented on an earlier push are "
            "not repeated._"
        )
        lines.append("")
    lines.append(MARKER)
    return "\n".join(lines)


def review(findings):
    repo = os.environ["GITHUB_REPOSITORY"]
    pr = os.environ["PR_NUMBER"]
    event = os.environ.get("REVIEW_EVENT", "COMMENT")

    commentable = diff_lines(repo, pr)
    seen = already_commented(repo, pr)

    inline, out_of_diff, suppressed = [], [], 0
    for f in findings:
        if marker_for(f) in seen:
            suppressed += 1
            continue
        if f["line"] in commentable.get(f["path"], set()):
            inline.append(
                {
                    "path": f["path"],
                    "line": f["line"],
                    "side": "RIGHT",
                    "body": describe(f),
                }
            )
        else:
            out_of_diff.append(f)

    if not inline and not out_of_diff:
        print("every finding was already commented; posting nothing")
        return 0

    payload = {
        "commit_id": os.environ["HEAD_SHA"],
        "event": event,
        "body": build_body(out_of_diff, len(findings), suppressed),
        "comments": inline,
    }

    try:
        post(repo, pr, payload)
    except subprocess.CalledProcessError as exc:
        # GitHub rejects the whole review if any single comment anchors to a
        # line it does not consider part of the diff. Losing every finding to
        # one bad anchor is the worst outcome, so fall back to a body-only
        # review that still reports all of them.
        print(f"::warning::inline review rejected ({exc.stderr.strip()}); "
              "falling back to a summary-only review")
        payload["body"] = build_body(findings, len(findings), suppressed)
        payload["comments"] = []
        post(repo, pr, payload)
    return 0


def post(repo, pr, payload):
    subprocess.run(
        ["gh", "api", "-X", "POST", f"repos/{repo}/pulls/{pr}/reviews", "--input", "-"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=True,
    )
    print(f"posted {len(payload['comments'])} inline comment(s) as {payload['event']}")


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    mode, path = sys.argv[1], sys.argv[2]
    findings = load(path)
    if not findings:
        print("zizmor found nothing")
        return 0
    if mode == "annotate":
        annotate(findings)
        return 0
    if mode == "review":
        return review(findings)
    print(f"unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
