#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

LOCKFILES = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "bun.lock": "bun",
    "bun.lockb": "bun",
}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]
USES_RE = re.compile(r"uses:\s*([\w.-]+/[\w.-]+)(?:/[\w./-]+)?@([0-9a-f]{40})")
VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)$")
WORKFLOWS = Path(".github/workflows")
MAX_ROWS = 50


def detect_manager() -> tuple[str, str]:
    package = Path("package.json")
    if not package.is_file():
        return "", "no package.json at the repository root"
    declared = json.loads(package.read_text()).get("packageManager", "").split("@")[0]
    lockfiles = {name: manager for name, manager in LOCKFILES.items() if Path(name).is_file()}
    managers = set(lockfiles.values())
    if not lockfiles:
        return "", "no lockfile is committed, so installs are not reproducible and vulnerabilities can't be checked: commit one"
    if declared in managers:
        leftovers = [name for name, manager in lockfiles.items() if manager != declared]
        return declared, f"leftover lockfile(s) {', '.join(leftovers)} for a package manager this repo doesn't use: remove them" if leftovers else ""
    if len(managers) > 1:
        return "", f"several lockfiles ({', '.join(lockfiles)}): keep only the one for the package manager this repo uses"
    found = managers.pop()
    if declared:
        return found, f"package.json says packageManager {declared}, but the lockfile is {next(iter(lockfiles))}"
    return found, ""


def run(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True).stdout


def major(version: str) -> int | None:
    match = re.match(r"v?(\d+)", str(version))
    return int(match.group(1)) if match else None


def outdated(manager: str) -> list[dict]:
    if manager == "npm":
        report = json.loads(run("npm", "outdated", "--json") or "{}")
        entries = {name: info[0] if isinstance(info, list) else info for name, info in report.items()}
        rows = [(name, info.get("current"), info.get("wanted"), info.get("latest")) for name, info in entries.items()]
    elif manager == "pnpm":
        report = json.loads(run("pnpm", "outdated", "--format", "json") or "{}")
        rows = [(name, info.get("current"), info.get("wanted"), info.get("latest")) for name, info in report.items()]
    elif manager == "yarn":
        lines = [json.loads(line) for line in run("yarn", "outdated", "--json").splitlines() if line.startswith("{")]
        table = next((line for line in lines if line.get("type") == "table"), None)
        rows = [tuple(row[:4]) for row in table["data"]["body"]] if table else []
    else:
        rows = []
        for line in run("bun", "outdated").splitlines():
            cells = [cell.strip() for cell in re.split(r"[│|]", line)[1:-1]]
            if len(cells) >= 4 and cells[0] and cells[0] != "Package" and not set(cells[0]) <= set("-─"):
                rows.append((re.sub(r"\s*\(dev\)$", "", cells[0]), cells[1], cells[2], cells[3]))
    return [
        {"name": name, "current": current or "missing", "wanted": wanted, "latest": latest,
         "is_major": major(current) != major(latest)}
        for name, current, wanted, latest in sorted(rows)
    ]


def vulnerabilities(path: Path) -> list[dict] | None:
    if not path.is_file() or not path.read_text().strip():
        return None
    found = {}
    for result in json.loads(path.read_text()).get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            key = (vuln["VulnerabilityID"], vuln["PkgName"], vuln.get("InstalledVersion"))
            found[key] = {
                "id": vuln["VulnerabilityID"],
                "package": vuln["PkgName"],
                "installed": vuln.get("InstalledVersion", ""),
                "fixed": vuln.get("FixedVersion", ""),
                "severity": vuln.get("Severity", "MEDIUM"),
                "url": vuln.get("PrimaryURL", ""),
            }
    return sorted(found.values(), key=lambda v: (SEVERITIES.index(v["severity"]), v["package"]))


def github(path: str):
    request = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError:
        return None


def latest_release(repo: str) -> dict | None:
    release = github(f"repos/{repo}/releases/latest")
    tag = release["tag_name"] if release else ((github(f"repos/{repo}/tags?per_page=1") or [{}])[0]).get("name")
    if not tag:
        return None
    if not VERSION_RE.match(tag):
        versions = [t["name"] for t in github(f"repos/{repo}/tags?per_page=100") or [] if VERSION_RE.match(t["name"])]
        if versions:
            tag = max(versions, key=lambda name: tuple(map(int, VERSION_RE.match(name).groups())))
    commit = github(f"repos/{repo}/commits/{tag}")
    return {"tag": tag, "sha": commit["sha"] if commit else ""}


def tag_for(repo: str, sha: str) -> str:
    names = [tag["name"] for tag in github(f"repos/{repo}/tags?per_page=100") or [] if tag["commit"]["sha"] == sha]
    return max(names, key=len) if names else sha[:7]


def action_pins() -> list[dict]:
    pins: dict[tuple[str, str], set[str]] = {}
    for file in sorted(WORKFLOWS.glob("*.y*ml")) if WORKFLOWS.is_dir() else []:
        for repo, sha in USES_RE.findall(file.read_text()):
            pins.setdefault((repo, sha), set()).add(file.name)
    releases: dict[str, dict | None] = {}
    actions = []
    for (repo, sha), files in sorted(pins.items()):
        if repo not in releases:
            releases[repo] = latest_release(repo)
        latest = releases[repo]
        tag = tag_for(repo, sha)
        is_current = bool(latest) and sha == latest["sha"]
        actions.append({
            "repo": repo, "sha": sha, "tag": tag, "latest": latest, "files": sorted(files),
            "is_current": is_current,
            "is_major_behind": bool(latest) and not is_current and major(tag) != major(latest["tag"]),
        })
    return actions


def render(manager: str, problem: str, install_failed: bool, vulns: list[dict] | None,
           packages: list[dict], actions: list[dict], fail_severity: str) -> tuple[str, list[str]]:
    issues = [problem] if problem else []
    lines = [f"Package manager: **{manager or 'unknown'}**", ""]

    lines += ["### Vulnerabilities", ""]
    if not manager:
        lines.append("Not checked: no usable lockfile.")
    elif vulns is None:
        issues.append("trivy produced no report (see the scan step's log)")
        lines.append("trivy produced no report.")
    elif not vulns:
        lines.append("None with a fix available (MEDIUM and above).")
    else:
        blocking = [v for v in vulns if SEVERITIES.index(v["severity"]) <= SEVERITIES.index(fail_severity)]
        if blocking:
            issues.append(f"{len(blocking)} vulnerable package version(s) at {fail_severity} or above with a fix available")
        lines += [f"{len(vulns)} with a fix available, {len(blocking)} at {fail_severity} or above.", "",
                  "| Severity | Advisory | Package | Installed | Fixed in |", "|---|---|---|---|---|"]
        for v in vulns[:MAX_ROWS]:
            advisory = f"[{v['id']}]({v['url']})" if v["url"] else v["id"]
            lines.append(f"| {v['severity']} | {advisory} | {v['package']} | {v['installed']} | {v['fixed']} |")
        if len(vulns) > MAX_ROWS:
            lines.append(f"\n{len(vulns) - MAX_ROWS} more not shown.")

    lines += ["", "### Outdated packages", ""]
    if install_failed:
        issues.append("the frozen-lockfile install failed (see the install step's log): most often the lockfile is out of sync with package.json")
        lines.append("Not checked: the install failed (see the install step's log).")
    elif not manager:
        lines.append("Not checked: no usable lockfile.")
    elif not packages:
        lines.append("All packages are on their latest version.")
    else:
        majors = sum(p["is_major"] for p in packages)
        lines += [f"{len(packages)} behind their latest version, {majors} of them a new major (read the changelog first). "
                  "Dependabot opens the update pull requests; this list is information only.", "",
                  "| Package | Installed | Within range | Latest | Change |", "|---|---|---|---|---|"]
        for p in packages[:MAX_ROWS]:
            lines.append(f"| {p['name']} | {p['current']} | {p['wanted']} | {p['latest']} | {'major' if p['is_major'] else 'minor/patch'} |")
        if len(packages) > MAX_ROWS:
            lines.append(f"\n{len(packages) - MAX_ROWS} more not shown.")

    lines += ["", "### GitHub Actions", ""]
    if not actions:
        lines.append("No actions pinned by commit.")
    else:
        lines += ["| Action | Pinned | Latest release | Workflows |", "|---|---|---|---|"]
        for a in actions:
            if a["is_major_behind"]:
                issues.append(f"{a['repo']} is pinned to {a['tag']}, latest is {a['latest']['tag']}")
            if not a["latest"]:
                status = "latest release unknown"
            elif a["is_current"]:
                status = "ok"
            else:
                status = f"{a['latest']['tag']}{', **new major**' if a['is_major_behind'] else ''}"
            lines.append(f"| {a['repo']} | {a['tag']} ({a['sha'][:7]}) | {status} | {', '.join(a['files'])} |")

    lines += ["", f"**{len(issues)} item(s) need action:**" if issues else "**Nothing needs action.**"]
    lines += [f"- {issue}" for issue in issues]
    return "\n".join(lines), issues


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("detect")
    report = commands.add_parser("report")
    report.add_argument("--trivy", type=Path, required=True)
    report.add_argument("--fail-severity", choices=SEVERITIES, default="HIGH")
    args = parser.parse_args()

    manager, problem = detect_manager()
    if args.command == "detect":
        print(f"manager={manager}")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as out:
                out.write(f"manager={manager}\n")
        return 0

    install_failed = os.environ.get("INSTALL_OUTCOME") == "failure"
    markdown, issues = render(
        manager, problem, install_failed,
        vulnerabilities(args.trivy) if manager else None,
        outdated(manager) if manager and not install_failed else [],
        action_pins(), args.fail_severity,
    )
    print(markdown)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(f"## Dependency check\n\n{markdown}\n")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
