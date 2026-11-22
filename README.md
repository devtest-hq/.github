# devtest-hq/.github

Org-wide GitHub defaults: the pull request template, and shared reusable
workflows.

## zizmor — GitHub Actions security review on pull requests

[zizmor](https://docs.zizmor.sh/) is a static analyser for GitHub Actions. It
finds template injection, over-scoped `GITHUB_TOKEN`, unpinned actions,
credentials left on disk by `actions/checkout`, and similar. This repo runs it
for the whole org and posts findings as **review comments on the pull request
diff**, alongside the human reviewer.

### Adding it to a repo

**Two files**, both in the target repo.

`.github/workflows/zizmor.yml` — copy
`.github/workflow-templates/zizmor.yml`, or pick "zizmor — Actions security
review" from the Actions → New workflow page, which offers the same file:

```yaml
name: zizmor
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
permissions: {}
jobs:
  zizmor:
    permissions:
      contents: read
      pull-requests: write
    uses: devtest-hq/.github/.github/workflows/zizmor.yml@zizmor-v1
```

`.github/zizmor.yml` — the pinning policy:

```yaml
rules:
  unpinned-uses:
    config:
      policies:
        # Our own reusable workflows may be tag-pinned; see "Why the tag
        # moves" below. Everything else needs a full commit hash.
        devtest-hq/*: ref-pin
        "*": hash-pin
```

**Do not skip the second file.** zizmor's default policy demands a commit hash
for every `uses:`, including `actions/checkout` and including the caller's own
`@zizmor-v1` line — so without it, adding the check makes every repo report a
High finding against the check itself. Verified against 1.30.1: with this
policy the caller is clean, while a third-party tag pin such as
`appleboy/ssh-action@v1` is still reported High.

zizmor's configuration is discovered per repository, so this file has to exist
in each one; there is no org-level equivalent.

### Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `request-changes` | `false` | Post as `REQUEST_CHANGES` instead of `COMMENT`, gating the merge button where branch protection requires an approving review. |
| `fail-on-findings` | `false` | Fail the check when zizmor reports anything. A zizmor *crash* fails the job regardless. |
| `min-severity` | `""` | `informational`, `low`, `medium` or `high`. Empty reports everything. |
| `persona` | `regular` | `regular`, `pedantic` or `auditor`. |

Both booleans default to `false` so a repo can adopt the check before its
existing findings are fixed. Raising them org-wide is one edit here plus moving
the `zizmor-v1` tag — not a pull request in every repo. That is the entire
reason this is a reusable workflow rather than a file copied 13 times.

### Why the tag moves, when everything else in this org is pinned by digest

`devtest-infra/CLAUDE.md` insists on pinned digests so upstream changes arrive
as a reviewable diff. This repo is ours: every change to it already arrives as
a reviewed pull request in our own org. Pinning callers to a commit SHA would
mean 13 pull requests to change one severity threshold, which is how a rollout
stops being maintained.

### What it does not do

It does not upload SARIF to GitHub code scanning, which is what zizmor's own
documentation recommends. Code scanning requires GitHub Code Security, which
this org's Team plan does not include (~$180/month at 6 active committers), and
it would not produce review comments anyway — it produces check annotations and
Security-tab alerts.

## For engineers: what zizmor will do on your pull requests

**What it is.** A static analyser for GitHub Actions. It reads your
`.github/workflows/*.yml` files and reports security problems in the CI itself.

**It does not read your application code.** zizmor only collects four kinds of
file: workflows, composite action definitions (`action.yml`), `dependabot.yml`
and pre-commit configs. Point it at a repo of pure JavaScript or Python and it
exits with "no inputs collected" — your source is never parsed. If you want
analysis of application code, that is a different tool and a separate decision.

**When it runs.** On every pull request, as a check named `zizmor / zizmor`.
Findings arrive as review comments on the diff, in the same place a human
reviewer's comments appear.

**It is advisory.** It cannot block a merge and cannot fail your build. That is
deliberate: the org has a backlog of pre-existing findings, and turning this on
as a gate would have blocked every open pull request on day one. It will become
blocking once repos are cleaned up, and you will be told before that happens.

### What it looks for

Roughly in the order you will meet them:

| Audit | Meaning | Fix |
| --- | --- | --- |
| `unpinned-uses` | An action referenced by tag rather than commit hash, e.g. `docker/build-push-action@v6`. A tag can be repointed at different code by its owner; a hash cannot. | `uses: owner/action@<40-char-sha> # v6` |
| `excessive-permissions` | No `permissions:` block, so the job gets the default token scope. | `permissions: {}` at the top, then grant each job only what it needs. |
| `artipacked` | `actions/checkout` leaves a credential in `.git/config` that later steps and uploaded artifacts can read. | `persist-credentials: false` |
| `template-injection` | The serious one. A `${{ ... }}` expanded straight into a `run:` body *becomes shell code*, so an attacker-controllable value — a pull request title, a branch name — can execute commands. | Pass it through `env:` and reference `"$VAR"` in the script. |
| `adhoc-packages` | Installing unpinned packages mid-workflow. | Pin the version. |
| `cache-poisoning` | Restoring a cache in a job that publishes artifacts. | Disable cache restore in release jobs. |

The full catalogue is at <https://docs.zizmor.sh/audits/>.

### Two things that will surprise you

1. **Findings appear for files your pull request did not touch.** zizmor audits
   the whole repository, so pre-existing problems are reported in the review
   *body* rather than as inline comments. Those are not yours to fix unless you
   want to — the inline comments on your own diff are the ones that concern your
   change.

2. **A repo needs `.github/zizmor.yml` as well as the workflow.** It carries the
   pinning policy: our own `devtest-hq/*` reusable workflows may use tags,
   everything else needs a hash. Without it, the check reports itself.

### If a finding is wrong

Add it to that repo's `.github/zizmor.yml` under `rules.<audit>.ignore`, with a
comment saying why:

```yaml
rules:
  artipacked:
    ignore:
      # Deploy job genuinely needs the credentials for the push back to main.
      - release.yml:42
```

Do not reach for `disable: true` — that switches the audit off for the whole
repository, including code nobody has looked at yet.

### Running it before you push

```bash
pipx install zizmor==1.30.1     # or: uv tool install zizmor==1.30.1
GH_TOKEN=$(gh auth token) zizmor .
```

The token matters. Without one, three audits — `known-vulnerable-actions`,
`impostor-commit` and `typosquat-uses` — silently do nothing, and you get a
smaller audit with no warning that it was smaller.

## Maintaining this workflow

The implementation is `.github/workflows/zizmor.yml` plus
`.github/scripts/zizmor_review.py` in this repo.

Callers resolve the **`zizmor-v1` tag**, which means the tip of `develop`.
`.github/workflows/move-zizmor-tag.yml` moves it on every push to `develop`,
so merging is all you need to do.

That is automated because the manual version failed in the obvious way: a fix
was merged, reported green, and changed nothing anywhere, because the tag
still pointed at the previous commit and every caller kept resolving the old
code. Nothing warns you. If the tag ever needs moving by hand:

```bash
git tag -f zizmor-v1 origin/develop && git push -f origin refs/tags/zizmor-v1
```

The same workflow moves `security-v1` and `deps-v1`. It has no checkout on
purpose: moving a ref is one API call, and a checkout able to push a tag would
keep its credentials on disk (an artipacked finding in the repo that reports
them). When a tag is missing (first run, or someone deleted it) it is created
rather than failing, because a missing tag breaks every caller in the org.
Pushing a tag does not fire a `push: branches:` event, so it cannot loop.

## deps-check — weekly dependency check

Every Monday at 06:00 UTC, each repo checks its own dependencies and writes
the result to the run's job summary. The run **fails** when there is something
to act on, so it shows up red in the Actions tab:

- a package version with a known vulnerability at `fail-severity` or above
  (default HIGH) that has a fixed version, found by trivy in the lockfile, with
  the same trivy digest as `security-code.yml` and the sec01 weekly scan, so
  the results match the SEOP issues;
- a GitHub Action pinned a major version behind its latest release;
- a lockfile problem: none committed, several of them, a `packageManager`
  field that disagrees with the lockfile, or a frozen-lockfile install that
  fails because the lockfile is out of sync with `package.json`.

Outdated packages are listed too (installed, within range, latest, and whether
the latest is a new major), but they never fail the run: **Dependabot** opens
the update pull requests for them.

The package manager comes from `packageManager` in `package.json`, otherwise
from the lockfile: npm, pnpm, yarn (classic) and bun are supported. The
install runs with `--ignore-scripts`, so no package code runs in the check.

### Adding it to a repo

**Two files**, both in the target repo.

`.github/workflows/deps-check.yml`: copy
`.github/workflow-templates/deps-check.yml`, or pick "deps-check — weekly
dependency check" from the Actions → New workflow page:

```yaml
name: deps-check
on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:
permissions: {}
jobs:
  deps-check:
    permissions:
      contents: read
    uses: devtest-hq/.github/.github/workflows/deps-check.yml@deps-v1
```

`.github/dependabot.yml`: weekly update pull requests for the packages and for
the Actions, minor and patch updates grouped into one pull request, majors one
per package, and a 7-day cooldown so a version is a week old before it is
proposed. Use `package-ecosystem: bun` instead of `npm` in a bun repo:

```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
      day: monday
    cooldown:
      default-days: 7
    open-pull-requests-limit: 5
    groups:
      minor-and-patch:
        update-types: [minor, patch]
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
      day: monday
    cooldown:
      default-days: 7
    groups:
      actions:
        patterns: ["*"]
```

Run it once by hand after adding it: Actions → deps-check → Run workflow.

### Inputs

| Input | Default | What it does |
|---|---|---|
| `fail-severity` | `HIGH` | `CRITICAL`, `HIGH` or `MEDIUM`: the lowest vulnerability severity that fails the run. MEDIUM and up are always listed. |

### Maintaining it

The implementation is `.github/workflows/deps-check.yml` plus
`.github/scripts/deps_check.py` (standard library only). Callers resolve the
`deps-v1` tag, which `move-zizmor-tag.yml` keeps at the tip of `develop`.
Try a change locally from a repo's root, after installing its dependencies:

```bash
python3 /path/to/.github/.github/scripts/deps_check.py detect
python3 /path/to/.github/.github/scripts/deps_check.py report --trivy trivy.json
```
