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

### Suppressing a finding

Per repo, in that repo's `.github/zizmor.yml`, with the reason written down:

```yaml
rules:
  artipacked:
    ignore:
      # Deploy job genuinely needs the credentials for the push back to main.
      - release.yml:42
```

Prefer `ignore` over `disable: true` — `disable` turns the audit off for the
whole repository, including code nobody has looked at yet.

### Local use

```bash
pipx install zizmor==1.30.1     # or: uv tool install zizmor==1.30.1
GH_TOKEN=$(gh auth token) zizmor .
```

A token is what puts zizmor in online mode; without one the
`known-vulnerable-actions`, `impostor-commit` and `typosquat-uses` audits
silently do nothing.
