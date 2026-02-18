# Unreleased Security Fix Scanner — Design Document

## Problem Statement

Open-source projects frequently fix security vulnerabilities via commits to their
main branch but delay cutting a release that includes the fix. Downstream
consumers who pin to published package versions (npm, PyPI, Go modules, etc.)
remain exposed even though a fix already exists in source control.

**This tool detects that gap** — security-fix commits that are *not yet* included
in any published release — and surfaces actionable alerts so maintainers of
dependent projects can make informed decisions (vendor a commit, open an upstream
issue, or wait-and-watch).

---

## Goals

| # | Goal |
|---|------|
| G1 | Scan a project's declared dependencies and identify upstream packages whose source repositories contain security-fix commits not yet included in a release. |
| G2 | Open a GitHub issue per finding, with enough context (CVE/advisory ID, commit, affected package, current pinned version) for the maintainer to act. |
| G3 | Automatically update the issue when a release that includes the fix is published. |
| G4 | Run as a scheduled GitHub Action and on-demand via CLI. |
| G5 | Support npm and PyPI ecosystems initially, with a pluggable design for adding more. |

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     GitHub Action (cron / workflow_dispatch)  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  unreleased-security-fix-scanner  (Go binary / CLI)    │  │
│  │                                                        │  │
│  │  1. Parse lockfile  ──►  dependency list               │  │
│  │  2. For each dep:                                      │  │
│  │     a. Query advisory DB  ──► known advisories         │  │
│  │     b. Resolve source repo (registry metadata)         │  │
│  │     c. Check if fix-commit is in a release             │  │
│  │  3. Produce findings (JSON / SARIF)                    │  │
│  │  4. Reconcile with existing GitHub issues              │  │
│  │     - Open new issues for new findings                 │  │
│  │     - Update issues when a release includes the fix    │  │
│  │     - Close issues when fix is released + adopted      │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
   OSV / GitHub          Package            Source Repos
   Advisory DB          Registries           (GitHub)
   (osv.dev API)      (npm, PyPI)
```

---

## Core Concepts

### Advisory Sources

The tool queries **OSV.dev** (Google's open-source vulnerability database) as its
primary advisory source. OSV aggregates data from GitHub Security Advisories
(GHSA), the National Vulnerability Database (NVD), PyPI advisories, npm
advisories, and more. Each OSV record includes:

- Affected package ranges (ecosystem + version constraints)
- References to fix commits (Git SHAs)
- References to upstream issues / PRs
- Fixed-in versions (when known)

Using OSV means we get cross-ecosystem coverage from a single, well-maintained
API with a simple query interface (`POST /v1/query`).

### Dependency Resolution

| Ecosystem | Lockfile(s) | Registry API |
|-----------|-------------|--------------|
| npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `https://registry.npmjs.org/{pkg}` |
| PyPI | `requirements.txt`, `poetry.lock`, `Pipfile.lock` | `https://pypi.org/pypi/{pkg}/json` |
| Go | `go.sum` | `https://proxy.golang.org` |

The scanner reads lockfiles to extract **(package, pinned-version)** tuples.
The registry API is used to map a package name → source repository URL.

### Fix-Commit-in-Release Detection

Given an advisory's fix commit SHA and the source repository:

1. **List releases/tags** via the GitHub API (`GET /repos/{owner}/{repo}/tags`
   and `GET /repos/{owner}/{repo}/releases`).
2. **Check ancestry**: for each tag (newest first), use
   `GET /repos/{owner}/{repo}/compare/{tag}...{commit}` or
   `git merge-base --is-ancestor {commit} {tag}` to determine whether the fix
   commit is an ancestor of the tag.
3. The **first tag** (by semver order) that includes the fix commit is the
   "fix release". If no tag includes it, the fix is **unreleased**.

### Issue Lifecycle

```
  ┌──────────┐   fix commit found,    ┌──────────┐
  │  (none)  │──no release includes──►│  OPENED  │
  └──────────┘   the fix              └────┬─────┘
                                           │
                           release published│that includes fix
                                           ▼
                                     ┌───────────┐
                                     │  UPDATED  │  ← comment added:
                                     │           │    "Fix included in
                                     └────┬──────┘     vX.Y.Z"
                                          │
                          project upgrades │to fixed version
                                          ▼
                                     ┌──────────┐
                                     │  CLOSED  │  (manual or automated)
                                     └──────────┘
```

Each issue is identified by a **deterministic label** derived from
`(advisory-id, package-name)` so the scanner is idempotent across runs.

Label format: `unreleased-fix:{advisory-id}:{package}`

---

## CLI Interface

```
unreleased-security-fix-scanner [flags]

Flags:
  --lockfile <path>        Path to lockfile (auto-detected if omitted)
  --ecosystem <name>       Force ecosystem (npm | pypi | go); auto-detected from lockfile
  --repo <owner/repo>      GitHub repo to manage issues in (default: current repo from GITHUB_REPOSITORY)
  --github-token <token>   GitHub token for API access (default: GITHUB_TOKEN env var)
  --output <format>        Output format: json | sarif | table (default: table)
  --dry-run                Print findings without creating/updating issues
  --config <path>          Path to config file (default: .unreleased-fix-scanner.yml)
  --severity <level>       Minimum severity to report: low | medium | high | critical (default: medium)
  --issue-labels <labels>  Additional labels to add to created issues (comma-separated)
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No unreleased fixes found (or all already tracked) |
| 1 | Unreleased fixes found and reported |
| 2 | Error during execution |

---

## Configuration File (`.unreleased-fix-scanner.yml`)

```yaml
severity: medium

ecosystems:
  - npm
  - pypi

lockfiles:
  - package-lock.json
  - requirements.txt

ignore:
  advisories:
    - GHSA-xxxx-yyyy-zzzz   # Known false positive
  packages:
    - some-internal-pkg      # Not a public package

issues:
  labels:
    - security
    - unreleased-fix
  assignees:
    - maintainer-handle
```

---

## Data Model

### Finding

```go
type Finding struct {
    Advisory    Advisory
    Package     Package
    FixCommit   string       // Git SHA of the fix
    FixReleased bool         // true if a release includes the fix
    FixRelease  string       // e.g. "v1.2.3" — empty if unreleased
    Severity    string       // critical, high, medium, low
    SourceRepo  string       // e.g. "github.com/foo/bar"
}

type Advisory struct {
    ID          string       // e.g. "GHSA-abcd-1234-efgh" or "CVE-2025-12345"
    Aliases     []string     // Cross-references (CVE ↔ GHSA)
    Summary     string
    Details     string
    Severity    string
    References  []string     // URLs
    Published   time.Time
    Modified    time.Time
}

type Package struct {
    Name        string       // e.g. "@babel/core" or "requests"
    Ecosystem   string       // npm, PyPI, Go
    Version     string       // Currently pinned version
}
```

### Issue Tracking Record

```go
type TrackedIssue struct {
    IssueNumber   int
    AdvisoryID    string
    PackageName   string
    Ecosystem     string
    FixCommit     string
    FixReleased   bool
    FixRelease    string
    CreatedAt     time.Time
    UpdatedAt     time.Time
}
```

---

## Package / Module Structure

```
unreleased-security-fix-scanner/
├── cmd/
│   └── scanner/
│       └── main.go              # CLI entry point (cobra)
├── pkg/
│   ├── config/
│   │   └── config.go            # YAML config loading + CLI flag merge
│   ├── lockfile/
│   │   ├── parser.go            # Interface + factory
│   │   ├── npm.go               # package-lock.json / yarn.lock
│   │   ├── pypi.go              # requirements.txt / poetry.lock / Pipfile.lock
│   │   └── gomod.go             # go.sum
│   ├── advisory/
│   │   ├── source.go            # Interface: AdvisorySource
│   │   └── osv.go               # OSV.dev client
│   ├── registry/
│   │   ├── registry.go          # Interface: PackageRegistry
│   │   ├── npm.go               # npm registry client
│   │   └── pypi.go              # PyPI JSON API client
│   ├── vcs/
│   │   ├── repo.go              # Interface: RepoClient
│   │   └── github.go            # GitHub API (tags, releases, commit ancestry)
│   ├── scanner/
│   │   └── scanner.go           # Orchestrator: ties lockfile → advisory → VCS checks
│   ├── reporter/
│   │   ├── reporter.go          # Interface: Reporter
│   │   ├── json.go              # JSON output
│   │   ├── sarif.go             # SARIF output (for GitHub code scanning)
│   │   └── table.go             # Human-readable table
│   └── issues/
│       ├── reconciler.go        # Issue creation / update / close logic
│       └── templates.go         # Issue body + comment templates
├── action.yml                   # GitHub Action metadata
├── .github/
│   └── workflows/
│       └── scan.yml             # Example workflow for this repo itself
├── .unreleased-fix-scanner.yml  # Example / default config
├── go.mod
├── go.sum
├── Dockerfile                   # For GitHub Action container
├── DESIGN.md                    # This document
└── README.md
```

---

## Workflow: Full Scan

```
                        ┌───────────────┐
                        │ Load config & │
                        │ parse flags   │
                        └──────┬────────┘
                               │
                        ┌──────▼────────┐
                        │ Detect / parse│
                        │ lockfile(s)   │
                        └──────┬────────┘
                               │
                    ┌──────────▼──────────┐
                    │ For each dependency: │
                    │ query OSV for       │
                    │ advisories          │
                    └──────────┬──────────┘
                               │
              ┌────────────────▼────────────────┐
              │ For each advisory with fix-commit│
              │ referenced:                      │
              │  1. Resolve source repo via      │
              │     registry metadata            │
              │  2. List tags/releases           │
              │  3. Check commit ancestry        │
              └────────────────┬────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Collect Findings     │
                    │ (unreleased fixes)   │
                    └──────────┬──────────┘
                               │
               ┌───────────────▼───────────────┐
               │ Report (JSON / SARIF / table)  │
               └───────────────┬───────────────┘
                               │
              ┌────────────────▼────────────────┐
              │ Reconcile with GitHub issues:    │
              │  • New finding → open issue      │
              │  • Fix now released → comment    │
              │    with release version, update  │
              │    labels                        │
              │  • Already tracked, no change →  │
              │    skip                          │
              └─────────────────────────────────┘
```

---

## Workflow: Issue Reconciliation (Detail)

On every run the reconciler:

1. **Lists existing issues** in the repo with label `unreleased-fix` (paginated
   GitHub API call).
2. **Builds a map** of `(advisory-id, package) → issue-number` from issue labels.
3. **For each current finding:**
   - If no matching issue exists → **create** one.
   - If a matching issue exists AND the fix is still unreleased → **no-op**.
   - If a matching issue exists AND a release now includes the fix →
     **add a comment** with the release version, update the title prefix to
     `[RELEASED]`, and optionally add the `fix-released` label.
4. **For stale issues** (issue exists but no corresponding finding, meaning the
   dependency was removed or the advisory was withdrawn) → add a comment and
   close.

---

## GitHub Action Definition

```yaml
# action.yml
name: 'Unreleased Security Fix Scanner'
description: >
  Scans your dependency lockfiles for upstream packages that have
  security-fix commits not yet included in a release.
branding:
  icon: 'shield'
  color: 'red'

inputs:
  lockfile:
    description: 'Path to lockfile (auto-detected if omitted)'
    required: false
  ecosystem:
    description: 'Force ecosystem: npm | pypi | go'
    required: false
  severity:
    description: 'Minimum severity: low | medium | high | critical'
    required: false
    default: 'medium'
  dry-run:
    description: 'If true, findings are printed but no issues are created'
    required: false
    default: 'false'
  config:
    description: 'Path to .unreleased-fix-scanner.yml'
    required: false
    default: '.unreleased-fix-scanner.yml'
  github-token:
    description: 'GitHub token (defaults to the Actions-provided token)'
    required: false
    default: ${{ github.token }}

outputs:
  findings-count:
    description: 'Number of unreleased security fixes found'
  findings-json:
    description: 'JSON array of findings'
  sarif-file:
    description: 'Path to SARIF output file (if generated)'

runs:
  using: 'docker'
  image: 'Dockerfile'
  args:
    - '--lockfile=${{ inputs.lockfile }}'
    - '--ecosystem=${{ inputs.ecosystem }}'
    - '--severity=${{ inputs.severity }}'
    - '--dry-run=${{ inputs.dry-run }}'
    - '--config=${{ inputs.config }}'
    - '--github-token=${{ inputs.github-token }}'
    - '--repo=${{ github.repository }}'
    - '--output=json'
```

### Example Consumer Workflow

```yaml
# .github/workflows/unreleased-fix-scan.yml
name: Unreleased Security Fix Scan
on:
  schedule:
    - cron: '0 6 * * 1'   # Every Monday at 06:00 UTC
  workflow_dispatch:

permissions:
  issues: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Unreleased Fix Scanner
        uses: <org>/unreleased-security-fix-scanner@v1
        with:
          severity: medium
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

---

## External API Usage

### OSV.dev

- **Endpoint:** `POST https://api.osv.dev/v1/query`
- **Rate limits:** Generous; no auth required.
- **Query by package:**
  ```json
  {
    "package": {
      "name": "requests",
      "ecosystem": "PyPI"
    },
    "version": "2.28.0"
  }
  ```
- **Response** includes `affected[].ranges[].events` with `{ "fixed": "<version>" }`
  and `affected[].database_specific` with commit SHAs where available.
- Also query `POST /v1/querybatch` for bulk lookups (one request per lockfile).

### GitHub API

| Purpose | Endpoint |
|---------|----------|
| List tags | `GET /repos/{owner}/{repo}/tags` |
| List releases | `GET /repos/{owner}/{repo}/releases` |
| Compare commits | `GET /repos/{owner}/{repo}/compare/{base}...{head}` |
| Check commit ancestry (via git) | `GET /repos/{owner}/{repo}/compare/{tag}...{sha}` — if `status` is `"behind"` or `"identical"`, the commit is an ancestor of the tag |
| Create issue | `POST /repos/{owner}/{repo}/issues` |
| Update issue | `PATCH /repos/{owner}/{repo}/issues/{number}` |
| List issues by label | `GET /repos/{owner}/{repo}/issues?labels=unreleased-fix` |
| Add comment | `POST /repos/{owner}/{repo}/issues/{number}/comments` |

**Auth:** `GITHUB_TOKEN` (classic or fine-grained PAT with `issues: write`,
`contents: read`).

### Package Registries

| Registry | Endpoint | Key field for source repo |
|----------|----------|--------------------------|
| npm | `GET https://registry.npmjs.org/{pkg}` | `.repository.url` |
| PyPI | `GET https://pypi.org/pypi/{pkg}/json` | `.info.project_urls.Source` or `.info.home_page` |

---

## Rate Limiting & Caching Strategy

- **GitHub API:** 5 000 req/hr with token. The scanner batches tag listing and
  uses conditional requests (`If-None-Match` / ETags). For large dependency
  trees, a local cache (JSON file in `.scanner-cache/`) persists across runs in
  CI via `actions/cache`.
- **OSV batch query:** One HTTP call per lockfile (up to 1 000 packages per
  batch). Cached for 24 hours.
- **Registry metadata:** Cached per-package for 24 hours.

---

## Issue Template

### New Issue (unreleased fix detected)

```markdown
## ⚠️ Unreleased Security Fix: {advisory_id}

**Package:** `{package_name}` ({ecosystem})
**Your version:** `{pinned_version}`
**Advisory:** [{advisory_id}]({advisory_url})
**Severity:** {severity}

### Summary

{advisory_summary}

### Details

A fix for this vulnerability was committed to the upstream source repository
but has **not yet been included in a published release**.

| Detail | Value |
|--------|-------|
| Fix commit | [`{short_sha}`]({commit_url}) |
| Source repo | [{source_repo}]({source_repo_url}) |
| Latest release | `{latest_release}` (does **not** include the fix) |

### Recommended Actions

1. **Watch** the upstream repo for a new release.
2. **Vendor** the fix commit if you need an immediate resolution.
3. **Open an issue** upstream requesting a release that includes the fix.

---

<sub>🔍 Detected by [unreleased-security-fix-scanner](https://github.com/<org>/unreleased-security-fix-scanner)</sub>
```

### Update Comment (fix released)

```markdown
## ✅ Fix Released

The fix for **{advisory_id}** is now included in **`{package_name}@{fix_release}`**.

Upgrade your dependency to `>= {fix_release}` to resolve this vulnerability.

| Detail | Value |
|--------|-------|
| Fix release | `{fix_release}` |
| Release date | {release_date} |
| Release URL | [{fix_release}]({release_url}) |

---

<sub>🔍 Updated by [unreleased-security-fix-scanner](https://github.com/<org>/unreleased-security-fix-scanner)</sub>
```

---

## Edge Cases & Design Decisions

### 1. Advisory without a fix commit SHA

Some advisories only list a "fixed-in version" without a commit SHA. In that
case, the scanner checks whether the `fixed-in` version has been published to
the registry. If published → no alert (the ecosystem can upgrade normally).
If not published → alert, but note the absence of a commit reference.

### 2. Source repo not on GitHub

The initial implementation targets GitHub-hosted source repos only. For non-
GitHub repos (GitLab, Bitbucket, self-hosted), the scanner logs a warning and
skips the ancestry check but still reports the advisory if the fixed version
is unreleased.

### 3. Monorepos / multiple packages per repo

A single source repo may host multiple packages. The scanner resolves per-
package: the tag naming convention varies (`v1.2.3`, `pkg/v1.2.3`, etc.), so
tag matching uses the registry's recorded tag prefix when available.

### 4. Transitive dependencies

The scanner operates on the **resolved** dependency graph (lockfile), which
includes transitive dependencies. This gives full coverage but may surface
many findings. The severity filter and ignore list help manage noise.

### 5. Private registries / packages

Private packages are unlikely to be in OSV. The scanner silently skips
packages that return no advisories or cannot be resolved via public APIs.

### 6. Multiple lockfiles

Projects may have more than one lockfile (e.g., `package-lock.json` +
`requirements.txt` in a full-stack repo). The scanner accepts multiple
`--lockfile` flags or discovers all supported lockfiles in the repo root.

### 7. Idempotency

Issues are keyed by `(advisory-id, package-name)` via a deterministic label.
Running the scanner multiple times will not create duplicate issues.

---

## Testing Strategy

| Layer | Approach |
|-------|----------|
| Lockfile parsers | Unit tests with fixture files for each format |
| OSV client | Unit tests with recorded HTTP responses (go-vcr or httptest) |
| Registry clients | Unit tests with recorded HTTP responses |
| VCS / ancestry check | Unit tests with mock GitHub API responses |
| Issue reconciler | Unit tests with mock GitHub issue API |
| Integration | End-to-end test using a known-vulnerable `package-lock.json` against live APIs (gated behind `--integration` flag) |
| GitHub Action | Test workflow in a dedicated test repo |

---

## Future Extensions

- **Additional ecosystems:** RubyGems, Cargo (crates.io), Maven, NuGet.
- **Slack / email notifications** in addition to GitHub issues.
- **SARIF upload** to GitHub Code Scanning for inline PR annotations.
- **Dependency graph API** integration (use GitHub's dependency graph instead of
  parsing lockfiles directly).
- **Auto-PR** that bumps the dependency version once the fix is released.
- **GitLab / Bitbucket** support for source repo ancestry checks and issue
  management.
- **SBOM ingestion** (CycloneDX / SPDX) as an alternative to lockfile parsing.
