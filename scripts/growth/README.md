# APKwarden Developer Growth & Discovery Agent

An automated intelligence and outreach crawler to discover active Android application repositories on GitHub, evaluate their build/CI pipelines, resolve public developer contacts compliantly, and draft high-converting, consent-first outreach notes.

---

### Core Philosophy: Why This Converts

Cold email asking developers to *"check out our repo and star us"* fails 99% of the time, burns domain reputation, and violates GitHub's Acceptable Use Policy.

Instead, this crawler implements a **high-intent qualification pipeline**:
1. **Target Shipped Apps with Working CI**: Prioritizes apps that actively build releases using Gradle and GitHub Actions (`assembleRelease` / `bundleRelease`).
2. **Strict Heuristic Drops**: Automatically rejects homework, student tutorials, course assignments (`(?i)(homework|assignment|codelab|tutorial)`), abandoned forks, and pure libraries (`com.android.library` without an app).
3. **Compliant Contact Resolution**: Only extracts emails explicitly published on public GitHub profiles, personal websites, or verified commit history. Respects `@users.noreply.github.com` privacy.
4. **Consent-First "One True Sentence" Hook**: Pulls concrete, verifiable facts about their exact workflow (e.g., `release.yml runs ./gradlew assembleRelease`) and asks for permission before sharing a scan report.

---

### Usage

The crawler uses standard Python 3.10+ and the authenticated `gh` CLI. No third-party dependencies required.

#### 1. Run Search Discovery (Default: Active Play Store Apps)
```bash
./scripts/growth/crawl.py --limit 30 --min-score 40
```

#### 2. Run on a Specific Repository
```bash
./scripts/growth/crawl.py --repo paug/AndroidMakersApp
```

#### 3. Custom Search Query
```bash
./scripts/growth/crawl.py --query "f-droid.org in:readme language:Kotlin fork:false pushed:>=2026-08-01 stars:5..500" --limit 20
```

---

### Output & Review Workflow

1. **SQLite Database (`scripts/growth/growth.db`)**:
   Tracks evaluated repos, maintainers, workflow paths, target SDKs, scores, and suppression lists to prevent duplicate processing.

   Query top qualified repos:
   ```bash
   sqlite3 scripts/growth/growth.db "SELECT full_name, score, release_workflow_path FROM repos WHERE status='QUALIFIED' ORDER BY score DESC;"
   ```

2. **Actionable Outreach Drafts (`scripts/growth/outreach_drafts/`)**:
   Every qualified repo with a resolved contact gets a ready-to-review markdown draft (e.g. `paug_AndroidMakersApp.md`).

   **Human-in-the-Loop Send**: The agent never sends cold emails automatically. A human reviews the draft, confirms the finding or CI observation, and sends up to 10 personalized notes per day.
