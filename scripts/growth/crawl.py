#!/usr/bin/env python3
"""
APKwarden Developer Growth & Discovery Crawler
Discovers high-intent Android app repositories with active CI and generates
personalized, consent-first outreach drafts for maintainers.

Uses standard Python library + `gh` CLI for authenticated requests.
"""

import sys
import os
import json
import subprocess
import sqlite3
import re
import time
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

DB_PATH = Path(__file__).parent / "growth.db"
DRAFTS_DIR = Path(__file__).parent / "outreach_drafts"

# Hard drop regex for homework, tutorials, student projects
HOMEWORK_REGEX = re.compile(
    r"(?i)(homework|assignment|codelab|tutorial|bootcamp|first[-_]?app|hello[-_]?world|"
    r"udacity|coursera|cs\s?\d{3,4}|coursework|practice|sample[-_]?project|learning[-_]?android)"
)

EXAMPLE_PACKAGE_REGEX = re.compile(
    r"(?i)(com\.example(\..*)?|com\.android\.example|org\.example(\..*)?|\.myapplication)$"
)

BOT_USERS = {
    "dependabot[bot]", "renovate[bot]", "github-actions[bot]", "weblate",
    "crowdin-bot", "imgbot[bot]", "allcontributors[bot]", "pre-commit-ci[bot]",
    "snyk-bot", "semantic-release-bot", "fossabot", "linear-code[bot]",
    "claude", "claude[bot]", "copilot[bot]", "github-classroom[bot]"
}


def init_db(conn: sqlite3.Connection):
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS repos (
                full_name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                stars INTEGER DEFAULT 0,
                pushed_at TEXT NOT NULL,
                description TEXT,
                primary_language TEXT,
                has_ci INTEGER DEFAULT 0,
                release_workflow_path TEXT,
                build_task TEXT,
                has_releases INTEGER DEFAULT 0,
                latest_release_tag TEXT,
                package_id TEXT,
                target_sdk INTEGER,
                score INTEGER DEFAULT 0,
                score_reasons TEXT,
                status TEXT DEFAULT 'DISCOVERED',
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS maintainers (
                login TEXT PRIMARY KEY,
                name TEXT,
                email TEXT,
                email_source TEXT,
                blog TEXT,
                bio TEXT,
                status TEXT DEFAULT 'IDENTIFIED',
                created_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS drafts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_full_name TEXT NOT NULL,
                maintainer_login TEXT NOT NULL,
                draft_path TEXT NOT NULL,
                subject TEXT NOT NULL,
                one_true_sentence TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING_APPROVAL',
                FOREIGN KEY (repo_full_name) REFERENCES repos(full_name),
                FOREIGN KEY (maintainer_login) REFERENCES maintainers(login)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS suppressions (
                email_or_login TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)


def run_gh_api(endpoint: str, params: Optional[Dict[str, Any]] = None, raw: bool = False) -> Any:
    cmd = ["gh", "api", "-X", "GET", endpoint]
    if params:
        for k, v in params.items():
            cmd.extend(["-f", f"{k}={v}"])
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout if raw else json.loads(res.stdout)
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else str(e)
        if "404" in err:
            return None
        if "rate limit" in err.lower():
            print(f"[!] Hit rate limit warning on {endpoint}: {err}", file=sys.stderr)
            time.sleep(10)
        return None
    except Exception as e:
        return None


def search_repositories(query: str, max_results: int = 50) -> List[Dict[str, Any]]:
    print(f"[*] Searching GitHub: '{query}' (limit: {max_results})...")
    results = []
    page = 1
    per_page = min(max_results, 30)

    while len(results) < max_results:
        data = run_gh_api("search/repositories", {
            "q": query,
            "per_page": str(per_page),
            "page": str(page),
            "sort": "updated"
        })
        if not data or "items" not in data or not data["items"]:
            break
        items = data["items"]
        results.extend(items)
        if len(items) < per_page:
            break
        page += 1
        time.sleep(1.5)  # Be polite to search API rate limit

    return results[:max_results]


def check_hard_drops(repo: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    # 1. Fork / Archive / Template check
    if repo.get("fork", False):
        return True, "is_fork"
    if repo.get("archived", False):
        return True, "is_archived"
    if repo.get("is_template", False):
        return True, "is_template"

    # 2. Recency check (pushed within last 180 days)
    pushed_at_str = repo.get("pushed_at")
    if pushed_at_str:
        pushed_at = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - pushed_at > timedelta(days=180):
            return True, "stale_push"

    # 3. Homework / Tutorial name check
    name = repo.get("name", "")
    desc = repo.get("description", "") or ""
    if HOMEWORK_REGEX.search(name) or HOMEWORK_REGEX.search(desc):
        return True, "homework_or_tutorial"

    return False, None


def enrich_repository(full_name: str) -> Optional[Dict[str, Any]]:
    """Inspects repo files via Contents API to verify application status, workflows, and releases."""
    info = {"is_app": False, "workflows": [], "release_workflow": None, "build_task": None}

    # 1. Check for application build.gradle / build.gradle.kts
    gradle_paths = [
        f"repos/{full_name}/contents/app/build.gradle.kts",
        f"repos/{full_name}/contents/app/build.gradle",
        f"repos/{full_name}/contents/build.gradle.kts",
        f"repos/{full_name}/contents/build.gradle"
    ]
    for gp in gradle_paths:
        file_obj = run_gh_api(gp)
        if file_obj and "content" in file_obj:
            try:
                import base64
                content = base64.b64decode(file_obj["content"]).decode("utf-8", errors="ignore")
                if "com.android.application" in content or "plugins.android.application" in content:
                    info["is_app"] = True
                    # Look for targetSdk
                    m = re.search(r"targetSdk(?:Version)?\s*=?\s*(\d+)", content)
                    if m:
                        info["target_sdk"] = int(m.group(1))
                    # Look for applicationId
                    m_pkg = re.search(r"applicationId\s*=?\s*[\"']([^\"']+)[\"']", content)
                    if m_pkg:
                        info["package_id"] = m_pkg.group(1)
                    break
            except Exception:
                pass

    if not info["is_app"]:
        return None  # Library or non-Android project

    # 2. Check for GitHub Actions workflows
    wf_list = run_gh_api(f"repos/{full_name}/contents/.github/workflows")
    if wf_list and isinstance(wf_list, list):
        for wf in wf_list:
            wf_name = wf.get("name", "")
            wf_path = wf.get("path", "")
            if wf_name.endswith((".yml", ".yaml")):
                info["workflows"].append(wf_path)
                # Inspect release workflows
                if any(x in wf_name.lower() for x in ["release", "build", "ci", "publish", "deploy"]):
                    wf_content_obj = run_gh_api(f"repos/{full_name}/contents/{wf_path}")
                    if wf_content_obj and "content" in wf_content_obj:
                        import base64
                        raw = base64.b64decode(wf_content_obj["content"]).decode("utf-8", errors="ignore")
                        if any(k in raw for k in ["assembleRelease", "bundleRelease", "assemble", "build"]):
                            info["release_workflow"] = wf_path
                            # Extract task
                            m_task = re.search(r"\./gradlew\s+([^\n]+)", raw)
                            if m_task:
                                info["build_task"] = m_task.group(1).strip()
                            break

    # 3. Check releases
    releases = run_gh_api(f"repos/{full_name}/releases", {"per_page": "3"})
    if releases and isinstance(releases, list) and len(releases) > 0:
        info["has_releases"] = True
        info["latest_release_tag"] = releases[0].get("tag_name")
        # Check if release has apk asset
        assets = releases[0].get("assets", [])
        for a in assets:
            if a.get("name", "").endswith((".apk", ".aab")):
                info["release_apk_url"] = a.get("browser_download_url")
                break
    else:
        info["has_releases"] = False

    return info


def resolve_maintainer(full_name: str) -> Optional[Dict[str, Any]]:
    """Identifies primary human maintainer and extracts public contact info."""
    owner_login = full_name.split("/")[0]

    # 1. First, check if the repo owner themselves is a user with a public profile email or blog
    owner_profile = run_gh_api(f"users/{owner_login}")
    if owner_profile and owner_profile.get("type") == "User":
        raw_email = owner_profile.get("email")
        if raw_email and not raw_email.endswith("noreply.github.com"):
            return {
                "login": owner_login,
                "name": owner_profile.get("name") or owner_login,
                "email": raw_email,
                "email_source": "profile",
                "blog": owner_profile.get("blog"),
                "bio": owner_profile.get("bio")
            }

    # 2. Inspect commits to find the primary active human committer
    commits = run_gh_api(f"repos/{full_name}/commits", {"per_page": "15"})
    if not commits or not isinstance(commits, list):
        if owner_profile and owner_profile.get("type") == "User" and owner_profile.get("blog"):
            return {
                "login": owner_login,
                "name": owner_profile.get("name") or owner_login,
                "email": None,
                "email_source": "blog",
                "blog": owner_profile.get("blog"),
                "bio": owner_profile.get("bio")
            }
        return None

    for c in commits:
        author = c.get("author")
        if not author:
            continue
        login = author.get("login", "")
        if login in BOT_USERS or login.endswith("[bot]"):
            continue

        # Fetch committer profile
        profile = run_gh_api(f"users/{login}")
        if not profile:
            continue

        raw_email = profile.get("email")
        if raw_email and not raw_email.endswith("noreply.github.com"):
            return {
                "login": login,
                "name": profile.get("name") or login,
                "email": raw_email,
                "email_source": "profile",
                "blog": profile.get("blog"),
                "bio": profile.get("bio")
            }

        if profile.get("blog"):
            return {
                "login": login,
                "name": profile.get("name") or login,
                "email": None,
                "email_source": "blog",
                "blog": profile.get("blog"),
                "bio": profile.get("bio")
            }

        # Check commit author email
        commit_email = c.get("commit", {}).get("author", {}).get("email")
        if commit_email and not commit_email.endswith("noreply.github.com"):
            if not any(x in commit_email for x in ["localhost", "test.com", "example.com"]):
                return {
                    "login": login,
                    "name": profile.get("name") or login,
                    "email": commit_email,
                    "email_source": "commit",
                    "blog": profile.get("blog"),
                    "bio": profile.get("bio")
                }

    return None


def calculate_score(repo: Dict[str, Any], enrich: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons = []

    if enrich.get("release_workflow"):
        score += 40
        reasons.append("Active release build workflow in CI (+40)")
    elif enrich.get("workflows"):
        score += 25
        reasons.append("GitHub Actions CI present (+25)")

    desc = (repo.get("description") or "").lower()
    if any(k in desc for k in ["wallet", "crypto", "security", "auth", "2fa", "password", "vpn", "messenger"]):
        score += 20
        reasons.append("Security-sensitive app domain (+20)")

    if enrich.get("has_releases"):
        score += 15
        reasons.append("Active GitHub Releases published (+15)")

    if enrich.get("release_apk_url"):
        score += 10
        reasons.append("Direct APK release asset available (+10)")

    if enrich.get("target_sdk", 36) < 36:
        score += 10
        reasons.append(f"Target SDK is {enrich.get('target_sdk')} (Play Policy update required) (+10)")

    return score, reasons


def generate_draft(repo_name: str, app_name: str, maintainer: Dict[str, Any], enrich: Dict[str, Any], reasons: List[str]) -> str:
    first_name = maintainer["name"].split()[0] if maintainer["name"] else maintainer["login"]
    wf_path = enrich.get("release_workflow") or ".github/workflows"
    build_task = enrich.get("build_task") or "./gradlew assembleRelease"
    pkg = enrich.get("package_id") or app_name

    one_true_sentence = f"Your release workflow `{wf_path}` already builds release APKs (via `{build_task}`), but currently has no automated security or permission check step."

    draft = f"""# Outreach Draft for {repo_name}

**Target**: {repo_name}
**Maintainer**: {maintainer['name']} (@{maintainer['login']})
**Contact**: {maintainer.get('email') or 'N/A (Check blog: ' + str(maintainer.get('blog')) + ')'} (Source: {maintainer.get('email_source')})
**Score Breakdown**:
{chr(10).join(f"- {r}" for r in reasons)}

---

### Email Draft (Consent-First)

**Subject**: {app_name} release CI & APKwarden

Hi {first_name},

I maintain APKwarden, an open-source, zero-configuration bytecode and security scanner designed specifically for Android CI/CD pipelines.

{one_true_sentence}

APKwarden runs in ~5 seconds directly on release APKs, catching reachable vulnerabilities, risky permissions (like tapjacking overlays), and cleartext traffic with zero library noise.

If you are interested, reply "send it" and I'll run APKwarden headlessly on your latest public release APK and send you the 1-page review. If it is noisy or unhelpful, I would love your honest critique as well.

Either way, no follow-up beyond this single note.

Best regards,

Shaurya  
APKwarden Maintainer  
https://github.com/no-hup/apkwarden
"""
    return draft


def main():
    parser = argparse.ArgumentParser(description="APKwarden Growth & Outreach Crawler")
    parser.add_argument("--repo", help="Target a specific repo (e.g. paug/AndroidMakersApp)")
    parser.add_argument("--query", help="Custom search query", default="play.google.com/store/apps/details in:readme topic:android fork:false archived:false pushed:>=2026-08-01 stars:5..500")
    parser.add_argument("--limit", type=int, default=15, help="Number of repos to search and process")
    parser.add_argument("--min-score", type=int, default=40, help="Minimum score to generate outreach draft")
    args = parser.parse_args()

    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    print(f"=== APKwarden Growth Crawler Started ===")
    if args.repo:
        repo_obj = run_gh_api(f"repos/{args.repo}")
        if not repo_obj:
            print(f"[!] Error: Could not fetch repository '{args.repo}'", file=sys.stderr)
            sys.exit(1)
        repos = [repo_obj]
    else:
        repos = search_repositories(args.query, max_results=args.limit)

    print(f"[*] Found {len(repos)} candidate repositories. Filtering & enriching...\n")

    qualified_count = 0
    draft_count = 0

    for r in repos:
        full_name = r["full_name"]
        print(f"--- Examining: {full_name} ---")

        # Check if already processed
        cur = conn.cursor()
        cur.execute("SELECT full_name FROM repos WHERE full_name = ?", (full_name,))
        if cur.fetchone():
            print(f"  [i] Already evaluated in database. Skipping.")
            continue

        # 1. Hard drops
        is_dropped, drop_reason = check_hard_drops(r)
        if is_dropped:
            print(f"  [-] Dropped: {drop_reason}")
            continue

        # 2. Enrich & check if Android application
        enrich = enrich_repository(full_name)
        if not enrich:
            print(f"  [-] Dropped: Not an Android application project (library or non-Android)")
            continue

        # 3. Calculate score
        score, reasons = calculate_score(r, enrich)
        print(f"  [+] Qualified App! Score: {score}/100 ({', '.join(reasons)})")
        qualified_count += 1

        # 4. Resolve maintainer contact
        maintainer = resolve_maintainer(full_name)
        if maintainer:
            print(f"  [👤] Maintainer: {maintainer['name']} (@{maintainer['login']}) | Email: {maintainer.get('email')} ({maintainer.get('email_source')})")
        else:
            print(f"  [?] Maintainer could not be resolved cleanly.")

        # Save to DB
        now_str = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO repos (
                    full_name, owner, name, stars, pushed_at, description,
                    primary_language, has_ci, release_workflow_path, build_task,
                    has_releases, latest_release_tag, package_id, target_sdk,
                    score, score_reasons, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                full_name, r["owner"]["login"], r["name"], r.get("stargazers_count", 0),
                r.get("pushed_at", ""), r.get("description", ""), r.get("language", ""),
                1 if enrich.get("workflows") else 0, enrich.get("release_workflow"), enrich.get("build_task"),
                1 if enrich.get("has_releases") else 0, enrich.get("latest_release_tag"),
                enrich.get("package_id"), enrich.get("target_sdk"), score, json.dumps(reasons),
                "QUALIFIED" if score >= args.min_score else "BACKLOG", now_str
            ))

            if maintainer:
                conn.execute("""
                    INSERT OR REPLACE INTO maintainers (
                        login, name, email, email_source, blog, bio, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    maintainer["login"], maintainer["name"], maintainer["email"],
                    maintainer["email_source"], maintainer.get("blog"), maintainer.get("bio"),
                    "ACTIVE", now_str
                ))

        # 5. Generate draft if score >= min_score and maintainer found
        if score >= args.min_score and maintainer and (maintainer.get("email") or maintainer.get("blog")):
            draft_text = generate_draft(full_name, r["name"], maintainer, enrich, reasons)
            slug = full_name.replace("/", "_")
            draft_file = DRAFTS_DIR / f"{slug}.md"
            draft_file.write_text(draft_text)
            print(f"  [📝] Draft generated: {draft_file.name}")
            draft_count += 1

            with conn:
                conn.execute("""
                    INSERT INTO drafts (
                        repo_full_name, maintainer_login, draft_path, subject,
                        one_true_sentence, created_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    full_name, maintainer["login"], str(draft_file),
                    f"{r['name']} release CI & APKwarden",
                    reasons[0] if reasons else "", now_str, "PENDING_APPROVAL"
                ))

        time.sleep(1)

    print(f"\n=== Run Complete ===")
    print(f"Qualified Repos: {qualified_count}")
    print(f"Outreach Drafts Generated: {draft_count} (Saved in {DRAFTS_DIR})")
    print(f"Database saved to: {DB_PATH}")


if __name__ == "__main__":
    main()
