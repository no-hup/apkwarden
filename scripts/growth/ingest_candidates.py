#!/usr/bin/env python3
"""
Ingest targeted Android candidates with direct release APK assets and valid maintainer emails.
Ensures no duplicates in growth.db and that each repo has a downloadable .apk release asset.
"""

import sys
import os
import json
import subprocess
import sqlite3
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from crawl import (
    DB_PATH, DRAFTS_DIR, init_db, run_gh_api, search_repositories,
    check_hard_drops, enrich_repository, resolve_maintainer,
    calculate_score, generate_draft, BOT_USERS
)

TARGET_QUERIES = [
    'f-droid.org/packages in:readme language:Kotlin stars:>15 pushed:>2026-01-01',
    'play.google.com/store/apps language:Kotlin stars:>15 pushed:>2026-06-01',
    'f-droid in:readme language:Kotlin stars:15..1000 pushed:>2026-01-01',
    'f-droid in:readme language:Java stars:15..1000 pushed:>2026-01-01',
    'topic:android-app language:Kotlin stars:20..1000 pushed:>2026-01-01',
    'play.google.com in:readme topic:android language:Kotlin stars:20..1000 pushed:>2026-01-01',
    'topic:f-droid language:Kotlin stars:10..1000 pushed:>2026-01-01',
    'topic:android-app language:Java stars:20..1000 pushed:>2026-01-01'
]

def get_existing_emails_and_repos(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("SELECT lower(email) FROM maintainers WHERE email IS NOT NULL AND email != ''")
    emails = {r[0] for r in cur.fetchall()}
    cur.execute("SELECT full_name FROM repos")
    repos = {r[0] for r in cur.fetchall()}
    return emails, repos

def verify_apk_asset(full_name: str, enrich: dict) -> tuple[bool, str, str]:
    """Ensures repo actually has a downloadable .apk file in its latest releases."""
    releases = run_gh_api(f"repos/{full_name}/releases", {"per_page": "3"})
    if not releases or not isinstance(releases, list):
        return False, None, None
    for rel in releases:
        tag = rel.get("tag_name")
        for asset in rel.get("assets", []):
            name = asset.get("name", "")
            if name.endswith(".apk"):
                return True, tag, asset.get("browser_download_url")
    return False, None, None

def ingest_candidates(target_new: int = 40):
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    existing_emails, existing_repos = get_existing_emails_and_repos(conn)
    print(f"[*] Starting ingestion. Existing repos: {len(existing_repos)}, Existing emails: {len(existing_emails)}")

    newly_added = 0
    seen_in_run = set()

    for q_idx, query in enumerate(TARGET_QUERIES):
        if newly_added >= target_new:
            break
        print(f"\n=======================================================")
        print(f"[*] Query {q_idx+1}/{len(TARGET_QUERIES)}: {query}")
        print(f"=======================================================")

        repos = search_repositories(query, max_results=40)
        print(f"[*] Found {len(repos)} search results.")

        for r in repos:
            if newly_added >= target_new:
                break
            full_name = r["full_name"]
            if full_name in seen_in_run or full_name in existing_repos:
                continue
            seen_in_run.add(full_name)

            # 1. Hard drops
            is_dropped, drop_reason = check_hard_drops(r)
            if is_dropped:
                continue

            # 2. Enrich repo (check if Android application)
            enrich = enrich_repository(full_name)
            if not enrich or not enrich.get("is_app"):
                continue

            # 3. Strictly verify APK release asset
            has_apk, tag, apk_url = verify_apk_asset(full_name, enrich)
            if not has_apk:
                continue
            enrich["release_apk_url"] = apk_url
            enrich["has_releases"] = True
            enrich["latest_release_tag"] = tag

            # 4. Score
            score, reasons = calculate_score(r, enrich)

            # 5. Resolve maintainer
            maintainer = resolve_maintainer(full_name)
            if not maintainer or not maintainer.get("email"):
                continue

            email = maintainer["email"].strip().lower()
            if email in existing_emails:
                print(f"  [i] Email {email} already in database. Skipping duplicate maintainer.")
                continue

            # Check bot emails / invalid patterns
            if any(b in email for b in ["noreply", "github", "bot@", "automation", "dependabot", "snyk"]):
                continue

            # Maintainer is valid!
            existing_emails.add(email)
            existing_repos.add(full_name)
            newly_added += 1

            print(f"  [+] [{newly_added}/{target_new}] QUALIFIED: {full_name} -> {maintainer['name']} <{email}> (Tag: {tag})")

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
                    1, tag, enrich.get("package_id"), enrich.get("target_sdk"), score, json.dumps(reasons),
                    "QUALIFIED", now_str
                ))

                conn.execute("""
                    INSERT OR REPLACE INTO maintainers (
                        login, name, email, email_source, blog, bio, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    maintainer["login"], maintainer["name"], maintainer["email"],
                    maintainer["email_source"], maintainer.get("blog"), maintainer.get("bio"),
                    "ACTIVE", now_str
                ))

            # Initial draft placeholder
            draft_text = generate_draft(full_name, r["name"], maintainer, enrich, reasons)
            slug = full_name.replace("/", "_")
            draft_file = DRAFTS_DIR / f"{slug}.md"
            draft_file.write_text(draft_text)

            with conn:
                conn.execute("""
                    INSERT INTO drafts (
                        repo_full_name, maintainer_login, draft_path, subject,
                        one_true_sentence, created_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    full_name, maintainer["login"], str(draft_file),
                    f"quick note on {r['name']}'s release CI",
                    reasons[0] if reasons else "", now_str, "PENDING_APPROVAL"
                ))

            time.sleep(1.0)

    print(f"\n[*] Finished ingestion! Newly added qualified targets with APKs: {newly_added}")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    ingest_candidates(count)
