#!/usr/bin/env python3
"""
Build 50 Qualified Android Candidates with Verified Emails.
Searches across multiple high-density slices until 50 candidates with verified emails are resolved.
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

# Import helper functions from crawl.py
from crawl import (
    DB_PATH, DRAFTS_DIR, init_db, run_gh_api, search_repositories,
    check_hard_drops, enrich_repository, resolve_maintainer,
    calculate_score, generate_draft
)

SEARCH_QUERIES = [
    'play.google.com/store/apps/details in:readme language:Kotlin fork:false archived:false pushed:>=2026-08-01 stars:5..500',
    'f-droid.org in:readme language:Kotlin fork:false archived:false pushed:>=2026-06-01 stars:5..500',
    'topic:android-app language:Kotlin fork:false archived:false pushed:>=2026-08-01 stars:10..300',
    'topic:jetpack-compose language:Kotlin fork:false archived:false pushed:>=2026-08-01 stars:10..300',
    'play.google.com/store/apps/details in:readme language:Java fork:false archived:false pushed:>=2026-06-01 stars:5..500',
    'f-droid.org in:readme language:Java fork:false archived:false pushed:>=2026-05-01 stars:5..500',
    'wallet OR 2fa OR vpn in:readme topic:android language:Kotlin fork:false archived:false pushed:>=2026-06-01',
    'topic:android-app language:Java fork:false archived:false pushed:>=2026-08-01 stars:5..300'
]

def main():
    target_count = 50
    if len(sys.argv) > 1:
        target_count = int(sys.argv[1])

    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    # Check current valid emails in DB
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM maintainers WHERE email IS NOT NULL AND email != ''")
    current_count = cur.fetchone()[0]
    print(f"[*] Starting discovery. Current maintainers with emails in DB: {current_count}")

    query_idx = 0
    seen_in_run = set()

    while current_count < target_count and query_idx < len(SEARCH_QUERIES):
        query = SEARCH_QUERIES[query_idx]
        print(f"\n=======================================================")
        print(f"[*] Running Slice {query_idx+1}/{len(SEARCH_QUERIES)}: {query}")
        print(f"=======================================================")

        repos = search_repositories(query, max_results=35)
        print(f"[*] Fetched {len(repos)} candidate repos from query.")

        for r in repos:
            if current_count >= target_count:
                break

            full_name = r["full_name"]
            if full_name in seen_in_run:
                continue
            seen_in_run.add(full_name)

            # Check if repo already processed
            cur.execute("SELECT full_name FROM repos WHERE full_name = ?", (full_name,))
            if cur.fetchone():
                continue

            # 1. Hard drops
            is_dropped, drop_reason = check_hard_drops(r)
            if is_dropped:
                continue

            # 2. Enrich & check if Android app
            enrich = enrich_repository(full_name)
            if not enrich or not enrich.get("is_app"):
                continue

            # 3. Calculate score
            score, reasons = calculate_score(r, enrich)

            # 4. Resolve maintainer
            maintainer = resolve_maintainer(full_name)
            if not maintainer or not maintainer.get("email"):
                # Save repo as evaluated but maintainer has no email
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
                        "NO_EMAIL", now_str
                    ))
                continue

            # We have a valid maintainer with an email!
            current_count += 1
            email = maintainer["email"]
            source = maintainer["email_source"]
            print(f"[{current_count}/{target_count}] MATCH: {full_name} (Score: {score}) -> {maintainer['name']} <{email}> ({source})")

            # Save repo & maintainer
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

            # Generate draft
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

            time.sleep(1)

        query_idx += 1

    print(f"\n[*] Discovery loop complete. Total maintainers with verified emails: {current_count}")


if __name__ == "__main__":
    main()
