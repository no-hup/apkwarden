#!/usr/bin/env python3
"""
APKwarden 2.0 Growth Crawler & Pre-Flight Pipeline

1. Discovers high-intent Android repos in high-stakes domains (Privacy, Security, F-Droid, VPN, Crypto)
   and recent targetSdk 34/35 releases.
2. Verifies direct downloadable .apk release asset and resolves verified human maintainer email.
3. Automatically downloads and scans release APK using apkwarden-0.1.0-all.jar (c756935).
4. High-Urgency Gate: Strictly filters for high-impact findings (Android 14 receiver crash risks,
   SSL bypasses, Dirty Stream path traversal, hardcoded secrets, or insecure exported WebViews).
5. Only generates drafts for repos meeting the urgency criteria, including the 1-click PR offer.
"""

import sys
import os
import json
import subprocess
import sqlite3
import re
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple

SCRIPTS_DIR = Path(__file__).parent
DB_PATH = SCRIPTS_DIR / "growth.db"
DRAFTS_DIR = SCRIPTS_DIR / "outreach_drafts_2_0"
DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
SCANS_DIR = Path("/tmp/apk_scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

JAR_PATH = Path("/Users/shaurya/Desktop/moonshot/apkwarden/apkwarden-cli/build/libs/apkwarden-0.1.0-all.jar")

# High-Urgency Rule IDs
HIGH_URGENCY_RULES = {
    "APK-SEC-014",  # Dynamic receiver missing export flag on targetSdk 34+ (Runtime Crash Risk)
    "APK-SEC-010",  # SslErrorHandler.proceed() bypass
    "APK-SEC-013",  # Insecure custom X509TrustManager
    "APK-SEC-005",  # Dirty Stream path traversal / file overwrite
    "APK-SEC-001",  # Intent Redirection in exported component
    "APK-SEC-017",  # Hardcoded cloud API secret / credential
    "APK-SEC-007",  # Arbitrary URL loaded in exported WebView
    "APK-SEC-009",  # JavaScript Interface exposed to untrusted content (HIGH/CRITICAL)
}

BOT_USERS = {
    "dependabot[bot]", "renovate[bot]", "github-actions[bot]", "weblate",
    "crowdin-bot", "imgbot[bot]", "allcontributors[bot]", "pre-commit-ci[bot]",
    "snyk-bot", "semantic-release-bot", "fossabot", "linear-code[bot]",
    "claude", "claude[bot]", "copilot[bot]", "github-classroom[bot]"
}

QUERY_CLUSTERS = [
    "topic:android topic:privacy fork:false archived:false pushed:>=2026-09-01 stars:15..600",
    "topic:android topic:f-droid fork:false archived:false pushed:>=2026-09-01 stars:15..600",
    "topic:android topic:security fork:false archived:false pushed:>=2026-09-01 stars:15..600",
    "topic:android topic:vpn fork:false archived:false pushed:>=2026-09-01 stars:15..600",
    "topic:android topic:crypto fork:false archived:false pushed:>=2026-09-01 stars:15..600",
]

def run_gh_api(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
    cmd = ["gh", "api", "-X", "GET", endpoint]
    if params:
        for k, v in params.items():
            cmd.extend(["-f", f"{k}={v}"])
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(res.stdout)
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else str(e)
        if "rate limit" in err.lower():
            print(f"[!] Rate limit hit on {endpoint}, sleeping 10s...", file=sys.stderr)
            time.sleep(10)
        return None
    except Exception:
        return None

def search_repositories(query: str, max_results: int = 15) -> List[Dict[str, Any]]:
    print(f"[*] Querying: '{query}' (limit: {max_results})...")
    data = run_gh_api("search/repositories", {
        "q": query,
        "per_page": str(min(max_results, 30)),
        "sort": "updated"
    })
    if not data or "items" not in data:
        return []
    return data["items"][:max_results]

def get_release_apk_info(full_name: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Returns (tag_name, apk_filename, download_url) if an APK is attached to releases."""
    releases = run_gh_api(f"repos/{full_name}/releases", {"per_page": "3"})
    if not releases or not isinstance(releases, list):
        return None, None, None
    for rel in releases:
        tag = rel.get("tag_name")
        for asset in rel.get("assets", []):
            name = asset.get("name", "")
            if name.endswith(".apk"):
                return tag, name, asset.get("browser_download_url")
    return None, None, None

def resolve_maintainer(full_name: str) -> Optional[Dict[str, Any]]:
    owner_login = full_name.split("/")[0]
    owner_profile = run_gh_api(f"users/{owner_login}")
    if owner_profile and owner_profile.get("type") == "User":
        raw_email = owner_profile.get("email")
        if raw_email and not raw_email.endswith("noreply.github.com"):
            return {
                "login": owner_login,
                "name": owner_profile.get("name") or owner_login,
                "email": raw_email,
                "source": "profile"
            }

    commits = run_gh_api(f"repos/{full_name}/commits", {"per_page": "10"})
    if commits and isinstance(commits, list):
        for c in commits:
            author = c.get("author")
            login = author.get("login") if author else None
            if login and login in BOT_USERS:
                continue
            commit_email = c.get("commit", {}).get("author", {}).get("email")
            if commit_email and not commit_email.endswith("noreply.github.com"):
                if not any(x in commit_email for x in ["localhost", "test.com", "example.com", "none@"]):
                    name = c.get("commit", {}).get("author", {}).get("name") or login or owner_login
                    return {
                        "login": login or owner_login,
                        "name": name,
                        "email": commit_email,
                        "source": "commit"
                    }
    return None

def download_apk(apk_name: str, download_url: str) -> Path:
    target_path = SCANS_DIR / apk_name
    if target_path.exists() and target_path.stat().st_size > 5000:
        return target_path
    print(f"  [↓] Downloading APK: {apk_name}...")
    subprocess.run(["curl", "-sL", "--connect-timeout", "15", "--max-time", "90", download_url, "-o", str(target_path)], check=True)
    return target_path

def run_apkwarden_scan(apk_path: Path) -> str:
    print(f"  [⚡] Running APKwarden v0.1.0: {apk_path.name}...")
    res = subprocess.run(["java", "-jar", str(JAR_PATH), "scan", str(apk_path), "--fail-on", "NEVER"], capture_output=True, text=True)
    return res.stdout

def parse_high_urgency_findings(output: str) -> Tuple[str, List[Dict[str, str]]]:
    # Extract Scorecard line
    m_score = re.search(r"Scorecard:\s*(.+)", output)
    scorecard = m_score.group(1).strip() if m_score else "App: 90/100"

    high_urgency_items = []
    rq_match = re.search(r"🚨 ACTIONABLE REVIEW QUEUE \(\d+ items\)\n─+\n(.*?)(?=\n🚨|\n⚠️|\n📦|\nℹ️|$)", output, re.DOTALL)
    if rq_match:
        rq_text = rq_match.group(1).strip()
        parts = rq_text.split("\n• ")
        for raw in parts:
            raw = raw.strip()
            if not raw:
                continue
            lines = raw.split("\n")
            title_line = lines[0].lstrip("• ")
            
            # Check if this item is in our high urgency list
            rule_id = None
            m_rule = re.search(r"\[(APK-SEC-\d+)\]", title_line)
            if m_rule:
                rule_id = m_rule.group(1)
            
            if rule_id and rule_id in HIGH_URGENCY_RULES:
                loc, impact, remed = "", "", ""
                for l in lines[1:]:
                    l = l.strip()
                    if l.startswith("Location:"):
                        loc = l.replace("Location:", "").strip()
                    elif l.startswith("Impact:"):
                        impact = l.replace("Impact:", "").strip()
                    elif l.startswith("Remediation:"):
                        remed = l.replace("Remediation:", "").strip()
                high_urgency_items.append({
                    "rule_id": rule_id,
                    "title": title_line,
                    "location": loc,
                    "impact": impact,
                    "remediation": remed
                })
    return scorecard, high_urgency_items

def generate_draft(full_name: str, app_name: str, maintainer: Dict[str, Any], apk_name: str, scorecard: str, finding: Dict[str, str], workflow_path: Optional[str]) -> str:
    first_name = maintainer["name"].split()[0] if maintainer["name"] else maintainer["login"]
    rule_id = finding["rule_id"]
    
    # Specific hook based on finding type
    if rule_id == "APK-SEC-014":
        subject = f"quick note on {app_name}'s APK (Android 14 receiver crash risk)"
        specific_note = "Between Android 14's strict broadcast receiver rules (which crash apps on startup if export flags are missing) and Play Store API requirements, shipping updates has gotten tricky."
    elif rule_id in ("APK-SEC-010", "APK-SEC-013"):
        subject = f"quick note on {app_name}'s APK (TLS/SSL handling note)"
        specific_note = "Shipping networking code on Android has gotten tricky between TLS handshake policies and strict Play Store checks."
    elif rule_id == "APK-SEC-005":
        subject = f"quick note on {app_name}'s APK (Dirty Stream file traversal note)"
        specific_note = "Between content provider path traversal gotchas and storage permission changes, file handling on modern Android has subtle edge cases."
    else:
        subject = f"quick pre-release security check of {app_name}'s APK"
        specific_note = "Between Android 14/15 platform changes and subtle bytecode regressions slipping into builds, shipping releases has gotten tricky."

    wf_mention = f"your release workflow (`{workflow_path}`)" if workflow_path else "your GitHub release pipeline"

    body = f"""Hey {first_name},

Came across {app_name} while looking at active Android repos on GitHub.

{specific_note}

I've been building apkwarden (github.com/no-hup/apkwarden), a free, airgapped CLI that runs as a quiet pre-flight check in CI. It catches platform gotchas and reachable bytecode flaws before release, and otherwise stays silent.

Ran a quick scan on your latest release APK ({apk_name}):

----------------------------------------------------------------------
APKWarden Release Pre-Flight: {apk_name}
Scorecard: {scorecard}
----------------------------------------------------------------------
ACTIONABLE REVIEW QUEUE (Top Finding Preview):

• {finding['title']}
  Location:    {finding['location']}
  Impact:      {finding['impact']}
  Remediation: {finding['remediation']}
----------------------------------------------------------------------

This is just one highlight from the scan—running `apkwarden <file.apk>` directly gives you the full audit.

Since {wf_mention} already builds your APKs, dropping in a 1-step check is an easy way to ensure unexpected regressions don't slip into release builds.

If you'd like to test this in your pipeline, reply with "send PR" and I'd be happy to open a clean 1-file PR adding `.github/workflows/apkwarden.yml` to your repo so you can see it run automatically on your next build without any setup on your end.

And if anything in the report looks like a false alarm, feel free to call it out!

Cheers,
Shaurya
https://github.com/no-hup/apkwarden
"""
    return subject, body

def main():
    print("=== Starting APKwarden 2.0 Growth Crawler & Urgency Gate ===")
    conn = sqlite3.connect(DB_PATH)
    
    # Check already processed repos in DB
    c = conn.cursor()
    c.execute("SELECT full_name FROM repos")
    known_repos = {row[0] for row in c.fetchall()}
    print(f"[*] Already known repos in DB: {len(known_repos)}")

    candidates_evaluated = 0
    high_urgency_found = []

    for query in QUERY_CLUSTERS:
        repos = search_repositories(query, max_results=12)
        print(f"[*] Found {len(repos)} repos for query.")
        
        for r in repos:
            full_name = r["full_name"]
            if full_name in known_repos:
                continue
            known_repos.add(full_name)
            candidates_evaluated += 1
            
            print(f"\n--- [{candidates_evaluated}] Evaluating: {full_name} ({r.get('stargazers_count', 0)}★) ---")
            
            # Check release APK
            tag, apk_name, download_url = get_release_apk_info(full_name)
            if not apk_name or not download_url:
                print("  [-] No downloadable .apk asset in releases. Skipping.")
                continue
            
            # Resolve maintainer
            maintainer = resolve_maintainer(full_name)
            if not maintainer or not maintainer.get("email"):
                print("  [-] No public maintainer email found. Skipping.")
                continue
            print(f"  [👤] Maintainer: {maintainer['name']} ({maintainer['email']}) [via {maintainer['source']}]")

            # Download and scan APK
            try:
                apk_path = download_apk(apk_name, download_url)
                scan_output = run_apkwarden_scan(apk_path)
                scorecard, urgent_items = parse_high_urgency_findings(scan_output)
                print(f"  [✓] Scanned! {scorecard} | High-urgency findings: {len(urgent_items)}")
                
                now_str = datetime.now(timezone.utc).isoformat()
                
                # Check for workflows
                wf_info = run_gh_api(f"repos/{full_name}/contents/.github/workflows")
                wf_path = None
                if wf_info and isinstance(wf_info, list):
                    for w in wf_info:
                        if "release" in w.get("name", "").lower() or "build" in w.get("name", "").lower():
                            wf_path = f".github/workflows/{w['name']}"
                            break
                    if not wf_path and wf_info:
                        wf_path = f".github/workflows/{wf_info[0]['name']}"

                if not urgent_items:
                    print("  [✋] HELD: No high-urgency findings (clean baseline or low severity only). Zero spam.")
                    with conn:
                        conn.execute("""
                            INSERT OR REPLACE INTO repos (
                                full_name, owner, name, stars, pushed_at, description,
                                status, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (full_name, r["owner"]["login"], r["name"], r.get("stargazers_count", 0),
                              r.get("pushed_at", ""), r.get("description", ""), "HELD_LOW_URGENCY", now_str))
                    continue

                # We have a high urgency finding!
                top_finding = urgent_items[0]
                print(f"  [🚨] HIGH URGENCY FINDING: {top_finding['title']}")
                
                subject, body = generate_draft(full_name, r["name"], maintainer, apk_name, scorecard, top_finding, wf_path)
                
                slug = full_name.replace("/", "_")
                draft_path = DRAFTS_DIR / f"{slug}.md"
                draft_content = f"""# Outreach Draft for {full_name}

**Target**: {full_name}
**Maintainer**: {maintainer['name']} (@{maintainer['login']})
**Contact**: {maintainer['email']}
**Urgent Finding**: {top_finding['title']}

---

### Plain-Text Email Draft (High-Urgency 2.0 with 1-Click PR)

**Subject**: {subject}

{body}
"""
                draft_path.write_text(draft_content)
                print(f"  [📝] High-Urgency Draft generated: {draft_path.name}")
                
                with conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO repos (
                            full_name, owner, name, stars, pushed_at, description,
                            status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (full_name, r["owner"]["login"], r["name"], r.get("stargazers_count", 0),
                          r.get("pushed_at", ""), r.get("description", ""), "QUALIFIED_HIGH_URGENCY", now_str))
                    
                    conn.execute("""
                        INSERT OR REPLACE INTO maintainers (
                            login, name, email, email_source, status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (maintainer["login"], maintainer["name"], maintainer["email"],
                          maintainer["source"], "IDENTIFIED", now_str))
                    
                    conn.execute("""
                        INSERT INTO drafts (
                            repo_full_name, maintainer_login, draft_path, subject,
                            one_true_sentence, created_at, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (full_name, maintainer["login"], str(draft_path),
                          subject, top_finding["title"], now_str, "PENDING_APPROVAL_HIGH_URGENCY"))

                high_urgency_found.append({
                    "repo": full_name,
                    "maintainer": maintainer["name"],
                    "email": maintainer["email"],
                    "finding": top_finding["title"],
                    "draft": str(draft_path)
                })

            except Exception as e:
                print(f"  [!] Error processing {full_name}: {e}")
                continue
            
            time.sleep(1)

    print("\n=======================================================")
    print(f"[*] 2.0 Crawler Run Complete!")
    print(f"  Candidates Evaluated:         {candidates_evaluated}")
    print(f"  High-Urgency Drafts Created:  {len(high_urgency_found)}")
    print("=======================================================")
    for h in high_urgency_found:
        print(f"• {h['repo']} -> {h['maintainer']} ({h['email']}): {h['finding']}")

if __name__ == "__main__":
    main()
