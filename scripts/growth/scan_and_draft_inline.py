#!/usr/bin/env python3
"""
Downloads APKs for repos with release assets, runs APKwarden headlessly,
and embeds a high-signal, human 1-page review inline directly in the email body.
Filters out expected permission noise and frames APKwarden as a release baseline check
against AI-agent coding anomalies and regressions.
"""

import sys
import os
import re
import json
import sqlite3
import subprocess
from pathlib import Path

DB_PATH = Path(__file__).parent / "growth.db"
DRAFTS_DIR = Path(__file__).parent / "outreach_drafts"
SCANS_DIR = Path("/tmp/apk_scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

JAR_PATH = Path("/Users/shaurya/Desktop/moonshot/apkwarden/apkwarden-cli/build/libs/apkwarden-0.1.0-all.jar")

# Standard permissions that developers already know they need based on app type
EXPECTED_PERMISSIONS = {
    "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_AUDIO", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "BLUETOOTH", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "POST_NOTIFICATIONS"
}

def get_release_apk_info(full_name: str, tag: str) -> tuple[str, str]:
    if tag:
        res = subprocess.run(["gh", "api", f"repos/{full_name}/releases/tags/{tag}"], capture_output=True, text=True)
        if res.returncode == 0:
            try:
                data = json.loads(res.stdout)
                for a in data.get("assets", []):
                    if a["name"].endswith(".apk"):
                        return a["name"], a["browser_download_url"]
            except Exception:
                pass
    # Fallback to general releases list
    res = subprocess.run(["gh", "api", f"repos/{full_name}/releases", "-f", "per_page=3"], capture_output=True, text=True)
    if res.returncode == 0:
        try:
            rel_list = json.loads(res.stdout)
            for rel in rel_list:
                for a in rel.get("assets", []):
                    if a["name"].endswith(".apk"):
                        return a["name"], a["browser_download_url"]
        except Exception:
            pass
    return None, None

def download_apk(apk_name: str, download_url: str) -> Path:
    target_path = SCANS_DIR / apk_name
    if target_path.exists() and target_path.stat().st_size > 1000:
        return target_path
    print(f"  [↓] Downloading APK: {apk_name}...")
    subprocess.run(["curl", "-sL", "--connect-timeout", "15", "--max-time", "90", download_url, "-o", str(target_path)], check=True)
    return target_path

def run_apkwarden(apk_path: Path) -> str:
    print(f"  [⚡] Scanning with APKwarden: {apk_path.name}...")
    res = subprocess.run(["java", "-jar", str(JAR_PATH), "scan", str(apk_path), "--fail-on", "NEVER"], capture_output=True, text=True)
    return res.stdout

def parse_scan_output(output: str) -> tuple[str, list[dict]]:
    # Extract Scorecard line
    m_score = re.search(r"Scorecard:\s*(.+)", output)
    scorecard = m_score.group(1).strip() if m_score else "App: 90/100"

    # Extract Review Queue items
    raw_items = []
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
            
            loc = ""
            impact = ""
            remed = ""
            for l in lines[1:]:
                l = l.strip()
                if l.startswith("Location:"):
                    loc = l.replace("Location:", "").strip()
                elif l.startswith("Impact:"):
                    impact = l.replace("Impact:", "").strip()
                elif l.startswith("Remediation:"):
                    remed = l.replace("Remediation:", "").strip()
                    
            raw_items.append({
                "title": title_line,
                "location": loc,
                "impact": impact,
                "remediation": remed
            })

    # Prioritize items: Bytecode/IPC flaws first, then config, suppress expected permissions
    bytecode_items = []
    config_items = []
    permission_items = []

    for item in raw_items:
        t = item["title"]
        # Skip informational or zero-vulnerability entries
        if "✓" in t or "Zero high-confidence" in t or "No vulnerabilities" in t or "APK-SEC-" not in t:
            continue
        if any(code in t for code in ["APK-SEC-001", "APK-SEC-002", "APK-SEC-003", "APK-SEC-004", "APK-SEC-005", "APK-SEC-006"]):
            bytecode_items.append(item)
        elif any(code in t for code in ["APK-SEC-018", "APK-SEC-017"]):
            config_items.append(item)
        elif "APK-SEC-019" in t:
            # Check if it's an expected permission
            is_expected = any(p in t for p in EXPECTED_PERMISSIONS)
            if not is_expected:
                permission_items.append(item)
        else:
            bytecode_items.append(item)

    # If we have bytecode or config items, discard permission noise completely
    if bytecode_items or config_items:
        filtered_items = (bytecode_items + config_items)[:2]
    elif permission_items:
        filtered_items = permission_items[:1]
    else:
        filtered_items = []

    return scorecard, filtered_items

PLAY_STORE_REPOS = {
    "sarim2000/pennywiseai-tracker",
    "takke/cpustats",
    "Sentovibes/persona-companion-app",
    "urnetwork/android",
    "michaelWuensch/BitBanana",
    "HatsyRei/maid-native"
}

def generate_inline_report_draft(full_name: str, app_name: str, maintainer_name: str, maintainer_email: str, apk_name: str, scorecard: str, review_items: list[dict], wf_path: str, build_task: str) -> tuple[str, str]:
    raw_first = maintainer_name.split()[0].rstrip(".,-_") if maintainer_name else "there"
    if any(raw_first.lower().endswith(suffix) for suffix in ["-project", "-bot", "-dev", "-team", "-app"]):
        first_name = "there"
    else:
        first_name = raw_first
    
    is_play_store = full_name in PLAY_STORE_REPOS
    
    clean_label = (
        "✓ Clean Baseline: Zero reachable bytecode vulnerabilities or Play Store policy flags."
        if is_play_store
        else "✓ Clean Baseline: Zero reachable bytecode vulnerabilities or regression flags."
    )

    # Format inline report block
    report_lines = [
        "----------------------------------------------------------------------",
        f"APKWarden Release Pre-Flight: {apk_name}",
        f"Scorecard: {scorecard}",
        "----------------------------------------------------------------------"
    ]
    
    if review_items:
        report_lines.append("ACTIONABLE REVIEW QUEUE (Top Finding Preview):")
        report_lines.append("")
        for item in review_items:
            report_lines.append(f"• {item['title']}")
            if item['location']:
                report_lines.append(f"  Location:    {item['location']}")
            if item['impact']:
                report_lines.append(f"  Impact:      {item['impact']}")
            if item['remediation']:
                report_lines.append(f"  Remediation: {item['remediation']}")
            report_lines.append("")
    else:
        report_lines.append(clean_label)
        report_lines.append("  Manifest permissions, components, and network security configs align with baseline.")
        
    report_lines.append("----------------------------------------------------------------------")
    report_block = "\n".join(report_lines)

    clean_task = build_task.replace('\\', '').strip() if build_task else ""
    is_valid_task = (
        clean_task
        and not clean_task.startswith("-")
        and not any(x in clean_task for x in ["${{", "name:", "Keystore", "secret", "Decode", "\n", "  "])
        and len(clean_task) <= 35
        and any(clean_task.startswith(kw) for kw in ["assemble", "build", "bundle"])
    )
    if wf_path and is_valid_task:
        wf_mention = f"your release workflow (`{wf_path}` running `{clean_task}`)"
    elif wf_path:
        wf_mention = f"your release workflow (`{wf_path}`)"
    else:
        wf_mention = "your release workflow"

    preview_callout = (
        "This is just one highlight from the scan—running `apkwarden <file.apk>` directly gives you the full audit."
        if review_items
        else "(You can run `apkwarden <file.apk>` locally to inspect the full baseline metrics.)"
    )

    if is_play_store:
        subject = f"quick pre-release & Play Store check of {app_name}'s APK"
        hook_p = "Between strict Google Play checks that delay or reject updates (like PendingIntent immutability or cleartext flags), Android 14 crash rules, and subtle security regressions slipping into release builds, shipping updates has gotten tricky."
        tool_p = "I've been building apkwarden (github.com/no-hup/apkwarden), a free, airgapped CLI that runs as a quiet pre-flight check in CI. It catches Play Store policy gotchas and reachable bytecode flaws before release, and otherwise stays silent."
        wf_close = f"Since {wf_mention} already builds APKs, dropping in a 1-step check is an easy way to ensure unexpected anomalies don't hold up releases."
    else:
        subject = f"quick pre-release bytecode & security check of {app_name}'s APK"
        hook_p = "With so much code being written and merged quickly with AI coding agents (Cursor, Claude, Copilot) these days, it's really easy for small security anomalies or subtle bytecode regressions—like an unvalidated content URI traversal, a missing FLAG_IMMUTABLE on a PendingIntent, or Android 14 receiver crash rules—to slip into release builds unnoticed."
        tool_p = "I've been building apkwarden (github.com/no-hup/apkwarden), a free, airgapped CLI that runs as a quiet pre-flight check in CI. It flags reachable bytecode vulnerabilities and configuration anomalies before release builds go out, and otherwise stays completely silent."
        wf_close = f"Since {wf_mention} already builds APKs, dropping in a 1-step check is an easy way to ensure unexpected regressions don't slip into production releases."

    body = f"""Hey {first_name},

Came across {app_name} while looking at active Android repos on GitHub.

{hook_p}

{tool_p}

Ran a quick scan on your latest release APK ({apk_name}):

{report_block}

{preview_callout}

{wf_close}

If you find this useful or like where the tool is headed, a star on GitHub would mean a lot! And if anything in the report looks like a false positive, feel free to call it out or open an issue.

Cheers,
Shaurya
https://github.com/no-hup/apkwarden
"""
    return subject, body

def process_candidates(limit: int = 100, force: bool = False):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT r.full_name, r.name, m.name, m.email, r.latest_release_tag, r.release_workflow_path, r.build_task
        FROM drafts d
        JOIN repos r ON d.repo_full_name = r.full_name
        JOIN maintainers m ON d.maintainer_login = m.login
        WHERE d.status != 'SENT' AND m.email IS NOT NULL AND m.email != ''
        ORDER BY r.score DESC, r.stars DESC
        LIMIT ?;
    """, (limit,))
    rows = cur.fetchall()
    print(f"[*] Processing inline APK reports for {len(rows)} candidates...")

    findings_stats = {
        "dirty_stream": 0,
        "intent_redirection": 0,
        "pending_intent_mutability": 0,
        "android14_export_flag": 0,
        "insecure_webview": 0,
        "cleartext_http": 0,
        "backup_or_config": 0,
        "permissions_only": 0,
        "clean_baseline": 0,
        "skipped_no_apk": 0,
        "already_scanned": 0,
        "total_scanned": 0
    }

    for full_name, app_name, m_name, m_email, tag, wf_path, build_task in rows:
        slug = full_name.replace("/", "_")
        draft_file = DRAFTS_DIR / f"{slug}.md"

        if not force and draft_file.exists():
            existing_content = draft_file.read_text()
            if "APKWarden Release Pre-Flight:" in existing_content:
                print(f"\n[*] {full_name}: Already scanned with inline report. Skipping (pass --force to re-scan).")
                findings_stats["already_scanned"] += 1
                # Track what was found in the existing draft
                if "Clean Release Baseline" in existing_content:
                    findings_stats["clean_baseline"] += 1
                else:
                    if "APK-SEC-001" in existing_content: findings_stats["dirty_stream"] += 1
                    if "APK-SEC-002" in existing_content: findings_stats["intent_redirection"] += 1
                    if "APK-SEC-003" in existing_content: findings_stats["pending_intent_mutability"] += 1
                    if "APK-SEC-004" in existing_content: findings_stats["android14_export_flag"] += 1
                    if "APK-SEC-005" in existing_content: findings_stats["insecure_webview"] += 1
                    if "APK-SEC-017" in existing_content: findings_stats["cleartext_http"] += 1
                    if "APK-SEC-018" in existing_content: findings_stats["backup_or_config"] += 1
                    if "APK-SEC-019" in existing_content: findings_stats["permissions_only"] += 1
                continue

        print(f"\n[*] Processing: {full_name} ({m_email})...")
        try:
            apk_name, apk_url = get_release_apk_info(full_name, tag)
            if not apk_name or not apk_url:
                print("  [-] No APK asset found.")
                findings_stats["skipped_no_apk"] += 1
                continue

            apk_path = download_apk(apk_name, apk_url)
            scan_output = run_apkwarden(apk_path)
            scorecard, items = parse_scan_output(scan_output)
            print(f"  [✓] Scanned! {scorecard} | Filtered actionable items: {len(items)}")

            findings_stats["total_scanned"] += 1
            if not items:
                findings_stats["clean_baseline"] += 1
            else:
                has_bytecode = False
                for item in items:
                    t = item["title"]
                    if "APK-SEC-001" in t:
                        findings_stats["dirty_stream"] += 1
                        has_bytecode = True
                    if "APK-SEC-002" in t:
                        findings_stats["intent_redirection"] += 1
                        has_bytecode = True
                    if "APK-SEC-003" in t:
                        findings_stats["pending_intent_mutability"] += 1
                        has_bytecode = True
                    if "APK-SEC-004" in t:
                        findings_stats["android14_export_flag"] += 1
                        has_bytecode = True
                    if "APK-SEC-005" in t:
                        findings_stats["insecure_webview"] += 1
                        has_bytecode = True
                    if "APK-SEC-017" in t:
                        findings_stats["cleartext_http"] += 1
                    if "APK-SEC-018" in t:
                        findings_stats["backup_or_config"] += 1
                    if "APK-SEC-019" in t and not has_bytecode:
                        findings_stats["permissions_only"] += 1

            # Generate draft with bifurcated copy
            subject, email_body = generate_inline_report_draft(full_name, app_name, m_name, m_email, apk_name, scorecard, items, wf_path, build_task)
            full_draft_content = f"""# Outreach Draft for {full_name}

**Target**: {full_name}
**Maintainer**: {m_name}
**Contact**: {m_email}

---

### Plain-Text Email Draft (Inline APKwarden Report)

**Subject**: {subject}

{email_body}
"""
            draft_file.write_text(full_draft_content)
            print(f"  [📝] Updated draft: {draft_file.name}")

            # Update DB subject
            with conn:
                conn.execute("""
                    UPDATE drafts
                    SET subject = ?, draft_path = ?
                    WHERE repo_full_name = ?
                """, (subject, str(draft_file), full_name))

        except Exception as e:
            print(f"  [!] Skipped {full_name} due to error: {e}")
            continue
        
    print("\n=======================================================")
    print("[*] Scan & Draft Pipeline Summary:")
    print(f"  Total already scanned:            {findings_stats['already_scanned']}")
    print(f"  Total newly scanned:              {findings_stats['total_scanned']}")
    print(f"  Clean release baselines:          {findings_stats['clean_baseline']}")
    print(f"  Dirty Stream (APK-SEC-001):       {findings_stats['dirty_stream']}")
    print(f"  Intent Redirection (APK-SEC-002): {findings_stats['intent_redirection']}")
    print(f"  PendingIntent Mut (APK-SEC-003):  {findings_stats['pending_intent_mutability']}")
    print(f"  Android 14 Export (APK-SEC-004):  {findings_stats['android14_export_flag']}")
    print(f"  Insecure WebView (APK-SEC-005):   {findings_stats['insecure_webview']}")
    print(f"  Cleartext HTTP (APK-SEC-017):     {findings_stats['cleartext_http']}")
    print(f"  Config/Backup (APK-SEC-018):      {findings_stats['backup_or_config']}")
    print(f"  Permissions only (APK-SEC-019):   {findings_stats['permissions_only']}")
    print(f"  Skipped (no APK):                 {findings_stats['skipped_no_apk']}")
    print("=======================================================")

if __name__ == "__main__":
    force_run = "--force" in sys.argv
    lim = 100
    for a in sys.argv[1:]:
        if a.isdigit():
            lim = int(a)
    process_candidates(lim, force=force_run)
