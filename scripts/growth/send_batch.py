#!/usr/bin/env python3
"""
Sender script to dispatch outreach emails via ~/Desktop/self/email-handler/send.py
Tracks dispatched messages in growth.db to prevent duplicate sending.
"""

import sys
import os
import sqlite3
import subprocess
import tempfile
import re
from pathlib import Path

EMAIL_HANDLER_DIR = Path.home() / "Desktop" / "self" / "email-handler"
VENV_PYTHON = EMAIL_HANDLER_DIR / ".venv" / "bin" / "python"
SEND_SCRIPT = EMAIL_HANDLER_DIR / "send.py"
DB_PATH = Path(__file__).parent / "growth.db"
DRAFTS_DIR = Path(__file__).parent / "outreach_drafts"

BCC_EMAIL = "jaguarbailey@gmail.com"
FROM_NAME = "Shaurya Jaiswal"
ALIAS = "outreach"

def extract_email_body(draft_path: Path) -> tuple[str, str]:
    """Extracts subject and plain text body from markdown draft."""
    content = draft_path.read_text()
    
    # Extract subject
    m_subj = re.search(r"\*\*Subject\*\*:\s*(.+)", content)
    subject = m_subj.group(1).strip() if m_subj else "quick note on release CI"
    
    # Extract body below the subject line
    parts = re.split(r"\*\*Subject\*\*:.+\n+", content)
    if len(parts) > 1:
        body = parts[1].strip()
    else:
        body = content.strip()
        
    return subject, body

def send_to_candidate(repo_full_name: str, to_email: str, draft_path: Path, dry_run: bool = False, as_draft: bool = False) -> bool:
    if not draft_path.exists():
        print(f"[!] Error: Draft not found at {draft_path}")
        return False
        
    subject, body = extract_email_body(draft_path)
    
    print(f"\n=======================================================")
    print(f"[*] Target: {repo_full_name}")
    print(f"[*] To:     {to_email}")
    print(f"[*] Subj:   {subject}")
    print(f"[*] BCC:    {BCC_EMAIL}")
    print(f"=======================================================")
    
    if dry_run:
        print("[i] DRY RUN: Would execute send.py with body:")
        print("-------------------------------------------------------")
        print(body[:200] + "...\n[truncated]")
        return True
        
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
        tf.write(body)
        temp_body_path = tf.name

    try:
        cmd = [
            str(VENV_PYTHON),
            str(SEND_SCRIPT),
            ALIAS,
            "--to", to_email,
            "--subject", subject,
            "--body-file", temp_body_path,
            "--from-name", FROM_NAME,
            "--bcc", BCC_EMAIL
        ]
        if as_draft:
            cmd.append("--draft")
            
        res = subprocess.run(cmd, cwd=str(EMAIL_HANDLER_DIR), capture_output=True, text=True, check=True)
        out = res.stdout.strip()
        print(f"[✓] Success: {out}")
        
        # Extract msgId if present
        m_id = re.search(r"id=([a-zA-Z0-9_-]+)", out)
        msg_id = m_id.group(1) if m_id else "SENT"
        
        # Update DB
        conn = sqlite3.connect(DB_PATH)
        with conn:
            conn.execute("""
                UPDATE drafts 
                SET status = 'SENT'
                WHERE repo_full_name = ?
            """, (repo_full_name,))
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Send failed: {e.stderr}", file=sys.stderr)
        return False
    finally:
        if os.path.exists(temp_body_path):
            os.remove(temp_body_path)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Dispatch outreach emails")
    parser.add_argument("--repo", help="Single repo to send to")
    parser.add_argument("--limit", type=int, default=20, help="Number of pending drafts to send")
    parser.add_argument("--dry-run", action="store_true", help="Print command without sending")
    parser.add_argument("--draft", action="store_true", help="Create as Gmail draft instead of sending")
    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    if args.repo:
        cur.execute("""
            SELECT d.repo_full_name, m.email, d.draft_path
            FROM drafts d
            JOIN maintainers m ON d.maintainer_login = m.login
            WHERE d.repo_full_name = ? AND m.email IS NOT NULL AND m.email != ''
        """, (args.repo,))
    else:
        cur.execute("""
            SELECT d.repo_full_name, m.email, d.draft_path
            FROM drafts d
            JOIN repos r ON d.repo_full_name = r.full_name
            JOIN maintainers m ON d.maintainer_login = m.login
            WHERE d.status = 'PENDING_APPROVAL' AND m.email IS NOT NULL AND m.email != ''
            ORDER BY r.score DESC, r.stars DESC
            LIMIT ?
        """, (args.limit,))
        
    rows = cur.fetchall()
    print(f"[*] Found {len(rows)} targets ready for dispatch.")
    
    sent_count = 0
    for repo_full_name, email, draft_path in rows:
        ok = send_to_candidate(repo_full_name, email, Path(draft_path), dry_run=args.dry_run, as_draft=args.draft)
        if ok:
            sent_count += 1
            
    print(f"\n[*] Finished. Total processed: {sent_count}/{len(rows)}")
