#!/usr/bin/env python3
"""
Batch-create GitHub issues from NEW_ISSUES_41_60.md using the gh CLI.

Usage:
  python3 scripts/create_issues.py              # Create all 20 issues
  python3 scripts/create_issues.py --dry-run    # Preview without creating
  python3 scripts/create_issues.py --only 41,42,43  # Create only specific issues
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

REPO = "connect-boiz/soroban-security-scanner"
INPUT_FILE = "NEW_ISSUES_41_60.md"

PRIORITY_LABELS = {
    "🟠 High": "priority-high",
    "🟡 Medium": "priority-medium",
    "🟢 Low": "priority-low",
}


def parse_issues(filepath: str) -> list[dict]:
    """Parse the markdown file and return a list of issue dicts."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Split on issue headers: "## Issue NN:"
    # Use a regex that captures the issue header as a delimiter
    pattern = r"(## Issue (\d+):[^\n]*)"
    parts = re.split(pattern, content)

    issues = []
    # parts will be: [before_first_issue, full_header_41, "41", body_41,
    #                 full_header_42, "42", body_42, ...]
    # Start from index 1
    i = 1
    while i < len(parts) - 2:
        header_line = parts[i].strip()
        issue_num = parts[i + 1]
        body_text = parts[i + 2].strip()

        # Stop at the first "---" to get just this issue's body (before the next separator)
        # But we want everything up to the next issue header or end of file
        # Since we're already splitting by issue headers, body_text is already isolated

        # Extract title: everything after "## Issue NN: " (handles both " : " and ":" separators)
        title = header_line.split(": ", 1)[-1].strip()

        # Remove the trailing "---" lines and anything after the summary table
        # Find the "## Summary" section if present and truncate there
        summary_pos = body_text.find("\n## Summary")
        if summary_pos != -1:
            body_text = body_text[:summary_pos]

        # Remove only a trailing "---" separator line, not content dashes
        body_text = re.sub(r'\n---+\s*$', '', body_text).strip()

        # Extract priority
        priority_match = re.search(r"\*\*Priority:\*\*\s*(.+)", body_text)
        priority_raw = priority_match.group(1).strip() if priority_match else "🟡 Medium"
        label = PRIORITY_LABELS.get(priority_raw, "priority-medium")

        issues.append({
            "number": int(issue_num),
            "title": title,
            "body": body_text,
            "labels": [label, "new-issue"],
        })
        i += 3

    return issues


def create_issue(issue: dict, dry_run: bool = False) -> bool:
    """Create a single GitHub issue. Returns True on success."""
    title = issue["title"]
    labels = ",".join(issue["labels"])
    number = issue["number"]

    body_file = None

    # Write body to a temporary file to avoid shell escaping issues
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", delete=False, encoding="utf-8"
    ) as f:
        f.write(issue["body"])
        body_file = f.name

    try:
        cmd = [
            "gh", "issue", "create",
            "--repo", REPO,
            "--title", title,
            "--body-file", body_file,
            "--label", labels,
        ]

        if dry_run:
            print(f"\n{'='*70}")
            print(f"[DRY RUN] Would create issue #{number}:")
            print(f"  Title:  {title}")
            print(f"  Labels: {labels}")
            print(f"  Body:   ({len(issue['body'])} chars) — first 150 chars:")
            print(f"    {issue['body'][:150]}...")
            print(f"{'='*70}")
            return True
        else:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                issue_url = result.stdout.strip()
                print(f"✅ Created issue #{number}: {issue_url}")
                return True
            else:
                print(f"❌ Failed to create issue #{number}:")
                print(f"   stderr: {result.stderr.strip()}")
                return False
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout creating issue #{number}")
        return False
    finally:
        if body_file:
            os.unlink(body_file)


def main():
    parser = argparse.ArgumentParser(
        description="Batch-create GitHub issues from NEW_ISSUES_41_60.md"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview issues without creating them",
    )
    parser.add_argument(
        "--only",
        type=str,
        help="Comma-separated list of issue numbers to create (e.g., 41,42,43)",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=INPUT_FILE,
        help=f"Path to the issues markdown file (default: {INPUT_FILE})",
    )
    args = parser.parse_args()

    input_file = args.file
    if not os.path.exists(input_file):
        print(f"❌ Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    issues = parse_issues(input_file)

    if not issues:
        print("❌ No issues parsed from the file.", file=sys.stderr)
        sys.exit(1)

    # Filter by --only if specified
    if args.only:
        selected = set()
        for n in args.only.split(","):
            try:
                selected.add(int(n.strip()))
            except ValueError:
                print(f"⚠️  Skipping invalid issue number: '{n.strip()}'", file=sys.stderr)
        if not selected:
            print(f"❌ No valid issue numbers in --only filter: {args.only}", file=sys.stderr)
            sys.exit(1)
        issues = [i for i in issues if i["number"] in selected]
        if not issues:
            print(f"❌ No parsed issues match --only filter: {args.only}", file=sys.stderr)
            sys.exit(1)

    print(f"Found {len(issues)} issues to create in repo '{REPO}'")
    if args.dry_run:
        print("Running in DRY RUN mode — no issues will be created.\n")

    success_count = 0
    fail_count = 0

    for issue in issues:
        if create_issue(issue, dry_run=args.dry_run):
            success_count += 1
        else:
            fail_count += 1

    print(f"\n{'='*70}")
    print(f"Done! Created: {success_count}, Failed: {fail_count}")
    if args.dry_run:
        print("(DRY RUN — no issues were actually created)")


if __name__ == "__main__":
    main()
