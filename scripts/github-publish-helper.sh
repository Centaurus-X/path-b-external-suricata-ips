#!/usr/bin/env bash
# Path-B GitHub publishing helper. Non-destructive by default.
set -euo pipefail

OWNER_REPO=""
VISIBILITY="public"
PUSH="0"
CREATE_RELEASE="0"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo) OWNER_REPO="$2"; shift 2 ;;
        --public) VISIBILITY="public"; shift ;;
        --private) VISIBILITY="private"; shift ;;
        --push) PUSH="1"; shift ;;
        --release) CREATE_RELEASE="1"; shift ;;
        -h|--help)
            cat <<'HELP'
Usage:
  bash scripts/github-publish-helper.sh --repo OWNER/path-b-external-suricata-ips --public --push --release

Requires: git and optionally GitHub CLI (gh).
HELP
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$OWNER_REPO" ]] || { echo "Please provide --repo OWNER/REPO." >&2; exit 2; }
command -v git >/dev/null || { echo "git missing" >&2; exit 1; }

if [[ ! -d .git ]]; then
    git init
fi

git add .
if ! git diff --cached --quiet; then
    git commit -m "Initial source-available lab release v5.12"
fi
git branch -M main

if command -v gh >/dev/null 2>&1; then
    if ! gh repo view "$OWNER_REPO" >/dev/null 2>&1; then
        gh repo create "$OWNER_REPO" "--$VISIBILITY" --source=. --remote=origin --description "Source-available lab preview: external ICAP server with Suricata backend for Squid SSL-Bump. Not production-ready."
    else
        if ! git remote get-url origin >/dev/null 2>&1; then
            git remote add origin "https://github.com/${OWNER_REPO}.git"
        fi
    fi
else
    if ! git remote get-url origin >/dev/null 2>&1; then
        git remote add origin "https://github.com/${OWNER_REPO}.git"
    fi
fi

if [[ "$PUSH" == "1" ]]; then
    git push -u origin main
fi

if [[ "$CREATE_RELEASE" == "1" ]]; then
    git tag -a v5.12-lab-preview -m "Path-B v5.12 Community Lab Preview" 2>/dev/null || true
    git push origin v5.12-lab-preview || true
    if command -v gh >/dev/null 2>&1; then
        gh release create v5.12-lab-preview --title "Path-B v5.12 Community Lab Preview" --notes-file RELEASE_NOTES-v5.12.md || true
    fi
fi
