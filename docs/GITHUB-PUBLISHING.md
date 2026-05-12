# GitHub Publishing Guide

## Recommended repository name

```text
path-b-external-suricata-ips
```

## Recommended description

```text
Source-available lab preview: external ICAP server with Suricata backend for Squid SSL-Bump test environments. Not production-ready.
```

## First commit

```bash
git init
git add .
git commit -m "Initial source-available lab release v5.12"
git branch -M main
```

## Create repository with GitHub CLI

```bash
gh repo create path-b-external-suricata-ips \
  --public \
  --source=. \
  --remote=origin \
  --push \
  --description "Source-available lab preview: external ICAP server with Suricata backend for Squid SSL-Bump. Not production-ready."
```

## Release

```bash
git tag -a v5.12-lab-preview -m "Path-B v5.12 Community Lab Preview"
git push origin v5.12-lab-preview

gh release create v5.12-lab-preview \
  --title "Path-B v5.12 Community Lab Preview" \
  --notes-file RELEASE_NOTES-v5.12.md
```

## Wiki

The `wiki/` directory can be used as repository documentation or copied to the GitHub wiki repository.

## Checklist

- `LICENSE.md` is present.
- README clearly says source-available and not production-ready.
- No generated CA, private keys, Windows kits, or runtime logs are committed.
- `deployment.env` is not committed.
- `deployment.env.example` is generic.
- Static validation action passes.
