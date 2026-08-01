#!/usr/bin/env bash
# Publish site/ to the gh-pages branch, which is what GitHub Pages serves.
#
# A GitHub Actions workflow would be the tidier mechanism, but the credentials this
# repo is pushed with do not carry the `workflow` scope, so `.github/workflows/*`
# cannot be created. Publishing the built directory to a branch needs no extra scope
# and the site is fully static, so there is nothing to build first.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/carlosrymer/inspect-ai-owasp-agentic-top10.git}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -r "$ROOT/site/." "$WORK/"
touch "$WORK/.nojekyll"   # serve the directory verbatim, no Jekyll processing

cd "$WORK"
git init -q
git add -A
git commit -q -m "Publish static site $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git branch -M gh-pages
git remote add origin "$REPO_URL"
git push -f origin gh-pages

echo "Published. https://carlosrymer.github.io/inspect-ai-owasp-agentic-top10/"
