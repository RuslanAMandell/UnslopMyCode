#!/bin/sh
# Cut a release.
#
# main is the working branch. Users install the tag named in
# .claude-plugin/marketplace.json, so nothing reaches them until this runs.
#
#   ./scripts/release.sh 0.3.0
set -e

VERSION="$1"
if [ -z "$VERSION" ]; then
  echo "usage: ./scripts/release.sh <version>   (for example 0.3.0)" >&2
  exit 2
fi
case "$VERSION" in
  v*) echo "pass the version without the leading v" >&2; exit 2 ;;
esac
TAG="v$VERSION"

if [ -n "$(git status --porcelain)" ]; then
  echo "working tree is dirty; commit or stash first" >&2
  exit 1
fi
if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
  echo "releases are cut from main" >&2
  exit 1
fi
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "$TAG already exists" >&2
  exit 1
fi
if ! grep -q "^## $VERSION" CHANGELOG.md; then
  echo "CHANGELOG.md has no '## $VERSION' section; write it first" >&2
  exit 1
fi

echo "==> tests"
make check

echo "==> stamping $VERSION"
python3 - "$VERSION" <<'PY'
import json, sys
from pathlib import Path
version = sys.argv[1]
p = Path(".claude-plugin/plugin.json"); d = json.loads(p.read_text())
d["version"] = version
p.write_text(json.dumps(d, indent=2) + "\n")
p = Path(".claude-plugin/marketplace.json"); d = json.loads(p.read_text())
d["metadata"]["version"] = version
d["plugins"][0]["version"] = version
d["plugins"][0]["source"]["ref"] = "v" + version
p.write_text(json.dumps(d, indent=2) + "\n")
PY

echo "==> validating manifests"
claude plugin validate . --strict

echo "==> re-running tests against the stamped manifests"
make check

git add .claude-plugin CHANGELOG.md
# The stamp is a no-op when the version was already written by hand. That is
# not a failure, and it must not stop the tag from being cut.
if git diff --cached --quiet; then
  echo "    manifests already at $VERSION, nothing to commit"
else
  git commit -m "release: $VERSION"
fi
git tag -a "$TAG" -m "$VERSION"

echo
echo "Staged locally. Nothing is live until you push:"
echo "    git push origin main && git push origin $TAG"
echo "    gh release create $TAG --title $VERSION --notes-from-tag"
