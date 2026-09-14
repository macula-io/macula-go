#!/usr/bin/env bash
# macula-ts 0.16.0, step 2: the release commit, on top of the prebuilds bot's
# commit for the pushed feature. Stops unless origin/main is exactly that commit.
S=/tmp/claude-1000/-home-rl-work-github-com/5e1dc09d-0b3b-458b-8750-1e1bbaef9ee8/scratchpad
W=$S/wt-macula-ts-go080
cd "$W" || exit 1
FEATURE=$(cat "$S/ts-feature.sha")
git fetch -q origin
BOT=$(git rev-parse origin/main)
if [ "$(git rev-parse origin/main^)" != "$FEATURE" ] || [ "$(git log -1 --format=%s origin/main)" != "Update cross-platform prebuilds" ]; then
  echo "STOP: origin/main is not the prebuilds bot commit directly on ${FEATURE:0:7}"
  git log --format='%h %an %s' -3 origin/main
  exit 1
fi
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "STOP: tracked changes in the worktree"; git status --short; exit 1; }
git merge -q --ff-only origin/main || exit 1
mise exec node@26.8.1 -- npm version 0.16.0 --no-git-tag-version > /dev/null || exit 1
python3 - "$W/CHANGELOG.md" <<'PY' || exit 1
import sys
p = sys.argv[1]; s = open(p, encoding="utf-8").read()
if s.count("## [Unreleased]") != 1: sys.exit("STOP: no single Unreleased header")
open(p, "w", encoding="utf-8").write(s.replace("## [Unreleased]", "## [0.16.0] - 2026-09-11"))
PY
/usr/bin/grep -n '"version": "0.16.0"' package.json package-lock.json | head -3
cat > "$S/ts-commit-release.txt" <<MSG
Release v0.16.0: the UCAN audience is the caller's node ID in hex, on macula-go v0.8.2

Version bump and CHANGELOG entry for the change in ${FEATURE:0:7}.
Prebuilds for that code are in ${BOT:0:7}.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01RDgYEpKJPTXSYgnZo7fc9q
MSG
git add package.json package-lock.json CHANGELOG.md
git -c user.name=beamologist -c user.email=raf.lefever@erlef.org commit -q -F "$S/ts-commit-release.txt" || exit 1
git show --stat --format='%h %s' HEAD | tail -5
git push origin HEAD:main 2>&1 | tail -1
git rev-parse HEAD > "$S/ts-release.sha"
echo "release commit pushed: $(awk '{print substr($1,1,7)}' "$S/ts-release.sha")"
