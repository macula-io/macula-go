#!/usr/bin/env bash
# macula-ts 0.16.0, step 3: tag origin/main as it is after the prebuilds run for
# the release commit, which publishes @macula-io/ts to npm, then confirm npm.
S=/tmp/claude-1000/-home-rl-work-github-com/5e1dc09d-0b3b-458b-8750-1e1bbaef9ee8/scratchpad
W=$S/wt-macula-ts-go080
cd "$W" || exit 1
RELEASE=$(cat "$S/ts-release.sha")
git fetch -q origin
TARGET=$(git rev-parse origin/main)
git merge-base --is-ancestor "$RELEASE" "$TARGET" || { echo "STOP: origin/main doesn't contain the release commit"; exit 1; }
V=$(git show "$TARGET:package.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
[ "$V" = "0.16.0" ] || { echo "STOP: package.json at ${TARGET:0:7} is $V"; exit 1; }
git log --format='%h %an %s' "${RELEASE}^..$TARGET"
cat > "$S/ts-tag-v0.16.0.txt" <<'MSG'
v0.16.0: the UCAN audience is the caller's node ID in hex, on macula-go v0.8.2

Breaking:
- Ucan.mint writes aud as the audience NodeID in lowercase hex. A provider
  gated with ucan.Required on macula-go v0.8.0 or later accepts a token only
  from the caller its aud names, in that form.
- serve() answers only CALLs signed by the caller they name.

resolveDirect takes opts.deadlineMs (10 s when unset). Direct dial tries
every advertisement that verifies. See CHANGELOG.md.
MSG
git -c user.name=beamologist -c user.email=raf.lefever@erlef.org tag -a v0.16.0 -F "$S/ts-tag-v0.16.0.txt" "$TARGET" || exit 1
git push origin v0.16.0 2>&1 | tail -1
git ls-remote origin refs/tags/v0.16.0 'refs/tags/v0.16.0^{}' | awk '{print substr($1,1,12), $2}'
echo "$TARGET" > "$S/ts-tag.sha"
