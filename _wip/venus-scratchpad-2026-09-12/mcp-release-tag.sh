#!/usr/bin/env bash
# macula-mcp v0.31.0: tag the release commit once its CI succeeded, matching
# the type of the v0.30.0 tag. Pushing the tag runs release.yml, which
# publishes @macula-io/mcp to npm.
S=/tmp/claude-1000/-home-rl-work-github-com/5e1dc09d-0b3b-458b-8750-1e1bbaef9ee8/scratchpad
W=$S/wt-macula-mcp-ts016
cd "$W" || exit 1
SHA=$(cat "$S/mcp-release.sha")
ci=$(gh run list --repo macula-io/macula-mcp --limit 10 --json workflowName,headSha,conclusion \
  --jq ".[] | select(.headSha==\"$SHA\" and .workflowName==\"CI\") | .conclusion" | head -1)
[ "$ci" = "success" ] || { echo "STOP: CI on ${SHA:0:7} is '${ci:-missing}'"; exit 1; }
git fetch -q origin
git merge-base --is-ancestor "$SHA" origin/main || { echo "STOP: origin/main doesn't contain ${SHA:0:7}"; exit 1; }
V=$(git show "$SHA:package.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
[ "$V" = "0.31.0" ] || { echo "STOP: package.json at ${SHA:0:7} is $V"; exit 1; }
if [ "$(git cat-file -t v0.30.0)" = "tag" ]; then
  git log -1 --format=%B "$SHA" > "$S/mcp-tag-v0.31.0.txt"
  git -c user.name=beamologist -c user.email=raf.lefever@erlef.org tag -a v0.31.0 -F "$S/mcp-tag-v0.31.0.txt" "$SHA" || exit 1
else
  git tag v0.31.0 "$SHA" || exit 1
fi
git push origin v0.31.0 2>&1 | tail -1
git ls-remote origin refs/tags/v0.31.0 'refs/tags/v0.31.0^{}' | awk '{print substr($1,1,12), $2}'
echo "$SHA" > "$S/mcp-tag.sha"
