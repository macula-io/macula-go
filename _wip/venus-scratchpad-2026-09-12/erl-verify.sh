#!/bin/sh
# Full eunit, lint and dialyzer on the direct-dial worktree, logs named by commit.
S=/tmp/claude-1000/-home-rl-work-github-com/5e1dc09d-0b3b-458b-8750-1e1bbaef9ee8/scratchpad
cd "$S/wt-macula-directdial" || exit 1
H=$(git rev-parse --short HEAD)
rm -f "$S/erl-verify.done" "$S/erl-verify.result"
date -u '+eunit start %H:%M:%SZ' > "$S/erl-verify.times"
mise exec -- rebar3 eunit > "$S/erl-eunit-$H.log" 2>&1; echo "eunit=$?" > "$S/erl-verify.result"
date -u '+lint start %H:%M:%SZ' >> "$S/erl-verify.times"
mise exec -- rebar3 as lint lint > "$S/erl-lint-$H.log" 2>&1; echo "lint=$?" >> "$S/erl-verify.result"
date -u '+dialyzer start %H:%M:%SZ' >> "$S/erl-verify.times"
mise exec -- rebar3 dialyzer > "$S/erl-dialyzer-$H.log" 2>&1; echo "dialyzer=$?" >> "$S/erl-verify.result"
date -u '+done %H:%M:%SZ' >> "$S/erl-verify.times"
touch "$S/erl-verify.done"
