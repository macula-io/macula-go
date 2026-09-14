#!/usr/bin/env bash
# Runs macula-php's live examples 08, 09, 10 and 13 from the worktree, each
# provider/caller pair in its own process group so a failure leaves nothing
# running.
set -m
S=/tmp/claude-1000/-home-rl-work-github-com/5e1dc09d-0b3b-458b-8750-1e1bbaef9ee8/scratchpad
cd "$S/wt-macula-php-go080" || exit 1
unset MACULA_LIBRARY_PATH
run() {
  name=$1; shift
  timeout 150 "$@" > "$S/php-live-$name.log" 2>&1 &
  pid=$!
  wait "$pid"; rc=$?
  kill -- -"$pid" 2>/dev/null
  echo "$name exit=$rc: $(tail -1 "$S/php-live-$name.log")"
}
run 08 bash examples/08_run_direct_dial_provider.sh
run 09 bash examples/09_run_ucan_gated_serve.sh
run 10 php examples/10_cert_chain_sanity_check.php
run 13 bash examples/13_run_direct_dial_ucan_gated.sh
