#!/bin/bash
set -eu
# Tests of the init's own duties.
cd "$(dirname -- "$0")"
ws=$PWD/workspace; rm -f "$ws"/log

echo "=== orphans are reaped (no zombies)"
../agent-sandbox --workspace "$ws" -- /bin/sh -c '
  # Orphans, which become children of PID 1. (Compare with --no-init and
  # a command that, unlike sh, never reaps children it did not start, e.g.
  # Python: they stay zombies.)
  for i in 1 2 3; do (sleep 0.2 &); done
  sleep 1
  echo "zombies: $(ps -eo stat | grep -c ^Z)"'

echo "=== leftovers when the command exits: graceful one, and one ignoring SIGTERM"
start=$(date +%s.%N)
../agent-sandbox --workspace "$ws" --stop-timeout 3 -- /bin/sh -c '
  sh -c "trap \"sleep 1; echo graceful leftover done >> ~/log; exit\" TERM; while :; do sleep 0.1; done" &
  sh -c "trap \"echo stubborn leftover ignored TERM >> ~/log\" TERM; while :; do sleep 0.1; done" &
  sleep 0.3; exit 7'
echo "exit status: $? (expected 7), took $(echo "$(date +%s.%N) - $start" | bc | cut -c1-4) s (expected ~3.3)"
cat "$ws"/log; rm -f "$ws"/log

echo "=== leftovers that all exit quickly don't make us wait"
start=$(date +%s.%N)
../agent-sandbox --workspace "$ws" --stop-timeout 3 -- /bin/sh -c 'sleep 100 & sleep 0.3'
echo "took $(echo "$(date +%s.%N) - $start" | bc | cut -c1-4) s (expected ~0.3)"
echo "leftover sandbox processes: $(ps -eo args | grep -cE '^(sleep 100|../agent-sandbox)')"
