#!/bin/bash
set -eu
# Do agent-sandbox's own processes (the monitor, the init) keep inherited file
# descriptors open, prolonging their lifetime?
cd "$(dirname -- "$0")"
ws="$PWD/workspace"

echo "=== a reader sees EOF when the command closes its output"
start=$(date +%s.%N)
../agent-sandbox --workspace "$ws" "$@" -- sh -c 'echo hello; exec >&- ; sleep 2' |
  { cat >/dev/null; echo "EOF after $(echo "$(date +%s.%N) - $start" | bc | cut -c1-4) s (command exits after 2 s)"; }

echo "=== descriptors of the monitor and the init, with fd 7 inherited"
exec 7</dev/zero
../agent-sandbox --workspace "$ws" "$@" -- sh -c '
  echo "  command: $(ls /proc/$$/fd | tr "\n" " ")(must include 7)"
  # Our init, if there is one (the sandbox can list its descriptors, not see where they lead)
  [ "$$" != 1 ] && [ "$(cat /proc/1/comm)" = agent-sandbox ] && echo "  init:    $(ls /proc/1/fd | tr "\n" " ")"
  sleep 1' &
sleep 0.5
monitor=$!
[ "$(cat /proc/$monitor/comm)" = agent-sandbox ] &&
  echo "  monitor: $(cd /proc/$monitor/fd && for f in *; do echo -n "$f->$(readlink $f) "; done)"
wait
