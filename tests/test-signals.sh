#!/bin/bash
set -eu
# Usage: test-signals.sh MODE [agent-sandbox options...]   (MODE: top | group | kill)
#
# Runs a service that takes 2 s to shut down after SIGTERM, with a
# background grandchild, in its own session, and signals it.
cd "$(dirname -- "$0")"
[ -n "${1:-}" ] || { echo >&2 "$0: incorrect arguments" && exit 1; }
mode=$1; shift
ws=$PWD/workspace; rm -f "$ws"/log
svc='trap "echo got TERM >> ~/log; sleep 2; echo shutdown done >> ~/log; exit 0" TERM
     sleep 1000 & echo started >> ~/log; while :; do sleep 0.1; done'
# Not a process group leader (no job control in scripts), so setsid doesn't fork
setsid ../agent-sandbox --workspace "$ws" "$@" -- /bin/bash -c "$svc" &
pid=$!
sleep 0.5
echo "process tree: $(ps -o args= --ppid "$pid" -p "$pid" | cut -c1-40 | paste -sd'|')"
case $mode in
  top)   kill -TERM "$pid" ;;
  group) kill -TERM -- -"$pid" ;;
  kill)  kill -KILL "$pid" ;;
esac
wait "$pid"; echo "exit status: $?"
sleep 0.3
cat "$ws"/log
echo "leftover sandbox processes: $(ps -eo args | grep -cE '^(sleep 1000|../agent-sandbox)')"
pkill -x -f 'sleep 1000'
