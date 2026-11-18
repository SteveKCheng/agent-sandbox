#!/bin/bash
set -eu
# Usage: test-pid1.sh MODE   (MODE: mixed | control-group)
#
# Simulates a systemd service with PrivatePIDs=yes: agent-sandbox starts as PID 1
# of a new PID namespace (made here by `unshare -pf`), and is stopped as
# systemd would: SIGTERM to the main process only (KillMode=mixed), or to
# every process (KillMode=control-group, the default).
[ -n "${1:-}" ] || { echo >&2 "$0: incorrect arguments" && exit 1; }
cd "$(dirname -- "$0")"
ws=$PWD/workspace; rm -f "$ws"/log
svc='trap "echo got TERM >> ~/log; sleep 2; echo shutdown done >> ~/log; exit 0" TERM
     sleep 1000 & echo started >> ~/log; while :; do sleep 0.1; done'
setsid unshare -Urpf --mount-proc ../agent-sandbox --workspace "$ws" -- /bin/bash -c "$svc" &
outer=$!
sleep 0.5
main=$(pgrep -P "$outer")     # PID 1 of the namespace, as seen from outside
echo "main process: $(ps -o args= -p "$main" | cut -c1-40)"
case $1 in
  mixed)         kill -TERM "$main" ;;
  control-group) kill -TERM -- -"$outer" ;;
esac
wait "$outer"; echo "exit status: $?"
cat "$ws"/log
echo "leftover sandbox processes: $(ps -eo args | grep -cE '^(sleep 1000|../agent-sandbox)')"
