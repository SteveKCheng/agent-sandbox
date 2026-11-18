#!/bin/bash
set -eu
# Can the sandbox signal, or read the environment of, the user's other processes?
cd "$(dirname -- "$0")"
sleep 300 & victim=$!
SECRET_TOKEN=hunter2 sleep 301 & victim2=$!
../agent-sandbox --workspace "$PWD/workspace" "$@" -- /bin/sh -c "
  echo \"processes visible: \$(ls -d /proc/[0-9]* | wc -l)\"
  echo -n 'cmdline of a host process: '; tr '\0' ' ' < /proc/$victim2/cmdline 2>&1; echo
  echo -n 'environ of a host process: '; tr '\0' '\n' < /proc/$victim2/environ 2>&1 | grep -o 'SECRET.*\|denied'
  kill -TERM $victim 2>&1 && echo 'SIGTERM sent to host process'
"
kill -0 $victim 2>/dev/null && echo "host process: alive" || echo "host process: KILLED"
kill $victim $victim2 2>/dev/null; wait 2>/dev/null
