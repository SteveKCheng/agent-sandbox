#!/usr/bin/env python3
"""Terminal tests: types into an interactive bash in a new pseudo-terminal,
as a user would, and prints what appears on the terminal.

Run: python3 -I test-tty.py"""
import os, pty, select, sys, time

here = os.path.dirname(os.path.abspath(__file__))
box = f"{here}/../agent-sandbox --workspace {here}/workspace"

script = [
    # Ctrl-C reaches the command, which dies of it, as without a sandbox
    (f"{box} -- sleep 5; echo exit status $?\n", 1.0),
    ("\x03", 0.5),
    # Ctrl-Z stops the sandbox like any job; fg resumes it
    (f"{box} -- sh -c 'sleep 1; echo slept'\n", 0.5),
    ("\x1a", 0.5),
    ("jobs; ps -o stat=,args= -C sleep\n", 0.5),
    ("fg\n", 1.5),
    # Job control in a shell inside the sandbox
    (f"{box} -- bash --norc -i\n", 1.0),
    ("sleep 30 &\n", 0.3),
    ("jobs; kill %1; exit\n", 1.0),
    ("exit\n", 0.5),
]

pid, fd = pty.fork()
if pid == 0:
    os.environ["PS1"] = "$ "
    os.execvp("bash", ["bash", "--norc", "-i"])
out = b""
def drain(seconds):
    global out
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try: out += os.read(fd, 4096)
            except OSError: return
drain(0.5)
for text, wait in script:
    os.write(fd, text.encode())
    drain(wait)
os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
