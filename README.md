# agent-sandbox

A small script/program, written in [Nim](https://nim-lang.org/), that creates sandboxes for AI agents, 
e.g. for them to write code and run build/debug tools.

Its goal is to allow agents to access the Linux command line, while not allowing them:

  - to modify any host system-installed binaries
  - to read or modify the host system configuration (so secrets are not leaked)
  - to read or modify any of the user's files except white-listed ones
  - (optionally) to access the network, with (app-specific) firewalling

No root privileges are needed.  Nim can compile into a small self-contained executable (with no dependencies other than on `libc` and `libm`) that can be dropped anywhere.

Your home directory's files, after filtering, are mounted inside the sandbox at the same paths as in the host system, so any absolute paths (e.g. `/home/user/subpath`) embedded inside your files and application data should continue to work.  The software that the AI agents builds inside the sandbox should be accessible and buildable outside the sandbox, without needing to synchronize files manually.

With this tool, you can easily switch "workspaces" for AI agents, giving each workspace its own sandboxing profile.

Originally, the author had used [Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) to instantiate the sandboxes.  He had a shell script to translate arguments for `bwrap` to make it easier to use for a subset of its full functionality.  But working around `bwrap`'s deficiencies in a shell script became too difficult.  And furthermore, the author realized that the ‘sandboxing’ involved nothing much more than translating arguments to Linux system calls to create namespaces and to bind-mount paths, and so experimented with re-implementing what he needed in Nim.  This project is the result.

