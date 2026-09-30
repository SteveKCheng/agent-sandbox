# agent-sandbox

An opinionated front-end to [Bubblewrap](https://github.com/containers/bubblewrap) that creates sandboxes for AI agents, e.g. for them to write code and run build/debug tools.

Its goal is to allow agents to access the Linux command line, while not allowing them:

  - to modify any host system-installed binaries
  - to read or modify the host system configuration (so secrets are not leaked)
  - to read or modify any of the user's files except white-listed ones
  - (optionally) to access the network, with (app-specific) firewalling

No root privileges are needed.  The script, written in GNU Bash, runs under your normal user account.  

Your home directory's files, after filtering, are mounted inside the sandbox at the same paths as in the host system, so any absolute paths (e.g. `/home/user/subpath`) embedded inside your files and application data should continue to work.  The software that the AI agents builds inside the sandbox should be accessible and buildable outside the sandbox, without needing to synchronize files manually.

`bwrap` can set up sandboxes in fairly arbitrary ways.  This front-end exposes a subset of the options available to make it easier to control.  You can easily switch "workspaces" for AI agents to work on different projects.

## Dependencies

  - [Bubblewrap](https://github.com/containers/bubblewrap) (`bwrap` command): constructs the namespaces for the sandbox
  - [Passt](https://passt.top/passt/) (`pasta` command): Layer-4 tunnelling to enable filtered network access
  - [GNU Bash](https://www.gnu.org/software/bash/): shell
  - [nftables](https://wiki.nftables.org/): kernel-level firewalling

