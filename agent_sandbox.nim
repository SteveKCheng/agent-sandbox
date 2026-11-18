## agent-sandbox: a quick-and-dirty prototype of a narrow `bwrap` replacement,
## reproducing what `ai-journal/bwrap/agent-sandbox` asks of `bwrap`.
##
## Not covered: --tunnel-net (pasta), --filter-file, port forwarding (wrap
## this program in specchio instead), --openssh, seccomp.
##
## Process structure, by default:
##
##   agent-sandbox (monitor, outside the sandbox: forwards signals, exits
##   │         with the command's status)
##   └─ agent-sandbox (init: PID 1 of the sandbox's PID namespace)
##      └─ command
##
## The monitor can't be avoided with a PID namespace: a process can never
## enter a new PID namespace itself, only its children can, so the process
## that the caller started stays outside.
##
## So the monitor exists only when agent-sandbox creates the PID namespace.
## Otherwise agent-sandbox sets up the other namespaces in its own process and
## `exec`s, keeping its PID:
##
##  - When agent-sandbox is already PID 1, e.g. in a systemd service with
##    PrivatePIDs=yes, it doesn't create another PID namespace, and
##    becomes the init itself:
##
##      agent-sandbox (init: PID 1 of systemd's PID namespace)
##      └─ command
##
##    systemd has mounted a /proc showing only that namespace, which
##    agent-sandbox bind-mounts into the sandbox, and tears down the whole
##    namespace when the init exits, as the kernel does.
##
##  - With --no-pid-ns, agent-sandbox `exec`s the command directly. Processes
##    it leaves behind aren't killed when it exits, and the sandbox sees
##    the host's /proc: it can list your other processes and their command
##    lines (but not their environment).
##
## In all cases, Landlock keeps the sandbox from signalling or tracing
## processes outside it.
##
## Before running the command, the sandbox is set up in two user namespaces:
##
##  1. ns1, created by `clone()` together with the mount, PID, IPC, UTS,
##     cgroup and network namespaces. We are root in it (UID 0 maps to the
##     user running agent-sandbox), so we can configure everything those
##     namespaces own: mounts, host name, the loopback interface.
##  2. ns2, created by `unshare()` at the end, together with a new mount
##     namespace. It maps the target UID (yours, or 0 with --root) to root
##     of ns1. Copying the mount namespace into a less privileged user
##     namespace makes the kernel lock all the mounts: read-only binds stay
##     read-only, and nothing can be unmounted to reveal what's beneath,
##     even by root in the sandbox. Root in the sandbox has no capabilities
##     over the network namespace, which ns1 owns, so it can't change
##     firewall rules or interfaces.
##
## This replaces the `unshare -Urn` / pasta outer namespace, which
## agent-sandbox needs because `bwrap` can't configure the network namespace
## for a non-root sandbox user.

import std/[algorithm, monotimes, os, posix, strutils, times]

# ------------------------------------------------------------- Linux FFI
#
# Most of these are in glibc's headers, but Nim's posix module only covers
# POSIX. Declaring them is one line each; constants are from the Linux ABI.

const
  CLONE_NEWNS = 0x00020000
  CLONE_NEWCGROUP = 0x02000000
  CLONE_NEWUTS = 0x04000000
  CLONE_NEWIPC = 0x08000000
  CLONE_NEWUSER = 0x10000000
  CLONE_NEWPID = 0x20000000
  CLONE_NEWNET = 0x40000000

  MS_RDONLY = 1
  MS_NOSUID = 2
  MS_NODEV = 4
  MS_NOEXEC = 8
  MS_REMOUNT = 32
  MS_BIND = 4096
  MS_REC = 16384
  MS_SLAVE = 1 shl 19
  MNT_DETACH = 2

  AT_FDCWD = -100
  AT_EMPTY_PATH = 0x1000
  AT_RECURSIVE = 0x8000
  OPEN_TREE_CLONE = 1
  OPEN_TREE_CLOEXEC = 0o2000000
  MOVE_MOUNT_F_EMPTY_PATH = 4
  MOUNT_ATTR_RDONLY = 1'u64
  MOUNT_ATTR_NOSUID = 2'u64
  MOUNT_ATTR_NODEV = 4'u64

  PR_SET_PDEATHSIG = 1
  PR_SET_NO_NEW_PRIVS = 38

  LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1'u64
  LANDLOCK_SCOPE_SIGNAL = 2'u64

  SIOCGIFFLAGS = 0x8913
  SIOCSIFFLAGS = 0x8914
  IFF_UP = 1

var
  SYS_clone {.importc, header: "<sys/syscall.h>".}: clong
  SYS_pivot_root {.importc, header: "<sys/syscall.h>".}: clong
  SYS_open_tree {.importc, header: "<sys/syscall.h>".}: clong
  SYS_move_mount {.importc, header: "<sys/syscall.h>".}: clong
  SYS_mount_setattr {.importc, header: "<sys/syscall.h>".}: clong
  SYS_landlock_create_ruleset {.importc, header: "<sys/syscall.h>".}: clong
  SYS_landlock_restrict_self {.importc, header: "<sys/syscall.h>".}: clong
  SYS_close_range {.importc, header: "<sys/syscall.h>".}: clong

type
  LandlockRulesetAttr = object
    handledAccessFs, handledAccessNet, scoped: uint64
  MountAttr = object
    attrSet, attrClr, propagation, usernsFd: uint64
  IfReq = object          # struct ifreq, only the part we use
    name: array[16, char]
    flags: cshort
    pad: array[22, byte]

proc syscall(number: clong): clong {.importc, header: "<unistd.h>", varargs.}
proc mount(src, target, fstype: cstring, flags: culong, data: cstring): cint
  {.importc, header: "<sys/mount.h>".}
proc umount2(target: cstring, flags: cint): cint {.importc, header: "<sys/mount.h>".}
proc unshare(flags: cint): cint {.importc, header: "<sched.h>".}
proc sethostname(name: cstring, len: csize_t): cint {.importc, header: "<unistd.h>".}
proc prctl(option: cint): cint {.importc, header: "<sys/prctl.h>", varargs.}
proc clearenv(): cint {.importc, header: "<stdlib.h>".}
proc pipe2(fds: var array[2, cint], flags: cint): cint {.importc, header: "<unistd.h>".}
proc ioctl(fd: cint, req: culong): cint {.importc, header: "<sys/ioctl.h>", varargs.}
proc getSigaction(sig: cint, act: ptr Sigaction, old: var Sigaction): cint
  {.importc: "sigaction", header: "<signal.h>".}   # posix.sigaction won't take nil

proc cExit(code: cint) {.importc: "exit", header: "<stdlib.h>", noreturn.}
  ## Nim's quit() saturates exit codes to 0..127 on POSIX (130 becomes 127)

proc check[T: SomeInteger](r: T, what: string): T {.discardable.} =
  ## Raise OSError (with the errno message) if a system call failed.
  if r < 0: raiseOSError(osLastError(), what)
  r

proc die(msg: string) {.noreturn.} =
  stderr.writeLine("agent-sandbox: " & msg)
  quit(1)

# ------------------------------------------------------------- Sandbox plan
#
# The command line and config files are translated into a list of
# operations, applied in order inside the new root, like bwrap's arguments.

type
  OpKind = enum
    opBind, opDir, opTmpfs, opSymlink, opFile, opProc, opDevpts, opMqueue
  Op = object
    dest: string
    case kind: OpKind
    of opBind:
      src: string
      readOnly, optional, devices: bool
      fd: cint                   # detached mount, from open_tree()
      isDir: bool
    of opDir, opTmpfs:
      mode: int
    of opSymlink:
      target: string
    of opFile:
      content: string
      fileMode: int
    of opProc, opDevpts, opMqueue:
      discard

proc `$`(op: Op): string =
  case op.kind
  of opBind:
    (if op.devices: "dev-bind" elif op.readOnly: "ro-bind" else: "bind") &
      (if op.optional: "-try " else: " ") & op.src & " " & op.dest
  of opDir: "dir " & op.dest
  of opTmpfs: "tmpfs (mode " & op.mode.toOct(4) & ") " & op.dest
  of opSymlink: "symlink " & op.target & " " & op.dest
  of opFile: "file " & op.dest & " <<" & op.content.strip.replace("\n", "\\n") & ">>"
  of opProc: "proc " & op.dest
  of opDevpts: "devpts " & op.dest
  of opMqueue: "mqueue " & op.dest

type
  Config = object
    ops: seq[Op]
    env: seq[(string, string)]
    command: seq[string]
    hostName: string
    shareNet: bool
    pidNs: bool                   # create a PID namespace (and a monitor)
    targetUid, targetGid: Uid     # inside the sandbox
    outerUid, outerGid: Uid       # outside, where agent-sandbox runs
    useInit: bool                 # run our init as PID 1 (see runInit)
    stopTimeout: float            # init: seconds to wait for leftover processes
    pidEnv: seq[string]           # variables to set to the command's PID

proc roBind(c: var Config, src: string, dest = "", optional = true) =
  c.ops.add Op(kind: opBind, src: src, dest: (if dest == "": src else: dest),
               readOnly: true, optional: optional)
proc rwBind(c: var Config, src: string, dest = "", optional = true) =
  c.ops.add Op(kind: opBind, src: src, dest: (if dest == "": src else: dest),
               optional: optional)
proc devBind(c: var Config, path: string, optional = true) =
  c.ops.add Op(kind: opBind, src: path, dest: path, devices: true, optional: optional)
proc tmpfs(c: var Config, dest: string, mode = 0o755) =
  c.ops.add Op(kind: opTmpfs, dest: dest, mode: mode)
proc dir(c: var Config, dest: string) =
  c.ops.add Op(kind: opDir, dest: dest, mode: 0o755)
proc symlink(c: var Config, target, dest: string) =
  c.ops.add Op(kind: opSymlink, target: target, dest: dest)
proc file(c: var Config, dest, content: string, mode = 0o444) =
  c.ops.add Op(kind: opFile, dest: dest, content: content, fileMode: mode)

proc bindOrSymlink(c: var Config, src, dest: string) =
  ## Re-create symbolic links instead of following them (e.g. /bin -> usr/bin).
  if symlinkExists(src): c.symlink(expandSymlink(src), dest)
  else: c.roBind(src, dest)

proc addDev(c: var Config) =
  ## A minimal /dev, as bwrap's --dev does.
  c.tmpfs("/dev")
  for node in ["null", "zero", "full", "random", "urandom", "tty"]:
    c.devBind("/dev/" & node, optional = false)
  c.ops.add Op(kind: opDevpts, dest: "/dev/pts")
  c.symlink("pts/ptmx", "/dev/ptmx")
  c.symlink("/proc/self/fd", "/dev/fd")
  for i, name in ["stdin", "stdout", "stderr"]:
    c.symlink("/proc/self/fd/" & $i, "/dev/" & name)
  if isatty(0) != 0:
    c.ops.add Op(kind: opBind, src: $ttyname(0), dest: "/dev/console", devices: true)

# ------------------------------------------------------------- Input files

iterator configLines(path: string): string =
  ## Non-empty lines, with whitespace trimmed, that aren't comments.
  for raw in lines(path):
    let line = raw.strip
    if line.len > 0 and not line.startsWith('#'):
      yield line

proc isValidEnvName(s: string): bool =
  s.len > 0 and s[0] in IdentStartChars and s.allCharsInSet(IdentChars)

proc addEnvSetting(env: var seq[(string, string)], s: string) =
  ## "NAME=VALUE", or just "NAME" to pass through our own value. If we
  ## don't have one, the variable stays unset in the sandbox (rather than
  ## set but empty), as with `docker run -e NAME`.
  let eq = s.find('=')
  let name = if eq < 0: s else: s[0 ..< eq]
  if not isValidEnvName(name):
    die("invalid format for environment setting: " & s)
  if eq >= 0: env.add (name, s[eq + 1 .. ^1])
  elif existsEnv(name): env.add (name, getEnv(name))

proc parseBindSpec(s: string): (string, string) =
  ## "SRC=DEST", or just "PATH" for the same path inside and outside.
  let eq = s.find('=')
  if eq < 0: (s, s) else: (s[0 ..< eq], s[eq + 1 .. ^1])

# ------------------------------------------------------------- Command line

const usage = """
Usage: agent-sandbox [OPTIONS] [--] [program args...]

  -E, --env-file PATH        File with settings for env. variables, one per
                             line, in the same forms as --env
  -r, --root                 Become root (UID=0) inside the sandbox
      --env NAME[=VALUE]     Set another env. variable; just NAME passes
                             through agent-sandbox's own value, if it has one
      --pid-env NAME         Set env. variable NAME to the program's PID, as
                             seen in the sandbox, e.g. LISTEN_PID or
                             SYSTEMD_EXEC_PID for systemd's socket activation
  -e, --etc-dir PATH         Template for /etc inside the sandbox
  -w, --work-manifest PATH   File listing paths to mount read/write
      --ro-bind SRC[=DEST]   Bind-mount a path read-only
      --rw-bind SRC[=DEST]   Bind-mount a path read/write
  -h, --host-name NAME       Host name in the sandbox
  -N, --share-net            Share the network with the host
      --workspace DIR        Directory mounted as the home directory
                             (default: /var/sandboxes/default-workspace)
      --no-init              Run the program itself as PID 1
      --stop-timeout SECONDS When the program exits, how long to wait for
                             other processes in the sandbox to exit after
                             SIGTERM, before they're killed (default: 5)
      --no-pid-ns            No PID namespace: agent-sandbox sets up the sandbox in
                             its own process and becomes the program, without
                             a monitor or init process. Other processes
                             remain visible in /proc, but can't be signalled.
  -d, --dry-run              Show the sandbox plan instead of running it
      --help                 Show this help

When agent-sandbox is PID 1 already (e.g. systemd's PrivatePIDs=yes), it uses
that PID namespace instead of creating one: no monitor, and it becomes
the init itself.
"""

type Options = object
  envFile, etcDir, hostName, workspace: string
  root, shareNet, dryRun, noInit, noPidNs: bool
  workManifests, envSettings, pidEnv: seq[string]
  stopTimeout: float
  roBinds, rwBinds: seq[(string, string)]
  command: seq[string]

proc parseCommandLine(args: seq[string]): Options =
  result.workspace = "/var/sandboxes/default-workspace"
  result.stopTimeout = 5
  var i = 0
  while i < args.len:
    var arg = args[i]
    inc i
    if arg == "--":
      result.command = args[i .. ^1]
      return
    if not arg.startsWith('-') or arg == "-":
      result.command = args[i - 1 .. ^1]   # first non-option starts the command
      return
    # "--name=value" form
    var inlineValue = ""
    var hasInline = false
    if arg.startsWith("--") and '=' in arg:
      let eq = arg.find('=')
      inlineValue = arg[eq + 1 .. ^1]
      hasInline = true
      arg = arg[0 ..< eq]
    proc value(): string =
      if hasInline: return inlineValue
      if i >= args.len: die("option " & arg & " requires an argument")
      inc i
      args[i - 1]
    case arg
    of "-E", "--env-file": result.envFile = value()
    of "-r", "--root": result.root = true
    of "--env": result.envSettings.add value()
    of "--pid-env":
      let name = value()
      if not isValidEnvName(name): die("invalid environment variable name: " & name)
      result.pidEnv.add name
    of "-e", "--etc-dir": result.etcDir = value()
    of "-w", "--work-manifest": result.workManifests.add value()
    of "--ro-bind": result.roBinds.add parseBindSpec(value())
    of "--rw-bind": result.rwBinds.add parseBindSpec(value())
    of "-h", "--host-name": result.hostName = value()
    of "-N", "--share-net": result.shareNet = true
    of "--workspace": result.workspace = value()
    of "--stop-timeout":
      let v = value()
      try: result.stopTimeout = parseFloat(v)
      except ValueError: die("invalid number for --stop-timeout: " & v)
    of "--no-init": result.noInit = true
    of "--no-pid-ns": result.noPidNs = true
    of "-d", "--dry-run": result.dryRun = true
    of "--help": stdout.write(usage); quit(0)
    else: die("unknown option: " & arg & " (see --help)")

# ------------------------------------------------------------- Building the plan
#
# This part follows agent-sandbox closely, in the same order.

proc realId(id: uint32, mapFile: string): uint32 =
  ## The user (or group) we really are. When we are root of a user namespace
  ## that maps only one ID, e.g. under `unshare -r`, pasta, or specchio
  ## --root (or systemd's PrivatePIDs= in a user service), that's the
  ## ID outside, from the map: "0 1000 1" means we're really 1000.
  if id != 0: return id
  let fields = readFile(mapFile).splitWhitespace
  if fields.len == 3 and fields[0] == "0" and fields[2] == "1":
    return uint32(parseUInt(fields[1]))
  id

proc buildConfig(o: Options): Config =
  var c: Config
  c.outerUid = geteuid()
  c.outerGid = getegid()
  c.shareNet = o.shareNet
  # Already PID 1 of a PID namespace, e.g. from systemd's PrivatePIDs=yes?
  # Then that namespace will do, and we can't mount a new /proc in it
  # anyway (it isn't owned by our user namespace)
  let isPid1 = getpid() == 1
  c.pidNs = not o.noPidNs and not isPid1
  let realUid = Uid(realId(uint32(getuid()), "/proc/self/uid_map"))
  let realGid = Gid(realId(uint32(getgid()), "/proc/self/gid_map"))
  if o.root:
    c.targetUid = 0; c.targetGid = 0
  else:
    c.targetUid = realUid; c.targetGid = realGid

  let pw = getpwuid(realUid)
  if pw == nil: die("current user not found in the user database")
  let realHome = $pw.pw_dir
  if realHome == "/":
    die("home directory of " & $pw.pw_name & " is /: refusing to mount over the root")
  let loginShell = $pw.pw_shell

  if o.shareNet:
    if o.hostName != "":
      die("cannot override host name of sandbox when sharing existing network")
  else:
    c.hostName = if o.hostName != "": o.hostName else: readFile("/proc/sys/kernel/hostname").strip & "-sandbox"

  if c.pidNs:
    c.ops.add Op(kind: opProc, dest: "/proc")
  else:
    # A new proc instance needs a new PID namespace: use the host's
    c.rwBind("/proc", optional = false)
  c.addDev()
  for p in ["/dev/dri", "/dev/udmabuf", "/dev/dma_heap"]: c.devBind(p)
  c.roBind("/sys")
  c.ops.add Op(kind: opMqueue, dest: "/dev/mqueue")
  c.tmpfs("/tmp", 0o1777)
  c.tmpfs("/run")
  c.dir("/run/lock")
  c.dir("/run/user/" & $c.targetUid)
  c.tmpfs("/dev/shm", 0o1777)
  c.dir("/var")
  c.symlink("../run", "/var/run")
  c.symlink("../run/lock", "/var/lock")
  c.symlink("../tmp", "/var/tmp")
  c.tmpfs("/var/cache")
  c.dir("/etc")
  c.rwBind(o.workspace, realHome, optional = false)

  for p in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt"]:
    c.bindOrSymlink(p, p)

  for p in [realHome / ".gitconfig", realHome / ".vimrc", realHome / ".ssh/known_hosts",
            "/etc/networks", "/etc/protocols", "/etc/services", "/etc/rpc",
            "/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/crypto-policies",
            "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.cache",
            "/etc/alternatives", "/etc/fonts", "/etc/localtime", "/etc/man_db.conf",
            "/etc/os-release"]:
    c.roBind(p)

  # Work directories, mounted read/write. Relative paths are relative
  # to the manifest file's directory.
  for manifest in o.workManifests:
    let baseDir = manifest.absolutePath.parentDir
    for line in configLines(manifest):
      c.rwBind(if line.isAbsolute: line else: baseDir / line)

  if o.etcDir != "":
    for kind, path in walkDir(o.etcDir):
      c.bindOrSymlink(path, "/etc" / path.extractFilename)

  for (src, dest) in o.roBinds: c.roBind(src, dest, optional = false)
  for (src, dest) in o.rwBinds: c.rwBind(src, dest, optional = false)

  # Environment: start empty, as bwrap --clearenv
  c.env.add ("HOME", realHome)
  c.env.add ("TERM", getEnv("TERM"))
  if o.envFile != "":
    for line in configLines(o.envFile): c.env.addEnvSetting(line)
  for s in o.envSettings: c.env.addEnvSetting(s)

  # /etc/passwd, /etc/group, /etc/machine-id
  if c.targetUid == 0:
    c.file("/etc/passwd", "root:x:0:0:Super User:" & realHome & ":" & loginShell & "\n" &
                          "nobody:x:65534:65534:Unmapped User:/:/usr/sbin/nologin\n")
    c.file("/etc/group", "root:x:0:\nnobody:x:65534:\n")
  else:
    let gr = getgrgid(realGid)
    let groupName = if gr != nil: $gr.gr_name else: "user"
    c.file("/etc/passwd",
      "root:x:0:0:Super User:/:/bin/sh\n" &
      $pw.pw_name & ":x:" & $c.targetUid & ":" & $c.targetGid & ":Normal User:" &
        realHome & ":" & loginShell & "\n" &
      "nobody:x:65534:65534:Unmapped User:/:/usr/sbin/nologin\n")
    c.file("/etc/group", "root:x:0:\n" & groupName & ":x:" & $c.targetGid & ":\n" &
                         "nobody:x:65534:\n")
  c.file("/etc/machine-id",
         readFile("/proc/sys/kernel/random/uuid").strip.replace("-", "") & "\n")

  if o.shareNet:
    c.roBind("/etc/hosts")
    c.roBind("/etc/resolv.conf")
  else:
    c.file("/etc/hosts", "127.0.0.1   localhost " & c.hostName & "\n" &
                         "::1         localhost " & c.hostName & "\n")

  c.command = o.command
  if c.command.len == 0: c.command = @[loginShell, "-l"]
  c.useInit = not o.noInit and (c.pidNs or isPid1)
  c.stopTimeout = o.stopTimeout
  c.pidEnv = o.pidEnv
  c

# ------------------------------------------------------------- Inside the sandbox

proc writeProcFile(path, data: string) =
  ## One write(2), as /proc/PID/uid_map etc. require.
  let fd = check(posix.open(path.cstring, O_WRONLY), "open " & path)
  defer: discard posix.close(fd)
  check(posix.write(fd, data.cstring, data.len), "write " & path)

proc mapIds(insideUid, outsideUid: Uid, insideGid, outsideGid: Gid) =
  writeProcFile("/proc/self/setgroups", "deny")
  writeProcFile("/proc/self/uid_map", $insideUid & " " & $outsideUid & " 1")
  writeProcFile("/proc/self/gid_map", $insideGid & " " & $outsideGid & " 1")

proc bringUpLoopback() =
  let s = check(cint(socket(AF_INET, SOCK_DGRAM, 0)), "socket")
  defer: discard posix.close(SocketHandle(s))
  var ifr: IfReq
  ifr.name[0] = 'l'; ifr.name[1] = 'o'
  check(ioctl(s, SIOCGIFFLAGS, addr ifr), "SIOCGIFFLAGS lo")
  ifr.flags = ifr.flags or IFF_UP
  check(ioctl(s, SIOCSIFFLAGS, addr ifr), "SIOCSIFFLAGS lo")

proc openBindSource(op: var Op) =
  ## Clone the source tree into a detached mount, while the host's file
  ## system is still visible. Read-only is applied to the whole tree at
  ## once with mount_setattr(), unlike bwrap, which remounts each submount.
  op.fd = cint(syscall(SYS_open_tree, AT_FDCWD, op.src.cstring,
                       OPEN_TREE_CLONE or OPEN_TREE_CLOEXEC or AT_RECURSIVE))
  if op.fd < 0:
    if op.optional and errno == ENOENT: return
    raiseOSError(osLastError(), "open_tree " & op.src)
  var attr = MountAttr(attrSet: MOUNT_ATTR_NOSUID)
  if op.readOnly: attr.attrSet = attr.attrSet or MOUNT_ATTR_RDONLY
  if not op.devices: attr.attrSet = attr.attrSet or MOUNT_ATTR_NODEV
  check(syscall(SYS_mount_setattr, op.fd, "".cstring, AT_EMPTY_PATH or AT_RECURSIVE,
                addr attr, sizeof(attr)), "mount_setattr " & op.src)
  var st: Stat
  check(fstat(op.fd, st), "fstat " & op.src)
  op.isDir = S_ISDIR(st.st_mode)

proc createMountPoint(path: string, isDir: bool) =
  createDir(path.parentDir)
  if isDir:
    createDir(path)
  elif not fileExists(path):
    let fd = check(posix.open(path.cstring, O_WRONLY or O_CREAT or O_CLOEXEC, 0o644),
                   "create " & path)
    discard posix.close(fd)

proc mountFs(fstype, dest: string, flags: int, data = "") =
  createDir(dest)
  check(mount(fstype.cstring, dest.cstring, fstype.cstring, culong(flags),
              if data == "": nil else: data.cstring),
        "mount " & fstype & " on " & dest)

proc applyOp(op: Op) =
  case op.kind
  of opBind:
    if op.fd < 0: return             # optional, and not found
    createMountPoint(op.dest, op.isDir)
    check(syscall(SYS_move_mount, op.fd, "".cstring, AT_FDCWD, op.dest.cstring,
                  MOVE_MOUNT_F_EMPTY_PATH), "move_mount " & op.dest)
    discard posix.close(op.fd)       # otherwise the init would keep it open
  of opDir:
    createDir(op.dest)
  of opTmpfs:
    mountFs("tmpfs", op.dest, MS_NOSUID or MS_NODEV, "mode=0" & op.mode.toOct(4))
  of opSymlink:
    createDir(op.dest.parentDir)
    createSymlink(op.target, op.dest)
  of opFile:
    createDir(op.dest.parentDir)
    writeFile(op.dest, op.content)
    check(chmod(op.dest.cstring, Mode(op.fileMode)), "chmod " & op.dest)
  of opProc:
    mountFs("proc", op.dest, MS_NOSUID or MS_NODEV or MS_NOEXEC)
  of opDevpts:
    mountFs("devpts", op.dest, MS_NOSUID or MS_NOEXEC, "newinstance,ptmxmode=0666,mode=620")
  of opMqueue:
    mountFs("mqueue", op.dest, MS_NOSUID or MS_NODEV or MS_NOEXEC)

proc setUpSandbox(c: var Config) =
  # In ns1, become root
  mapIds(0, c.outerUid, 0, c.outerGid)

  if c.hostName != "":
    check(sethostname(c.hostName.cstring, csize_t(c.hostName.len)), "sethostname")
  if not c.shareNet:
    bringUpLoopback()
    writeProcFile("/proc/sys/net/ipv4/ping_group_range", "0 0")

  # Don't propagate our mounts back to the host
  check(mount(nil, "/", nil, MS_SLAVE or MS_REC, nil), "make / a slave mount")

  for op in c.ops.mitems:
    if op.kind == opBind: openBindSource(op)

  # New root on a tmpfs. We put it over /tmp, which hides the host's /tmp,
  # but bind sources have already been opened above.
  let origCwd = getCurrentDir()
  mountFs("tmpfs", "/tmp", MS_NOSUID or MS_NODEV, "mode=0755")
  setCurrentDir("/tmp")
  createDir(".oldroot")
  check(syscall(SYS_pivot_root, ".".cstring, ".oldroot".cstring), "pivot_root")
  setCurrentDir("/")

  for op in c.ops: applyOp(op)

  # proc can only be mounted while a fully visible proc is still there,
  # so the old root goes away only now
  check(umount2("/.oldroot", MNT_DETACH), "unmount old root")
  removeDir("/.oldroot")
  check(mount(nil, "/", nil, MS_REMOUNT or MS_BIND or MS_RDONLY or MS_NOSUID or MS_NODEV,
              nil), "remount / read-only")

  # ns2: the target user, with all mounts locked (see the top of this file)
  check(unshare(CLONE_NEWUSER or CLONE_NEWNS), "unshare ns2")
  mapIds(c.targetUid, 0, c.targetGid, 0)
  check(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "PR_SET_NO_NEW_PRIVS")

  # Landlock scoping (Linux 6.12+): the sandbox can't signal processes
  # outside it, or connect to their abstract Unix sockets. (ptrace outside
  # is already denied to any Landlock domain.) This is what makes running
  # without a PID namespace acceptable; with one, it's a second line of
  # defence, e.g. for agent-sandbox and specchio outside.
  var ruleset = LandlockRulesetAttr(
    scoped: LANDLOCK_SCOPE_SIGNAL or LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET)
  let rulesetFd = check(syscall(SYS_landlock_create_ruleset, addr ruleset,
                                sizeof(ruleset), 0), "landlock_create_ruleset")
  check(syscall(SYS_landlock_restrict_self, rulesetFd, 0), "landlock_restrict_self")
  discard posix.close(cint(rulesetFd))

  let home = c.env[0][1]
  try: setCurrentDir(origCwd)
  except OSError: setCurrentDir(home)

  discard clearenv()
  for (name, value) in c.env: putEnv(name, value)

proc execCommand(c: Config) =
  # Only now do we know the PID: the init's fork() has happened, if any
  for name in c.pidEnv: putEnv(name, $getpid())
  let cargv = allocCStringArray(c.command)
  discard execvp(cargv[0], cargv)
  raiseOSError(osLastError(), "exec " & c.command[0])

# ------------------------------------------------------------- Supervising children
#
# The same loop serves the monitor outside the sandbox and the init inside.

const forwardedSignals = [SIGTERM, SIGHUP, SIGINT, SIGQUIT, SIGUSR1, SIGUSR2]

proc blockSignals(origMask: var Sigset): Sigset =
  ## Block SIGCHLD and the signals we forward, to read them synchronously
  ## with sigwaitinfo(): no signal handlers, and no signals lost in between.
  ## Signals ignored when we start stay ignored, as in specchio (children
  ## inherit that).
  discard sigemptyset(result)
  discard sigaddset(result, SIGCHLD)
  for sig in forwardedSignals:
    var current: Sigaction
    discard getSigaction(sig, nil, current)
    if current.sa_handler != SIG_IGN: discard sigaddset(result, sig)
  discard check(sigprocmask(SIG_BLOCK, result, origMask), "sigprocmask")

proc dropInherited(keep: openArray[cint] = []) =
  ## Called by the monitor and the init once the child has its copies of
  ## the descriptors we inherited (e.g. sockets from systemd's socket
  ## activation): drop ours, so that we don't keep files, pipes or sockets
  ## open for longer than the command does. For example, a reader of the
  ## command's output should see EOF when the command closes it, not only
  ## once we exit. As in specchio: standard input and output go to
  ## /dev/null, standard error stays for messages, and everything above
  ## it is closed, except `keep`.
  let null = check(posix.open("/dev/null", O_RDWR or O_CLOEXEC), "open /dev/null")
  for fd in [0.cint, 1]:
    check(dup2(null, fd), "dup2 /dev/null")
  if null > 2: discard posix.close(null)

  # close_range() over the gaps between the descriptors we keep
  var first = 3'u32
  for fd in sorted(@keep):
    if fd < 3: continue
    if uint32(fd) > first:
      check(syscall(SYS_close_range, first, uint32(fd) - 1, 0'u32), "close_range")
    first = max(first, uint32(fd) + 1)
  check(syscall(SYS_close_range, first, high(uint32), 0'u32), "close_range")

proc exitCode(status: cint): cint =
  ## As a shell reports it: 128 + N for death by signal N.
  if WIFEXITED(status): WEXITSTATUS(status) else: 128 + WTERMSIG(status)

proc supervise(main: Pid, waitSet: var Sigset, asInit: bool,
               stopTimeout = 0.0): cint =
  ## Wait for `main` to exit, and return its exit code. Signals sent by
  ## other processes are forwarded to it; signals from the terminal aren't,
  ## because the terminal sends them to the whole foreground process
  ## group, `main` included.
  ##
  ## As init, also reap every other child: orphaned processes in the PID
  ## namespace become our children. Once `main` has exited, ask everything
  ## left to stop, and wait for it, up to `stopTimeout` seconds. When we
  ## exit, the kernel SIGKILLs whatever is left in the namespace.
  var mainExited = false
  var mainStatus: cint
  var deadline: MonoTime
  while true:
    # SIGCHLD doesn't queue: one may stand for several exited children
    while true:
      var status: cint
      let pid = waitpid(-1, status, WNOHANG)
      if pid == 0: break                    # none exited (yet)
      if pid < 0:
        if errno == EINTR: continue
        if errno == ECHILD and mainExited: return exitCode(mainStatus)
        raiseOSError(osLastError(), "waitpid")
      if pid == main:
        mainExited = true
        mainStatus = status
        if not asInit: return exitCode(status)
        # kill(-1) reaches every process in our PID namespace except us,
        # so be sure we're PID 1 of one
        doAssert getpid() == 1
        discard kill(Pid(-1), SIGTERM)
        deadline = getMonoTime() + initDuration(milliseconds = int(stopTimeout * 1000))

    var info: SigInfo
    var sig: cint
    if mainExited:
      let left = deadline - getMonoTime()
      if left <= DurationZero: return exitCode(mainStatus)
      var timeout = Timespec(tv_sec: posix.Time(left.inSeconds),
                             tv_nsec: clong(left.inNanoseconds mod 1_000_000_000))
      sig = sigtimedwait(waitSet, info, timeout)
      if sig < 0 and errno == EAGAIN: return exitCode(mainStatus)
    else:
      sig = sigwaitinfo(waitSet, info)
    if sig < 0:
      if errno == EINTR: continue
      raiseOSError(osLastError(), "sigwaitinfo")
    if sig != SIGCHLD and info.si_code <= 0:
      # After `main` has exited, pass signals on to whatever is left
      discard kill(if mainExited: Pid(-1) else: main, sig)

proc runInit(c: Config, waitSet: var Sigset, origMask: Sigset) {.noreturn.} =
  ## Be PID 1 of the sandbox, and run the command as our child.
  ##
  ## Why not let the command be PID 1? The kernel only delivers signals to
  ## PID 1 for which it has installed a handler (except SIGKILL and SIGSTOP
  ## from outside), so a program that relies on the default action of
  ## SIGTERM or SIGINT would ignore them. And orphaned processes become
  ## children of PID 1, which must reap them, or they stay zombies.
  ##
  ## Job control needs nothing from us: the command stays in our session
  ## and process group, so it can use the terminal (dumb-init's default
  ## mode, with setsid(), loses it). On Ctrl-Z, the terminal sends SIGTSTP
  ## to the group: the command stops, and so does the monitor, which the
  ## shell sees as a stopped job. We ignore it, as PID 1 does with signals
  ## it has no handler for. `fg` sends SIGCONT to the group.
  let pid = fork()
  if pid < 0: raiseOSError(osLastError(), "fork")
  if pid == 0:
    var mask = origMask              # posix.sigprocmask wants a var
    var unused: Sigset
    check(sigprocmask(SIG_SETMASK, mask, unused), "sigprocmask")
    execCommand(c)
  dropInherited()
  cExit(supervise(pid, waitSet, asInit = true, c.stopTimeout))

# ------------------------------------------------------------- Main

proc main() =
  let o = parseCommandLine(commandLineParams())
  var c = buildConfig(o)

  if o.dryRun:
    echo "host name: ", c.hostName, ", uid/gid: ", c.targetUid, "/", c.targetGid
    for op in c.ops: echo op
    for (n, v) in c.env: echo "env ", n, "=", v
    for name in c.pidEnv: echo "env ", name, "=<PID of the program>"
    echo "exec: ", c.command, (if c.useInit: ", under our init" else: "")
    return

  var flags = CLONE_NEWUSER or CLONE_NEWNS or CLONE_NEWIPC or CLONE_NEWCGROUP
  if not c.shareNet: flags = flags or CLONE_NEWUTS or CLONE_NEWNET

  # Signals that arrive now wait until we're ready to forward them
  var origMask: Sigset
  var waitSet: Sigset
  if c.useInit or c.pidNs: waitSet = blockSignals(origMask)

  if not c.pidNs:
    # Become the sandbox: whoever started us keeps our PID, and their
    # signals, Ctrl-C, and wait() go straight to the init or the program.
    try:
      check(unshare(cint(flags)), "unshare")
      setUpSandbox(c)
      if c.useInit: runInit(c, waitSet, origMask)
      execCommand(c)
    except CatchableError as e:
      die(e.msg)

  # The child finds out whether we died before its PDEATHSIG was set
  # by reading from this pipe: EOF means we're gone.
  var deathPipe: array[2, cint]
  check(pipe2(deathPipe, O_CLOEXEC or O_NONBLOCK), "pipe2")

  flags = flags or CLONE_NEWPID or SIGCHLD.int
  let pid = Pid(check(syscall(SYS_clone, clong(flags), nil, nil, nil, nil), "clone"))

  if pid == 0:
    # Child: becomes the sandbox, as PID 1 of the new PID namespace
    try:
      discard prctl(PR_SET_PDEATHSIG, SIGKILL)
      discard posix.close(deathPipe[1])
      var b: char
      if posix.read(deathPipe[0], addr b, 1) == 0: exitnow(1)
      discard posix.close(deathPipe[0])
      setUpSandbox(c)
      if c.useInit: runInit(c, waitSet, origMask)
      var unused: Sigset
      check(sigprocmask(SIG_SETMASK, origMask, unused), "sigprocmask")
      execCommand(c)
    except CatchableError as e:
      stderr.writeLine("agent-sandbox: " & e.msg)
    exitnow(127)

  # Parent: the monitor. It keeps the pipe's write end open: the child
  # sees EOF on the read end only once we're gone.
  dropInherited([deathPipe[1]])
  cExit(supervise(pid, waitSet, asInit = false))

main()
