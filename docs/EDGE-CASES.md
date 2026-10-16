# Edge cases and inherited risks

This file lists the cases where a simple "delete the big folder" gives a wrong result, and what spaceaudit does about each one. An inherited risk is a risk that comes from something outside the folder itself: a tool that depends on it, a program that holds it open, or a disk feature that keeps the space.

## Measurement

| Case | What goes wrong | What spaceaudit does |
|---|---|---|
| Sparse VM disk images (Docker.raw, OrbStack data.img.raw) | `ls` shows the maximum size (for example 494 GB). The real use is much smaller. | Measures allocated blocks (`st_blocks * 512`), the same as `du`. |
| Hard links (pnpm store, Time Machine style copies) | `du` of two folders counts the same data twice. A delete of one link frees nothing. | Counts each inode once per finding and notes the hard-linked bytes. |
| APFS clones (Finder duplicate, `cp -c`) | Two clones share blocks. The sum of sizes is larger than the real use. | Cannot be detected from user space. The README says so. |
| iCloud "Optimize Mac Storage" files | Online-only files show a size but use no local space. | Detects the dataless flag and reports the count. |
| Folders that need Full Disk Access (Mail, Messages, Safari, some containers) | A scan reads them as empty and reports a size that is too small. | Counts unreadable folders and marks the finding "partial". |
| Root-only folders, other users | The home scan cannot explain all used space. | Reports the "not explained" gap between volume use and what it measured, with the sudo command to look. |
| Other volumes and mount points inside home | A walk crosses into an external disk. | Stays on one device. |
| Symbolic links | A walk follows a link and counts the target, or a delete follows it. | Never follows links. Notes the count, because `rm -rf` removes links, not targets. |
| Paths with spaces, quotes or newlines | A generated command breaks or deletes the wrong path. | Single-quotes every path. The Finder "move to Trash" alternative is omitted when a path holds a quote. |

| Identical copies of a large file | Space used more than once. | SHA-256 on files of 64 MB or more. Hard links to one file are not reported as duplicates. iCloud placeholders are skipped, because reading them downloads them. |

## Space that does not come back

| Case | Why | What spaceaudit does |
|---|---|---|
| A program holds a deleted file open | The blocks stay used until the program closes the file. | Lists deleted-but-open files (`lsof +L1`), counts each inode once, and names the largest holders. |
| APFS local snapshots | A snapshot keeps every block that it references. | Lists the snapshots and gives the thin command. |
| Docker or VM disk images | Pruning inside the VM does not always shrink the image file. | Says to check free space after a prune, and names the runtime's own reclaim option. |
| Trash | Moving to the Trash frees nothing. | Offers Trash as the undo-friendly path, and says that only emptying it frees space. |

## Programs that use the data now

| Case | Risk | What spaceaudit does |
|---|---|---|
| An app writes its cache while you delete it | Corrupt cache, crash, or the delete is incomplete. | Takes one `lsof` snapshot and blocks any finding that an open file touches. A safe finding moves to review. |
| A dev server runs in a project | Deleting `node_modules` or `.next` breaks the running server. | The project and its git root count as in use when any process has a file open there. |
| A project that you edited recently | You are probably still working on it. | Blocked when a project file (6 levels deep, outside build folders) or the git index, HEAD or reflog changed in the last 48 hours (`--active`). |
| Uncommitted changes in the repo | Work in progress. | Blocked, with the file count. |
| An app that runs now | It is in use, whatever Spotlight says. | Never reported as unused. |

## Data that looks regenerable but is not

| Case | Risk | Rule |
|---|---|---|
| `node_modules` with no lock file | A reinstall picks newer versions and the project can break. | Moves to review. Looks for the lock file up to the repo root, for monorepos. |
| `node_modules` with `npm link` packages | A reinstall drops the links. | Lists the linked packages. |
| A private registry (`.npmrc`) | A reinstall needs a login. | Adds a risk. |
| `build`, `dist`, `out`, `coverage`, `vendor` | These names are also used for real source folders. | Reported only when the project marker exists. Dropped when git tracks any file inside. Review when git does not ignore it. |
| `target` with no Cargo.toml or pom.xml | It is not build output. | Not reported. |
| Python virtual environments | Packages that you installed by hand are not in a requirements file. | Review, with that risk. |
| `~/.m2/repository` | Artifacts from `mvn install` exist only here. | Review. |
| Go module cache | Read-only files: `rm -rf` fails. | Uses `go clean -modcache`. |
| Git worktrees | Uncommitted changes and unpushed commits are lost. `rm` leaves stale worktree records. | Checks status, upstream and remote branches. Uses `git worktree remove`, which refuses a dirty tree. Risky when the main repo is gone. |
| Git-ignored files in a clean worktree (`.env`, `terraform.tfstate`, local config) | `git status` does not show them, and a delete loses them. | Lists ignored files that are not build output and moves the worktree to review. |
| Claude Code `~/.claude/projects` | Each project folder also holds `memory/`. | The command removes only old `.jsonl` transcripts and skips `memory/`. |
| Chrome on-device AI model | Chrome downloads the model again after a plain delete. | The command is the Chrome setting that deletes the model and stops the download. |
| Node.js versions | Global npm packages live inside each version. | Keeps the default and current version, and counts global packages in the others. |
| Xcode archives | They hold the dSYMs that decode crash reports of shipped builds. | Risky. |
| iPhone backups | It can be the only backup of a device. | Risky. Points to Finder > Manage Backups. |
| Cursor `state.vscdb` | Holds all chat history. | Risky. |
| Docker volumes | Hold local databases. | Risky. Lists them instead of pruning. |
| Downloads archives | An archive can be the only copy. | Review. Notes when a folder with the same name is next to it. |

## Tools that depend on the item

| Item | What breaks | What spaceaudit says |
|---|---|---|
| Xcode.app when `xcode-select` points into it | git, clang, make and `/usr/bin/python3`, and any daemon that uses that Python. | Risky, blocked, and gives the switch command (`sudo xcode-select -s /Library/Developer/CommandLineTools`) first. |
| Command Line Tools | The same tools when Xcode is absent. | Keep. |
| `~/.nvm`, `~/.cargo/bin`, `~/.local/bin` | Your installed command-line tools. | Never offered. |
| `~/.gradle/gradle.properties`, `~/.m2/settings.xml`, `~/.kube/config`, gcloud credentials | Logins and repository credentials. | The rules include only the cache subfolders, never these files. |
| Rust toolchains | Projects that pin a version in rust-toolchain.toml. | Review, with `rustup toolchain list` as the verify step. |
| Android SDK | React Native, Flutter and Gradle Android builds. | Review. |
| Simulator caches in `/Library` | Needs root. | Marked sudo. |

## Verify commands

Every verify command must only read. `npm cache verify` looks like a check but garbage-collects the cache, and `git status` can rewrite `.git/index`. The tool uses `du` for npm and `git --no-optional-locks` for git. A test checks every verify command.

## Last-used dates

| Signal | Problem | Use |
|---|---|---|
| Spotlight `kMDItemLastUsedDate` | Empty when Spotlight is off or read-only, and for apps opened from a terminal. | First signal. |
| Newest change in the app's preferences, container, cache and saved state | Background helpers can touch them. | Second signal. The report names the source. |
| File access time | macOS does not update it reliably. | Not used. |
| Project activity | Build output changes on every build. | The newest change to project files outside build folders and `.git`, plus the last commit date. |
