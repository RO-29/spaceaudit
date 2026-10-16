# spaceaudit

A read-only disk space audit for macOS. It finds what fills your disk, and for each item it tells you how safe it is to remove, why, what can go wrong, how to check it yourself, the exact command, and how to get it back.

**spaceaudit never deletes, moves or changes a file.** It only recommends. A test fails the build if the code calls any API that can change a file, and external commands run only from a read-only allowlist. You check every path and every command yourself before you run it.

It comes in five forms that share one scanner:

| Form | Use it when | Run |
|---|---|---|
| CLI summary | You want a quick answer in the terminal | `spaceaudit` or `spaceaudit -v` |
| TUI | You want to browse, filter and copy commands | `spaceaudit tui` |
| HTML report | You want a designed report with a treemap, filters and copy buttons | `spaceaudit html` |
| Mac app | You prefer a window | `SpaceAudit.app` |
| Review script | You want to clean up in an editor | `spaceaudit script` |

Also: `spaceaudit md` (Markdown), `spaceaudit json` (machine-readable), `spaceaudit rules` (the rule catalog), and `scripts/quick-audit.sh` (a shell-only size list for a Mac with no tools installed).

## Install

Requires macOS 14 or later. Building needs Go 1.24+ and the Command Line Tools (for `swiftc`).

```sh
git clone git@github.com:RO-29/spaceaudit.git && cd spaceaudit
make install              # CLI into ~/.local/bin
make app                  # dist/SpaceAudit.app (universal, ad-hoc signed)
```

The app is not notarized. The first time, right-click it and choose Open.

Give Full Disk Access to your terminal or to SpaceAudit.app (System Settings > Privacy & Security > Full Disk Access). Without it, macOS hides some folders, and the report marks those findings "partial".

## The four levels

| Level | Meaning |
|---|---|
| Safe | The owner program makes it again by itself. It holds no user data. |
| Review | Regenerable, but it costs a download, a rebuild or some state, or a program uses it now. |
| Risky | It can hold data that exists only here, or a tool depends on it. |
| Keep | Information only. Manage it in its own app. |

A finding moves from safe to review automatically when a running program has a file open inside it, or when you edited its project in the last 48 hours.

## What each finding contains

- **Paths** and **size** (allocated blocks, so sparse VM images are not inflated).
- **Why**: the reason, with dates: newest change inside, last commit, last use of an app (Spotlight, or the app's own data folders when Spotlight is off).
- **Risks**: what you lose, including inherited risks (a tool that depends on it, a credential file nearby, a lock file that is missing).
- **Blockers**: live conditions that must change first (quit an app, a dev server uses the project, uncommitted changes).
- **Verify**: commands that only read, to check the claim yourself.
- **Command**: the tool's own clean command when one exists (`go clean -cache`, `pnpm store prune`, `git worktree remove`, `docker builder prune`), otherwise `rm -rf --` with a quoted path.
- **Alternative**: a Finder "move to Trash" command, so you can undo.
- **Restore**: how to get it back.

## What it checks

- About 60 known locations: package manager caches, toolchains, Xcode and simulators, editors, browsers, AI models, app data, system files. See [docs/RULES.md](docs/RULES.md).
- Every folder in `~/Library/Caches` and `~/.cache` that no rule claims.
- Chromium and Electron caches inside every app (Slack, Notion, Chrome, Discord, Teams, editors).
- Editor workspace state for folders that no longer exist, and old extension versions.
- Project build folders (`node_modules`, `target`, `.next`, `dist`, `.venv`, `Pods`, and more), each judged in its project: marker file, git tracked or ignored, lock file, last edit, live use.
- Git worktrees: uncommitted changes, unpushed commits.
- Unused large apps, with the Xcode and `xcode-select` dependency.
- Downloads: age, source URL, installers already installed, archives already extracted.
- Docker, OrbStack, Colima, Rancher, Podman disk images, and what a prune frees.
- Homebrew (`brew cleanup -n`), APFS snapshots, deleted files that programs still hold open, and space the scan cannot explain.

[docs/EDGE-CASES.md](docs/EDGE-CASES.md) lists every case where a plain delete gives the wrong result, and how the tool handles it.

## Flags

```
-v            reasons, risks and commands in the terminal summary
-o FILE       output file (it refuses to overwrite a file that spaceaudit did not write)
--quick       skip the home walk (about 20 s instead of some minutes)
--min 50      hide findings under 50 MB
--large 1     list single files and bundles of 1 GB or more
--active 48h  a project edited within this time counts as active
--stale-days 30
--no-docker   do not ask the Docker daemon
--home DIR    scan another home folder
```

## Safety design

- No code path can delete. `internal/safety_test.go` scans the source for `os.Remove`, `os.Rename`, `os.WriteFile`, `syscall.Unlink` and `exec.Command`, and fails on any match outside the allowlisted runner.
- `internal/probe` runs only allowlisted read-only commands (`docker system df`, `brew cleanup -n`, `git status --porcelain`, `lsof`, `mdls`, ...). The test proves that `docker system prune`, `brew cleanup`, `git clean` and `rm` are refused.
- The review script comments out every command and exits on its first line, so running it by mistake does nothing. A test runs it to prove that.
- The only file it writes is the report that you ask for.

## Limits

- APFS clones cannot be seen from user space, so a delete can free less than shown.
- "Last used" is a signal, not proof. Spotlight can be off, and background helpers can touch app data.
- A rule can be wrong for your setup. That is why every finding has a verify step. **You are responsible for what you delete. Verify each item on your own Mac first.**

## License

MIT
