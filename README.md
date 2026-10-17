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
| Inventory | You want to know where the space goes | `spaceaudit inventory`: browsers with every profile, AI agents and tools, programming languages, Downloads by type |
| Recheck | You cleaned up and want to see what changed | `spaceaudit recheck` measures only the items of the last full scan again |
| Plan | You chose what to clean | `spaceaudit plan` (safe items by default, `--level` to change). Running it runs only the verify lines. |

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

- The known locations in [docs/RULES.md](docs/RULES.md): package manager caches, toolchains, Xcode and simulators, editors, browsers, AI models, app data and system files.
- Node.js versions in nvm, fnm and volta that are not the default or the current version, with their global packages.
- Duplicate files of 64 MB or more (same size, then same partial hash, then same SHA-256). iCloud placeholders are skipped, because reading one downloads it.
- Chromium caches inside sandboxed app containers (for example new Teams).
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

## Inventory

The inventory is a map, not advice. Each part says what it holds and how safe it is to clear.

- **Browsers:** Safari, Chrome (and Beta, Canary), Chromium, Arc, Dia, Brave, Edge, Vivaldi, Opera, Comet, Firefox (and Developer Edition), Zen, LibreWolf, Floorp, Waterfox, Orion. Every profile with its name and account, and its parts: HTTP and code caches, service workers, site databases, cookies, history, extensions (each named from its manifest, with size), extension settings. Browser-wide parts: the on-device AI model, profile snapshots, components, speech packs.
- **AI agents and tools:** Claude Code, Claude desktop, Codex, ChatGPT desktop, Cursor and cursor-agent, Windsurf, Kiro, Zed, OpenCode, OpenClaw, pi, Gemini CLI, Hermes, Amp, Aider, Goose, Crush, Continue, Copilot, and AI extensions inside VS Code-family editors (Cline, Roo Code, Kilo Code, Copilot, Codex, Gemini Code Assist, Amazon Q), plus Ollama, LM Studio, Jan and the Hugging Face cache. Each folder has its own level: session history is review, caches and logs are safe, an unknown folder is keep. Parts over 100 MB list their largest members.
- **Programming languages:** JavaScript and TypeScript, Python, Go, Rust, Java/Kotlin/Scala, Swift and Apple platforms, Ruby, PHP, Dart and Flutter, .NET, Haskell, Julia, Elixir, C and C++: project dependency and build folders (with the largest projects), caches, toolchains and installed versions.
- **Downloads:** grouped into installers, archives, videos, audio, images, documents, code and data, folders and other, each with age groups and the largest items.

## Scheduled scans

```sh
scripts/schedule.sh install 6        # a read-only full scan every 6 hours
scripts/schedule.sh status
scripts/schedule.sh run-now
scripts/schedule.sh remove
```

The job is a launchd agent (`~/Library/LaunchAgents/io.github.ro-29.spaceaudit.scan.plist`) that runs at background priority. It replaces one report, `~/spaceaudit-reports/spaceaudit-latest.html` by default, with a new version each time. The report shows its version number, when it was updated and when the next update is due. A History section charts free space and the safe, review and risky totals of every version, with the change between runs. The history lives in `~/Library/Application Support/spaceaudit/history.jsonl`. The log is `~/Library/Logs/SpaceAudit/scheduled.log`.

A scheduled job runs without the Full Disk Access of your terminal. macOS can hide Mail, Messages and Safari data from it, and the report marks those findings "partial". To include them, add the `spaceaudit` binary inside SpaceAudit.app to Full Disk Access.

## Recheck

Every full scan is kept in `~/Library/Application Support/spaceaudit/last-scan.json`. After you clean up, `spaceaudit recheck` (or the Recheck button in the app) measures only those items again and says for each one: gone, partly gone, smaller, unchanged or larger, plus the free space then and now. It compares the same measure and the same age filter as the scan. An item that could not be measured fully says "not checked", never "smaller". `-i report.json` or `-i report.html` compares with an older report.

## Choosing what to clean

Every front end lets you build a plan from the findings you choose. A plan is a shell script that runs only the read-only verify commands. Each cleanup command is in the plan as a comment, so nothing is deleted until you edit the file and uncomment that line.

- HTML report: tick items, then use the plan bar (copy verify, copy commands, download plan.sh). "Quick wins" adds the largest safe items in one click.
- TUI: `space` marks, `A` marks the visible safe items, `p` copies the plan, `w` writes it to a new file, `s` changes the sort, `?` shows every key.
- Mac app: select rows (Cmd-click or Shift-click), then use the plan bar. Columns sort when you click their header.
- CLI: `spaceaudit plan --level safe,review`.

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
--level LIST  only these levels: safe,review,risky,keep
--home DIR    scan another home folder
```

## How a delete command is built

spaceaudit prints delete commands. It never runs them. Every delete command comes from one function, and each one has this shape:

```sh
p='/Users/you/project/node_modules'; n='node_modules'; [ "${p##*/}" = "$n" ] && [ -d "$p" ] && [ ! -L "$p" ] && rm -rf -- "$p"
```

- The path is absolute and single-quoted. There is no `$HOME`, no glob and no second path on the line.
- If the path is cut, edited or empty, the name check fails and nothing runs.
- If the target is missing or is a symbolic link, nothing runs. "Delete the contents" uses `find -P ... -mindepth 1 -maxdepth 1`, which never follows a link out of the folder.
- No command is made for `/`, your home folder, a top-level folder of your home or of `~/Library`, system roots, cloud folders (iCloud Drive, CloudStorage, DriveFS, Dropbox), a symbolic link, or a path with `..` or a control character. A finding with such a path shows "No delete command" and the reason.
- Placeholders are plain words (`NAME`, `VERSION`), never `<name>`, which a shell reads as a redirection.

Tests run these commands for real in a temporary folder, in `sh` and `zsh`, with an empty `HOME`, sibling folders with similar names, symbolic links that point outside, and names with spaces, quotes, `$` and backticks. They also damage each command (empty path, path cut to the parent or to the home folder, lost quote) and prove that nothing is deleted.

## Safety design

- No code path can delete. `internal/safety_test.go` scans the source for `os.Remove`, `os.Rename`, `os.WriteFile`, `syscall.Unlink` and `exec.Command`, and fails on any match outside the allowlisted runner.
- `internal/probe` runs only allowlisted read-only commands (`docker system df`, `brew cleanup -n`, `git status --porcelain`, `lsof`, `mdls`, ...). The test proves that `docker system prune`, `brew cleanup`, `git clean` and `rm` are refused.
- The review script comments out every command and exits on its first line, so running it by mistake does nothing. A test runs it to prove that.
- A plan runs only verify commands. A test fails when a plan line is anything else.
- Every verify command must be read-only. A test checks each one against a list of read-only commands, and it fails on `-delete`, `-exec`, `rm`, `prune` or `clean`. (`npm cache verify` is not on that list: npm's documentation says it garbage-collects the cache.)
- The only file it writes is the report that you ask for.
- A finding whose path holds a control character (for example a line break in a folder name) is dropped, and every text field is flattened to one line, so a file name cannot inject a command into a script.

## Limits

- APFS clones cannot be seen from user space, so a delete can free less than shown.
- "Last used" is a signal, not proof. Spotlight can be off, and background helpers can touch app data.
- Paths that the tool does not know are not classified. They appear only in the "Where the space goes" map and, when they are 1 GB or more, as "large item" findings with low confidence.
- Other users' home folders, root-only folders and purgeable space are not measured. The report shows the gap as "not explained".
- A rule can be wrong for your setup. That is why every finding has a verify step. **You are responsible for what you delete. Verify each item on your own Mac first.**

## License

MIT
