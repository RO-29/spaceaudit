#!/usr/bin/env python3
"""Checks a spaceaudit JSON report against the Mac it ran on. Exit 1 on any failure."""
import json, os, re, subprocess, sys

report = json.load(open(sys.argv[1]))
fails, notes = [], []

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

ver = sh("sw_vers -productVersion").stdout.strip()
notes.append(f"macOS {ver}, {len(report['findings'])} findings, scan {report['durationSec']:.0f}s")
if report.get("tool") != "spaceaudit":
    fails.append("not a spaceaudit report")

guard = re.compile(r"^p='[^']*(?:'\\''[^']*)*'; n='[^']*(?:'\\''[^']*)*'; \[ \"\$\{p##\*/\}\" = \"\$n\" \] && \[ -[df] \"\$p\" \] && \[ ! -L \"\$p\" \] && (sudo )?(rm -rf -- \"\$p\"|rm -f -- \"\$p\"|find -P \"\$p\" -mindepth 1 -maxdepth 1 -exec rm -rf -- \{\} \+)")
raw_rm = re.compile(r"(^|[;&|]\s*)(sudo\s+)?rm\s")
for f in report["findings"]:
    for c in f["commands"]:
        body = c.split("   #")[0]
        if raw_rm.search(body) and not guard.match(body):
            fails.append(f"unguarded delete in {f['rule']}: {c[:120]}")
        if body.startswith("p="):
            if not guard.match(body):
                fails.append(f"malformed guard in {f['rule']}: {c[:120]}")
            for shell in ("/bin/sh", "/bin/zsh"):
                if os.path.exists(shell) and subprocess.run([shell, "-n", "-c", body]).returncode != 0:
                    fails.append(f"{shell} cannot parse {f['rule']}: {c[:120]}")
        for p in f["paths"]:
            if any(ord(ch) < 32 for ch in p):
                fails.append(f"control character in path of {f['rule']}")

# Swap lives on the VM volume on every supported version.
swap = [f for f in report["findings"] if f["rule"] == "swapfiles"]
if os.path.isdir("/System/Volumes/VM") and sh("ls /System/Volumes/VM | grep -c swapfile").stdout.strip() not in ("", "0") and not swap:
    fails.append("swap files exist in /System/Volumes/VM but the swapfiles rule found none")

# Snapshot facts must split Time Machine from update snapshots.
snap = [x for x in report["facts"] if x["key"] == "local snapshots"]
if not snap or "Time Machine" not in snap[0]["value"]:
    fails.append(f"snapshot fact missing or not split: {snap}")

# Simulator runtimes: the parser must see every runtime that simctl lists.
rt = sh("xcrun simctl runtime list -v 2>/dev/null")
listed = len(re.findall(r"^\s*Image Path:", rt.stdout, re.M))
found = len([f for f in report["findings"] if f["rule"] == "simulator-runtime"])
notes.append(f"simctl lists {listed} runtime images, report has {found} (scan used --min 0)")
if listed and found == 0:
    fails.append("simctl lists runtimes but the report has none: the parser does not match this Xcode")

# The scan must never have opened cloud folders.
for f in report["findings"]:
    for p in f["paths"]:
        if "/Library/Mobile Documents/" in p or "/Library/CloudStorage/" in p:
            fails.append(f"cloud folder in a finding: {p}")

print("\n".join(notes))
print("\n".join("FAIL " + x for x in fails) or "all checks passed")
sys.exit(1 if fails else 0)
