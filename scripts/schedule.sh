#!/bin/sh
# Runs a read-only full scan on a schedule and keeps one HTML report up to date, with a version per run.
# Usage: scripts/schedule.sh install [hours] [report.html] | remove | status | run-now
set -eu
LABEL=io.github.ro-29.spaceaudit.scan
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$HOME/Library/Logs/SpaceAudit/scheduled.log"
DOMAIN="gui/$(id -u)"

bin() {
  for b in /Applications/SpaceAudit.app/Contents/Resources/spaceaudit "$HOME/Applications/SpaceAudit.app/Contents/Resources/spaceaudit" "$HOME/.local/bin/spaceaudit"; do
    [ -x "$b" ] && { echo "$b"; return; }
  done
  echo "spaceaudit not found. Install the app or run make install." >&2; exit 1
}

case "${1:-status}" in
install)
  HOURS="${2:-6}"
  OUT="${3:-$HOME/spaceaudit-reports/spaceaudit-latest.html}"
  BIN="$(bin)"
  mkdir -p "$(dirname "$OUT")" "$(dirname "$LOG")" "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$BIN</string><string>html</string><string>-o</string><string>$OUT</string><string>--no-open</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>SPACEAUDIT_EVERY</key><string>${HOURS}h</string><key>HOME</key><string>$HOME</string></dict>
  <key>StartInterval</key><integer>$((HOURS * 3600))</integer>
  <key>RunAtLoad</key><false/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
  plutil -lint "$PLIST" >/dev/null
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  launchctl bootstrap "$DOMAIN" "$PLIST"
  echo "Scheduled: a read-only full scan every $HOURS hours."
  echo "Report:    $OUT (the same file, one new version per run)"
  echo "Log:       $LOG"
  echo "Run one now with: $0 run-now"
  ;;
remove)
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  rm -f -- "$PLIST"
  echo "Schedule removed. Reports and history stay."
  ;;
run-now)
  launchctl kickstart "$DOMAIN/$LABEL" && echo "Started. Follow it with: tail -f $LOG"
  ;;
status)
  if launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
    launchctl print "$DOMAIN/$LABEL" | grep -E "state =|run interval|last exit code|runs =" | sed 's/^[[:space:]]*/  /'
    echo "  plist: $PLIST"
  else
    echo "Not scheduled."
  fi
  ;;
*) echo "usage: $0 install [hours] [report.html] | remove | status | run-now" >&2; exit 2 ;;
esac
