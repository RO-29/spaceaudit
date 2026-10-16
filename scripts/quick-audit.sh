#!/bin/sh
# Zero-dependency, read-only first look for a Mac without Go or the app. It measures and prints; it changes nothing.
# For reasons, risks, blockers and commands per item, use the full tool: spaceaudit scan -v
set -u
H="$HOME"
echo "spaceaudit quick-audit (read-only). Nothing is deleted."
echo
df -h /System/Volumes/Data 2>/dev/null | awk 'NR==2{print "Disk: " $3 " used of " $2 ", " $4 " free"}'
echo
printf '%-10s %-8s %s\n' SIZE LEVEL PATH
row() { # level path...
  lvl=$1; shift
  for p in "$@"; do
    [ -e "$p" ] || continue
    s=$(du -sh "$p" 2>/dev/null | cut -f1)
    printf '%-10s %-8s %s\n' "$s" "$lvl" "$p"
  done
}
row safe   "$H/Library/Caches" "$H/.npm/_cacache" "$H/Library/Caches/Yarn" "$H/Library/Caches/go-build" "$H/Library/Developer/Xcode/DerivedData" \
           "$H/.gradle/caches" "$H/Library/Caches/pip" "$H/.cargo/registry" "$H/Library/Logs"
row review "$H/.m2/repository" "$H/go/pkg/mod" "$H/.rustup/toolchains" "$H/Library/Android/sdk" "$H/Library/Developer/CoreSimulator/Devices" \
           "$H/Library/Application Support/Google/Chrome/OptGuideOnDeviceModel" "$H/.ollama/models" "$H/.cache/huggingface" "$H/.Trash" "$H/Downloads"
row keep   "$H/Library/Containers/com.docker.docker/Data/vms" "$H/Library/Group Containers/HUAQ24HBR6.dev.orbstack/data" "$H/.colima" \
           "$H/Library/Application Support/MobileSync/Backup" "$H/Library/Group Containers/group.net.whatsapp.WhatsApp.shared" "$H/Pictures"
echo
echo "node_modules folders outside ~/Library (top 15):"
find "$H" -xdev \( -path "$H/Library" -o -path "$H/.*" \) -prune -o -type d -name node_modules -prune -print 2>/dev/null \
  | while IFS= read -r d; do du -sk "$d" 2>/dev/null; done | sort -rn | head -15 | awk -F'\t' '{printf "%8.1f GB  %s\n", $1/1048576, $2}'
echo
echo "This is a size list only. Do not delete from it. Run spaceaudit for the reasons and risks, and verify every path yourself."
