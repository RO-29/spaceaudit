#!/bin/sh
# Renders the app icon (a gauge on a gradient) with Core Graphics, then packs it with iconutil.
set -eu
OUT="$1"
WORK=$(mktemp -d)
cat > "$WORK/icon.swift" <<'SWIFT'
import AppKit
let size = CGFloat(Double(CommandLine.arguments[1])!)
let img = NSImage(size: NSSize(width: size, height: size))
img.lockFocus()
let r = NSRect(x: size * 0.1, y: size * 0.1, width: size * 0.8, height: size * 0.8)
let bg = NSBezierPath(roundedRect: r, xRadius: size * 0.18, yRadius: size * 0.18)
NSGradient(starting: NSColor(calibratedRed: 0.20, green: 0.22, blue: 0.55, alpha: 1), ending: NSColor(calibratedRed: 0.10, green: 0.62, blue: 0.55, alpha: 1))!.draw(in: bg, angle: -60)
let c = NSPoint(x: size / 2, y: size * 0.42)
let colors: [NSColor] = [.systemGreen, .systemOrange, .systemRed]
for (i, col) in colors.enumerated() {
    let arc = NSBezierPath()
    arc.appendArc(withCenter: c, radius: size * 0.26, startAngle: 180 - CGFloat(i) * 60, endAngle: 120 - CGFloat(i) * 60, clockwise: true)
    arc.lineWidth = size * 0.07
    col.setStroke(); arc.stroke()
}
let needle = NSBezierPath(); needle.move(to: c); needle.line(to: NSPoint(x: c.x - size * 0.13, y: c.y + size * 0.17))
needle.lineWidth = size * 0.035; needle.lineCapStyle = .round; NSColor.white.setStroke(); needle.stroke()
NSColor.white.setFill(); NSBezierPath(ovalIn: NSRect(x: c.x - size * 0.04, y: c.y - size * 0.04, width: size * 0.08, height: size * 0.08)).fill()
img.unlockFocus()
let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[2]))
SWIFT
swiftc -O "$WORK/icon.swift" -o "$WORK/icon" 2>/dev/null
mkdir -p "$WORK/AppIcon.iconset"
for s in 16 32 128 256 512; do
  "$WORK/icon" $s "$WORK/AppIcon.iconset/icon_${s}x${s}.png"
  "$WORK/icon" $((s * 2)) "$WORK/AppIcon.iconset/icon_${s}x${s}@2x.png"
done
iconutil -c icns "$WORK/AppIcon.iconset" -o "$OUT"
rm -rf "$WORK"
