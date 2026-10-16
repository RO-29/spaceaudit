// SpaceAudit: a native window over the bundled spaceaudit CLI. It shows advice and copies commands; it never deletes.
import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct Finding: Codable, Identifiable, Hashable {
    let id: String
    let rule: String
    let category: String
    let title: String
    let paths: [String]
    let bytes: Int64
    let safety: String
    let confidence: String
    let modified: Date?
    let lastUsed: Date?
    let reasons: [String]
    let risks: [String]
    let blockers: [String]
    let verify: [String]
    let commands: [String]
    let alternate: [String]?
    let restore: String?
    let notes: [String]?
    let partial: Bool?
    let needsSudo: Bool?
    var sizeKey: Int64 { bytes }
    var levelRank: Int { ["safe": 0, "review": 1, "risky": 2][safety] ?? 3 }
    var actionable: Bool { safety != "keep" && !commands.isEmpty }
}

struct Volume: Codable { let mount: String; let total: Int64; let used: Int64; let available: Int64 }
struct Totals: Codable { let safe: Int64; let review: Int64; let risky: Int64; let keep: Int64 }
struct Fact: Codable, Hashable { let key: String; let value: String; let note: String? }
struct Report: Codable {
    let version: String
    let host: String
    let generatedAt: Date
    let durationSec: Double
    let volume: Volume
    let totals: Totals
    let findings: [Finding]
    let facts: [Fact]?
    let warnings: [String]?
}

func human(_ b: Int64) -> String { ByteCountFormatter.string(fromByteCount: b, countStyle: .binary) }

func color(_ s: String) -> Color {
    switch s {
    case "safe": return .green
    case "review": return .orange
    case "risky": return .red
    default: return .blue
    }
}

@MainActor
final class Scanner: ObservableObject {
    @Published var report: Report?
    @Published var running = false
    @Published var progress = ""
    @Published var error: String?
    @Published var started = Date()

    var cli: URL {
        if let u = Bundle.main.url(forResource: "spaceaudit", withExtension: nil) { return u }
        return URL(fileURLWithPath: "/usr/local/bin/spaceaudit")
    }

    func scan(quick: Bool) {
        running = true; error = nil; progress = "Starting the read-only scan"; started = Date()
        let exe = cli
        Task.detached {
            let p = Process()
            p.executableURL = exe
            p.arguments = ["json", "-o", "-"] + (quick ? ["--quick"] : [])
            let out = Pipe(), err = Pipe()
            p.standardOutput = out; p.standardError = err
            err.fileHandleForReading.readabilityHandler = { h in
                let s = String(decoding: h.availableData, as: UTF8.self)
                if let line = s.split(separator: "\n").last(where: { $0.hasPrefix("progress: ") }) {
                    let text = String(line.dropFirst(10))
                    Task { @MainActor in self.progress = text }
                }
            }
            do { try p.run() } catch {
                await MainActor.run { self.error = "Cannot start \(exe.path): \(error.localizedDescription)"; self.running = false }
                return
            }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            err.fileHandleForReading.readabilityHandler = nil
            let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601withFractions
            let result = Result { try dec.decode(Report.self, from: data) }
            await MainActor.run {
                switch result {
                case .success(let r): self.report = r
                case .failure(let e): self.error = "The scan output could not be read: \(e)"
                }
                self.running = false
            }
        }
    }

    // Runs the CLI to write a report file. The CLI refuses to overwrite a file it did not write.
    func export(_ kind: String, to url: URL, quick: Bool = false) {
        running = true; progress = "Writing the \(kind) report"; started = Date()
        let exe = cli
        Task.detached {
            let p = Process()
            p.executableURL = exe
            p.arguments = [kind, "-o", url.path, "--no-open"] + (quick ? ["--quick"] : [])
            try? p.run(); p.waitUntilExit()
            await MainActor.run {
                self.running = false
                if kind == "html" { NSWorkspace.shared.open(url) } else { NSWorkspace.shared.activateFileViewerSelecting([url]) }
            }
        }
    }

    // A new file in the temporary folder, so the guard against overwrites never blocks it.
    func openHTML() {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("spaceaudit-\(Int(Date().timeIntervalSince1970)).html")
        export("html", to: url)
    }
}

extension JSONDecoder.DateDecodingStrategy {
    static let iso8601withFractions = custom { d in
        let s = try d.singleValueContainer().decode(String.self)
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let v = f.date(from: s) { return v }
        f.formatOptions = [.withInternetDateTime]
        if let v = f.date(from: s) { return v }
        return Date(timeIntervalSince1970: 0)
    }
}

// The plan runs only verify lines. Cleanup commands stay comments until the user edits them.
func planText(_ fs: [Finding]) -> String {
    var s = "#!/bin/sh\n# spaceaudit plan: \(fs.count) items, \(human(fs.reduce(0) { $0 + $1.bytes })).\n"
    s += "# Running this file runs only the verify commands. Uncomment a cleanup command only after you check it.\n"
    for f in fs {
        s += "\n# --- [\(f.safety)] \(f.title) (\(human(f.bytes)))\n"
        f.blockers.forEach { s += "# BLOCKER: \($0)\n" }
        f.risks.forEach { s += "# risk: \($0)\n" }
        s += "echo '== \(f.title.replacingOccurrences(of: "'", with: ""))'\n"
        f.verify.forEach { s += "\($0)\n" }
        f.commands.forEach { s += "# \($0.replacingOccurrences(of: "\n", with: "\n# "))\n" }
        if let r = f.restore, !r.isEmpty { s += "# restore: \(r)\n" }
    }
    return s
}

func copy(_ lines: [String]) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
}

struct ContentView: View {
    @StateObject var scanner = Scanner()
    @State var level = "all"
    @State var search = ""
    @State var selection = Set<Finding.ID>()
    @State var order = [KeyPathComparator(\Finding.levelRank), KeyPathComparator(\Finding.sizeKey, order: .reverse)]

    var filtered: [Finding] {
        (scanner.report?.findings ?? []).filter { f in
            (level == "all" || f.safety == level) &&
            (search.isEmpty || (f.title + " " + f.paths.joined(separator: " ")).localizedCaseInsensitiveContains(search))
        }.sorted(using: order)
    }
    var chosen: [Finding] { (scanner.report?.findings ?? []).filter { selection.contains($0.id) } }
    var partialCount: Int { (scanner.report?.findings ?? []).filter { $0.partial == true }.count }

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(get: { level }, set: { level = $0 ?? "all" })) {
                Section("Level") {
                    ForEach(["all", "safe", "review", "risky", "keep"], id: \.self) { l in
                        HStack {
                            Circle().fill(l == "all" ? Color.secondary : color(l)).frame(width: 8, height: 8)
                            Text(l.capitalized)
                            Spacer()
                            Text("\((scanner.report?.findings ?? []).filter { l == "all" || $0.safety == l }.count)").foregroundStyle(.secondary)
                        }.tag(l)
                    }
                }
                if let facts = scanner.report?.facts, !facts.isEmpty {
                    Section("Facts") {
                        ForEach(facts, id: \.self) { f in
                            VStack(alignment: .leading) { Text(f.key).font(.caption).foregroundStyle(.secondary); Text(f.value).font(.callout) }
                                .help(f.note ?? "")
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 210)
        } content: {
            VStack(spacing: 0) {
                header
                if partialCount > 0 {
                    HStack {
                        Image(systemName: "lock.shield").foregroundStyle(.orange)
                        Text("macOS hid some folders from \(partialCount) findings, so their sizes are too small. Give SpaceAudit Full Disk Access, then scan again.").font(.callout)
                        Spacer()
                        Button("Open Settings") { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!) }
                    }.padding(10).background(Color.orange.opacity(0.12)).padding(.horizontal, 12).padding(.bottom, 8)
                }
                Table(filtered, selection: $selection, sortOrder: $order) {
                    TableColumn("Level", value: \.levelRank) { f in
                        Text(f.safety.uppercased()).font(.caption.bold()).foregroundStyle(color(f.safety))
                    }.width(64)
                    TableColumn("Size", value: \.sizeKey) { f in Text(human(f.bytes)).monospacedDigit() }.width(80)
                    TableColumn("Recommendation", value: \.title) { f in
                        HStack {
                            if !f.blockers.isEmpty { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red).help(f.blockers[0]) }
                            if f.needsSudo == true { Image(systemName: "lock.fill").foregroundStyle(.secondary).help("Needs sudo") }
                            Text(f.title).lineLimit(1)
                        }
                    }
                    TableColumn("Category", value: \.category) { f in Text(f.category).foregroundStyle(.secondary) }.width(150)
                }
                if !selection.isEmpty { planBar }
            }
            .searchable(text: $search, prompt: "Search title or path")
            .navigationSplitViewColumnWidth(min: 460, ideal: 620)
        } detail: {
            if selection.count == 1, let id = selection.first, let f = scanner.report?.findings.first(where: { $0.id == id }) {
                DetailView(f: f)
            } else if selection.count > 1 {
                VStack(spacing: 10) {
                    Image(systemName: "checklist").font(.system(size: 44)).foregroundStyle(.secondary)
                    Text("\(selection.count) items · \(human(chosen.reduce(0) { $0 + $1.bytes }))").font(.title3.bold())
                    Text("Use the plan bar to copy or save a plan. A plan runs only the verify commands.").foregroundStyle(.secondary).multilineTextAlignment(.center)
                }.padding()
            } else {
                VStack(spacing: 10) {
                    Image(systemName: "internaldrive").font(.system(size: 44)).foregroundStyle(.secondary)
                    Text("Select a recommendation").font(.title3)
                    Text("SpaceAudit never deletes anything. Verify each path and command yourself.").foregroundStyle(.secondary).multilineTextAlignment(.center)
                }.padding()
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Button { scanner.scan(quick: false) } label: { Label("Full scan", systemImage: "arrow.clockwise") }.disabled(scanner.running)
                Button { scanner.scan(quick: true) } label: { Label("Quick scan", systemImage: "hare") }.disabled(scanner.running)
                Button { scanner.openHTML() } label: { Label("Open HTML report", systemImage: "safari") }.disabled(scanner.running)
                Button { save("html", "spaceaudit-report.html") } label: { Label("Save HTML report", systemImage: "doc.richtext") }.disabled(scanner.running)
                Button { save("script", "spaceaudit-review.sh") } label: { Label("Review script", systemImage: "terminal") }.disabled(scanner.running)
            }
        }
        .overlay {
            if scanner.running {
                VStack(spacing: 12) {
                    ProgressView()
                    Text("Working (read-only)").font(.headline)
                    Text(scanner.progress).foregroundStyle(.secondary)
                    TimelineView(.periodic(from: .now, by: 1)) { ctx in
                        Text("\(Int(ctx.date.timeIntervalSince(scanner.started)))s elapsed. A full scan of a large home folder takes some minutes.").font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(28).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
            }
        }
        .alert("Scan failed", isPresented: Binding(get: { scanner.error != nil }, set: { if !$0 { scanner.error = nil } })) {
            Button("OK") {}
        } message: { Text(scanner.error ?? "") }
        .onAppear { if scanner.report == nil { scanner.scan(quick: true) } }
    }

    var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let r = scanner.report {
                let v = r.volume, t = r.totals
                HStack(alignment: .firstTextBaseline) {
                    Text("\(human(v.available)) free").font(.title2.bold())
                    Text("of \(human(v.total))").foregroundStyle(.secondary)
                    Text("· scanned \(r.generatedAt.formatted(.relative(presentation: .named)))").foregroundStyle(.secondary).font(.caption)
                    Spacer()
                    Text("safe \(human(t.safe))").foregroundStyle(.green)
                    Text("review \(human(t.review))").foregroundStyle(.orange)
                    Text("risky \(human(t.risky))").foregroundStyle(.red)
                }.font(.callout.monospacedDigit())
                GeometryReader { g in
                    let total = Double(max(1, v.used + v.available))
                    let parts: [(Int64, Color)] = [(t.safe, .green), (t.review, .orange), (t.risky, .red), (max(0, v.used - t.safe - t.review - t.risky), .gray), (v.available, Color.gray.opacity(0.25))]
                    HStack(spacing: 0) { ForEach(0..<parts.count, id: \.self) { i in Rectangle().fill(parts[i].1).frame(width: g.size.width * Double(parts[i].0) / total) } }
                        .clipShape(Capsule())
                }.frame(height: 10)
            } else {
                Text("No scan yet").foregroundStyle(.secondary)
            }
        }.padding(12)
    }

    var planBar: some View {
        HStack {
            Text("\(chosen.count) selected · \(human(chosen.reduce(0) { $0 + $1.bytes }))").bold()
            if chosen.contains(where: { !$0.blockers.isEmpty }) { Text("some are blocked").foregroundStyle(.red).font(.caption) }
            Spacer()
            Button("Copy verify") { copy(chosen.flatMap(\.verify)) }
            Button("Copy commands") { copy(chosen.filter(\.actionable).flatMap(\.commands)) }
            Button("Save plan…") {
                let panel = NSSavePanel(); panel.nameFieldStringValue = "spaceaudit-plan.sh"
                if panel.runModal() == .OK, let url = panel.url {
                    // A user-chosen new file; the save panel already asked before replacing one.
                    try? planText(chosen.filter(\.actionable)).data(using: .utf8)?.write(to: url)
                    NSWorkspace.shared.activateFileViewerSelecting([url])
                }
            }.buttonStyle(.borderedProminent)
            Button("Clear") { selection.removeAll() }
        }.padding(10).background(.bar)
    }

    func save(_ kind: String, _ name: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        if panel.runModal() == .OK, let url = panel.url { scanner.export(kind, to: url) }
    }
}

struct DetailView: View {
    let f: Finding
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text(f.safety.uppercased()).font(.caption.bold()).padding(.horizontal, 8).padding(.vertical, 3)
                        .background(color(f.safety).opacity(0.15), in: RoundedRectangle(cornerRadius: 6)).foregroundStyle(color(f.safety))
                    Text(human(f.bytes)).font(.title3.bold().monospacedDigit())
                    Spacer()
                    Text("confidence \(f.confidence)").font(.caption).foregroundStyle(.secondary)
                }
                Text(f.title).font(.title2.bold()).textSelection(.enabled)
                if !f.paths.isEmpty {
                    section("Paths") {
                        ForEach(f.paths.prefix(10), id: \.self) { p in Text(p).font(.system(.callout, design: .monospaced)).textSelection(.enabled) }
                        Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting(f.paths.prefix(10).map { URL(fileURLWithPath: $0) }) }
                    }
                }
                if !f.blockers.isEmpty { bullets("Blockers", f.blockers, .red) }
                bullets("Why", f.reasons, .primary)
                if !f.risks.isEmpty { bullets("Risks", f.risks, .orange) }
                codeBlock("1. Verify first", f.verify)
                codeBlock("2. Command (run only after you verify)", f.commands)
                if let a = f.alternate, !a.isEmpty { codeBlock("Undo-friendly alternative", a) }
                if let r = f.restore, !r.isEmpty { section("How to get it back") { Text(r).textSelection(.enabled) } }
                if let n = f.notes, !n.isEmpty { bullets("Notes", n, .secondary) }
                Text("SpaceAudit did not run any of these commands. Read them, verify the paths yourself, then run them in Terminal if you choose.")
                    .font(.footnote).foregroundStyle(.secondary)
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    func section<C: View>(_ t: String, @ViewBuilder _ c: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 6) { Text(t.uppercased()).font(.caption.bold()).foregroundStyle(.secondary); c() }
    }
    func bullets(_ t: String, _ xs: [String], _ c: Color) -> some View {
        section(t) { ForEach(xs, id: \.self) { x in HStack(alignment: .top) { Text("•"); Text(x).foregroundStyle(c).textSelection(.enabled) } } }
    }
    func codeBlock(_ t: String, _ lines: [String]) -> some View {
        section(t) {
            if lines.isEmpty { Text("None").foregroundStyle(.secondary) } else {
                HStack(alignment: .top) {
                    Text(lines.prefix(20).joined(separator: "\n")).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button("Copy") { copy(lines) }
                }.padding(10).background(Color.gray.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}

@main
struct SpaceAuditApp: App {
    var body: some Scene {
        WindowGroup("SpaceAudit") { ContentView().frame(minWidth: 1000, minHeight: 620) }
    }
}
