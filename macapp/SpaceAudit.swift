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

// Splits the stderr stream into whole lines. The read handler runs on one serial queue.
final class LineBuffer: @unchecked Sendable {
    private var pending = ""
    func add(_ d: Data) -> [String] {
        pending += String(decoding: d, as: UTF8.self)
        var out: [String] = []
        while let nl = pending.firstIndex(of: "\n") { out.append(String(pending[..<nl])); pending = String(pending[pending.index(after: nl)...]) }
        return out
    }
}

struct ScanEvent: Codable { let step: Int; let steps: Int; let title: String; let detail: String?; let files: Int64?; let bytes: Int64?; let found: Int; let foundBytes: Int64 }

struct RecheckItem: Codable, Identifiable { let id: String; let title: String; let safety: String; let category: String; let before: Int64; let now: Int64; let status: String; let note: String? }
struct RecheckReport: Codable { let checkedAt: Date; let baseScanAt: Date; let volumeBefore: Volume; let volumeNow: Volume; let freed: Int64; let items: [RecheckItem] }

@MainActor
final class Scanner: ObservableObject {
    @Published var report: Report?
    @Published var running = false
    @Published var progress = ""
    @Published var error: String?
    @Published var started = Date()
    @Published var event: ScanEvent?
    @Published var stepTitles: [Int: String] = [:]
    @Published var files: Int64 = 0
    @Published var bytesRead: Int64 = 0
    @Published var currentPath = ""
    @Published var quick = true
    @Published var recheck: RecheckReport?
    private var process: Process?
    private var cancelled = false

    var cli: URL {
        if let u = Bundle.main.url(forResource: "spaceaudit", withExtension: nil) { return u }
        return URL(fileURLWithPath: "/usr/local/bin/spaceaudit")
    }

    // A plain text log of every scan, so a scan that stops can be diagnosed.
    nonisolated static let logURL: URL = {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/SpaceAudit")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("scan.log")
    }()

    nonisolated static func log(_ line: String) {
        let text = "\(ISO8601DateFormatter().string(from: Date())) \(line)\n"
        if let h = try? FileHandle(forWritingTo: logURL) { h.seekToEndOfFile(); h.write(Data(text.utf8)); try? h.close() }
        else { try? Data(text.utf8).write(to: logURL) }
    }

    func cancel() { cancelled = true; process?.terminate() }

    func scan(quick: Bool) {
        running = true; error = nil; progress = "Starting the read-only scan"; started = Date()
        event = nil; stepTitles = [:]; files = 0; bytesRead = 0; currentPath = ""; self.quick = quick; cancelled = false
        let exe = cli
        Scanner.log("scan start quick=\(quick)")
        let p = Process()
        p.executableURL = exe
        p.arguments = ["json", "-o", "-"] + (quick ? ["--quick"] : [])
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        process = p
        let buf = LineBuffer()
        err.fileHandleForReading.readabilityHandler = { h in
            for line in buf.add(h.availableData) {
                if line.hasPrefix("event: "), let ev = try? JSONDecoder().decode(ScanEvent.self, from: Data(line.dropFirst(7).utf8)) {
                    Task { @MainActor in self.apply(ev) }
                    if ev.files == nil { Scanner.log("step \(ev.step)/\(ev.steps) \(ev.title) found=\(ev.found)") }
                } else if line.hasPrefix("progress: ") {
                    let t = String(line.dropFirst(10)); Task { @MainActor in self.progress = t }
                }
            }
        }
        Task.detached {
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
                case .success(let r): self.report = r; Scanner.log("scan done findings=\(r.findings.count) seconds=\(Int(r.durationSec))")
                case .failure(let e):
                    if self.cancelled { Scanner.log("scan cancelled") } else { self.error = "The scan output could not be read: \(e)"; Scanner.log("scan failed: \(e)") }
                }
                self.running = false; self.process = nil
            }
        }
    }

    private func apply(_ ev: ScanEvent) {
        if ev.files == nil { stepTitles[ev.step] = ev.title }
        if let f = ev.files { files = f }
        if let b = ev.bytes { bytesRead = b }
        if let d = ev.detail, !d.isEmpty { currentPath = d }
        event = ev
    }

    // Measures again only the items of the last full scan.
    func runRecheck() {
        running = true; progress = "Rechecking the items of the last full scan"; started = Date(); event = nil; stepTitles = [:]
        let exe = cli
        Task.detached {
            let p = Process(); p.executableURL = exe; p.arguments = ["recheck", "--json"]
            let out = Pipe(); p.standardOutput = out; p.standardError = Pipe()
            try? p.run()
            let data = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
            let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601withFractions
            let r = try? dec.decode(RecheckReport.self, from: data)
            await MainActor.run {
                self.running = false
                if let r { self.recheck = r } else { self.error = "No full scan to compare against. Run a Full scan first." }
            }
        }
    }

    // Runs the CLI to write a report file. The CLI refuses to overwrite a file it did not write.
    func export(_ kind: String, to url: URL, quick: Bool = false) {
        running = true; progress = "Writing the \(kind) report"; started = Date(); event = nil; stepTitles = [:]
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
        .toolbarRole(.editor)
        .toolbar {
            ToolbarItemGroup {
                Button { scanner.scan(quick: false) } label: { Label("Full scan", systemImage: "arrow.clockwise").labelStyle(.titleAndIcon) }
                    .help("Scan everything, including project folders, worktrees and duplicates (some minutes)").disabled(scanner.running)
                Button { scanner.scan(quick: true) } label: { Label("Quick scan", systemImage: "hare").labelStyle(.titleAndIcon) }
                    .help("Scan known caches and apps only (under a minute)").disabled(scanner.running)
                Button { scanner.openHTML() } label: { Label("HTML report", systemImage: "safari").labelStyle(.titleAndIcon) }
                    .help("Write a full HTML report and open it in the browser").disabled(scanner.running)
                Button { scanner.runRecheck() } label: { Label("Recheck", systemImage: "checkmark.arrow.trianglehead.counterclockwise") .labelStyle(.titleAndIcon) }
                    .help("Measure again only the items of the last full scan, to see what your cleanup freed").disabled(scanner.running)
                Menu {
                    Button("Save HTML report…") { save("html", "spaceaudit-report.html") }
                    Button("Save Markdown report…") { save("md", "spaceaudit-report.md") }
                    Button("Save review script…") { save("script", "spaceaudit-review.sh") }
                } label: { Label("Export", systemImage: "square.and.arrow.up").labelStyle(.titleAndIcon) }.disabled(scanner.running)
            }
        }
        .overlay {
            if scanner.running {
                ZStack {
                    Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
                    ScanView(scanner: scanner)
                }.transition(.opacity)
            }
        }
        .sheet(isPresented: Binding(get: { scanner.recheck != nil }, set: { if !$0 { scanner.recheck = nil } })) {
            if let r = scanner.recheck { RecheckView(r: r) { scanner.recheck = nil } }
        }
        .alert("Scan failed", isPresented: Binding(get: { scanner.error != nil }, set: { if !$0 { scanner.error = nil } })) {
            Button("OK") {}
        } message: { Text(scanner.error ?? "") }
        .onAppear {
            if scanner.report == nil { scanner.scan(quick: !CommandLine.arguments.contains("--autoscan-full")) }
        }
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
                Text(scanner.running ? "Scanning…" : "No scan yet. Press Quick scan or Full scan.").foregroundStyle(.secondary)
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

// The scan screen: every step with its state, what is being read now, and live counts.
struct ScanView: View {
    @ObservedObject var scanner: Scanner
    @State private var spin = false

    var steps: Int { scanner.event?.steps ?? (scanner.quick ? 6 : 9) }
    var current: Int { scanner.event?.step ?? 0 }
    var fraction: Double { steps == 0 ? 0 : Double(max(0, current - 1)) / Double(steps) }

    var body: some View {
        VStack(spacing: 22) {
            HStack(spacing: 22) {
                ZStack {
                    Circle().stroke(Color.secondary.opacity(0.15), lineWidth: 12)
                    Circle().trim(from: 0, to: max(0.03, fraction))
                        .stroke(AngularGradient(colors: [.teal, .blue, .indigo, .teal], center: .center), style: StrokeStyle(lineWidth: 12, lineCap: .round))
                        .rotationEffect(.degrees(-90)).animation(.easeInOut(duration: 0.6), value: fraction)
                    Circle().trim(from: 0, to: 0.12).stroke(Color.white.opacity(0.55), style: StrokeStyle(lineWidth: 3, lineCap: .round))
                        .padding(14).rotationEffect(.degrees(spin ? 360 : 0))
                        .animation(.linear(duration: 1.6).repeatForever(autoreverses: false), value: spin)
                    VStack(spacing: 2) {
                        Text("\(scanner.event?.found ?? 0)").font(.system(size: 34, weight: .bold, design: .rounded)).contentTransition(.numericText())
                        Text("found").font(.caption).foregroundStyle(.secondary)
                        Text(human(scanner.event?.foundBytes ?? 0)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }.frame(width: 150, height: 150).onAppear { spin = true }
                VStack(alignment: .leading, spacing: 6) {
                    Text(scanner.event == nil && scanner.stepTitles.isEmpty ? scanner.progress : "Scanning your Mac").font(.title2.bold())
                    Text("Read-only. SpaceAudit changes nothing.").foregroundStyle(.secondary)
                    TimelineView(.periodic(from: .now, by: 1)) { ctx in
                        Text("\(Int(ctx.date.timeIntervalSince(scanner.started)))s · step \(max(current, 1)) of \(steps) · \(scanner.quick ? "quick scan" : "full scan")")
                            .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    if scanner.files > 0 {
                        HStack(spacing: 18) {
                            Label("\(scanner.files.formatted()) files", systemImage: "doc.on.doc").contentTransition(.numericText())
                            Label(human(scanner.bytesRead), systemImage: "internaldrive")
                        }.font(.callout.monospacedDigit()).padding(.top, 4)
                    }
                }
                Spacer(minLength: 0)
            }
            VStack(alignment: .leading, spacing: 9) {
                ForEach(1...max(steps, 1), id: \.self) { i in
                    HStack(spacing: 10) {
                        Group {
                            if i < current || scanner.event?.title == "Done" { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
                            else if i == current { ProgressView().controlSize(.small) }
                            else { Image(systemName: "circle").foregroundStyle(.tertiary) }
                        }.frame(width: 18)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(scanner.stepTitles[i] ?? (i == current ? (scanner.event?.title ?? "") : "Waiting")).foregroundStyle(i > current ? .secondary : .primary)
                                .fontWeight(i == current ? .semibold : .regular)
                            if i == current, !scanner.currentPath.isEmpty {
                                Text(scanner.currentPath).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                    .id(scanner.currentPath).transition(.opacity)
                            }
                        }
                    }
                }
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
            HStack {
                Text("A full scan of a large home folder takes some minutes. You can keep working.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", role: .cancel) { scanner.cancel() }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(28).frame(width: 620)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20))
        .shadow(color: .black.opacity(0.18), radius: 30, y: 10)
        .animation(.easeInOut(duration: 0.3), value: current)
    }
}

// What changed since the last full scan, per item.
struct RecheckView: View {
    let r: RecheckReport
    let close: () -> Void
    func tint(_ s: String) -> Color { ["gone": .green, "partly gone": .green, "smaller": .green, "larger": .orange][s] ?? .secondary }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Recheck").font(.title.bold())
            Text("Compared with the full scan of \(r.baseScanAt.formatted(date: .abbreviated, time: .shortened)).").foregroundStyle(.secondary)
            HStack(spacing: 28) {
                VStack(alignment: .leading) { Text("Freed by these items").font(.caption).foregroundStyle(.secondary); Text(human(r.freed)).font(.title2.bold()).foregroundStyle(.green) }
                VStack(alignment: .leading) { Text("Free space then").font(.caption).foregroundStyle(.secondary); Text(human(r.volumeBefore.available)).font(.title2.bold()) }
                VStack(alignment: .leading) { Text("Free space now").font(.caption).foregroundStyle(.secondary); Text(human(r.volumeNow.available)).font(.title2.bold()) }
            }
            Table(r.items.sorted { ($0.status == "unchanged" ? 1 : 0, -($0.before - $0.now)) < ($1.status == "unchanged" ? 1 : 0, -($1.before - $1.now)) }) {
                TableColumn("Status") { i in Text(i.status.uppercased()).font(.caption.bold()).foregroundStyle(tint(i.status)) }.width(100)
                TableColumn("Before") { i in Text(human(i.before)).monospacedDigit() }.width(80)
                TableColumn("Now") { i in Text(human(i.now)).monospacedDigit() }.width(80)
                TableColumn("Item") { i in Text(i.title).lineLimit(1).help(i.note ?? "") }
            }.frame(minHeight: 320)
            Text("Free space can take some minutes to change: snapshots and programs that hold deleted files keep the blocks until they let go.").font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Done", action: close).keyboardShortcut(.defaultAction) }
        }.padding(24).frame(width: 760, height: 560)
    }
}

@main
struct SpaceAuditApp: App {
    var body: some Scene {
        WindowGroup("SpaceAudit") { ContentView().frame(minWidth: 1000, minHeight: 620) }
    }
}
