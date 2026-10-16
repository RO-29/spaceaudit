package scan

import "github.com/RO-29/spaceaudit/internal/model"

// Rule is one known location. {p} in a command becomes the quoted path; {rm} becomes a delete of that path.
type Rule struct {
	ID       string
	Category string
	Title    string
	Paths    []string
	PerPath  bool // one finding per matched path, not one for all
	Safety   model.Safety
	Reasons  []string
	Risks    []string
	Verify   []string
	Commands []string
	Tool     string   // Commands need this binary; without it the rule falls back to {rm}
	Quit     []string // process names that must not run
	Restore  string
	Sudo     bool
}

const (
	catDev     = "Developer caches"
	catPkg     = "Package manager caches"
	catBuild   = "Build output"
	catIDE     = "Editors and IDEs"
	catBrowser = "Browsers and app caches"
	catVM      = "Containers and VMs"
	catSystem  = "System"
	catUser    = "Your files"
	catAI      = "AI tools and models"
	catApps    = "Applications"
)

var catalog = []Rule{
	// Package managers. Each one prefers the tool's own clean command, which knows its layout.
	{ID: "npm-cache", Category: catPkg, Title: "npm download cache", Paths: []string{"~/.npm/_cacache"}, Safety: model.Safe,
		Reasons: []string{"npm keeps every downloaded package tarball here and downloads it again when it is missing."},
		Risks:   []string{"Offline installs fail until npm downloads the packages again."},
		Verify:  []string{"npm cache verify"}, Commands: []string{"npm cache clean --force"}, Tool: "npm",
		Restore: "Nothing to restore. The next npm install fills it again."},
	{ID: "yarn-cache", Category: catPkg, Title: "Yarn cache", Paths: []string{"~/Library/Caches/Yarn", "~/.yarn/berry/cache", "~/.cache/yarn"}, Safety: model.Safe,
		Reasons: []string{"Yarn keeps package archives here and downloads them again when they are missing."},
		Risks:   []string{"Yarn Berry projects with zero-install keep their own .yarn/cache in the repo. This rule does not touch those."},
		Verify:  []string{"yarn cache dir"}, Commands: []string{"yarn cache clean"}, Tool: "yarn",
		Restore: "Nothing to restore. The next yarn install fills it again."},
	{ID: "pnpm-store", Category: catPkg, Title: "pnpm content store", Paths: []string{"~/Library/pnpm/store", "~/.local/share/pnpm/store", "~/.pnpm-store"}, Safety: model.Safe,
		Reasons: []string{"pnpm prune removes only packages that no project links to."},
		Risks:   []string{"Projects hard-link files from this store, so a plain rm frees less than the size shown. Use pnpm store prune, not rm."},
		Verify:  []string{"pnpm store status"}, Commands: []string{"pnpm store prune"}, Tool: "pnpm",
		Restore: "Nothing to restore. pnpm install fetches missing packages."},
	{ID: "bun-cache", Category: catPkg, Title: "Bun install cache", Paths: []string{"~/.bun/install/cache"}, Safety: model.Safe,
		Reasons: []string{"Bun downloads packages again when they are missing."},
		Verify:  []string{"ls {p}"}, Commands: []string{"bun pm cache rm"}, Tool: "bun", Restore: "Nothing to restore."},
	{ID: "pip-cache", Category: catPkg, Title: "pip download cache", Paths: []string{"~/Library/Caches/pip", "~/.cache/pip"}, Safety: model.Safe,
		Reasons: []string{"pip keeps downloaded wheels here. It downloads them again when they are missing."},
		Verify:  []string{"pip3 cache info"}, Commands: []string{"pip3 cache purge"}, Tool: "pip3", Restore: "Nothing to restore."},
	{ID: "uv-cache", Category: catPkg, Title: "uv cache", Paths: []string{"~/.cache/uv", "~/Library/Caches/uv"}, Safety: model.Safe,
		Reasons: []string{"uv keeps wheels and built packages here."},
		Risks:   []string{"uv virtual environments link to this cache. Run uv sync in each project after a clean."},
		Verify:  []string{"uv cache dir"}, Commands: []string{"uv cache prune"}, Tool: "uv", Restore: "uv sync downloads what is missing."},
	{ID: "poetry-cache", Category: catPkg, Title: "Poetry cache", Paths: []string{"~/Library/Caches/pypoetry"}, Safety: model.Safe,
		Reasons: []string{"Poetry keeps package archives here."},
		Verify:  []string{"poetry cache list"}, Commands: []string{"{rm}"}, Restore: "poetry install downloads what is missing."},
	{ID: "conda-pkgs", Category: catPkg, Title: "Conda package cache", Paths: []string{"~/miniconda3/pkgs", "~/anaconda3/pkgs", "~/miniforge3/pkgs", "~/opt/anaconda3/pkgs"}, Safety: model.Safe,
		Reasons: []string{"Conda keeps package archives after it installs them."},
		Verify:  []string{"conda clean --all --dry-run"}, Commands: []string{"conda clean --all --yes"}, Tool: "conda", Restore: "Conda downloads packages again when it needs them."},
	{ID: "go-build", Category: catDev, Title: "Go build cache", Paths: []string{"~/Library/Caches/go-build"}, Safety: model.Safe,
		Reasons: []string{"Go rebuilds this cache on the next build or test."},
		Risks:   []string{"The first build after a clean is slower."},
		Verify:  []string{"go env GOCACHE"}, Commands: []string{"go clean -cache"}, Tool: "go", Restore: "Nothing to restore."},
	{ID: "go-mod", Category: catDev, Title: "Go module cache", Paths: []string{"~/go/pkg/mod"}, Safety: model.Review,
		Reasons: []string{"Go downloads modules again from the proxy."},
		Risks:   []string{"Go writes these files read-only, so rm -rf fails. Use go clean -modcache.", "Private modules need GOPRIVATE access to download again.", "A replace directive that points into this folder breaks."},
		Verify:  []string{"go env GOMODCACHE"}, Commands: []string{"go clean -modcache"}, Tool: "go", Restore: "go mod download"},
	{ID: "cargo-registry", Category: catDev, Title: "Cargo registry cache", Paths: []string{"~/.cargo/registry/cache", "~/.cargo/registry/src", "~/.cargo/git/checkouts"}, Safety: model.Safe,
		Reasons: []string{"Cargo downloads crates again when a build needs them."},
		Risks:   []string{"Keep ~/.cargo/bin: it holds installed tools. This rule does not include it."},
		Verify:  []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "cargo fetch"},
	{ID: "rustup-toolchains", Category: catDev, Title: "Rust toolchains", Paths: []string{"~/.rustup/toolchains"}, Safety: model.Review,
		Reasons: []string{"Old toolchains stay after an update."},
		Risks:   []string{"A project with rust-toolchain.toml needs its pinned version. Remove only versions that no project pins."},
		Verify:  []string{"rustup toolchain list"}, Commands: []string{"rustup toolchain uninstall <name>"}, Tool: "rustup", Restore: "rustup toolchain install <name>"},
	{ID: "gradle-caches", Category: catDev, Title: "Gradle caches and wrapper downloads", Paths: []string{"~/.gradle/caches", "~/.gradle/wrapper/dists", "~/.gradle/daemon"}, Safety: model.Safe,
		Reasons: []string{"Gradle downloads dependencies and wrapper versions again."},
		Risks:   []string{"Stop the Gradle daemon first, or it can write while you delete.", "Keep ~/.gradle/gradle.properties: it can hold credentials. This rule does not include it."},
		Quit:    []string{"java"}, Verify: []string{"du -sh {p}"}, Commands: []string{"gradle --stop 2>/dev/null; {rm}"}, Restore: "The next Gradle build downloads what it needs."},
	{ID: "maven-repo", Category: catDev, Title: "Maven local repository", Paths: []string{"~/.m2/repository"}, Safety: model.Review,
		Reasons: []string{"Maven downloads public artifacts again."},
		Risks:   []string{"Artifacts that you built with mvn install exist only here. They cannot download again.", "Keep ~/.m2/settings.xml: it holds repository credentials. This rule does not include it."},
		Verify:  []string{"find {p} -name '*SNAPSHOT*' -maxdepth 4 | head"}, Commands: []string{"{rm}"}, Restore: "mvn dependency:resolve, and mvn install for your own modules."},
	{ID: "cocoapods", Category: catDev, Title: "CocoaPods cache", Paths: []string{"~/Library/Caches/CocoaPods"}, Safety: model.Safe,
		Reasons: []string{"CocoaPods downloads pods again."},
		Verify:  []string{"pod cache list"}, Commands: []string{"pod cache clean --all"}, Tool: "pod", Restore: "pod install"},
	{ID: "swiftpm", Category: catDev, Title: "Swift Package Manager cache", Paths: []string{"~/Library/Caches/org.swift.swiftpm", "~/Library/org.swift.swiftpm"}, Safety: model.Safe,
		Reasons: []string{"SwiftPM downloads packages again."}, Verify: []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "swift package resolve"},
	{ID: "terraform-plugins", Category: catDev, Title: "Terraform plugin cache", Paths: []string{"~/.terraform.d/plugin-cache"}, Safety: model.Safe,
		Reasons: []string{"terraform init downloads providers again."}, Verify: []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "terraform init"},
	{ID: "gcloud-logs", Category: catDev, Title: "gcloud command logs", Paths: []string{"~/.config/gcloud/logs"}, Safety: model.Safe,
		Reasons: []string{"These are text logs of old gcloud runs."},
		Risks:   []string{"Do not delete other gcloud folders: they hold your login credentials."},
		Verify:  []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "Nothing to restore."},
	{ID: "kube-cache", Category: catDev, Title: "kubectl discovery cache", Paths: []string{"~/.kube/cache", "~/.kube/http-cache"}, Safety: model.Safe,
		Reasons: []string{"kubectl rebuilds API discovery data on the next call."},
		Risks:   []string{"Keep ~/.kube/config. This rule does not include it."},
		Verify:  []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "Nothing to restore."},
	{ID: "mongodb-binaries", Category: catDev, Title: "Downloaded MongoDB test binaries", Paths: []string{"~/.cache/mongodb-binaries"}, Safety: model.Safe,
		Reasons: []string{"mongodb-memory-server downloads these binaries again for tests."}, Verify: []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "The next test run downloads them."},
	{ID: "playwright", Category: catDev, Title: "Playwright and Puppeteer browsers", Paths: []string{"~/Library/Caches/ms-playwright", "~/.cache/puppeteer"}, Safety: model.Safe,
		Reasons: []string{"These are test browsers that the tools download again."},
		Verify:  []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "npx playwright install"},

	// Xcode and simulators.
	{ID: "xcode-deriveddata", Category: catDev, Title: "Xcode DerivedData", Paths: []string{"~/Library/Developer/Xcode/DerivedData"}, Safety: model.Safe,
		Reasons: []string{"Xcode rebuilds this on the next build."}, Quit: []string{"Xcode"},
		Verify: []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "Build the project again."},
	{ID: "xcode-devicesupport", Category: catDev, Title: "Old device support files", Paths: []string{"~/Library/Developer/Xcode/iOS DeviceSupport", "~/Library/Developer/Xcode/watchOS DeviceSupport", "~/Library/Developer/Xcode/tvOS DeviceSupport"}, Safety: model.Safe,
		Reasons: []string{"Xcode copies these again when you connect a device."},
		Risks:   []string{"The first connection of each device takes some minutes."},
		Verify:  []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "Connect the device again."},
	{ID: "xcode-archives", Category: catDev, Title: "Xcode archives", Paths: []string{"~/Library/Developer/Xcode/Archives"}, Safety: model.Risky,
		Reasons: []string{"Archives are the builds that you sent to the App Store."},
		Risks:   []string{"They hold the dSYM files that decode crash reports. You cannot make an archive of an old release again."},
		Verify:  []string{"ls {p}"}, Commands: []string{"Remove old archives in Xcode > Window > Organizer."}, Restore: "None. Keep archives of releases that users still run."},
	{ID: "simulator-devices", Category: catDev, Title: "iOS simulator devices", Paths: []string{"~/Library/Developer/CoreSimulator/Devices"}, Safety: model.Review,
		Reasons: []string{"Each simulator keeps its own apps and data."},
		Risks:   []string{"delete unavailable removes only simulators for runtimes that are gone. erase all removes app data in every simulator."},
		Verify:  []string{"xcrun simctl list devices"}, Commands: []string{"xcrun simctl delete unavailable"}, Tool: "xcrun", Restore: "Xcode makes default simulators again."},
	{ID: "simulator-caches", Category: catDev, Title: "Simulator system caches", Paths: []string{"/Library/Developer/CoreSimulator/Caches"}, Safety: model.Safe, Sudo: true,
		Reasons: []string{"The simulator rebuilds its dyld cache when it starts."},
		Risks:   []string{"The folder belongs to root, so the command needs sudo. The next simulator start is slower."},
		Verify:  []string{"sudo du -sh {p}"}, Commands: []string{"sudo rm -rf -- {p}/*"}, Restore: "Start a simulator."},
	{ID: "android-avd", Category: catDev, Title: "Android emulator images", Paths: []string{"~/.android/avd"}, Safety: model.Review,
		Reasons: []string{"Each virtual device keeps a full disk image."},
		Risks:   []string{"Apps and data inside the emulator go away."},
		Verify:  []string{"ls {p}"}, Commands: []string{"Delete devices in Android Studio > Device Manager."}, Restore: "Make the device again in Device Manager."},
	{ID: "android-sdk", Category: catDev, Title: "Android SDK", Paths: []string{"~/Library/Android/sdk"}, Safety: model.Review,
		Reasons: []string{"The SDK is large and stays after you remove Android Studio."},
		Risks:   []string{"React Native, Flutter and Gradle builds for Android need it."},
		Verify:  []string{"du -sh {p}/*"}, Commands: []string{"{rm}"}, Restore: "Android Studio > SDK Manager downloads it again."},

	// Editors.
	{ID: "vscode-vsix", Category: catIDE, Title: "Cached extension installers", Paths: []string{"~/Library/Application Support/Code/CachedExtensionVSIXs", "~/Library/Application Support/Cursor/CachedExtensionVSIXs", "~/Library/Application Support/Windsurf/CachedExtensionVSIXs"}, PerPath: true, Safety: model.Safe,
		Reasons: []string{"These are copies of extension packages that are already installed."},
		Verify:  []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "Nothing to restore."},
	{ID: "editor-cacheddata", Category: catIDE, Title: "Editor compiled code cache", Paths: []string{"~/Library/Application Support/Code/CachedData", "~/Library/Application Support/Cursor/CachedData", "~/Library/Application Support/Windsurf/CachedData", "~/Library/Application Support/Code/logs", "~/Library/Application Support/Cursor/logs"}, Safety: model.Safe,
		Reasons: []string{"The editor rebuilds this cache. Old versions of it stay after each update."},
		Quit:    []string{"Code", "Electron", "Cursor", "Windsurf"}, Verify: []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "Nothing to restore."},
	{ID: "cursor-state", Category: catIDE, Title: "Cursor global state database", Paths: []string{"~/Library/Application Support/Cursor/User/globalStorage/state.vscdb"}, Safety: model.Risky,
		Reasons: []string{"This one file holds Cursor chat and agent history, so it grows large."},
		Risks:   []string{"Deleting it removes all Cursor chat history and some settings. It does not come back."},
		Quit:    []string{"Cursor"}, Verify: []string{"ls -lh {p}"}, Commands: []string{"Quit Cursor, then move the file to the Trash and keep it until Cursor works."}, Restore: "Put the file back from the Trash."},
	{ID: "jetbrains-caches", Category: catIDE, Title: "JetBrains caches and logs", Paths: []string{"~/Library/Caches/JetBrains", "~/Library/Logs/JetBrains"}, Safety: model.Safe,
		Reasons: []string{"The IDE indexes the project again."},
		Risks:   []string{"The first start after a clean indexes for some minutes."},
		Quit:    []string{"idea", "goland", "pycharm", "webstorm"}, Verify: []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "Open the project."},

	// AI tools.
	{ID: "ollama-models", Category: catAI, Title: "Ollama models", Paths: []string{"~/.ollama/models"}, Safety: model.Review,
		Reasons: []string{"Local models are many gigabytes each."},
		Risks:   []string{"Download again takes time and bandwidth. A custom Modelfile model must be built again."},
		Verify:  []string{"ollama list"}, Commands: []string{"ollama rm <model>"}, Tool: "ollama", Restore: "ollama pull <model>"},
	{ID: "huggingface", Category: catAI, Title: "Hugging Face model cache", Paths: []string{"~/.cache/huggingface"}, Safety: model.Review,
		Reasons: []string{"Model weights download again on the next use."},
		Risks:   []string{"Gated models need your token to download again."},
		Verify:  []string{"huggingface-cli scan-cache"}, Commands: []string{"huggingface-cli delete-cache"}, Tool: "huggingface-cli", Restore: "The next load downloads the model."},
	{ID: "lmstudio", Category: catAI, Title: "LM Studio models", Paths: []string{"~/.lmstudio/models", "~/.cache/lm-studio/models"}, Safety: model.Review,
		Reasons: []string{"Local models are many gigabytes each."}, Verify: []string{"ls {p}"}, Commands: []string{"Delete models in LM Studio > My Models."}, Restore: "Download them again in LM Studio."},
	{ID: "claude-transcripts", Category: catAI, Title: "Claude Code session transcripts", Paths: []string{"~/.claude/projects"}, Safety: model.Review,
		Reasons: []string{"Each session keeps a full transcript."},
		Risks:   []string{"claude --resume and memory of old sessions need these files."},
		Verify:  []string{"ls -lt {p} | head"}, Commands: []string{"find {p} -name '*.jsonl' -mtime +90 -print"}, Restore: "None."},
	{ID: "codex-tmp", Category: catAI, Title: "Codex temporary files", Paths: []string{"~/.codex/.tmp", "~/.codex/cache"}, Safety: model.Safe,
		Reasons: []string{"Codex makes these again."}, Quit: []string{"codex"}, Verify: []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "Nothing to restore."},
	{ID: "codex-sessions", Category: catAI, Title: "Codex session history", Paths: []string{"~/.codex/sessions"}, Safety: model.Review,
		Reasons: []string{"Each Codex run keeps a log."}, Risks: []string{"codex resume needs these files."},
		Verify: []string{"ls {p}"}, Commands: []string{"find {p} -type f -mtime +90 -print"}, Restore: "None."},

	// Browsers. Chromium keeps the HTTP cache in ~/Library/Caches, which the generic rule covers.
	{ID: "chrome-ai-model", Category: catBrowser, Title: "Chrome on-device AI model", Paths: []string{"~/Library/Application Support/Google/Chrome/OptGuideOnDeviceModel"}, Safety: model.Review,
		Reasons: []string{"Chrome downloads a Gemini Nano model for its built-in AI features."},
		Risks:   []string{"Chrome downloads it again unless you turn off chrome://settings/ai (On-device AI)."},
		Quit:    []string{"Google Chrome"}, Verify: []string{"ls -lh {p}/*"}, Commands: []string{"{rm}"}, Restore: "Chrome downloads it again when the feature is on."},

	// Apps that own their data.
	{ID: "whatsapp", Category: catUser, Title: "WhatsApp messages and media", Paths: []string{"~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared"}, Safety: model.Keep,
		Reasons: []string{"This is your chat history and media."},
		Risks:   []string{"Deleting files here corrupts the WhatsApp database."},
		Verify:  []string{"du -sh {p}/*"}, Commands: []string{"Use WhatsApp > Settings > Storage and data > Manage storage."}},
	{ID: "telegram", Category: catUser, Title: "Telegram media cache", Paths: []string{"~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram"}, Safety: model.Keep,
		Reasons: []string{"Telegram keeps downloaded media."}, Commands: []string{"Use Telegram > Settings > Data and Storage > Storage Usage."}},
	{ID: "ios-backups", Category: catUser, Title: "iPhone and iPad backups", Paths: []string{"~/Library/Application Support/MobileSync/Backup"}, Safety: model.Risky,
		Reasons: []string{"Finder keeps a full device backup here."},
		Risks:   []string{"This can be the only backup of a device. Delete a backup only when iCloud or a newer backup has the same data."},
		Verify:  []string{"ls -lt {p}"}, Commands: []string{"Finder > select the device > Manage Backups."}},
	{ID: "mail-downloads", Category: catUser, Title: "Mail attachment downloads", Paths: []string{"~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"}, Safety: model.Safe,
		Reasons: []string{"These are copies of attachments that you opened. The originals stay in Mail."},
		Verify:  []string{"ls {p}"}, Commands: []string{"{rm}"}, Restore: "Open the attachment in Mail again."},
	{ID: "messages-attachments", Category: catUser, Title: "Messages attachments", Paths: []string{"~/Library/Messages/Attachments"}, Safety: model.Keep,
		Reasons:  []string{"These are photos and files from your conversations."},
		Commands: []string{"Use System Settings > General > Storage > Messages."}},
	{ID: "photos-library", Category: catUser, Title: "Photos library", Paths: []string{"~/Pictures/*.photoslibrary"}, PerPath: true, Safety: model.Keep,
		Reasons:  []string{"This is your photo library."},
		Risks:    []string{"Never delete files inside it. Turn on Photos > Settings > iCloud > Optimize Mac Storage to free space."},
		Commands: []string{"Use Photos > Settings > iCloud > Optimize Mac Storage."}},
	{ID: "trash", Category: catUser, Title: "Trash", Paths: []string{"~/.Trash"}, Safety: model.Review,
		Reasons: []string{"Files in the Trash still use disk space."},
		Risks:   []string{"Emptying the Trash is permanent. Look at what is inside first."},
		Verify:  []string{"ls -la {p}"}, Commands: []string{"Finder > Empty Trash"}},

	// System.
	{ID: "user-logs", Category: catSystem, Title: "Your application logs", Paths: []string{"~/Library/Logs"}, Safety: model.Safe,
		Reasons: []string{"Apps write new logs as they run."},
		Risks:   []string{"You lose old crash reports that a support team can ask for."},
		Verify:  []string{"du -sh {p}/*"}, Commands: []string{"find {p} -type f -mtime +30 -print"}, Restore: "Nothing to restore."},
	{ID: "sleepimage", Category: catSystem, Title: "Sleep image", Paths: []string{"/private/var/vm/sleepimage"}, Safety: model.Keep,
		Reasons:  []string{"macOS writes RAM here during hibernation. macOS makes it again after a delete."},
		Commands: []string{"Do not delete. macOS manages this file."}},
	{ID: "swapfiles", Category: catSystem, Title: "Swap files", Paths: []string{"/private/var/vm/swapfile*"}, Safety: model.Keep,
		Reasons:  []string{"macOS uses these as virtual memory. A restart releases them."},
		Commands: []string{"Do not delete. Restart the Mac to release swap."}},
	{ID: "clt", Category: catSystem, Title: "Command Line Tools", Paths: []string{"/Library/Developer/CommandLineTools"}, Safety: model.Keep,
		Reasons:  []string{"git, clang, make and python3 come from here when Xcode is not the selected developer folder."},
		Commands: []string{"Do not delete."}},
}
