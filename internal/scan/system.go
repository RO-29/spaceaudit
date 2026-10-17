package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/probe"
)

// volume reads the data volume numbers with df.
func volume(home string) model.Volume {
	for _, m := range []string{"/System/Volumes/Data", home, "/"} {
		out, err := probe.Run(10*time.Second, "df", "-k", m)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) < 2 {
			continue
		}
		f := strings.Fields(lines[len(lines)-1])
		if len(f) < 4 {
			continue
		}
		n := func(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v * 1024 }
		return model.Volume{Mount: m, Total: n(f[1]), Used: n(f[2]), Available: n(f[3])}
	}
	return model.Volume{}
}

// mdTime reads one Spotlight date attribute. Spotlight can be off, so a zero time means unknown.
func mdTime(attr, p string) time.Time {
	out, err := probe.Run(10*time.Second, "mdls", "-raw", "-name", attr, p)
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(out))
	if err != nil {
		return time.Time{}
	}
	return t
}

func mdString(attr, p string) string {
	out, err := probe.Run(10*time.Second, "mdls", "-raw", "-name", attr, p)
	if err != nil || strings.TrimSpace(out) == "(null)" {
		return ""
	}
	return strings.TrimSpace(out)
}

// apps reports large applications that Spotlight says you have not opened for a long time.
func (e *Env) apps() []model.Finding {
	var paths []string
	for _, dir := range []string{"/Applications", filepath.Join(e.Home, "Applications")} {
		m, _ := filepath.Glob(filepath.Join(dir, "*.app"))
		paths = append(paths, m...)
	}
	xsel, _ := probe.Run(5*time.Second, "xcode-select", "-p")
	xsel = strings.TrimSpace(xsel)
	if xsel != "" {
		note := ""
		if strings.HasPrefix(xsel, "/Applications/Xcode") {
			note = "git, clang and /usr/bin/python3 run from Xcode.app. Do not remove Xcode before you switch to the Command Line Tools."
		}
		e.fact("xcode-select", xsel, note)
	}
	return parallel(e.Opt.Jobs, len(paths), func(i int) *model.Finding {
		p := paths[i]
		u := fsx.Measure(p)
		if u.Bytes < 200<<20 || u.Bytes < e.Opt.MinBytes {
			return nil
		}
		name := strings.TrimSuffix(filepath.Base(p), ".app")
		if len(e.UsersOf(p)) > 0 {
			return nil // it runs now, so it is in use
		}
		used, source := mdTime("kMDItemLastUsedDate", p), "Spotlight kMDItemLastUsedDate"
		if d := e.appDataTime(p, name); d.After(used) {
			used, source = d, "newest change in the app's preferences, container or cache"
		}
		idle := used.IsZero() || e.Now.Sub(used) > 90*24*time.Hour
		isXcode := strings.HasPrefix(name, "Xcode")
		if !idle && !isXcode && !strings.HasPrefix(name, "Install macOS") {
			return nil
		}
		f := model.Finding{
			ID: id("app", p), Rule: "app", Category: catApps, Title: name, Paths: []string{p}, Bytes: u.Bytes, Files: u.Files,
			Safety: model.Review, Confidence: "medium", Modified: u.Newest, LastUsed: used, UsedSource: source,
			Verify:   []string{"mdls -name kMDItemLastUsedDate " + e.Q(p)},
			Commands: []string{"Quit the app, then drag it to the Trash, or run its own uninstaller if it has one."},
			Restore:  "Install it again from the App Store, the vendor site or brew install --cask.",
		}
		if used.IsZero() {
			f.Reasons = append(f.Reasons, "Neither Spotlight nor the app's data folders show that you opened it.")
			f.Confidence = "low"
		} else {
			f.Reasons = append(f.Reasons, "Last use "+Ago(e.Now, used)+" (source: "+source+").")
		}
		f.Risks = append(f.Risks, "Settings and data stay in ~/Library after you remove an app. Some apps also install helpers or system extensions that only their uninstaller removes.")
		if st, err := os.Stat(p); err == nil && !writable(st) {
			f.NeedsSudo = true
			f.Risks = append(f.Risks, "Another user or root owns the app, so the Trash asks for an admin password.")
		}
		if strings.HasPrefix(name, "Install macOS") {
			f.Safety = model.Safe
			f.Reasons = append(f.Reasons, "This is a macOS installer. The App Store downloads it again.")
		}
		if isXcode {
			f.Safety = model.Risky
			if strings.HasPrefix(xsel, p) {
				f.Blockers = append(f.Blockers, "xcode-select points into this app. git, clang and /usr/bin/python3 stop working when it goes.")
				rmx, _ := e.del(delAuto, p, true)
				f.Commands = []string{"sudo xcode-select -s /Library/Developer/CommandLineTools", rmx}
				if !fsx.Exists("/Library/Developer/CommandLineTools") {
					f.Commands = append([]string{"xcode-select --install"}, f.Commands...)
				}
			}
			f.Risks = append(f.Risks, "iOS and macOS app builds, simulators and xcodebuild need Xcode.")
		}
		if users := e.UsersOf(p); len(users) > 0 {
			f.Blockers = append(f.Blockers, "Running now: "+strings.Join(limit(users, 4), ", ")+".")
		}
		e.annotate(&f, u)
		return &f
	})
}

// appDataTime is the newest change in the folders an app writes when it runs.
// Spotlight can be off or read-only, so this is the second signal for "last used".
func (e *Env) appDataTime(app, name string) time.Time {
	id, _ := probe.Run(5*time.Second, "plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(app, "Contents/Info.plist"))
	id = strings.TrimSpace(id)
	var newest time.Time
	var cands []string
	if id != "" {
		for _, d := range []string{"Library/Preferences/" + id + ".plist", "Library/Containers/" + id + "/Data/Library/Preferences", "Library/Caches/" + id, "Library/Application Support/" + id, "Library/HTTPStorages/" + id, "Library/Saved Application State/" + id + ".savedState"} {
			cands = append(cands, filepath.Join(e.Home, d))
		}
	}
	cands = append(cands, filepath.Join(e.Home, "Library/Application Support", name))
	for _, c := range cands {
		if fsx.Blocked(c) != "" {
			continue // another app's container: reading it can show a privacy prompt
		}
		if st, err := os.Stat(c); err == nil && st.ModTime().After(newest) && st.ModTime().Before(e.Now.Add(time.Hour)) {
			newest = st.ModTime()
		}
	}
	return newest
}

func writable(st os.FileInfo) bool {
	return st.Mode().Perm()&0o200 != 0 && ownerIsMe(st)
}

// downloads reports large files in Downloads, with age, origin and whether an installer is already installed.
func (e *Env) downloads() []model.Finding {
	dir := filepath.Join(e.Home, "Downloads")
	if why := fsx.Blocked(dir); why != "" {
		e.skip(dir, why)
		return nil
	}
	var files []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && p != dir && strings.Count(strings.TrimPrefix(p, dir), "/") > 2 {
			return filepath.SkipDir
		}
		if d.IsDir() {
			for _, ext := range bundleExt {
				if strings.HasSuffix(d.Name(), ext) {
					return filepath.SkipDir // a file inside a bundle is part of it, never a separate delete
				}
			}
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil && info.Size() >= 100<<20 {
				files = append(files, p)
			}
		}
		return nil
	})
	installed := installedApps()
	return parallel(e.Opt.Jobs, len(files), func(i int) *model.Finding {
		p := files[i]
		u := fsx.Measure(p)
		if u.Bytes < e.Opt.MinBytes {
			return nil
		}
		used := mdTime("kMDItemLastUsedDate", p)
		added := mdTime("kMDItemDateAdded", p)
		from := mdString("kMDItemWhereFroms", p)
		f := model.Finding{
			ID: id("download", p), Rule: "download", Category: catUser, Title: filepath.Base(p), Paths: []string{p},
			Bytes: u.Bytes, Files: 1, Safety: model.Review, Confidence: "medium", Modified: u.Newest, LastUsed: used, UsedSource: "Spotlight kMDItemLastUsedDate",
			Verify: []string{"ls -lh " + e.Q(p)}, Commands: []string{e.delOnly(p)}, Restore: "Download it again from its source.", Allocated: u.Bytes,
		}
		if t := Trash(p); t != "" {
			f.Alternate = []string{t}
		}
		if !added.IsZero() {
			f.Reasons = append(f.Reasons, "Downloaded "+Ago(e.Now, added)+".")
		}
		if !used.IsZero() {
			f.Reasons = append(f.Reasons, "Last opened "+Ago(e.Now, used)+".")
		} else {
			f.Reasons = append(f.Reasons, "Spotlight has no record that you opened it.")
		}
		if from != "" {
			f.Reasons = append(f.Reasons, "Source: "+squash(from)+".")
		}
		ext := strings.ToLower(filepath.Ext(p))
		switch ext {
		case ".dmg", ".pkg":
			if app := matchInstalled(filepath.Base(p), installed); app != "" {
				f.Reasons = append(f.Reasons, "The name matches the installed "+app+", so this can be its installer. Check that it is not a disk image of your own files.")
			} else {
				f.Reasons = append(f.Reasons, "A disk image or package. It can be an installer, or an image of your own files.")
			}
		case ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar":
			base := strings.TrimSuffix(p, ext)
			base = strings.TrimSuffix(base, ".tar")
			if fsx.Exists(base) {
				f.Reasons = append(f.Reasons, "A folder with the same name is next to it, so it looks already extracted.")
			}
			f.Risks = append(f.Risks, "An archive can be the only copy of the files inside it. Open it before you delete it.")
		default:
			f.Risks = append(f.Risks, "This is a personal file. Only you can tell whether you still need it.")
		}
		return &f
	})
}

func squash(s string) string {
	s = strings.NewReplacer("(", "", ")", "", "\"", "", "\n", " ").Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 140 {
		s = s[:140] + "..."
	}
	return s
}

func installedApps() []string {
	var names []string
	for _, dir := range []string{"/Applications", filepath.Join(os.Getenv("HOME"), "Applications")} {
		m, _ := filepath.Glob(filepath.Join(dir, "*.app"))
		for _, p := range m {
			names = append(names, strings.TrimSuffix(filepath.Base(p), ".app"))
		}
	}
	return names
}

var wordRe = regexp.MustCompile(`[A-Za-z]{3,}`)

// matchInstalled needs the whole app name (spaces ignored) in the file name, not only the first word.
func matchInstalled(file string, apps []string) string {
	f := strings.ToLower(strings.ReplaceAll(file, " ", ""))
	for _, a := range apps {
		n := strings.ToLower(strings.ReplaceAll(a, " ", ""))
		if len(n) >= 4 && strings.Contains(f, n) {
			return a + ".app"
		}
	}
	return ""
}

// largeFiles lists big files and bundles that no other finding explains.
func (e *Env) largeFiles(ls []large, bundles []string, covered []string) []model.Finding {
	for _, b := range bundles {
		u := e.measure(b)
		if u.Bytes >= e.Opt.LargeBytes {
			ls = append(ls, large{b, u.Bytes, u.Newest, u.Bytes})
		}
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].bytes > ls[j].bytes })
	var out []model.Finding
	for _, l := range ls {
		if isClaimed(l.path, covered) || fsx.Under(l.path, filepath.Join(e.Home, "Downloads")) {
			continue
		}
		cloned := int64(0)
		if priv, ok := fsx.PrivateSize(l.path); ok && priv < l.bytes {
			cloned, l.bytes = l.bytes-priv, priv
		}
		f := model.Finding{
			ID: id("large", l.path), Rule: "large-item", Category: catUser, Title: e.Pretty(l.path), Paths: []string{l.path},
			Bytes: l.bytes, Allocated: l.bytes + cloned, Files: 1, Safety: model.Review, Confidence: "low", Modified: l.mod,
			Reasons:  []string{"This single item is large. No rule knows what it is, so only you can judge it.", "Last changed " + Ago(e.Now, l.mod) + "."},
			Risks:    []string{"It can be the only copy of your data. Move it to an external disk or cloud storage if you are not sure."},
			Verify:   []string{"ls -lh " + e.Q(l.path), "file " + e.Q(l.path)},
			Commands: []string{"Move it to an external disk or cloud storage, then delete the local copy."},
		}
		if cloned > 0 {
			f.Notes = append(f.Notes, fsx.Human(cloned)+" is shared with an APFS clone, so a delete frees only the size shown.")
		}
		if strings.HasSuffix(l.path, ".photoslibrary") {
			f.Safety = model.Keep
			f.Commands = []string{"Use Photos > Settings > iCloud > Optimize Mac Storage."}
		}
		if strings.HasSuffix(l.path, ".raw") || strings.HasSuffix(l.path, ".img") || strings.HasSuffix(l.path, ".qcow2") {
			f.Reasons = append(f.Reasons, "This looks like a virtual machine disk. Its size is the space it uses, not its maximum size.")
			f.Risks = append(f.Risks, "Deleting a VM disk deletes everything in that VM. Use the VM tool to remove or shrink it.")
			f.Safety = model.Risky
		}
		if users := e.UsersOf(l.path); len(users) > 0 {
			f.Blockers = append(f.Blockers, "Open now by "+strings.Join(limit(users, 3), ", ")+".")
		}
		out = append(out, f)
		if len(out) >= 40 {
			break
		}
	}
	return out
}

var vmDisks = []struct{ name, glob, hint string }{
	{"Docker Desktop", "~/Library/Containers/com.docker.docker/Data/vms/*/data/Docker.raw", "Docker Desktop > Settings > Resources > Disk image size, or Troubleshoot > Clean / Purge data"},
	{"OrbStack", "~/Library/Group Containers/HUAQ24HBR6.dev.orbstack/data/data.img*", "OrbStack frees space inside the image by itself after a prune"},
	{"Colima", "~/.colima/_lima/*/diffdisk", "since v0.9 container data is on a separate disk: colima delete keeps it, colima delete --data removes it. Space returns after a restart or colima ssh -- sudo fstrim -a"},
	{"Colima data", "~/.colima/_lima/_disks/*/datadisk", "colima delete --data removes it with every image and volume"},
	{"Rancher Desktop", "~/Library/Application Support/rancher-desktop/lima/*/diffdisk", "Rancher Desktop > Troubleshooting > Factory Reset"},
	{"Podman", "~/.local/share/containers/podman/machine/*/*.raw", "podman machine rm"},
	{"UTM", "~/Library/Containers/com.utmapp.UTM/Data/Documents/*.utm", "Remove the VM in UTM"},
	{"Parallels", "~/Parallels/*.pvm", "Remove the VM in Parallels Control Center"},
}

var dfLine = regexp.MustCompile(`^(\S+(?: \S+)?)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)`)

// containers measures each container runtime disk and, when a daemon answers, what a prune can free.
func (e *Env) containers() []model.Finding {
	var out []model.Finding
	for _, v := range vmDisks {
		for _, p := range fsx.Glob(v.glob, e.Home) {
			u := fsx.Measure(p)
			if u.Bytes < e.Opt.MinBytes {
				continue
			}
			f := model.Finding{
				ID: id("vm", p), Rule: "vm-disk", Category: catVM, Title: v.name + " disk image", Paths: []string{p}, Bytes: u.Bytes, Files: u.Files,
				Safety: model.Keep, Confidence: "high", Modified: u.Newest,
				Reasons:  []string{"All images, containers and volumes of " + v.name + " live inside this one file.", "The size is the space it uses now. The file can show a larger apparent size because it is sparse."},
				Risks:    []string{"Never delete this file by hand. It deletes every container, image and volume, with any database data inside them."},
				Verify:   []string{"docker system df -v"},
				Commands: []string{"Prune inside the runtime (see the Docker findings). " + v.hint + "."},
			}
			out = append(out, f)
		}
	}
	if e.Opt.NoDocker || !haveTool("docker") {
		return out
	}
	df, err := probe.Run(25*time.Second, "docker", "system", "df")
	if err != nil {
		e.fact("docker", "daemon not reachable", "Start Docker, OrbStack or Colima and scan again to see what a prune frees.")
		return out
	}
	ctx, _ := probe.Run(5*time.Second, "docker", "context", "ls", "--format", "{{if .Current}}{{.Name}}{{end}}")
	e.fact("docker", "context "+strings.TrimSpace(ctx), "")
	type row struct {
		total, active int
		size, recl    string
	}
	rows := map[string]row{}
	for _, line := range strings.Split(df, "\n")[1:] {
		m := dfLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		t, _ := strconv.Atoi(m[2])
		a, _ := strconv.Atoi(m[3])
		rows[m[1]] = row{t, a, m[4], m[5]}
	}
	add := func(key, title string, s model.Safety, cmd, reason, risk, restore string) {
		r, ok := rows[key]
		if !ok {
			return
		}
		b := parseSize(r.recl)
		if b < e.Opt.MinBytes {
			return
		}
		out = append(out, model.Finding{
			ID: id("docker", key), Rule: "docker-" + strings.ToLower(strings.ReplaceAll(key, " ", "-")), Category: catVM, Title: title,
			Bytes: b, Safety: s, Confidence: "medium",
			Reasons: []string{reason, "docker system df: " + strconv.Itoa(r.total) + " total, " + strconv.Itoa(r.active) + " in use, " + r.size + " size, " + r.recl + " reclaimable."},
			Risks:   []string{risk, "The VM disk file can keep its size until the runtime trims it. Check free space after the prune."},
			Verify:  []string{"docker system df -v"}, Commands: []string{cmd}, Restore: restore,
		})
	}
	add("Build Cache", "Docker build cache", model.Safe, "docker builder prune", "BuildKit layer cache from old builds.", "The next build of each image is slower.", "The next build fills it again.")
	add("Images", "Docker images that no container uses", model.Review, "docker image prune -a", "Images with no container, including old tags.", "Images that you built and did not push are lost. Pulled images download again.", "docker pull or docker build")
	add("Containers", "Stopped Docker containers", model.Review, "docker container prune", "Containers that are not running.", "Files written inside a stopped container are lost.", "docker run makes new containers.")
	add("Local Volumes", "Docker volumes that no container uses", model.Risky, "docker volume ls -f dangling=true   # then: docker volume rm NAME", "Volumes are where containers keep databases and other data.", "A volume can hold the only copy of a local database. Inspect each one before you remove it.", "None.")
	return out
}

var sizeRe = regexp.MustCompile(`^([\d.]+)\s*([kKMGT]?B)`)

func parseSize(s string) int64 {
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	mult := map[string]float64{"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m[2]]
	return int64(v * mult)
}

var brewFree = regexp.MustCompile(`free approximately ([\d.]+\s*[KMGT]?B)`)

// homebrew asks brew what cleanup would remove, without removing it.
func (e *Env) homebrew() []model.Finding {
	if !haveTool("brew") {
		return nil
	}
	out, err := probe.Run(120*time.Second, "brew", "cleanup", "-n")
	if err != nil && out == "" {
		return nil
	}
	m := brewFree.FindStringSubmatch(out)
	if m == nil {
		return nil
	}
	b := parseSize(strings.ReplaceAll(m[1], " ", ""))
	if b < e.Opt.MinBytes {
		return nil
	}
	cache, _ := probe.Run(10*time.Second, "brew", "--cache")
	return []model.Finding{{
		ID: id("brew"), Rule: "brew-cleanup", Category: catPkg, Title: "Homebrew old versions and downloads", Paths: []string{strings.TrimSpace(cache)},
		Bytes: b, Safety: model.Safe, Confidence: "high",
		Reasons:  []string{"brew cleanup -n reports that it can free about " + m[1] + ": old formula versions and cached downloads.", "A cask stays in Caskroom when you drag its app to the Trash. brew cleanup does not remove it: run brew list --cask, then brew uninstall --cask NAME."},
		Risks:    []string{"You cannot roll back to a removed old version without a new download.", "A formula that you pinned with brew pin is kept."},
		Verify:   []string{"brew cleanup -n", "brew autoremove --dry-run"},
		Commands: []string{"brew cleanup --prune=all"},
		Restore:  "brew install FORMULA@VERSION when a versioned formula exists.",
	}}
}

// systemFacts checks the things that make a delete free less space than expected.
func (e *Env) systemFacts() []model.Finding {
	var out []model.Finding
	if snaps, err := probe.Run(20*time.Second, "tmutil", "listlocalsnapshots", "/"); err == nil {
		n := strings.Count(snaps, "com.apple.TimeMachine.")
		upd := strings.Count(snaps, "com.apple.os.update-")
		e.fact("local snapshots", strconv.Itoa(n)+" Time Machine, "+strconv.Itoa(upd)+" macOS update", "Deleted data stays on disk while a snapshot holds it. macOS update snapshots are part of the update and need no action; tmutil does not remove them.")
		if n > 0 {
			out = append(out, model.Finding{
				ID: id("snapshots"), Rule: "apfs-snapshots", Category: catSystem, Title: strconv.Itoa(n) + " local Time Machine snapshots", Safety: model.Review, Confidence: "medium",
				Reasons:  []string{"Time Machine keeps local snapshots. They hold the blocks of deleted files, and macOS removes them by itself after about 24 hours or when space is low."},
				Risks:    []string{"After a delete, you can lose the local restore point that Time Machine made. Your Time Machine disk backups stay."},
				Verify:   []string{"tmutil listlocalsnapshots /"},
				Commands: []string{"tmutil thinlocalsnapshots / 999999999999 4   # or remove all: sudo tmutil deletelocalsnapshots /"}, NeedsSudo: true,
				Notes: []string{"The scan cannot measure snapshot size. macOS also removes them by itself when space is low."},
			})
		}
	}
	out = append(out, e.deletedOpen()...)
	out = append(out, e.simRuntimes()...)
	tmp := os.TempDir()
	if u := fsx.Measure(tmp); u.Bytes >= e.Opt.MinBytes {
		out = append(out, model.Finding{
			ID: id("tmp"), Rule: "user-temp", Category: catSystem, Title: "Your temporary folder", Paths: []string{tmp}, Bytes: u.Bytes, Files: u.Files,
			Safety: model.Review, Confidence: "medium", Modified: u.Newest,
			Reasons: []string{"Programs write temporary files here. macOS removes old ones by itself and at restart."},
			Risks:   []string{"Running programs keep live files here. A manual delete can crash them."},
			Verify:  []string{"du -sh " + shq(tmp) + "* | sort -h | tail"}, Commands: []string{"Restart the Mac. Do not delete this folder by hand."},
		})
	}
	return out
}
