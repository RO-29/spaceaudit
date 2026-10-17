package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RO-29/spaceaudit/internal/model"
)

func TestBrowserProfilesAndExtensions(t *testing.T) {
	e, home := testEnv(t)
	ch := filepath.Join(home, "Library/Application Support/Google/Chrome")
	write(t, filepath.Join(ch, "Local State"), 0)
	os.WriteFile(filepath.Join(ch, "Local State"), []byte(`{"profile":{"info_cache":{"Default":{"name":"Work","user_name":"a@b.c"},"Profile 1":{"name":"Home"}}}}`), 0o644)
	write(t, filepath.Join(ch, "Default/IndexedDB/x"), 2<<20)
	ext := filepath.Join(ch, "Profile 1/Extensions/abc/1.0")
	write(t, filepath.Join(ext, "big.bin"), 3<<20)
	os.WriteFile(filepath.Join(ext, "manifest.json"), []byte(`{"name":"__MSG_appName__","default_locale":"en"}`), 0o644)
	write(t, filepath.Join(ext, "_locales/en/messages.json"), 0)
	os.WriteFile(filepath.Join(ext, "_locales/en/messages.json"), []byte(`{"appName":{"message":"Ad Blocker"}}`), 0o644)
	write(t, filepath.Join(home, "Library/Caches/Google/Chrome/Default/Cache/data"), 1<<20)
	var chrome *model.InvItem
	for _, it := range e.browserInventory().Items {
		if it.Name == "Google Chrome" {
			chrome = &it
		}
	}
	if chrome == nil {
		t.Fatal("Chrome was not detected")
	}
	names := ""
	for _, g := range chrome.Groups {
		names += g.Name + "|"
		for _, p := range g.Parts {
			if p.Name == "Site databases (IndexedDB)" && p.Safety != model.Risky {
				t.Error("IndexedDB must be risky: it can hold offline work")
			}
			if p.Name == "Extensions" && (len(p.Top) == 0 || !strings.Contains(p.Top[0], "Ad Blocker")) {
				t.Errorf("extension name not read from the manifest: %v", p.Top)
			}
		}
	}
	if !strings.Contains(names, "Work (a@b.c)") || !strings.Contains(names, "Home") {
		t.Errorf("profile names = %q", names)
	}
}

func TestAIFolderLabels(t *testing.T) {
	e, home := testEnv(t)
	write(t, filepath.Join(home, ".codex/sessions/2026/a.jsonl"), 2<<20)
	write(t, filepath.Join(home, ".codex/.tmp/x"), 2<<20)
	write(t, filepath.Join(home, ".claude/projects/p/memory/m.md"), 2<<20)
	write(t, filepath.Join(home, ".claude/mystery/x"), 2<<20)
	got := map[string]model.Safety{}
	for _, it := range e.aiInventory().Items {
		for _, p := range it.Parts {
			got[filepath.Base(p.Path)] = p.Safety
		}
	}
	for dir, want := range map[string]model.Safety{"sessions": model.Review, ".tmp": model.Safe, "projects": model.Review, "mystery": model.Keep} {
		if got[dir] != want {
			t.Errorf("%s labelled %q, want %q (an unknown folder must be keep, history must never be safe)", dir, got[dir], want)
		}
	}
}

func TestDownloadsByType(t *testing.T) {
	e, home := testEnv(t)
	d := filepath.Join(home, "Downloads")
	write(t, filepath.Join(d, "Tool.dmg"), 2<<20)
	write(t, filepath.Join(d, "movie.MKV"), 3<<20)
	write(t, filepath.Join(d, "old.pdf"), 1<<20)
	old := time.Now().Add(-200 * 24 * time.Hour)
	os.Chtimes(filepath.Join(d, "old.pdf"), old, old)
	write(t, filepath.Join(d, "Thing.app/Contents/x"), 1<<20)
	kinds := map[string]model.InvItem{}
	for _, it := range e.downloadsInventory().Items {
		kinds[it.Name] = it
	}
	if kinds["Installers and disk images"].Kind != "2 items" {
		t.Errorf("installers = %+v (the .app bundle counts as an installer)", kinds["Installers and disk images"])
	}
	if _, ok := kinds["Videos"]; !ok {
		t.Error("an upper-case .MKV must count as a video")
	}
	if p := kinds["Documents"].Parts; len(p) != 1 || p[0].Name != "Older than 6 months" {
		t.Errorf("documents age = %+v", p)
	}
}
