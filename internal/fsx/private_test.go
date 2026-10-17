package fsx

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A clone made with cp -c shares every block, so deleting either copy frees almost nothing.
func TestPrivateSizeSeesClones(t *testing.T) {
	dir := t.TempDir()
	a, b, c := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	data := make([]byte, 8<<20)
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(a, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/cp", "-c", a, b).CombinedOutput(); err != nil {
		t.Skipf("cp -c not supported here: %s", out)
	}
	if err := os.WriteFile(c, data, 0o644); err != nil {
		t.Fatal(err)
	}
	pa, ok := PrivateSize(a)
	if !ok {
		t.Skip("volume does not report private size")
	}
	pc, _ := PrivateSize(c)
	if pa > 1<<20 {
		t.Errorf("a clone pair: private size of a = %d, want about 0", pa)
	}
	if pc < 7<<20 {
		t.Errorf("an independent copy: private size = %d, want about 8 MB", pc)
	}
	u := Measure(dir)
	if u.Cloned < 15<<20 {
		t.Errorf("Measure.Cloned = %d, want about 16 MB shared between a and b", u.Cloned)
	}
	if u.Freeable > 10<<20 || u.Freeable < 7<<20 {
		t.Errorf("Measure.Freeable = %d, want about 8 MB (only c frees space)", u.Freeable)
	}
}
