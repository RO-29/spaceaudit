package report

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/RO-29/spaceaudit/internal/model"
)

func sample() model.Report {
	return model.Report{Version: "t", Findings: []model.Finding{{
		Title: "x</script><b>", Safety: model.Safe, Bytes: 1 << 20, Paths: []string{"/a"},
		Commands: []string{"rm -rf -- '/a'", "line1\nline2"}, Verify: []string{"ls '/a'"}, Reasons: []string{}, Risks: []string{}, Blockers: []string{},
	}}}
}

// Running the review script must do nothing: every command line is a comment.
func TestScriptRunsNothing(t *testing.T) {
	var b bytes.Buffer
	Script(&b, sample())
	for i, line := range strings.Split(b.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "echo 'This file runs nothing") {
			continue
		}
		t.Errorf("line %d is not a comment: %q", i+1, line)
	}
	out, err := exec.Command("/bin/sh", "-c", b.String()).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "runs nothing") {
		t.Fatalf("script run: %v %s", err, out)
	}
}

func TestHTMLEscapesData(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, sample()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if strings.Contains(s, "x</script>") {
		t.Fatal("a finding title can close the data script tag")
	}
	if strings.Contains(s, "__DATA__") {
		t.Fatal("data was not injected")
	}
}
