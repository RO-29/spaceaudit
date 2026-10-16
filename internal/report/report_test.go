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

// The overwrite guard reads the first 4 KB, so every format must name spaceaudit early.
func TestEveryFormatIsMarkedEarly(t *testing.T) {
	for name, fn := range map[string]func(*bytes.Buffer){
		"html": func(b *bytes.Buffer) { _ = HTML(b, sample()) }, "md": func(b *bytes.Buffer) { Markdown(b, sample()) },
		"script": func(b *bytes.Buffer) { Script(b, sample()) }, "json": func(b *bytes.Buffer) { r := sample(); r.Tool = "spaceaudit"; _ = JSON(b, r) },
	} {
		var b bytes.Buffer
		fn(&b)
		head := b.String()
		if len(head) > 4096 {
			head = head[:4096]
		}
		if !strings.Contains(head, "spaceaudit") {
			t.Errorf("%s output does not name spaceaudit in its first 4 KB", name)
		}
	}
}

// A plan may run only echo and the findings' own verify lines; every cleanup command is a comment.
func TestPlanRunsOnlyVerify(t *testing.T) {
	r := sample()
	var b bytes.Buffer
	Plan(&b, r)
	allowed := map[string]bool{}
	for _, f := range r.Findings {
		for _, v := range f.Verify {
			allowed[v] = true
		}
	}
	for i, line := range strings.Split(b.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "echo '") || allowed[line] {
			continue
		}
		t.Errorf("plan line %d runs something that is not a verify command: %q", i+1, line)
	}
	if !strings.Contains(b.String(), "# rm -rf -- '/a'") {
		t.Error("the cleanup command must be in the plan as a comment")
	}
}
