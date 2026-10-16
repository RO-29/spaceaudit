package report

import (
	_ "embed"
	"encoding/json"
	"io"
	"strings"

	"github.com/RO-29/spaceaudit/internal/model"
)

//go:embed report.html
var page string

// HTML writes a self-contained report page. The data is inline, so the file works offline.
func HTML(w io.Writer, r model.Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	data := strings.ReplaceAll(string(b), "</", `<\/`)
	_, err = io.WriteString(w, strings.Replace(page, "__DATA__", data, 1))
	return err
}
