package report

import (
	"encoding/json"
	"io"

	"github.com/skromesch/agent-audit/internal/model"
)

func WriteJSON(result *model.ScanResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
