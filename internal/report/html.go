package report

import (
	"html/template"
	"io"
	"time"

	"github.com/skromesch/agent-audit/internal/model"
)

var htmlTmpl = template.Must(
	template.New("report").Funcs(template.FuncMap{
		"severityClass": func(s model.Severity) string {
			switch s {
			case model.SeverityCritical:
				return "critical"
			case model.SeverityWarning:
				return "warning"
			default:
				return "info"
			}
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
	}).Parse(htmlTemplate),
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>agent-audit Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1a1a1a}
h1{border-bottom:2px solid #333;padding-bottom:8px}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 12px;border:1px solid #ddd}
th{background:#f5f5f5}
.critical{color:#c00;font-weight:bold}
.warning{color:#e67e00;font-weight:bold}
.info{color:#0066cc}
code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:.9em}
</style>
</head>
<body>
<h1>agent-audit Report</h1>
<p><strong>Root:</strong> <code>{{.Root}}</code><br>
<strong>Scanned:</strong> {{formatTime .ScannedAt}}</p>

<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>Agents detected</td><td>{{len .Agents}}</td></tr>
<tr><td>MCP servers</td><td>{{len .MCPServers}}</td></tr>
<tr><td>Skills</td><td>{{len .Skills}}</td></tr>
<tr><td>Critical findings</td><td class="critical">{{.CriticalCount}}</td></tr>
<tr><td>Warning findings</td><td class="warning">{{.WarningCount}}</td></tr>
</table>

<h2>Security Findings</h2>
<table>
<tr><th>Severity</th><th>Tool</th><th>Path</th><th>Description</th></tr>
{{range .Findings}}
<tr>
<td class="{{severityClass .Severity}}">{{.Severity}}</td>
<td>{{.Tool}}</td>
<td><code>{{.Path}}</code></td>
<td>{{.Description}}</td>
</tr>
{{end}}
</table>

<h2>MCP Servers</h2>
<table>
<tr><th>Name</th><th>Command / URL</th><th>Source</th></tr>
{{range .MCPServers}}
<tr><td>{{.Name}}</td><td><code>{{if .URL}}{{.URL}}{{else}}{{.Command}}{{end}}</code></td><td><code>{{.Source}}</code></td></tr>
{{end}}
</table>
</body>
</html>`

func WriteHTML(result *model.ScanResult, w io.Writer) error {
	return htmlTmpl.Execute(w, result)
}
