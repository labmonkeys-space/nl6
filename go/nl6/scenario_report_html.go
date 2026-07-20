/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"html/template"
	"strconv"
)

// scenario_report_html.go — a self-contained, human-readable HTML rendering of
// the finalized scenario report (GET .../report?format=html). Same data as the
// JSON/CSV projections, laid out as a static page (embedded CSS, no external
// fonts/JS/frameworks) with stat cards, a per-time-bucket loss-localization bar
// chart, run-tag panel, identity totals, and the per-participant table. The
// machine-readable JSON/CSV remain the source of truth; this is the operator's
// at-a-glance view.

// reportHTMLData is the view model: the report plus values precomputed in Go so
// the template stays arithmetic-free.
type reportHTMLData struct {
	R          *scenarioReport
	PhaseClass string // ok | warn | neutral — drives the phase pill colour
	Cards      []htmlStatCard
	Bars       []htmlBar     // sub-window localization chart
	BarMax     uint64        // 0 → no in-window sends (chart shows an empty note)
	Rows       []htmlPartRow // per-participant rows with a status class
}

type htmlStatCard struct {
	Label string
	Value string
	Sub   string
	Warn  bool // clay left-border accent when a loss bucket is non-zero
}

type htmlBar struct {
	Index     int
	Count     uint64
	HeightPct int // 0..100, relative to BarMax
}

type htmlPartRow struct {
	Row         scenarioCounterRow
	StatusClass string // ok | bad
	StatusLabel string
}

// buildReportHTMLData projects the wire report into the view model.
func buildReportHTMLData(rep *scenarioReport) reportHTMLData {
	s := rep.Summary
	d := reportHTMLData{R: rep}

	switch s.Phase {
	case "stopped":
		d.PhaseClass = "ok"
	case "aborted":
		d.PhaseClass = "warn"
	default:
		d.PhaseClass = "neutral"
	}

	d.Cards = []htmlStatCard{
		{Label: "Participants", Value: itoa(s.ParticipantsArmed), Sub: plural(s.ParticipantsExcluded, "exclusion", "exclusions")},
		{Label: "Records sent", Value: u64(s.Sent), Sub: fmt.Sprintf("%s in-window · %s drain", u64(s.InWindow), u64(s.Drain))},
		{Label: "Send failures", Value: u64(s.SendFailures), Sub: "nl6 could not send", Warn: s.SendFailures > 0},
		{Label: "Dropped", Value: u64(s.Dropped), Sub: "never confirmed on the wire", Warn: s.Dropped > 0},
	}

	// Loss-localization bar chart over the summary's per-bucket in-window tally.
	for _, n := range s.SubWindows {
		if n > d.BarMax {
			d.BarMax = n
		}
	}
	d.Bars = make([]htmlBar, len(s.SubWindows))
	for i, n := range s.SubWindows {
		h := 0
		if d.BarMax > 0 {
			h = int(n * 100 / d.BarMax)
		}
		d.Bars[i] = htmlBar{Index: i, Count: n, HeightPct: h}
	}

	d.Rows = make([]htmlPartRow, 0, len(rep.Counters))
	for _, c := range rep.Counters {
		row := htmlPartRow{Row: c, StatusClass: "ok", StatusLabel: "clean"}
		if c.SendFailures > 0 || c.Dropped > 0 {
			row.StatusClass, row.StatusLabel = "bad", "issues"
		}
		d.Rows = append(d.Rows, row)
	}
	return d
}

// reportHTML renders the finalized report as a static HTML page.
func reportHTML(rep *scenarioReport) []byte {
	var buf bytes.Buffer
	// Execution only fails on a template bug, which the tests catch; ignore.
	_ = reportHTMLTemplate.Execute(&buf, buildReportHTMLData(rep))
	return buf.Bytes()
}

// small template-free formatting helpers (keep the template arithmetic-free);
// integer formatting goes through strconv, matching the reportCSV projection.
func u64(v uint64) string { return strconv.FormatUint(v, 10) }
func itoa(v int) string   { return strconv.Itoa(v) }
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// reportHTMLTemplate is parsed once at init; a parse error is a programming
// error and panics via template.Must.
var reportHTMLTemplate = template.Must(template.New("report").Parse(reportHTMLSource))

const reportHTMLSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nl6 scenario report — {{.R.Summary.ID}}</title>
<style>
:root{
  --bg:#FAF9F5; --surface:#FFFFFF; --oat:#E3DACC;
  --ink:#141413; --gray700:#3D3D3A; --gray500:#87867F;
  --clay:#D97757; --olive:#788C5D; --rust:#B04A3F;
  --gray100:#F0EEE6; --gray300:#D1CFC5;
  --serif:Georgia,"Times New Roman",serif;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:"SF Mono",ui-monospace,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.5}
.wrap{max-width:860px;margin:0 auto;padding:40px 24px 64px}
h1{font-family:var(--serif);font-weight:600;font-size:32px;margin:0 0 10px}
h2{font-family:var(--serif);font-weight:600;font-size:20px;margin:0 0 14px;padding-bottom:8px;border-bottom:1.5px solid var(--gray300)}
section{margin-top:52px}
.mono{font-family:var(--mono)}
.muted{color:var(--gray500)}
.meta-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.id{font-family:var(--mono);font-size:14px;color:var(--gray700)}
.pill{display:inline-block;font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.06em;
  padding:3px 9px;border-radius:999px;border:1.5px solid var(--gray300);background:var(--gray100);color:var(--gray700)}
.pill-ok{background:rgba(120,140,93,.14);border-color:var(--olive);color:var(--olive)}
.pill-warn{background:rgba(176,74,63,.12);border-color:var(--rust);color:var(--rust)}
.pill-neutral{background:var(--gray100)}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.card{background:var(--surface);border:1.5px solid var(--gray300);border-radius:10px;padding:16px}
.card.warn{border-left:4px solid var(--clay)}
.card .label{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--gray500)}
.card .value{font-family:var(--serif);font-size:40px;line-height:1.1;margin:6px 0 4px}
.card .sub{font-size:12px;color:var(--gray500)}
.kv{display:grid;grid-template-columns:180px 1fr;gap:6px 18px;background:var(--surface);
  border:1.5px solid var(--gray300);border-radius:10px;padding:16px 18px}
.kv dt{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--gray500);margin:0}
.kv dd{margin:0;font-family:var(--mono);font-size:13px;color:var(--gray700);word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1.5px solid var(--gray300);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--gray100);font-size:13px}
th{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--gray500);background:var(--gray100)}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--gray100)}
td.num{font-family:var(--mono);text-align:right}
.tag{display:inline-block;font-family:var(--mono);font-size:11px;padding:2px 8px;border-radius:999px}
.tag.ok{background:rgba(120,140,93,.14);color:var(--olive)}
.tag.bad{background:rgba(176,74,63,.12);color:var(--rust)}
.chart{background:var(--surface);border:1.5px solid var(--gray300);border-radius:10px;padding:18px}
.bars{display:flex;align-items:flex-end;gap:8px;height:140px}
.bar{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:6px;height:100%}
.bar .col{width:100%;background:var(--clay);border-radius:4px 4px 0 0;min-height:2px}
.bar .n{font-family:var(--mono);font-size:11px;color:var(--gray500)}
.bar .ix{font-family:var(--mono);font-size:10px;color:var(--gray500)}
footer{margin-top:56px;padding-top:16px;border-top:1.5px solid var(--gray300);font-size:12px;color:var(--gray500)}
@media(max-width:720px){.cards{grid-template-columns:repeat(2,1fr)}.kv{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Load-test scenario report</h1>
    <div class="meta-row">
      <span class="id">{{.R.Summary.ID}}</span>
      <span class="pill pill-{{.PhaseClass}}">{{.R.Summary.Phase}}</span>
      <span class="pill">{{.R.Summary.Protocol}}</span>
      <span class="muted">duration {{.R.Summary.Duration}}</span>
    </div>
  </header>

  <section class="cards">
    {{range .Cards}}
    <div class="card{{if .Warn}} warn{{end}}">
      <div class="label">{{.Label}}</div>
      <div class="value">{{.Value}}</div>
      <div class="sub">{{.Sub}}</div>
    </div>
    {{end}}
  </section>

  <section>
    <h2>Window &amp; fingerprint</h2>
    <dl class="kv">
      <dt>T0</dt><dd>{{.R.Summary.Metadata.T0}}</dd>
      <dt>T1</dt><dd>{{.R.Summary.Metadata.T1}}</dd>
      <dt>drain end</dt><dd>{{.R.Summary.Metadata.DrainEnd}}</dd>
      <dt>seed</dt><dd>{{.R.Summary.Metadata.Seed}}</dd>
      <dt>nl6 version</dt><dd>{{.R.Summary.Metadata.Nl6Version}}</dd>
      <dt>config sha256</dt><dd>{{.R.Summary.Metadata.ConfigSHA256}}</dd>
    </dl>
  </section>

  <section>
    <h2>Loss localization</h2>
    <div class="chart">
      {{if gt .BarMax 0}}
      <div class="bars">
        {{range .Bars}}
        <div class="bar" title="bucket {{.Index}}: {{.Count}} sent">
          <span class="n">{{.Count}}</span>
          <div class="col" style="height:{{.HeightPct}}%"></div>
          <span class="ix">{{.Index}}</span>
        </div>
        {{end}}
      </div>
      <p class="muted" style="margin:12px 0 0;font-size:12px">
        In-window sends per bucket — {{.R.Summary.Metadata.SubWindowCount}} equal buckets
        of {{.R.Summary.Metadata.SubWindowDuration}} over the planned window (sums to in_window).
      </p>
      {{else}}
      <p class="muted" style="margin:0">No in-window sends to localize.</p>
      {{end}}
    </div>
  </section>

  <section>
    <h2>Identity totals</h2>
    <dl class="kv">
      <dt>emitted</dt><dd>{{.R.Summary.Emitted}}</dd>
      <dt>sent</dt><dd>{{.R.Summary.Sent}} <span class="muted">(in_window {{.R.Summary.InWindow}} + drain {{.R.Summary.Drain}})</span></dd>
      <dt>suppressed pre-window</dt><dd>{{.R.Summary.SuppressedPreWindow}}</dd>
      <dt>send failures</dt><dd>{{.R.Summary.SendFailures}}</dd>
      <dt>dropped</dt><dd>{{.R.Summary.Dropped}}</dd>
      <dt>background suppressed</dt><dd>{{.R.Summary.Informational.BackgroundSuppressed}} <span class="muted">(informational)</span></dd>
    </dl>
  </section>

  <section>
    <h2>Run tagging</h2>
    <dl class="kv">
      <dt>mechanism</dt><dd>{{.R.Summary.Metadata.RunTags.Mechanism}}</dd>
      <dt>value</dt><dd>{{if .R.Summary.Metadata.RunTags.Value}}{{.R.Summary.Metadata.RunTags.Value}}{{else}}<span class="muted">—</span>{{end}}</dd>
      <dt>PEN</dt><dd>{{.R.Summary.Metadata.RunTags.PEN}}{{if .R.Summary.Metadata.RunTags.Degraded}} <span class="tag bad">degraded</span>{{end}}</dd>
      <dt>note</dt><dd class="muted">{{.R.Summary.Metadata.RunTags.Note}}</dd>
    </dl>
  </section>

  <section>
    <h2>Participants</h2>
    <table>
      <thead><tr>
        <th>source ip</th><th>collector</th><th class="num">sent</th><th class="num">in&nbsp;window</th>
        <th class="num">drain</th><th class="num">failures</th><th class="num">dropped</th><th>status</th>
      </tr></thead>
      <tbody>
      {{range .Rows}}
        <tr>
          <td class="mono">{{.Row.SourceIP}}</td>
          <td class="mono">{{if .Row.Collector}}{{.Row.Collector}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td class="num">{{.Row.Sent}}</td>
          <td class="num">{{.Row.InWindow}}</td>
          <td class="num">{{.Row.Drain}}</td>
          <td class="num">{{.Row.SendFailures}}</td>
          <td class="num">{{.Row.Dropped}}</td>
          <td><span class="tag {{.StatusClass}}">{{.StatusLabel}}</span></td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </section>

  {{if .R.Summary.Excluded}}
  <section>
    <h2>Excluded participants</h2>
    <table>
      <thead><tr><th>device</th><th>reason</th><th>remediation hint</th></tr></thead>
      <tbody>
      {{range .R.Summary.Excluded}}
        <tr><td class="mono">{{.Device}}</td><td>{{.Reason}}</td><td class="muted">{{.RemediationHint}}</td></tr>
      {{end}}
      </tbody>
    </table>
  </section>
  {{end}}

  <footer>
    Generated by nl6 {{.R.Summary.Metadata.Nl6Version}} · This is the human-readable view;
    the same data is served as JSON (drop <span class="mono">?format=html</span>) and CSV
    (<span class="mono">?format=csv</span>). <span class="mono">sent</span> is the reconciliation denominator.
  </footer>
</div>
</body>
</html>
`
