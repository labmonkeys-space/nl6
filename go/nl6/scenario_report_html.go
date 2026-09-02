/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strconv"
	"strings"
)

// scenario_report_html.go — a self-contained, human-readable HTML rendering of
// the finalized scenario report (GET .../report?format=html). Same data as the
// JSON/CSV projections, laid out as a static page (embedded CSS + inline logo,
// no external fonts/JS/frameworks) with stat cards, a per-time-bucket loss-
// localization bar chart, run-tag panel, identity totals, and the participant
// table. Styled to match the nl6 website's light mode (monospace headings,
// green accent, warm background). The machine-readable JSON/CSV remain the
// source of truth; this is the operator's at-a-glance view.

// nl6LogoSVG is a committed copy of assets/nl6-logo-with-text-light.svg (the
// horizontal wordmark for light backgrounds), embedded so the report is fully
// self-contained. Update it if the canonical logo changes.
//
//go:embed nl6-logo-with-text-light.svg
var nl6LogoSVG string

// nl6LogoInline strips the XML declaration + DOCTYPE (invalid inside HTML) and
// returns the bare <svg> element as trusted markup. The SVG is a static asset,
// not report data, so marking it template.HTML is safe.
func nl6LogoInline() template.HTML {
	s := nl6LogoSVG
	if i := strings.Index(s, "<svg"); i >= 0 {
		s = s[i:]
	}
	// #nosec G203 -- s is a static embedded asset (the nl6 wordmark SVG), never
	// report or user data; every report field is auto-escaped by html/template.
	return template.HTML(s)
}

// reportHTMLData is the view model: the report plus values precomputed in Go so
// the template stays arithmetic-free.
type reportHTMLData struct {
	R          *scenarioReport
	Logo       template.HTML
	PhaseClass string // ok | warn | neutral — drives the phase pill colour
	Cards      []htmlStatCard
	Bars       []htmlBar     // sub-window localization chart
	BarMax     uint64        // 0 → no in-window sends (chart shows an empty note)
	Rows       []htmlPartRow // per-participant rows with a status class
	Apps       []htmlAppRow  // fleet-wide application rows (flow scenarios)
}

type htmlStatCard struct {
	Label string
	Value string
	Sub   string
	Warn  bool // red left-border accent when a loss bucket is non-zero
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

// htmlAppRow pairs an application row with its pre-formatted rate so the
// template stays arithmetic/format-free.
type htmlAppRow struct {
	Row scenarioAppRow
	Avg string // avg_bytes_per_second, 1-decimal
}

// buildReportHTMLData projects the wire report into the view model.
func buildReportHTMLData(rep *scenarioReport) reportHTMLData {
	s := rep.Summary
	d := reportHTMLData{R: rep, Logo: nl6LogoInline()}

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

	d.Apps = make([]htmlAppRow, 0, len(rep.Applications))
	for _, a := range rep.Applications {
		d.Apps = append(d.Apps, htmlAppRow{Row: a, Avg: strconv.FormatFloat(a.AvgBytesPerSecond, 'f', 1, 64)})
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
  --bg:oklch(0.985 0.004 90); --bg1:oklch(0.97 0.005 90); --bg2:oklch(0.94 0.006 90);
  --surface:#ffffff;
  --fg:oklch(0.22 0.01 250); --fg-dim:oklch(0.42 0.01 250); --fg-mute:oklch(0.62 0.01 250);
  --hair:rgba(0,0,0,.1); --hair-strong:rgba(0,0,0,.22);
  --green:#319c46; --green-dark:#258035; --green-soft:rgba(49,156,70,.12);
  --red:#b0413a; --red-soft:rgba(176,65,58,.12);
  --mono:"JetBrains Mono","IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  --radius:2px;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:14px;line-height:1.55}
.wrap{max-width:880px;margin:0 auto;padding:40px 24px 64px}
h1{font-family:var(--mono);font-weight:500;font-size:22px;letter-spacing:-.01em;margin:0}
h2{font-family:var(--mono);font-weight:500;font-size:14px;text-transform:uppercase;letter-spacing:.05em;
  color:var(--fg-dim);margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid var(--hair)}
section{margin-top:44px}
.mono{font-family:var(--mono)}
.muted{color:var(--fg-mute)}
.brand-head{display:flex;align-items:center;gap:14px;margin-bottom:12px}
.brand-logo{display:block}
.brand-logo svg{height:28px;width:auto;display:block}
.brand-div{width:1px;height:24px;background:var(--hair-strong)}
.meta-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:2px}
.id{font-family:var(--mono);font-size:13px;color:var(--fg-dim)}
.pill{display:inline-block;font-family:var(--mono);font-size:11px;letter-spacing:.04em;text-transform:uppercase;
  padding:2px 8px;border:1px solid var(--hair-strong);border-radius:var(--radius);color:var(--fg-dim)}
.pill-ver{text-transform:none}
.gdot{color:var(--green)}
.pill-ok{border-color:var(--green);color:var(--green-dark);background:var(--green-soft)}
.pill-warn{border-color:var(--red);color:var(--red);background:var(--red-soft)}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.card{background:var(--surface);border:1px solid var(--hair);border-radius:var(--radius);padding:14px 16px}
.card.warn{border-left:3px solid var(--red)}
.card .label{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--fg-mute)}
.card .value{font-family:var(--mono);font-weight:500;font-size:34px;line-height:1.1;margin:6px 0 3px}
.card .sub{font-size:11px;color:var(--fg-mute)}
.kv{display:grid;grid-template-columns:190px 1fr;gap:5px 18px;background:var(--surface);
  border:1px solid var(--hair);border-radius:var(--radius);padding:16px 18px}
.kv dt{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--fg-mute);margin:0}
.kv dd{margin:0;font-family:var(--mono);font-size:12.5px;color:var(--fg-dim);word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--hair);border-radius:var(--radius);overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--hair);font-size:12.5px}
th{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--fg-mute);background:var(--bg1)}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--bg1)}
td.num{font-family:var(--mono);text-align:right}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.04em;padding:2px 7px;border-radius:var(--radius)}
.tag.ok{background:var(--green-soft);color:var(--green-dark)}
.tag.bad{background:var(--red-soft);color:var(--red)}
.chart{background:var(--surface);border:1px solid var(--hair);border-radius:var(--radius);padding:18px}
.bars{display:flex;align-items:flex-end;gap:8px;height:130px}
.bar{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:6px;height:100%}
.bar .col{width:100%;background:var(--green);border-radius:var(--radius) var(--radius) 0 0;min-height:2px}
.bar .n,.bar .ix{font-family:var(--mono);font-size:10px;color:var(--fg-mute)}
footer{margin-top:52px;padding-top:16px;border-top:1px solid var(--hair);font-size:11px;color:var(--fg-mute);font-family:var(--mono)}
@media(max-width:720px){.cards{grid-template-columns:repeat(2,1fr)}.kv{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand-head">
      <span class="brand-logo">{{.Logo}}</span>
      <span class="brand-div"></span>
      <h1>Load-test scenario report</h1>
    </div>
    <div class="meta-row">
      <span class="pill pill-ver"><span class="gdot">●</span> {{.R.Summary.Metadata.Nl6Version}}</span>
      <span class="id">{{.R.Summary.ID}}</span>
      <span class="pill pill-{{.PhaseClass}}">{{.R.Summary.Phase}}</span>
      <span class="pill">{{.R.Summary.Protocol}}</span>
      <span class="muted">· duration {{.R.Summary.Duration}}</span>
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
      {{if .R.Summary.Metadata.DrainStragglers}}
      <dt title="The drain barrier gave up at its ceiling with sends still in flight. Those sends were not cancelled and kept moving ledger counters after this report was snapshotted, so the totals below are a lower bound and the affected participants may not satisfy the ledger identity.">drain stragglers</dt><dd><strong>{{.R.Summary.Metadata.DrainStragglers}} &mdash; finalized with stragglers; totals are a lower bound</strong></dd>
      {{end}}
      <dt>seed</dt><dd>{{.R.Summary.Metadata.Seed}}</dd>
      <dt>nl6 version</dt><dd>{{.R.Summary.Metadata.Nl6Version}}</dd>
      <dt>config sha256</dt><dd>{{.R.Summary.Metadata.ConfigSHA256}}</dd>
      <dt title="Identifies the devices that actually ran. Two runs with the same config sha256 but different values here measured different fleets.">resolved participants sha256</dt><dd>{{.R.Summary.Metadata.ResolvedParticipantsSHA256}}</dd>
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
      <p class="muted" style="margin:12px 0 0;font-size:11px">
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

  {{if .Apps}}
  <section>
    <h2>Application traffic (trusted-sender ground truth)</h2>
    <table>
      <thead><tr>
        <th>proto</th><th class="num">dst&nbsp;port</th><th>hint</th>
        <th class="num">records</th><th class="num">bytes</th><th class="num">packets</th>
        <th class="num">avg&nbsp;B/s</th>
      </tr></thead>
      <tbody>
      {{range .Apps}}
        <tr>
          <td class="mono">{{.Row.L4Proto}}</td>
          <td class="num">{{.Row.DstPort}}</td>
          <td>{{if .Row.AppHint}}{{.Row.AppHint}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td class="num">{{.Row.Records}}</td>
          <td class="num">{{.Row.Bytes}}</td>
          <td class="num">{{.Row.Packets}}</td>
          <td class="num">{{.Avg}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
    <p class="muted" style="margin:12px 0 0;font-size:11px">
      Sent-basis totals per (l4_proto, dst_port); avg&nbsp;B/s = in-window bytes / window.
      Reconcile a collector on totals over a padded query window — not per-bucket.
    </p>
  </section>
  {{end}}

  {{if or .R.Summary.Excluded .R.Summary.ExcludedByReason}}
  <section>
    <h2>Excluded participants</h2>
    {{if .R.Summary.ExcludedByReason}}
    <table>
      <caption>All {{.R.Summary.ParticipantsExcluded}} exclusions, by reason</caption>
      <thead><tr><th>reason</th><th>participants</th></tr></thead>
      <tbody>
      {{range $reason, $n := .R.Summary.ExcludedByReason}}
        <tr><td>{{$reason}}</td><td class="mono">{{$n}}</td></tr>
      {{end}}
      </tbody>
    </table>
    {{end}}
    <table>
      {{if .R.Summary.ExcludedTruncated}}
      <caption>First {{len .R.Summary.Excluded}} of {{.R.Summary.ParticipantsExcluded}}
        individually — fix what these show, re-arm, and the next batch surfaces</caption>
      {{else}}
      <caption>Each exclusion individually</caption>
      {{end}}
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
    Generated by nl6 {{.R.Summary.Metadata.Nl6Version}} · human-readable view;
    the same data is served as JSON (no ?format) and CSV (?format=csv).
    sent is the reconciliation denominator.
  </footer>
</div>
</body>
</html>
`
