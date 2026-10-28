"""Local browser dashboard for the Cloud Firewall Rule Analyzer."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from analyzer import analyze_rules, write_html_report, write_report

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloud Firewall Rule Analyzer</title>
<style>
* { box-sizing: border-box; }
body { margin: 0; background: #f3f5fb; color: #172033; font: 15px/1.5 system-ui, Arial, sans-serif; }
header { background: #202f57; color: white; padding: 24px 5vw; }
header h1 { margin: 0; }
header p { color: #d9e1f6; margin: 5px 0 0; }
main { max-width: 1150px; margin: 24px auto; padding: 0 18px; }
.panel { background: white; border-radius: 14px; padding: 20px; margin-bottom: 18px; box-shadow: 0 3px 15px #1720330c; }
button { background: #3459a6; color: white; border: 0; border-radius: 8px; padding: 11px 16px; font-weight: 700; cursor: pointer; margin: 5px 6px 5px 0; }
button.secondary { background: #e8edf8; color: #20345f; }
textarea { width: 100%; min-height: 180px; font: 13px/1.5 Consolas, monospace; padding: 12px; border: 1px solid #cbd4e5; border-radius: 8px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
.stat { padding: 14px; background: #f4f6fb; border-radius: 10px; }
.stat b { display: block; font-size: 25px; }
.tablewrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 850px; }
th, td { padding: 10px; border: 1px solid #dce2ed; text-align: left; vertical-align: top; }
th { background: #e8eef9; }
.HIGH { color: #b42318; font-weight: 800; }
.MEDIUM { color: #9a6700; font-weight: 800; }
.INFO { color: #175cd3; font-weight: 800; }
.muted { color: #5b6680; }
.error { color: #b42318; white-space: pre-wrap; }
.success { color: #067647; }
footer { color: #59647a; font-size: 13px; padding: 8px 0 30px; }
</style>
</head>
<body>
<header><h1>Cloud Firewall Rule Analyzer</h1><p>Milestone 4 · Integrated local demonstration dashboard</p></header>
<main>
<section class="panel">
<h2>1. Firewall rule input</h2>
<p class="muted">Edit the sample JSON and click Analyze. Required fields: source, protocol, port, action. This tool runs locally and does not change cloud settings.</p>
<textarea id="rules" spellcheck="false">[
  {"id":"FW-001","source":"0.0.0.0/0","protocol":"tcp","port":22,"action":"allow"},
  {"id":"FW-002","source":"0.0.0.0/0","protocol":"tcp","port":443,"action":"allow"},
  {"id":"FW-003","source":"10.0.0.0/8","protocol":"tcp","port":"8000-8100","action":"allow"},
  {"id":"FW-004","source":"0.0.0.0/0","protocol":"tcp","port":5432,"action":"allow"}
]</textarea>
<button id="analyze">Analyze rules</button>
<button class="secondary" id="restore">Restore sample</button>
<button class="secondary" id="download">Download JSON report</button>
<p id="message" class="muted">Ready. Select Analyze rules to start.</p>
</section>
<section class="panel"><h2>2. Analysis summary</h2>
<div id="stats" class="stats">
<div class="stat">Total rules<b>—</b></div><div class="stat">Findings<b>—</b></div>
</div></section>
<section class="panel"><h2>3. Findings and recommendations</h2><div class="tablewrap">
<table><thead><tr><th>Severity</th><th>Score</th><th>Rule</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody id="findings"><tr><td colspan="6">No analysis run yet.</td></tr></tbody></table></div></section>
<section class="panel"><h2>4. Input validation</h2><ul id="errors"><li>No validation errors yet.</li></ul></section>
<footer>Educational prototype using predefined checks. No live cloud connection or automatic firewall changes.</footer>
</main>
<script>
const initial = document.getElementById('rules').value;
let lastReport = null;
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));

document.getElementById('restore').onclick = () => {
  document.getElementById('rules').value = initial;
  document.getElementById('message').textContent = 'Sample restored.';
};

document.getElementById('analyze').onclick = async () => {
  const message = document.getElementById('message');
  try {
    message.className = 'muted';
    message.textContent = 'Analyzing…';
    const rules = JSON.parse(document.getElementById('rules').value);
    if (!Array.isArray(rules)) throw Error('Input must be a JSON list of rules.');
    const response = await fetch('/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({rules})
    });
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Analysis failed.');
    lastReport = data;
    const s = data.summary;
    const summaryItems = [
      ['Total rules', s.total_rules], ['Valid rules', s.valid_rules],
      ['Invalid rules', s.invalid_rules], ['Findings', s.findings],
      ['High risk', s.high], ['Medium risk', s.medium]
    ];
    document.getElementById('stats').innerHTML = summaryItems.map(item =>
      '<div class="stat">' + esc(item[0]) + '<b>' + esc(item[1]) + '</b></div>'
    ).join('');
    document.getElementById('findings').innerHTML = data.findings.length
      ? data.findings.map(f => '<tr><td class="' + esc(f.severity) + '">' + esc(f.severity)
        + '</td><td>' + esc(f.risk_score) + '</td><td>' + esc(f.rule_id) + '</td><td>'
        + esc(f.title) + '</td><td>' + esc(f.evidence) + '</td><td>'
        + esc(f.recommendation) + '</td></tr>').join('')
      : '<tr><td colspan="6">No findings.</td></tr>';
    document.getElementById('errors').innerHTML = data.validation_errors.length
      ? data.validation_errors.map(error => '<li class="error">' + esc(error) + '</li>').join('')
      : '<li class="success">No validation errors.</li>';
    message.className = 'success';
    message.textContent = 'Analysis complete. Report files were saved.';
  } catch (error) {
    message.className = 'error';
    message.textContent = 'Could not analyze input: ' + error.message;
  }
};

document.getElementById('download').onclick = () => {
  if (!lastReport) {
    document.getElementById('message').textContent = 'Run an analysis first.';
    return;
  }
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type: 'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'firewall-analysis-report.json';
  link.click();
  URL.revokeObjectURL(link.href);
};
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def send_body(self, status, body, content_type):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_body(200, PAGE, "text/html; charset=utf-8")
        elif path == "/health":
            self.send_body(200, '{"status":"ok"}', "application/json; charset=utf-8")
        else:
            self.send_body(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if urlparse(self.path).path != "/analyze":
            self.send_body(404, '{"error":"Not found"}', "application/json; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                raise ValueError("Request must be non-empty and under 2 MB.")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            rules = payload.get("rules")
            if not isinstance(rules, list):
                raise ValueError("'rules' must be a JSON list.")
            report = analyze_rules(rules)
            write_report(report, "report.json")
            write_html_report(report, "report.html")
            self.send_body(200, json.dumps(report), "application/json; charset=utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            self.send_body(400, json.dumps({"error": str(exc)}), "application/json; charset=utf-8")

    def log_message(self, format_string, *args):
        print("[web] " + format_string % args)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("Cloud Firewall Rule Analyzer dashboard is running.")
    print("Open http://127.0.0.1:8000 in your browser.")
    print("Press Ctrl+C to stop. Local-only; no cloud firewall changes.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
