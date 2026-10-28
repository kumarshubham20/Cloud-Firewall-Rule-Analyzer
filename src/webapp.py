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
<meta name="theme-color" content="#0b1220">
<title>Sentinel | Cloud Firewall Analyzer</title>
<style>
:root{color-scheme:dark;--bg:#0b1220;--surface:#111c2f;--surface2:#16243a;--line:#263750;--text:#edf4ff;--muted:#9bacc5;--blue:#6ea8fe;--cyan:#5eead4;--red:#f87171;--amber:#fbbf24;--green:#34d399}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(ellipse at 10% 0%,#162746 0,transparent 36%),var(--bg);color:var(--text);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
button,textarea{font:inherit}
.topbar{border-bottom:1px solid var(--line);background:#0b1220e8;backdrop-filter:blur(12px)}
.topinner{max-width:1280px;margin:auto;padding:18px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px}
.brand{display:flex;align-items:center;gap:12px}.logo{width:42px;height:42px;border-radius:13px;background:linear-gradient(135deg,#4f8cff,#5eead4);display:grid;place-items:center;color:#081324;font-weight:900;font-size:19px;box-shadow:0 8px 28px #4f8cff30}
.brandname{font-size:17px;font-weight:800;letter-spacing:-.3px}.brandtag{font-size:12px;color:var(--muted)}
.statuspill{border:1px solid #236c5c;background:#0d2a2a;color:#8df2d7;padding:7px 11px;border-radius:999px;font-size:12px;white-space:nowrap}
main{max-width:1280px;margin:0 auto;padding:34px 28px 48px}
.eyebrow{color:var(--cyan);text-transform:uppercase;letter-spacing:1.8px;font-size:11px;font-weight:800}
.hero{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:28px}
h1{font-size:clamp(28px,3vw,40px);line-height:1.12;letter-spacing:-1.2px;margin:9px 0 12px}
.lead{color:var(--muted);max-width:700px;margin:0}
.hero-note{border:1px solid var(--line);border-radius:14px;padding:13px 16px;background:#111c2f;min-width:180px}
.hero-note strong{display:block;font-size:13px}.hero-note span{font-size:12px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:18px}
.card{background:linear-gradient(145deg,#121e31,#101a2b);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 14px 34px #00000014;min-width:0}
.inputcard{grid-column:span 7}.guidecard{grid-column:span 5}.summarycard,.findingscard,.validationcard{grid-column:1/-1}
.sectionhead{display:flex;align-items:flex-start;gap:12px;margin-bottom:16px}
.step{width:32px;height:32px;border:1px solid #33517a;background:#172b48;color:#9bc4ff;border-radius:10px;display:grid;place-items:center;font-weight:800;flex-shrink:0}
h2{font-size:17px;letter-spacing:-.25px;margin:1px 0 4px}.sub{color:var(--muted);font-size:13px;margin:0}
textarea{display:block;width:100%;min-height:238px;resize:vertical;background:#091322;border:1px solid #30425c;border-radius:12px;color:#d9e8ff;padding:15px;font:13px/1.7 "Cascadia Code",Consolas,monospace;outline:none;tab-size:2}
textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px #6ea8fe20}
.actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:14px}
button{border:1px solid transparent;border-radius:10px;padding:10px 15px;font-weight:750;font-size:13px;cursor:pointer;transition:transform .15s,filter .15s}
button:hover{filter:brightness(1.08);transform:translateY(-1px)}button:focus-visible{outline:3px solid #6ea8fe88;outline-offset:2px}
.primary{background:linear-gradient(135deg,#6ea8fe,#7dd3fc);color:#081426}.secondary{background:#18263b;color:#dbe8fb;border-color:#30425c}.tertiary{background:transparent;color:#9fb4d0;border-color:#30425c}
.message{min-height:22px;font-size:13px;margin:13px 0 0;color:var(--muted)}.message.success{color:var(--green)}.message.error{color:var(--red)}
.guide-list{display:grid;gap:12px;margin-top:16px}
.guideitem{display:flex;gap:11px;align-items:flex-start;padding:12px;border:1px solid #273a54;background:#0d1829;border-radius:12px}
.guideicon{width:30px;height:30px;display:grid;place-items:center;border-radius:9px;background:#172b48;color:#83b6ff;flex-shrink:0;font-weight:800}
.guideitem strong{display:block;font-size:13px;margin-bottom:2px}.guideitem span{display:block;color:var(--muted);font-size:12px}
.summarygrid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px}
.stat{padding:16px;border-radius:13px;background:#0c1728;border:1px solid #243650}
.statlabel{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:7px}
.dot{width:7px;height:7px;border-radius:50%;background:#6ea8fe}.stat b{display:block;font-size:29px;line-height:1.3;margin-top:7px;letter-spacing:-.8px}
.stat.risk b{color:var(--red)}.stat.warn b{color:var(--amber)}.stat.safe b{color:var(--green)}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;min-width:790px;font-size:13px}
th{background:#17253b;color:#b9cbe4;text-transform:uppercase;letter-spacing:.6px;font-size:10px;font-weight:800}
th,td{padding:13px 14px;border-bottom:1px solid #263750;text-align:left;vertical-align:top}
tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#17243a80}
.severity{display:inline-block;border-radius:6px;padding:4px 8px;font-size:10px;font-weight:900;letter-spacing:.5px}
.HIGH{background:#421f2b;color:#ffaaa9}.MEDIUM{background:#3c3018;color:#fbd27c}.INFO{background:#172d4a;color:#9ac5ff}
.score{font-weight:850;font-variant-numeric:tabular-nums}.empty{color:var(--muted);text-align:center;padding:24px}
.validation-list{margin:0;padding:0;list-style:none;display:grid;gap:8px}
.validation-list li{border:1px solid #263750;background:#0c1728;padding:11px 13px;border-radius:10px;font-size:13px}
.validation-list .error{color:#ffaaa9;border-color:#663040}.validation-list .success{color:#82e6c2;border-color:#245b4e}
.foot{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;color:#7f92ad;font-size:12px;margin-top:22px;padding:0 2px}
kbd{font:11px ui-monospace,monospace;border:1px solid #344761;border-radius:5px;padding:2px 5px;color:#c3d4eb}
@media(max-width:900px){.inputcard,.guidecard{grid-column:1/-1}.summarygrid{grid-template-columns:repeat(3,minmax(0,1fr))}.hero{align-items:flex-start;flex-direction:column}.hero-note{width:100%}}
@media(max-width:520px){.topinner{padding:14px 16px}main{padding:24px 14px 32px}.card{padding:16px}.summarygrid{grid-template-columns:repeat(2,minmax(0,1fr))}.stat b{font-size:25px}.brandname{font-size:14px}.brandtag{font-size:11px}.statuspill{font-size:10px;padding:6px 8px}}
</style>
</head>
<body>
<div class="topbar"><div class="topinner">
  <div class="brand"><div class="logo">S</div><div><div class="brandname">SENTINEL <span style="color:#80baff">/</span> Firewall Analyzer</div><div class="brandtag">Cloud security · Configuration review</div></div></div>
  <div class="statuspill">● LOCAL DEMO MODE</div>
</div></div>
<main>
<section class="hero">
 <div><div class="eyebrow">Milestone 4 · Integrated prototype</div><h1>Cloud Firewall Rule Analyzer</h1><p class="lead">Review firewall rules, spot potentially risky exposure, validate configuration, and get clear remediation guidance — all in one local dashboard.</p></div>
 <div class="hero-note"><strong>◈ Privacy-first demo</strong><span>Runs locally · No live firewall changes</span></div>
</section>
<div class="grid">
<section class="card inputcard">
 <div class="sectionhead"><div class="step">01</div><div><h2>Firewall rule input</h2><p class="sub">Paste or edit a JSON array of firewall rules to inspect.</p></div></div>
 <textarea id="rules" spellcheck="false" aria-label="Firewall rules JSON">[
  {"id":"FW-001","source":"0.0.0.0/0","protocol":"tcp","port":22,"action":"allow"},
  {"id":"FW-002","source":"0.0.0.0/0","protocol":"tcp","port":443,"action":"allow"},
  {"id":"FW-003","source":"10.0.0.0/8","protocol":"tcp","port":"8000-8100","action":"allow"},
  {"id":"FW-004","source":"0.0.0.0/0","protocol":"tcp","port":5432,"action":"allow"}
]</textarea>
 <div class="actions"><button class="primary" id="analyze">▶ &nbsp; Analyze rules</button><button class="secondary" id="restore">Restore sample</button><button class="tertiary" id="download">↓ &nbsp; Export JSON report</button></div>
 <p id="message" class="message" role="status">Ready when you are. Select Analyze rules to begin.</p>
</section>
<aside class="card guidecard">
 <div class="sectionhead"><div class="step">i</div><div><h2>What this tool checks</h2><p class="sub">A quick guide to the analysis pipeline.</p></div></div>
 <div class="guide-list">
  <div class="guideitem"><div class="guideicon">1</div><div><strong>Validate the input</strong><span>Checks source ranges, protocol, port, and action fields.</span></div></div>
  <div class="guideitem"><div class="guideicon">2</div><div><strong>Inspect exposure</strong><span>Flags selected public admin and database ports.</span></div></div>
  <div class="guideitem"><div class="guideicon">3</div><div><strong>Explain the risk</strong><span>Shows evidence, severity, and practical recommendations.</span></div></div>
  <div class="guideitem"><div class="guideicon">4</div><div><strong>Export the report</strong><span>Download a JSON report for review or documentation.</span></div></div>
 </div>
</aside>
<section class="card summarycard">
 <div class="sectionhead"><div class="step">02</div><div><h2>Analysis overview</h2><p class="sub">Summary updates after you analyze the submitted rules.</p></div></div>
 <div id="stats" class="summarygrid">
  <div class="stat"><div class="statlabel"><i class="dot"></i>Total rules</div><b>—</b></div>
  <div class="stat"><div class="statlabel"><i class="dot"></i>Valid rules</div><b>—</b></div>
  <div class="stat"><div class="statlabel"><i class="dot"></i>Invalid rules</div><b>—</b></div>
  <div class="stat"><div class="statlabel"><i class="dot"></i>Findings</div><b>—</b></div>
  <div class="stat risk"><div class="statlabel"><i class="dot" style="background:var(--red)"></i>High risk</div><b>—</b></div>
  <div class="stat warn"><div class="statlabel"><i class="dot" style="background:var(--amber)"></i>Medium risk</div><b>—</b></div>
 </div>
</section>
<section class="card findingscard">
 <div class="sectionhead"><div class="step">03</div><div><h2>Findings & recommendations</h2><p class="sub">Review the evidence behind each flagged rule and how to reduce exposure.</p></div></div>
 <div class="tablewrap"><table><thead><tr><th>Severity</th><th>Score</th><th>Rule ID</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody id="findings"><tr><td colspan="6" class="empty">No analysis run yet. Analyze the sample rules to see findings.</td></tr></tbody></table></div>
</section>
<section class="card validationcard">
 <div class="sectionhead"><div class="step">04</div><div><h2>Input validation</h2><p class="sub">Errors are shown here so malformed rules can be corrected.</p></div></div>
 <ul id="errors" class="validation-list"><li class="empty">No validation results yet.</li></ul>
</section>
</div>
<footer class="foot"><span>Sentinel · Cloud Firewall Rule Analyzer · Educational prototype</span><span>Predefined checks only · No cloud account connection · No automatic changes</span></footer>
</main>
<script>
const initial = document.getElementById('rules').value;
let lastReport = null;
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));

document.getElementById('restore').onclick = () => {
  document.getElementById('rules').value = initial;
  document.getElementById('message').className = 'message';
  document.getElementById('message').textContent = 'Sample restored. Select Analyze rules to run the checks.';
};
document.getElementById('analyze').onclick = async () => {
  const message = document.getElementById('message');
  try {
    message.className = 'message';
    message.textContent = 'Analyzing rules…';
    const rules = JSON.parse(document.getElementById('rules').value);
    if (!Array.isArray(rules)) throw Error('Input must be a JSON list of rules.');
    const response = await fetch('/analyze', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({rules})
    });
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Analysis failed.');
    lastReport = data;
    const s = data.summary;
    const items = [
      ['Total rules',s.total_rules,''],['Valid rules',s.valid_rules,'safe'],
      ['Invalid rules',s.invalid_rules,s.invalid_rules?'risk':''],
      ['Findings',s.findings,''],['High risk',s.high,'risk'],['Medium risk',s.medium,'warn']
    ];
    document.getElementById('stats').innerHTML = items.map(x =>
      '<div class="stat '+x[2]+'"><div class="statlabel"><i class="dot"></i>'+esc(x[0])+'</div><b>'+esc(x[1])+'</b></div>'
    ).join('');
    document.getElementById('findings').innerHTML = data.findings.length
      ? data.findings.map(f => '<tr><td><span class="severity '+esc(f.severity)+'">'+esc(f.severity)+'</span></td><td class="score">'+esc(f.risk_score)+'</td><td>'+esc(f.rule_id)+'</td><td>'+esc(f.title)+'</td><td>'+esc(f.evidence)+'</td><td>'+esc(f.recommendation)+'</td></tr>').join('')
      : '<tr><td colspan="6" class="empty">No findings for the submitted rules.</td></tr>';
    document.getElementById('errors').innerHTML = data.validation_errors.length
      ? data.validation_errors.map(e => '<li class="error">'+esc(e)+'</li>').join('')
      : '<li class="success">✓ No validation errors. All submitted rules passed input validation.</li>';
    message.className = 'message success';
    message.textContent = '✓ Analysis complete. Results are ready and report files were saved.';
  } catch (error) {
    message.className = 'message error';
    message.textContent = 'Could not analyze input: ' + error.message;
  }
};
document.getElementById('download').onclick = () => {
  if (!lastReport) {
    const m = document.getElementById('message');
    m.className = 'message error'; m.textContent = 'Run an analysis first, then export the report.';
    return;
  }
  const blob = new Blob([JSON.stringify(lastReport,null,2)],{type:'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob); link.download = 'firewall-analysis-report.json';
  link.click(); URL.revokeObjectURL(link.href);
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
