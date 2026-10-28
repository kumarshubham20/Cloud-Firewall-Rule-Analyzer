"""Local browser dashboard for the Cloud Firewall Rule Analyzer."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from analyzer import analyze_rules, write_html_report, write_report

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#08111f"><title>Sentinel Security | Firewall Analyzer</title>
<style>
:root{color-scheme:dark;--bg:#08111f;--panel:#101c2e;--panel2:#14243a;--line:#263a55;--text:#edf4ff;--muted:#9aadc7;--blue:#76aaff;--cyan:#5eead4;--red:#fb7185;--amber:#fbbf24;--green:#4adea6}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
button,textarea{font:inherit}button{cursor:pointer;transition:.16s ease}button:hover{filter:brightness(1.12);transform:translateY(-1px)}button:focus-visible,textarea:focus-visible,a:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.layout{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:236px;background:#091321;border-right:1px solid var(--line);padding:23px 15px;display:flex;flex-direction:column;z-index:3}
.brand{display:flex;align-items:center;gap:11px;padding:0 8px 27px}.brandmark{width:39px;height:39px;border-radius:12px;background:linear-gradient(135deg,#79aaff,#5eead4);display:grid;place-items:center;color:#061426;font-size:19px;font-weight:950;box-shadow:0 7px 22px #4d94ff2b}.brand strong{font-size:14px;letter-spacing:.5px}.brand small{display:block;color:var(--muted);font-size:11px}
.navlabel{color:#627792;font-size:10px;font-weight:850;letter-spacing:1.6px;padding:13px 11px 8px}.nav{display:grid;gap:5px}.nav a{display:flex;gap:11px;align-items:center;text-decoration:none;color:#9fb1ca;padding:11px 12px;border-radius:10px;font-size:13px;border:1px solid transparent}.nav a:hover,.nav a.active{background:#15263d;color:#eaf3ff;border-color:#29415f}.navicon{width:22px;text-align:center;color:#83b6ff;font-size:15px}.sidebottom{margin-top:auto;border:1px solid var(--line);background:#101d30;border-radius:12px;padding:13px}.sidebottom b{font-size:12px;display:block}.sidebottom p{font-size:11px;color:var(--muted);margin:5px 0 0}
.main{margin-left:236px;min-width:0}.topbar{height:68px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 clamp(20px,3vw,46px);background:#0a1423d9;position:sticky;top:0;z-index:2;backdrop-filter:blur(14px)}.crumb{font-size:12px;color:var(--muted)}.crumb b{color:var(--text);font-weight:700}.topright{display:flex;align-items:center;gap:12px}.live{display:flex;align-items:center;gap:7px;border:1px solid #245c50;background:#0d2927;color:#8ef1d5;border-radius:99px;padding:7px 11px;font-size:10px;font-weight:850;letter-spacing:.5px}.live i{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green)}
.content{max-width:1550px;margin:auto;padding:32px clamp(20px,3vw,46px) 44px}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:25px;margin-bottom:25px}.eyebrow{color:var(--cyan);font-size:10px;font-weight:900;letter-spacing:2px;text-transform:uppercase}h1{font-size:clamp(29px,3vw,42px);line-height:1.12;letter-spacing:-1.5px;margin:9px 0 11px}.lead{max-width:750px;color:var(--muted);margin:0;font-size:14px}.heroactions{display:flex;gap:9px;flex-wrap:wrap}.btn{border:1px solid #314761;background:#182941;color:#e1edff;border-radius:10px;padding:10px 13px;font-size:12px;font-weight:800}.btn.primary{background:linear-gradient(130deg,#7daeff,#68d9db);border:0;color:#071426}.btn.ghost{background:transparent}
.kpi-banner{display:flex;align-items:center;gap:15px;padding:16px 19px;border:1px solid #27405b;border-radius:15px;background:linear-gradient(100deg,#122842,#102034);margin-bottom:19px}.shield{width:43px;height:43px;display:grid;place-items:center;border-radius:13px;background:#1a3554;color:#9dc7ff;font-size:22px;flex-shrink:0}.kpi-copy{flex:1}.kpi-copy b{font-size:13px;display:block}.kpi-copy span{font-size:12px;color:var(--muted)}.posture{min-width:175px}.postureline{height:6px;background:#263b53;border-radius:99px;overflow:hidden;margin:7px 0 4px}.postureline span{display:block;width:0;height:100%;background:linear-gradient(90deg,var(--green),var(--amber),var(--red));transition:width .25s}.posture small{color:var(--muted);font-size:10px}
.grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(300px,.9fr);gap:18px}.card{background:linear-gradient(145deg,#111f32,#0f1a2b);border:1px solid var(--line);border-radius:16px;padding:21px;min-width:0;box-shadow:0 12px 32px #00000010}.card.full{grid-column:1/-1}.head{display:flex;gap:12px;align-items:flex-start;margin-bottom:16px}.step{width:32px;height:32px;border-radius:10px;border:1px solid #34537a;background:#172e4c;color:#9cc6ff;display:grid;place-items:center;font-size:12px;font-weight:900;flex-shrink:0}.head h2{font-size:16px;margin:1px 0 4px;letter-spacing:-.3px}.sub{font-size:12px;color:var(--muted);margin:0}
.presets{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 12px}.presets label{font-size:11px;color:var(--muted);margin-right:2px}.preset{border:1px solid #30455f;background:#13243a;color:#bcd0e8;border-radius:8px;padding:7px 10px;font-size:11px;font-weight:750}.preset:hover{border-color:#70a9ff}.preset.selected{border-color:#6ea8fe;color:#dceaff;background:#1a3556}
textarea{width:100%;min-height:230px;resize:vertical;display:block;border:1px solid #30435d;border-radius:11px;background:#081321;color:#d8e7fb;padding:14px;font:12px/1.7 "Cascadia Code",Consolas,monospace;outline:none}textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px #6ea8fe1b}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:13px}.message{font-size:12px;min-height:19px;color:var(--muted);margin:12px 0 0}.message.success{color:var(--green)}.message.error{color:var(--red)}
.checks{display:grid;gap:10px}.check{display:flex;align-items:flex-start;gap:11px;padding:12px;border:1px solid #273b55;border-radius:11px;background:#0b1727}.checknum{width:27px;height:27px;border-radius:8px;background:#193454;color:#9fc6ff;display:grid;place-items:center;font-size:11px;font-weight:900;flex-shrink:0}.check b{display:block;font-size:12px;margin-bottom:2px}.check span{display:block;color:var(--muted);font-size:11px}
.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:11px}.stat{border:1px solid #293c55;border-radius:12px;background:#0b1727;padding:15px;min-width:0}.statlabel{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:11px}.dot{width:6px;height:6px;border-radius:50%;background:var(--blue);flex-shrink:0}.stat b{font-size:28px;line-height:1.35;letter-spacing:-.8px;display:block;margin-top:7px;font-variant-numeric:tabular-nums}.stat.risk b{color:var(--red)}.stat.warn b{color:var(--amber)}.stat.safe b{color:var(--green)}
.tablewrap{overflow:auto;border:1px solid #293c55;border-radius:11px}table{border-collapse:collapse;width:100%;min-width:800px;font-size:12px}th{background:#17283f;color:#aebfda;font-size:10px;text-transform:uppercase;letter-spacing:.65px}th,td{text-align:left;vertical-align:top;padding:12px 13px;border-bottom:1px solid #263950}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#192a40}.severity{display:inline-block;padding:4px 7px;border-radius:6px;font-size:10px;font-weight:900}.HIGH{color:#ffb1bd;background:#482331}.MEDIUM{color:#ffdc88;background:#443719}.INFO{color:#a9ccff;background:#1a3452}.score{font-weight:900;font-variant-numeric:tabular-nums}.empty{text-align:center;color:var(--muted);padding:24px}
.filters{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 13px}.filters input,.filters select{background:#0a1727;border:1px solid #30445f;color:var(--text);border-radius:9px;padding:10px 12px;min-height:39px;font:inherit;font-size:12px}.filters input{flex:1;min-width:200px}.filters select{min-width:140px}.filtercount{font-size:11px;color:var(--muted);white-space:nowrap}
.riskbars{display:grid;gap:14px}.riskrow{display:grid;grid-template-columns:115px minmax(60px,1fr) 35px;align-items:center;gap:12px;font-size:12px;color:var(--muted)}.risktrack{height:10px;background:#081321;border:1px solid #293c55;border-radius:99px;overflow:hidden}.riskfill{height:100%;border-radius:99px;transition:width .25s}.riskfill.high{background:linear-gradient(90deg,#ef4444,#fb7185)}.riskfill.medium{background:linear-gradient(90deg,#d97706,#fbbf24)}.riskfill.info{background:linear-gradient(90deg,#3b82f6,#67e8f9)}.risknumber{text-align:right;color:var(--text);font-weight:900}
.validation-list{display:grid;gap:8px;list-style:none;margin:0;padding:0}.validation-list li{padding:11px 13px;border:1px solid #293c55;background:#0b1727;border-radius:9px;font-size:12px}.validation-list .success{color:#8ce8c6;border-color:#285748}.validation-list .error{color:#ffb1bd;border-color:#60303e}
.footer{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:#7186a2;font-size:11px;padding:19px 2px 0}.footer strong{color:#a5b8d2;font-weight:700}
@media(min-width:1500px){.content{padding-top:38px}.card{padding:24px}.grid{gap:20px}}
@media(max-width:1050px){.sidebar{width:68px;padding:18px 9px}.brand{padding:0 5px 25px}.brandtext,.navlabel,.navtext,.sidebottom{display:none}.brandmark{width:42px;height:42px}.nav a{justify-content:center;padding:12px 7px}.navicon{width:auto}.main{margin-left:68px}.stats{grid-template-columns:repeat(3,minmax(0,1fr))}.grid{grid-template-columns:minmax(0,1fr)}.card.full{grid-column:auto}}
@media(max-width:600px){.topbar{height:58px;padding:0 15px}.content{padding:22px 13px 30px}.hero{align-items:flex-start;flex-direction:column}.heroactions{width:100%}.kpi-banner{align-items:flex-start;flex-wrap:wrap}.posture{width:100%}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:15px}.lead{font-size:13px}.grid{gap:13px}.status-extra{display:none}}
@media print{body{background:#fff!important;color:#172033!important;font-size:11px}.sidebar,.topbar,.heroactions,.presets,.actions,.filters,.sidebottom{display:none!important}.main{margin:0!important}.content{max-width:none;padding:0!important}.card,.stat,.kpi-banner{background:#fff!important;color:#172033!important;box-shadow:none!important;border:1px solid #cbd5e1!important;break-inside:avoid}.sub,.lead,.kpi-copy span,.footer,.statlabel,.riskrow{color:#475569!important}.tablewrap{overflow:visible!important;border-color:#cbd5e1!important}table{min-width:0!important;font-size:9px}th,td{padding:5px!important;border-color:#cbd5e1!important;color:#172033!important}th{background:#e2e8f0!important}.severity{border:1px solid #94a3b8}.risktrack{border-color:#94a3b8!important}.empty{color:#475569!important}}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
 <div class="brand"><div class="brandmark">S</div><div class="brandtext"><strong>SENTINEL</strong><small>Security workspace</small></div></div>
 <div class="navlabel">WORKSPACE</div>
 <nav class="nav"><a class="active" href="#overview"><span class="navicon">▦</span><span class="navtext">Overview</span></a><a href="#input"><span class="navicon">⌘</span><span class="navtext">Rule analysis</span></a><a href="#findings"><span class="navicon">⚑</span><span class="navtext">Findings</span></a><a href="#validation"><span class="navicon">✓</span><span class="navtext">Validation</span></a></nav>
 <div class="navlabel">PROJECT</div><nav class="nav"><a href="#about"><span class="navicon">ⓘ</span><span class="navtext">How it works</span></a></nav>
 <div class="sidebottom"><b>◈ Local analysis mode</b><p>Sample data is processed on this computer. No cloud firewall is modified.</p></div>
</aside>
<div class="main">
<header class="topbar"><div class="crumb">Security workspace &nbsp;/&nbsp; <b>Firewall analyzer</b></div><div class="topright"><span class="status-extra" style="font-size:11px;color:var(--muted)">Milestone 4 prototype</span><span class="live"><i></i> LOCAL DEMO</span></div></header>
<main class="content" id="overview">
<section class="hero"><div><div class="eyebrow">Cloud security · Configuration review</div><h1>Cloud Firewall Rule Analyzer</h1><p class="lead">Find risky network exposure, validate firewall configurations, and turn technical findings into clear, actionable recommendations.</p></div><div class="heroactions"><button class="btn ghost" id="resetTop">↺ Reset demo</button><button class="btn primary" id="runTop">▶ Run analysis</button></div></section>
<section class="kpi-banner" aria-live="polite"><div class="shield">⬡</div><div class="kpi-copy"><b id="postureTitle">Security posture awaiting analysis</b><span id="postureText">Run the sample rules to calculate a demo risk overview.</span></div><div class="posture"><div class="postureline"><span id="postureBar"></span></div><small id="postureScore">No score calculated</small></div></section>
<div class="grid">
<section class="card" id="input">
 <div class="head"><div class="step">01</div><div><h2>Firewall rule input</h2><p class="sub">Choose a scenario or edit the JSON directly.</p></div></div>
 <div class="presets"><label>DEMO SCENARIOS</label><button class="preset selected" data-preset="risky">Risky rules</button><button class="preset" data-preset="safe">Safer rules</button><button class="preset" data-preset="invalid">Invalid input</button></div>
 <textarea id="rules" spellcheck="false" aria-label="Firewall rules JSON">[
  {"id":"FW-001","source":"0.0.0.0/0","protocol":"tcp","port":22,"action":"allow"},
  {"id":"FW-002","source":"0.0.0.0/0","protocol":"tcp","port":443,"action":"allow"},
  {"id":"FW-003","source":"10.0.0.0/8","protocol":"tcp","port":"8000-8100","action":"allow"},
  {"id":"FW-004","source":"0.0.0.0/0","protocol":"tcp","port":5432,"action":"allow"}
]</textarea>
 <div class="actions"><button class="btn primary" id="analyze">▶ &nbsp; Analyze rules</button><button class="btn" id="restore">Restore default</button><button class="btn" id="download">↓ &nbsp; Export JSON</button><button class="btn" id="downloadCsv">↓ &nbsp; Export findings CSV</button><button class="btn" id="copySummary">▣ &nbsp; Copy summary</button><button class="btn" id="printReport">⎙ &nbsp; Print report</button></div>
 <p id="message" class="message" role="status">Ready. Select a scenario and run analysis.</p>
</section>
<aside class="card" id="about">
 <div class="head"><div class="step">i</div><div><h2>Analysis pipeline</h2><p class="sub">What happens when you click Analyze.</p></div></div>
 <div class="checks">
  <div class="check"><div class="checknum">1</div><div><b>Validate input</b><span>Check source CIDR, protocol, port and action fields.</span></div></div>
  <div class="check"><div class="checknum">2</div><div><b>Inspect exposure</b><span>Check selected public admin and database ports.</span></div></div>
  <div class="check"><div class="checknum">3</div><div><b>Score findings</b><span>Show severity, score, evidence and remediation guidance.</span></div></div>
  <div class="check"><div class="checknum">4</div><div><b>Generate report</b><span>Save report.json and report.html for review.</span></div></div>
 </div>
</aside>
<section class="card full">
 <div class="head"><div class="step">02</div><div><h2>Analysis overview</h2><p class="sub">Counts from the latest submitted rule set.</p></div></div>
 <div class="stats" id="stats">
 <div class="stat"><div class="statlabel"><i class="dot"></i>Total rules</div><b>—</b></div><div class="stat"><div class="statlabel"><i class="dot"></i>Valid rules</div><b>—</b></div><div class="stat"><div class="statlabel"><i class="dot"></i>Invalid rules</div><b>—</b></div><div class="stat"><div class="statlabel"><i class="dot"></i>Findings</div><b>—</b></div><div class="stat risk"><div class="statlabel"><i class="dot" style="background:var(--red)"></i>High risk</div><b>—</b></div><div class="stat warn"><div class="statlabel"><i class="dot" style="background:var(--amber)"></i>Medium risk</div><b>—</b></div>
 </div>
</section>
<section class="card full" id="findings">
 <div class="head"><div class="step">03</div><div><h2>Findings & recommendations</h2><p class="sub">Review each flagged rule, supporting evidence, and suggested next step.</p></div></div>
 <div class="filters"><input id="findingSearch" type="search" placeholder="Search rule ID, issue, or evidence…" aria-label="Search findings"><select id="severityFilter" aria-label="Filter findings by severity"><option value="ALL">All severities</option><option value="HIGH">High risk</option><option value="MEDIUM">Medium risk</option><option value="INFO">Informational</option></select><span id="resultCount" class="filtercount">0 findings</span></div><div class="tablewrap"><table><thead><tr><th>Severity</th><th>Score</th><th>Rule ID</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody id="findingRows"><tr><td colspan="6" class="empty">No analysis run yet. Analyze the sample to see findings.</td></tr></tbody></table></div>
</section>
<section class="card full" id="riskDistribution"><div class="head"><div class="step">05</div><div><h2>Risk distribution</h2><p class="sub">Visual breakdown of findings by severity for the current sample.</p></div></div><div id="riskBars" class="riskbars"><div class="empty">Run an analysis to view the risk breakdown.</div></div></section>
<section class="card full" id="exposureCheck"><div class="head"><div class="step">06</div><div><h2>Firewall exposure explorer</h2><p class="sub">Inspect which input rules allow a selected TCP port from a selected IPv4 address. Educational rule matching only; this does not simulate routing, rule priority, or cloud-provider behavior.</p></div></div><div class="filters"><input id="probeIp" aria-label="Source IPv4 address" placeholder="Source IPv4 (e.g. 8.8.8.8)" value="8.8.8.8"><input id="probePort" aria-label="Destination TCP port" type="number" min="1" max="65535" value="22"><button class="btn primary" id="probeRun">Check exposure</button></div><div id="probeResult" class="message">Run an analysis, then test an IP address and port.</div></section>
<section class="card full" id="validation">
 <div class="head"><div class="step">04</div><div><h2>Input validation</h2><p class="sub">Validation messages help explain malformed or unsupported rule data.</p></div></div>
 <ul id="errors" class="validation-list"><li class="empty">No validation results yet.</li></ul>
</section>
<footer class="footer"><span><strong>SENTINEL</strong> · Cloud Firewall Rule Analyzer</span><span>Educational prototype · Predefined checks · No live cloud changes</span></footer>
</main>
</div>
</div>
<script>
const textarea=document.getElementById('rules');
const initial=textarea.value;
const presets={
risky:initial,
safe:JSON.stringify([
 {"id":"SAFE-001","source":"10.10.0.0/16","protocol":"tcp","port":22,"action":"allow"},
 {"id":"SAFE-002","source":"0.0.0.0/0","protocol":"tcp","port":443,"action":"allow"},
 {"id":"SAFE-003","source":"192.168.1.0/24","protocol":"tcp","port":5432,"action":"allow"}
],null,2),
invalid:JSON.stringify([
 {"id":"BAD-001","source":"not-a-cidr","protocol":"tcp","port":70000,"action":"allow"},
 {"id":"BAD-002","source":"0.0.0.0/0","protocol":"unknown","port":22,"action":"permit"}
],null,2)
};
let lastReport=null;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function setMessage(text,kind=''){const m=document.getElementById('message');m.className='message '+kind;m.textContent=text}
function choosePreset(name){textarea.value=presets[name];document.querySelectorAll('[data-preset]').forEach(b=>b.classList.toggle('selected',b.dataset.preset===name));setMessage('Loaded '+name+' demo scenario. Click Analyze rules to run it.')}
document.querySelectorAll('[data-preset]').forEach(b=>b.addEventListener('click',()=>choosePreset(b.dataset.preset)));
document.getElementById('restore').onclick=()=>{choosePreset('risky');setMessage('Default sample restored. Click Analyze rules to run it.')};
document.getElementById('resetTop').onclick=()=>{choosePreset('risky');lastReport=null;setMessage('Demo reset. Ready for a new analysis.')};
document.getElementById('runTop').onclick=()=>document.getElementById('analyze').click();
document.getElementById('analyze').onclick=async()=>{
 try{
  setMessage('Analyzing rules…');
  const rules=JSON.parse(textarea.value);
  if(!Array.isArray(rules))throw Error('Input must be a JSON list of firewall rules.');
  const response=await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rules})});
  const data=await response.json();if(!response.ok)throw Error(data.error||'Analysis failed.');
  lastReport=data;const s=data.summary;
  const items=[['Total rules',s.total_rules,''],['Valid rules',s.valid_rules,'safe'],['Invalid rules',s.invalid_rules,s.invalid_rules?'risk':''],['Findings',s.findings,''],['High risk',s.high,'risk'],['Medium risk',s.medium,'warn']];
  document.getElementById('stats').innerHTML=items.map((x,i)=>'<div class="stat '+x[2]+'"><div class="statlabel"><i class="dot" style="background:'+(i===4?'var(--red)':i===5?'var(--amber)':i===1?'var(--green)':'var(--blue)')+'"></i>'+esc(x[0])+'</div><b>'+esc(x[1])+'</b></div>').join('');
  renderFindings();
  const riskLevels=[{name:'High risk',key:'HIGH',cls:'high'},{name:'Medium risk',key:'MEDIUM',cls:'medium'},{name:'Informational',key:'INFO',cls:'info'}];
  const riskCounts=riskLevels.map(x=>({...x,count:data.findings.filter(f=>f.severity===x.key).length}));
  const maxRisk=Math.max(1,...riskCounts.map(x=>x.count));
  document.getElementById('riskBars').innerHTML=riskCounts.map(x=>'<div class="riskrow"><span>'+x.name+'</span><div class="risktrack"><div class="riskfill '+x.cls+'" style="width:'+(x.count/maxRisk*100)+'%"></div></div><b class="risknumber">'+x.count+'</b></div>').join('');
  document.getElementById('errors').innerHTML=data.validation_errors.length?data.validation_errors.map(e=>'<li class="error">'+esc(e)+'</li>').join(''):'<li class="success">✓ No validation errors. All submitted rules passed input validation.</li>';
  const score=Math.min(100,Math.round((Number(s.high||0)*35+Number(s.medium||0)*18+Number(s.findings||0)*5+Number(s.invalid_rules||0)*10)/Math.max(1,Number(s.total_rules||0))));
  document.getElementById('postureBar').style.width=score+'%';
  document.getElementById('postureTitle').textContent=score>=55?'Elevated exposure detected':score>=25?'Review recommended':'No major flagged exposure in this sample';
  document.getElementById('postureText').textContent=s.findings+' finding(s) and '+s.invalid_rules+' invalid rule(s) detected by the predefined checks.';
  document.getElementById('postureScore').textContent='Demo risk indicator: '+score+'/100 · heuristic, not a compliance rating';
  setMessage('✓ Analysis complete. Results displayed; report.json and report.html were saved.','success');
 }catch(e){setMessage('Could not analyze input: '+e.message,'error')}
};
function renderFindings(){
 if(!lastReport)return;
 const query=document.getElementById('findingSearch').value.trim().toLowerCase();
 const severity=document.getElementById('severityFilter').value;
 const rows=lastReport.findings.filter(f=>{
  const matchesSeverity=severity==='ALL'||f.severity===severity;
  const text=[f.rule_id,f.title,f.evidence,f.recommendation,f.severity].join(' ').toLowerCase();
  return matchesSeverity&&text.includes(query);
 });
 document.getElementById('resultCount').textContent=rows.length+' of '+lastReport.findings.length+' findings';
 document.getElementById('findingRows').innerHTML=rows.length?rows.map(f=>'<tr><td><span class="severity '+esc(f.severity)+'">'+esc(f.severity)+'</span></td><td class="score">'+esc(f.risk_score)+'</td><td>'+esc(f.rule_id)+'</td><td>'+esc(f.title)+'</td><td>'+esc(f.evidence)+'</td><td>'+esc(f.recommendation)+'</td></tr>').join(''):'<tr><td colspan="6" class="empty">No findings match the current search or severity filter.</td></tr>';
}
document.getElementById('findingSearch').addEventListener('input',renderFindings);
document.getElementById('severityFilter').addEventListener('change',renderFindings);
document.getElementById('downloadCsv').onclick=()=>{
 if(!lastReport){setMessage('Run an analysis first, then export findings.','error');return}
 const fields=['severity','risk_score','rule_id','title','evidence','recommendation'];
 const quote=v=>'"'+String(v??'').replace(/"/g,'""')+'"';
 const csv=[fields.join(','),...lastReport.findings.map(f=>fields.map(k=>quote(f[k])).join(','))].join('\\r\\n');
 const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8;'})),a=document.createElement('a');
 a.href=url;a.download='firewall-findings.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
document.getElementById('copySummary').onclick=async()=>{
 if(!lastReport){setMessage('Run an analysis first, then copy the summary.','error');return}
 const s=lastReport.summary;
 const summary='Cloud Firewall Rule Analyzer — Analysis Summary\\nTotal rules: '+s.total_rules+'\\nValid rules: '+s.valid_rules+'\\nInvalid rules: '+s.invalid_rules+'\\nFindings: '+s.findings+'\\nHigh risk: '+s.high+'\\nMedium risk: '+s.medium+'\\nInformational: '+s.info;
 try{await navigator.clipboard.writeText(summary);setMessage('Analysis summary copied to clipboard.','success')}
 catch(e){setMessage('Clipboard access was blocked by the browser. Use Export JSON instead.','error')}
};
document.getElementById('printReport').onclick=()=>{
 if(!lastReport){setMessage('Run an analysis first, then print the report.','error');return}
 window.print();
};
function ipv4ToInt(ip){const parts=ip.split('.');if(parts.length!==4||parts.some(x=>!/^(0|[1-9][0-9]{0,2})$/.test(x)||Number(x)>255))throw Error('Enter a valid IPv4 address.');return parts.reduce((v,x)=>v*256+Number(x),0)}
function matchesCidr(ip,cidr){const parts=String(cidr).split('/');if(parts.length!==2)return false;const prefix=Number(parts[1]);if(!Number.isInteger(prefix)||prefix<0||prefix>32)return false;try{const addr=ipv4ToInt(parts[0]);const value=ipv4ToInt(ip);const divisor=2**(32-prefix);return Math.floor(addr/divisor)===Math.floor(value/divisor)}catch(e){return false}}
function portMatches(value,port){if(typeof value==='number')return value===port;const v=String(value);if(/^\\d+$/.test(v))return Number(v)===port;const m=v.match(/^(\\d+)-(\\d+)$/);return !!m&&port>=Number(m[1])&&port<=Number(m[2])}
document.getElementById('probeRun').onclick=()=>{
 const result=document.getElementById('probeResult');
 try{
  if(!lastReport)throw Error('Click Analyze rules before checking exposure.');
  const ip=document.getElementById('probeIp').value.trim();ipv4ToInt(ip);
  const port=Number(document.getElementById('probePort').value);if(!Number.isInteger(port)||port<1||port>65535)throw Error('Port must be between 1 and 65535.');
  const rules=JSON.parse(textarea.value);
  const matching=rules.filter(r=>r&&typeof r==='object'&&String(r.action).toLowerCase()==='allow'&&String(r.protocol).toLowerCase()==='tcp'&&matchesCidr(ip,r.source)&&portMatches(r.port,port));
  result.className='message '+(matching.length?'error':'success');
  result.textContent=matching.length?'Potential exposure: '+matching.length+' matching ALLOW rule(s): '+matching.map(r=>r.id||'(unnamed)').join(', ')+'. This is a rule-level match, not proof of network reachability.':'No matching TCP ALLOW rule found in the submitted sample. This does not prove the service is inaccessible.';
 }catch(e){result.className='message error';result.textContent=e.message}
};
document.getElementById('download').onclick=()=>{
 if(!lastReport){setMessage('Run an analysis first, then export the report.','error');return}
 const blob=new Blob([JSON.stringify(lastReport,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download='firewall-analysis-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
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
