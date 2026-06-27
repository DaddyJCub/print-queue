"""The single-page device UI (HTML/CSS/JS) served at ``/``.

Kept as one self-contained string so the agent needs no template engine or
static-file plumbing — just the stdlib server.
"""

from __future__ import annotations

import json


def render_page(info: dict, api_key: str = "") -> str:
    boot = json.dumps({"info": info, "apiKey": api_key})
    return _PAGE.replace("/*__BOOT__*/", boot)


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Printer</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         background:#0a0a0b; color:#e7e7ea; }
  header { padding:14px 18px; border-bottom:1px solid #232327; display:flex; align-items:center; gap:12px; }
  header .dot { width:11px; height:11px; border-radius:50%; background:#52525b; }
  header .dot.on { background:#34d399; }
  header h1 { font-size:17px; margin:0; font-weight:650; }
  header .sub { font-size:12px; color:#8a8a93; }
  .wrap { max-width:1100px; margin:0 auto; padding:16px; display:grid; gap:16px;
          grid-template-columns: 1fr 1fr; }
  .card { background:#141417; border:1px solid #232327; border-radius:16px; padding:16px; }
  .card h2 { font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:#9a9aa3; margin:0 0 12px; }
  .full { grid-column: 1 / -1; }
  .stat { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid #1d1d21; font-size:14px; }
  .stat:last-child { border-bottom:0; }
  .stat b { color:#fff; font-weight:600; }
  .bar { height:10px; background:#1d1d21; border-radius:6px; overflow:hidden; margin-top:8px; }
  .bar > div { height:100%; background:#6366f1; width:0%; transition:width .4s; }
  button { font:inherit; border:0; border-radius:10px; padding:8px 12px; background:#26262b;
           color:#e7e7ea; cursor:pointer; }
  button:hover { background:#323239; }
  button.primary { background:#4f46e5; } button.primary:hover { background:#6366f1; }
  button.warn { background:#7c2d12; color:#fed7aa; } button.warn:hover { background:#9a3412; }
  button.danger { background:#7f1d1d; color:#fecaca; } button.danger:hover { background:#991b1b; }
  button:disabled { opacity:.4; cursor:not-allowed; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .files { display:flex; flex-direction:column; gap:6px; max-height:260px; overflow:auto; }
  .file { display:flex; align-items:center; justify-content:space-between; gap:8px;
          background:#0f0f12; border:1px solid #232327; border-radius:10px; padding:8px 10px; font-size:13px; }
  .file .nm { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .muted { color:#8a8a93; font-size:12px; }
  input[type=number] { width:74px; background:#0f0f12; border:1px solid #2b2b31; color:#fff;
                       border-radius:8px; padding:6px; }
  img.cam { width:100%; border-radius:12px; display:block; background:#000; }
  .jog { display:grid; grid-template-columns:repeat(3,1fr); gap:6px; max-width:230px; }
  .jog button { padding:10px 0; }
  #toast { position:fixed; bottom:18px; left:50%; transform:translateX(-50%); background:#26262b;
           border:1px solid #3a3a42; padding:10px 16px; border-radius:10px; opacity:0; transition:opacity .2s;
           pointer-events:none; font-size:14px; }
  #toast.show { opacity:1; }
  .modal { position:fixed; inset:0; background:rgba(0,0,0,.55); display:none; align-items:center; justify-content:center; z-index:20; }
  .modal.show { display:flex; }
  .modal .box { width:min(560px, calc(100% - 24px)); background:#141417; border:1px solid #2b2b31; border-radius:14px; padding:14px; }
  .modal .ttl { font-size:15px; font-weight:650; margin-bottom:8px; }
  .modal .sub { color:#a1a1aa; font-size:13px; margin-bottom:10px; }
  .modal .opts { display:grid; grid-template-columns:1fr auto; gap:8px; align-items:center; margin-bottom:12px; }
  .modal label { color:#c7c7d0; font-size:13px; }
  .modal input[type=number] { width:90px; }
  .modal .actions { display:flex; gap:8px; justify-content:flex-end; }
  @media (max-width:760px){ .wrap{ grid-template-columns:1fr; } }
</style>
</head>
<body>
<header>
  <span id="dot" class="dot"></span>
  <div>
    <h1 id="pname">Printer</h1>
    <div class="sub" id="psub"></div>
  </div>
</header>
<div class="wrap">
  <div class="card">
    <h2>Status</h2>
    <div class="stat"><span>State</span><b id="s-state">—</b></div>
    <div class="stat"><span>Nozzle</span><b id="s-noz">—</b></div>
    <div class="stat"><span>Bed</span><b id="s-bed">—</b></div>
    <div class="stat"><span>File</span><b id="s-file">—</b></div>
    <div class="stat"><span>Progress</span><b id="s-prog">—</b></div>
    <div class="bar"><div id="s-barfill"></div></div>
    <div class="row" style="margin-top:14px">
      <button class="warn" id="b-pause">Pause</button>
      <button id="b-resume">Resume</button>
      <button class="danger" id="b-cancel">Cancel</button>
    </div>
  </div>

  <div class="card">
    <h2>Camera</h2>
    <img class="cam" id="cam" alt="camera" />
    <div class="muted" id="cam-msg" style="display:none">No camera configured.</div>
  </div>

  <div class="card full">
    <h2>Files</h2>
    <div class="row" style="margin-bottom:10px">
      <input type="file" id="up" accept=".gcode,.gco,.g" />
      <button class="primary" id="b-upload">Upload</button>
      <span class="muted">Or use Orca's “Send to printer” (OctoPrint host).</span>
    </div>
    <div class="files" id="files"></div>
  </div>

  <div class="card">
    <h2>Temperatures</h2>
    <div class="row" style="margin-bottom:8px">
      <span style="width:60px">Nozzle</span>
      <input type="number" id="t-noz" value="210" min="0" max="300" />
      <button id="b-noz">Set</button>
      <button id="b-noz-off">Off</button>
    </div>
    <div class="row">
      <span style="width:60px">Bed</span>
      <input type="number" id="t-bed" value="60" min="0" max="120" />
      <button id="b-bed">Set</button>
      <button id="b-bed-off">Off</button>
    </div>
  </div>

  <div class="card">
    <h2>Move</h2>
    <div class="row" style="margin-bottom:10px">
      <span class="muted">Step</span>
      <select id="step" style="background:#0f0f12;color:#fff;border:1px solid #2b2b31;border-radius:8px;padding:6px">
        <option>0.1</option><option selected>1</option><option>10</option><option>50</option>
      </select>
      <button id="b-home">Home all</button>
    </div>
    <div class="jog">
      <span></span><button data-ax="Y" data-s="1">Y+</button><span></span>
      <button data-ax="X" data-s="-1">X−</button><button id="b-homexy">⌂</button><button data-ax="X" data-s="1">X+</button>
      <span></span><button data-ax="Y" data-s="-1">Y−</button><span></span>
      <button data-ax="Z" data-s="1">Z+</button><span></span><button data-ax="Z" data-s="-1">Z−</button>
    </div>
  </div>
</div>
<div id="toast"></div>
<div id="newfile-modal" class="modal" aria-hidden="true">
  <div class="box">
    <div class="ttl">New file received</div>
    <div class="sub" id="newfile-name">A new file is ready.</div>
    <div class="opts">
      <label for="nf-noz">Preheat nozzle</label>
      <input type="number" id="nf-noz" min="0" max="300" value="210" />
      <label for="nf-bed">Preheat bed</label>
      <input type="number" id="nf-bed" min="0" max="120" value="60" />
    </div>
    <div class="actions">
      <button id="nf-dismiss">Dismiss</button>
      <button id="nf-start" class="primary">Start now</button>
      <button id="nf-preheat-start" class="warn">Preheat + Start</button>
    </div>
  </div>
</div>
<script>
const BOOT = /*__BOOT__*/;
const KEY = BOOT.apiKey || "";
const H = KEY ? { "X-Api-Key": KEY } : {};
let camFails = 0;
let knownFiles = new Set();
let initializedFiles = false;
let pendingFile = null;

function toast(m){ const t=document.getElementById("toast"); t.textContent=m; t.classList.add("show");
  clearTimeout(t._t); t._t=setTimeout(()=>t.classList.remove("show"),2200); }
async function api(path, opts={}){
  opts.headers = Object.assign({}, H, opts.headers||{});
  const r = await fetch(path, opts);
  if(!r.ok){ let m="Error "+r.status; try{ m=(await r.json()).error||m; }catch(e){} toast(m); throw new Error(m); }
  return r.headers.get("content-type","").includes("json") ? r.json() : r;
}
function fmtBytes(n){ if(!n) return "0"; const u=["B","KB","MB"]; let i=0,v=n; while(v>=1024&&i<2){v/=1024;i++;} return v.toFixed(1)+u[i]; }
function showNewFileModal(name){
  pendingFile = name;
  document.getElementById("newfile-name").textContent = "File ready: " + name;
  document.getElementById("nf-noz").value = document.getElementById("t-noz").value || 210;
  document.getElementById("nf-bed").value = document.getElementById("t-bed").value || 60;
  const m = document.getElementById("newfile-modal");
  m.classList.add("show");
  m.setAttribute("aria-hidden", "false");
}
function hideNewFileModal(){
  const m = document.getElementById("newfile-modal");
  m.classList.remove("show");
  m.setAttribute("aria-hidden", "true");
  pendingFile = null;
}

document.getElementById("pname").textContent = BOOT.info.name || "Printer";
document.getElementById("psub").textContent = (BOOT.info.printer_code||"") + " · agent v" + (BOOT.info.agent_version||"");

async function refresh(){
  let s; try { s = await api("/api/state"); } catch(e){ document.getElementById("dot").classList.remove("on"); return; }
  document.getElementById("dot").classList.toggle("on", !!s.connected);
  document.getElementById("s-state").textContent = s.state || "—";
  const nz = s.nozzle_temp!=null ? Math.round(s.nozzle_temp)+" / "+Math.round(s.nozzle_target||0)+"°" : "—";
  const bd = s.bed_temp!=null ? Math.round(s.bed_temp)+" / "+Math.round(s.bed_target||0)+"°" : "—";
  document.getElementById("s-noz").textContent = nz;
  document.getElementById("s-bed").textContent = bd;
  document.getElementById("s-file").textContent = s.current_file || "—";
  const p = s.progress!=null ? s.progress : 0;
  document.getElementById("s-prog").textContent = (s.progress!=null ? p+"%" : "—");
  document.getElementById("s-barfill").style.width = p+"%";
  const printing = s.state==="printing" || s.state==="uploading" || s.print_active;
  document.getElementById("b-pause").disabled = !printing;
  document.getElementById("b-cancel").disabled = !printing;
}
async function loadFiles(){
  let d; try { d = await api("/api/files"); } catch(e){ return; }
  const box = document.getElementById("files");
  const currentNames = new Set((d.files || []).map(f => f.name));
  if (!initializedFiles) {
    knownFiles = new Set(currentNames);
    initializedFiles = true;
  } else {
    const newcomers = (d.files || []).filter(f => !knownFiles.has(f.name));
    if (newcomers.length) {
      // list is newest-first from backend; prefer first newcomer for prompt.
      showNewFileModal(newcomers[0].name);
    }
    knownFiles = new Set(currentNames);
  }
  if(!d.files.length){ box.innerHTML = '<div class="muted">No files yet — upload one or send from Orca.</div>'; return; }
  box.innerHTML = "";
  d.files.forEach(f=>{
    const el = document.createElement("div"); el.className="file";
    el.innerHTML = `<span class="nm" title="${f.name}">${f.name} <span class="muted">· ${fmtBytes(f.size)}</span></span>`;
    const row = document.createElement("div"); row.className="row";
    const pb = document.createElement("button"); pb.className="primary"; pb.textContent="Print";
    pb.onclick = async()=>{ await api("/api/print",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file:f.name})}); toast("Print started"); refresh(); };
    const db = document.createElement("button"); db.className="danger"; db.textContent="✕";
    db.onclick = async()=>{ await api("/api/files/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file:f.name})}); loadFiles(); };
    row.appendChild(pb); row.appendChild(db); el.appendChild(row); box.appendChild(el);
  });
}
function post(path, body){ return api(path,{method:"POST",headers:body?{"Content-Type":"application/json"}:{},body:body?JSON.stringify(body):undefined}); }

document.getElementById("b-upload").onclick = async()=>{
  const f = document.getElementById("up").files[0]; if(!f){ toast("Pick a file"); return; }
  const fd = new FormData(); fd.append("file", f);
  const res = await api("/api/files",{method:"POST",body:fd});
  toast("Uploaded");
  document.getElementById("up").value="";
  if (res && res.name) showNewFileModal(res.name);
  loadFiles();
};
document.getElementById("b-pause").onclick = ()=>post("/api/pause").then(()=>toast("Paused"));
document.getElementById("b-resume").onclick = ()=>post("/api/resume").then(()=>toast("Resumed"));
document.getElementById("b-cancel").onclick = ()=>{ if(confirm("Cancel the print?")) post("/api/cancel").then(()=>{toast("Canceled");refresh();}); };
document.getElementById("b-noz").onclick = ()=>post("/api/temp",{target:"nozzle",value:+document.getElementById("t-noz").value}).then(()=>toast("Nozzle set"));
document.getElementById("b-bed").onclick = ()=>post("/api/temp",{target:"bed",value:+document.getElementById("t-bed").value}).then(()=>toast("Bed set"));
document.getElementById("b-noz-off").onclick = ()=>post("/api/temp",{target:"nozzle",value:0}).then(()=>toast("Nozzle off"));
document.getElementById("b-bed-off").onclick = ()=>post("/api/temp",{target:"bed",value:0}).then(()=>toast("Bed off"));
document.getElementById("b-home").onclick = ()=>post("/api/home",{axes:""}).then(()=>toast("Homing"));
document.getElementById("b-homexy").onclick = ()=>post("/api/home",{axes:"XY"}).then(()=>toast("Homing XY"));
document.querySelectorAll(".jog button[data-ax]").forEach(b=>{
  b.onclick = ()=>{ const step=+document.getElementById("step").value; post("/api/jog",{axis:b.dataset.ax,distance:(+b.dataset.s)*step}); };
});
document.getElementById("nf-dismiss").onclick = ()=>hideNewFileModal();
document.getElementById("nf-start").onclick = async()=>{
  if (!pendingFile) return;
  await api("/api/print",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file:pendingFile})});
  toast("Print started");
  hideNewFileModal();
  refresh();
};
document.getElementById("nf-preheat-start").onclick = async()=>{
  if (!pendingFile) return;
  const noz = +document.getElementById("nf-noz").value || 0;
  const bed = +document.getElementById("nf-bed").value || 0;
  if (noz > 0) await post("/api/temp",{target:"nozzle",value:noz});
  if (bed > 0) await post("/api/temp",{target:"bed",value:bed});
  await api("/api/print",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file:pendingFile})});
  toast("Preheat commands sent, print started");
  hideNewFileModal();
  refresh();
};
function tickCam(){
  const img = document.getElementById("cam");
  fetch("/api/snapshot",{headers:H}).then(r=>{
    if(!r.ok){ if(++camFails>=2){ img.style.display="none"; document.getElementById("cam-msg").style.display="block"; } return; }
    return r.blob().then(b=>{ camFails=0; img.src=URL.createObjectURL(b); });
  }).catch(()=>{});
}
refresh(); loadFiles(); tickCam();
setInterval(refresh, 2000);
setInterval(loadFiles, 8000);
setInterval(tickCam, 3000);
</script>
</body>
</html>"""
