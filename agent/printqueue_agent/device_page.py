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
  header { padding:14px 18px; border-bottom:1px solid #232327; display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
  header h1 { font-size:17px; margin:0; font-weight:650; }
  header .sub { font-size:12px; color:#8a8a93; }
  .conn { display:flex; gap:8px; flex-wrap:wrap; }
  .chip { display:inline-flex; align-items:center; gap:7px; background:#141417; border:1px solid #232327;
          border-radius:999px; padding:5px 11px; font-size:12.5px; color:#9a9aa3; white-space:nowrap;
          transition:border-color .3s, color .3s; }
  .chip .cdot { width:9px; height:9px; border-radius:50%; background:#52525b; transition:background .3s, box-shadow .3s; }
  .chip.on { color:#e7e7ea; border-color:rgba(52,211,153,.35); }
  .chip.on .cdot { background:#34d399; box-shadow:0 0 8px rgba(52,211,153,.75); }
  .chip.off { color:#d4d4d8; border-color:rgba(248,113,113,.4); }
  .chip.off .cdot { background:#f87171; box-shadow:0 0 8px rgba(248,113,113,.55); }
  .chip svg { width:14px; height:14px; opacity:.8; }
  .head-actions { margin-left:auto; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .head-badge { font-size:12px; color:#8a8a93; }
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
  button.estop { background:#dc2626; color:#fff; font-weight:700; letter-spacing:.02em;
                 box-shadow:0 0 0 1px #ef4444 inset; }
  button.estop:hover { background:#ef4444; }
  button:disabled { opacity:.4; cursor:not-allowed; }
  input[type=range] { accent-color:#6366f1; }
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
  .offline-note { display:none; align-items:center; gap:9px; background:#2a1414; border-bottom:1px solid #5b2a2a;
                  color:#fecaca; font-size:12.5px; line-height:1.35; padding:9px 18px; }
  .offline-note svg { width:15px; height:15px; flex:0 0 auto; }
  @media (max-width:760px){
    .wrap{ grid-template-columns:1fr; padding:12px; gap:12px; }
    header{ padding:12px 14px; gap:10px; }
    .head-actions{ margin-left:0; width:100%; }
    .conn{ width:100%; }
    button{ padding:11px 14px; }               /* larger tap targets */
    .jog{ max-width:none; }
    .jog button{ padding:15px 0; font-size:15px; }
    input[type=number]{ padding:9px; }
    .estop{ margin-left:auto; }
    .offline-note{ padding:9px 14px; }
  }
</style>
</head>
<body>
<header>
  <div>
    <h1 id="pname">Printer</h1>
    <div class="sub" id="psub"></div>
  </div>
  <div class="conn">
    <span class="chip" id="chip-printer" title="Printer">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8" rx="1"/></svg>
      <span class="cdot"></span><span class="clabel">Printer</span>
    </span>
    <span class="chip" id="chip-server" title="Printellect server">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
      <span class="cdot"></span><span class="clabel">Printellect</span>
    </span>
  </div>
  <div class="head-actions">
    <button class="estop" id="b-estop" title="Emergency stop (M112)">⛔ STOP</button>
    <span id="u-head-badge" class="head-badge">checking...</span>
    <button id="b-update-check-top">Check now</button>
    <button class="primary" id="b-update-start-top" disabled>Update</button>
  </div>
</header>
<div class="offline-note" id="offline-note">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.7 5.1A11 11 0 0 1 21.16 9"/><path d="M5 12.55a11 11 0 0 1 4.2-2.5"/><path d="M8.53 16.11a6 6 0 0 1 6.53-.5"/><line x1="12" y1="20" x2="12.01" y2="20"/><line x1="2" y1="2" x2="22" y2="22"/></svg>
  <span>Offline from Printellect — local printing and controls still work. Software updates, remote jobs, and dashboard camera are paused until the connection returns.</span>
</div>
<div class="wrap">
  <div class="card">
    <h2>Status</h2>
    <div class="stat"><span>State</span><b id="s-state">—</b></div>
    <div class="stat"><span>Nozzle</span><b id="s-noz">—</b></div>
    <div class="stat"><span>Bed</span><b id="s-bed">—</b></div>
    <div class="stat"><span>File</span><b id="s-file">—</b></div>
    <div class="stat"><span>Progress</span><b id="s-prog">—</b></div>
    <div class="bar"><div id="s-barfill"></div></div>
    <div class="stat" style="margin-top:8px"><span>Elapsed</span><b id="s-elapsed">—</b></div>
    <div class="stat"><span>Remaining</span><b id="s-eta">—</b></div>
    <div class="row" style="margin-top:14px">
      <button class="warn" id="b-pause">Pause</button>
      <button id="b-resume">Resume</button>
      <button class="danger" id="b-cancel">Cancel</button>
    </div>
    <div style="margin-top:12px; border-top:1px solid #1d1d21; padding-top:10px;">
      <div class="row" style="justify-content:space-between; align-items:center;">
        <span class="muted">Software updates</span>
        <span id="u-badge" class="muted">checking...</span>
      </div>
      <div id="u-detail" class="muted" style="margin-top:6px">Checking for agent/firmware updates.</div>
      <div class="row" style="margin-top:8px">
        <button id="b-update-check">Check now</button>
        <button class="primary" id="b-update-start" disabled>Update now</button>
        <button id="b-restart" title="Restart the agent to apply updated software">Restart agent</button>
      </div>
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
    <div class="row" style="margin-bottom:8px">
      <span style="width:60px">Bed</span>
      <input type="number" id="t-bed" value="60" min="0" max="120" />
      <button id="b-bed">Set</button>
      <button id="b-bed-off">Off</button>
    </div>
    <div class="row" style="margin-bottom:10px">
      <span class="muted" style="width:60px">Presets</span>
      <button data-preset="pla">PLA</button>
      <button data-preset="petg">PETG</button>
      <button data-preset="off">All off</button>
    </div>
    <div class="row" style="border-top:1px solid #1d1d21; padding-top:10px">
      <span style="width:60px">Fan</span>
      <input type="range" id="fan" min="0" max="100" value="0" step="1" style="flex:1; min-width:120px" />
      <span id="fan-val" class="muted" style="width:42px; text-align:right">0%</span>
      <button id="b-fan-off">Off</button>
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
let pendingUpdateCmdIds = [];
let updatePollRunning = false;

function toast(m){ const t=document.getElementById("toast"); t.textContent=m; t.classList.add("show");
  clearTimeout(t._t); t._t=setTimeout(()=>t.classList.remove("show"),2200); }
async function api(path, opts={}){
  opts.headers = Object.assign({}, H, opts.headers||{});
  const r = await fetch(path, opts);
  if(!r.ok){ let m="Error "+r.status; try{ m=(await r.json()).error||m; }catch(e){} toast(m); throw new Error(m); }
  return r.headers.get("content-type","").includes("json") ? r.json() : r;
}
function fmtBytes(n){ if(!n) return "0"; const u=["B","KB","MB"]; let i=0,v=n; while(v>=1024&&i<2){v/=1024;i++;} return v.toFixed(1)+u[i]; }
function fmtDur(s){ if(s==null) return "—"; s=Math.max(0,Math.floor(s)); const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),ss=s%60;
  return h ? `${h}h ${m}m` : (m ? `${m}m ${ss}s` : `${ss}s`); }
function shortVersion(v){
  const s = String(v || "?");
  const i = s.indexOf("+auto.");
  if (i < 0) return { base: s, build: null };
  return { base: s.slice(0, i), build: s.slice(i + 6) };
}
function fmtCheckedAt(iso){
  if (!iso) return "";
  const d = new Date(String(iso).replace(' ', 'T'));
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function renderSub(d){
  const local = shortVersion(BOOT.info.agent_version || "?");
  if (!d) {
    document.getElementById("psub").textContent = (BOOT.info.printer_code||"") + " · local v" + local.base;
    return;
  }
  const server = shortVersion(d.current_agent_version || "?");
  const avail = shortVersion(d.available_agent_version || d.current_agent_version || "?");
  const mode = d.agent_upgrade_available ? `update available (v${avail.base})` : "up to date";
  const buildBits = [];
  if (local.build) buildBits.push(`local build ${local.build}`);
  if (server.build) buildBits.push(`server build ${server.build}`);
  document.getElementById("psub").textContent = `${BOOT.info.printer_code||""} · local v${local.base} · server v${server.base}${buildBits.length ? ' · ' + buildBits.join(' · ') : ''} · ${mode}`;
}
function setUpdateUi(available, badge, detail){
  const badgeEl = document.getElementById("u-badge");
  const headBadgeEl = document.getElementById("u-head-badge");
  const detailEl = document.getElementById("u-detail");
  const startBtn = document.getElementById("b-update-start");
  const startTopBtn = document.getElementById("b-update-start-top");
  if (badgeEl) badgeEl.textContent = badge || "—";
  if (headBadgeEl) headBadgeEl.textContent = badge || "—";
  if (detailEl) detailEl.textContent = detail || "";
  if (startBtn) startBtn.disabled = !available;
  if (startTopBtn) startTopBtn.disabled = !available;
}
function describeUpdateState(d){
  const bits = [];
  if (d.agent_upgrade_available) bits.push(`agent ${d.current_agent_version || "?"} -> ${d.available_agent_version || "?"}`);
  if (d.firmware_upgrade_available) bits.push(`fw ${d.current_firmware_version || "?"} -> ${d.available_firmware_version || "?"}`);
  const checked = fmtCheckedAt(d.checked_at);
  if (!bits.length) return `Agent and firmware are up to date. (agent v${d.current_agent_version || "?"}${d.current_firmware_version ? `, fw ${d.current_firmware_version}` : ""}${checked ? `, checked ${checked}` : ""})`;
  return "Available: " + bits.join("  | ") + (checked ? ` · checked ${checked}` : "");
}
async function refreshUpdateState(silent){
  try {
    const d = await api("/api/update-state");
    const available = !!(d.agent_upgrade_available || d.firmware_upgrade_available);
    setUpdateUi(available, available ? "update available" : "up to date", describeUpdateState(d));
    renderSub(d);
    if (!silent) {
      toast(available ? "Update available" : "No updates available");
    }
  } catch(e) {
    setUpdateUi(false, "offline", "Could not check central update service right now.");
    renderSub(null);
    if (!silent) toast("Could not check updates");
  }
}
async function startSelfUpdate(){
  const btn = document.getElementById("b-update-start");
  try {
    if (btn) btn.disabled = true;
    const d = await post("/api/update");
    const queued = d.queued || [];
    if (!queued.length) {
      toast("No updates queued");
      await refreshUpdateState(true);
      return;
    }
    pendingUpdateCmdIds = queued.map(x => x.cmd_id).filter(Boolean);
    const labels = queued.map(x => `${x.action}${x.version ? ' v'+x.version : ''}`).join(", ");
    toast("Update queued: " + labels);
    setUpdateUi(false, "updating", "Update started. Verifying...");
    pollSelfUpdateVerification();
  } catch(e) {
    if (("" + e.message).toLowerCase().includes("already up to date")) {
      setUpdateUi(false, "up to date", "Agent and firmware are already up to date.");
      toast("Already up to date");
      return;
    }
    toast("Update failed");
    refreshUpdateState(true);
  }
}
async function pollSelfUpdateVerification(){
  if (updatePollRunning || !pendingUpdateCmdIds.length) return;
  updatePollRunning = true;
  const deadline = Date.now() + 180000;
  const query = encodeURIComponent(pendingUpdateCmdIds.join(","));
  while (Date.now() < deadline) {
    try {
      const d = await api(`/api/update-verification?cmd_ids=${query}`);
      if (d.state === "verified") {
        // The agent restarted with new code — reload so the new UI is served.
        setUpdateUi(false, "verified", `Updated to agent ${d.agent_version || "?"}${d.firmware_version ? ' · fw '+d.firmware_version : ''} — reloading…`);
        toast("Updated — reloading to apply");
        pendingUpdateCmdIds = [];
        updatePollRunning = false;
        reloadWhenAgentBack();
        return;
      }
      if (d.state === "failed") {
        setUpdateUi(false, "failed", d.detail || "Update failed");
        toast("Update verification failed");
        pendingUpdateCmdIds = [];
        updatePollRunning = false;
        return;
      }
    } catch(e) {}
    await new Promise(res => setTimeout(res, 3000));
  }
  updatePollRunning = false;
  setUpdateUi(false, "timeout", "Verification timed out. Check again in a minute.");
}
async function reloadWhenAgentBack(maxMs){
  // Wait for the restarted agent to answer again, then reload so the freshly
  // served page (with any new UI) replaces this stale one.
  const deadline = Date.now() + (maxMs || 60000);
  await new Promise(r => setTimeout(r, 2000));  // let the old process exit first
  while (Date.now() < deadline){
    try {
      const r = await fetch("/api/state", { headers: H, cache: "no-store" });
      if (r.ok){ location.reload(); return; }
    } catch(e) {}
    await new Promise(r => setTimeout(r, 1500));
  }
  location.reload();  // fall back to reloading anyway
}
async function restartAgent(){
  if (!confirm("Restart the agent now? The device page will reload automatically once it's back.")) return;
  try {
    await post("/api/restart");
    toast("Restarting agent…");
    setUpdateUi(false, "restarting", "Agent restarting — the page will reload when it's back.");
    reloadWhenAgentBack();
  } catch(e) {
    // e.g. refused while a print is running.
    toast(("" + e.message).includes("print") ? "Can't restart during a print" : "Restart failed");
  }
}
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
renderSub(null);

function setChip(id, state){ // state: true=on, false=off, null=unknown
  const el = document.getElementById(id); if(!el) return;
  el.classList.toggle("on", state === true);
  el.classList.toggle("off", state === false);
  const kind = id.indexOf("printer") >= 0 ? "Printer" : "Printellect server";
  el.title = kind + ": " + (state === true ? "connected" : state === false ? "disconnected" : "unknown");
}
let bootAgentVersion = (BOOT.info && BOOT.info.agent_version) || null;
async function refresh(){
  let s; try { s = await api("/api/state"); } catch(e){ setChip("chip-printer", null); setChip("chip-server", null); return; }
  // If the running agent's version changed from what served this page, it has
  // restarted with new code (an update or restart) — reload so the new UI shows.
  // This is the robust path: it doesn't depend on the update-verification poll,
  // which can time out or be driven by an older page.
  if (s.agent_version && bootAgentVersion && s.agent_version !== bootAgentVersion){
    location.reload();
    return;
  }
  setChip("chip-printer", !!s.connected);
  setChip("chip-server", !!s.server_connected);
  const off = document.getElementById("offline-note");
  if (off) off.style.display = (s.server_connected === false) ? "flex" : "none";
  document.getElementById("s-state").textContent = s.state || "—";
  const nz = s.nozzle_temp!=null ? Math.round(s.nozzle_temp)+" / "+Math.round(s.nozzle_target||0)+"°" : "—";
  const bd = s.bed_temp!=null ? Math.round(s.bed_temp)+" / "+Math.round(s.bed_target||0)+"°" : "—";
  document.getElementById("s-noz").textContent = nz;
  document.getElementById("s-bed").textContent = bd;
  document.getElementById("s-file").textContent = s.current_file || "—";
  const p = s.progress!=null ? s.progress : 0;
  document.getElementById("s-prog").textContent = (s.progress!=null ? p+"%" : "—");
  document.getElementById("s-barfill").style.width = p+"%";
  document.getElementById("s-elapsed").textContent = s.elapsed_s!=null ? fmtDur(s.elapsed_s) : "—";
  document.getElementById("s-eta").textContent = s.eta_s!=null ? fmtDur(s.eta_s) : "—";
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
const PRESETS = { pla:{noz:200,bed:60}, petg:{noz:240,bed:80}, off:{noz:0,bed:0} };
document.querySelectorAll("button[data-preset]").forEach(b=>{
  b.onclick = async()=>{
    const p = PRESETS[b.dataset.preset]; if(!p) return;
    document.getElementById("t-noz").value = p.noz;
    document.getElementById("t-bed").value = p.bed;
    await post("/api/temp",{target:"nozzle",value:p.noz});
    await post("/api/temp",{target:"bed",value:p.bed});
    toast(b.dataset.preset==="off" ? "Heaters off" : b.dataset.preset.toUpperCase()+" preset set");
  };
});
const fanEl = document.getElementById("fan"), fanVal = document.getElementById("fan-val");
fanEl.oninput = ()=>{ fanVal.textContent = fanEl.value+"%"; };
fanEl.onchange = ()=>post("/api/fan",{speed:Math.round(fanEl.value*255/100)}).then(()=>toast("Fan "+fanEl.value+"%"));
document.getElementById("b-fan-off").onclick = ()=>{ fanEl.value=0; fanVal.textContent="0%"; post("/api/fan",{speed:0}).then(()=>toast("Fan off")); };
document.getElementById("b-estop").onclick = ()=>{
  if(confirm("EMERGENCY STOP — immediately halt the printer (M112)?\nThe printer will need a reset or power-cycle to recover."))
    post("/api/estop").then(()=>toast("⛔ Emergency stop sent")).then(refresh);
};
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
document.getElementById("b-update-check").onclick = ()=>refreshUpdateState(false);
document.getElementById("b-update-start").onclick = ()=>startSelfUpdate();
document.getElementById("b-update-check-top").onclick = ()=>refreshUpdateState(false);
document.getElementById("b-update-start-top").onclick = ()=>startSelfUpdate();
document.getElementById("b-restart").onclick = ()=>restartAgent();
function tickCam(){
  const img = document.getElementById("cam");
  fetch("/api/snapshot",{headers:H}).then(r=>{
    if(!r.ok){ if(++camFails>=2){ img.style.display="none"; document.getElementById("cam-msg").style.display="block"; } return; }
    return r.blob().then(b=>{ camFails=0; img.src=URL.createObjectURL(b); });
  }).catch(()=>{});
}
refresh(); loadFiles(); tickCam();
refreshUpdateState(true);
setInterval(refresh, 2000);
setInterval(loadFiles, 8000);
setInterval(tickCam, 3000);
setInterval(()=>refreshUpdateState(true), 60000);
</script>
</body>
</html>"""
