"""frontend.py - Embedded SPA for the Mini SOAR web interface."""

FRONTEND_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mini SOAR</title>
<style>
/* -- CSS vars - dark theme (default, locked) -- */
:root{
  --bg:#0e0f10;--s1:#16181a;--s2:#1e2123;--s3:#24282b;--border:#2a2e31;
  --text:#e6e7e8;--muted:#9aa0a3;--faint:#6b7174;
  --green:#3f8c5f;--green-dim:#2c6344;--red:#9b2c3a;--red-soft:#b3454f;
  --crit:#c23b46;--high:#c27a2e;--med:#c9b03a;--low:#3f8c5f;--info:#6b7280;
  --cat-windows:#4a6fa5;--cat-linux:#3f8c8c;--cat-ai:#7a5ea8;
  --cat-mail:#a8793f;--cat-web:#4a96a8;--cat-server:#5a5aa0;--cat-mixed:#6b7280;
  --shadow:rgba(0,0,0,.5);
}
/* -- light theme -- */
html.light{
  --bg:#f4f5f7;--s1:#ffffff;--s2:#f0f1f3;--s3:#e4e6ea;--border:#d1d5db;
  --text:#1a1d23;--muted:#6b7280;--faint:#9ca3af;
  --green:#2d7a4f;--green-dim:#d1fae5;--red:#9b2c3a;--red-soft:#b3454f;
  --crit:#b91c2c;--high:#b45309;--med:#a16207;--low:#2d7a4f;--info:#6b7280;
  --cat-windows:#2558a3;--cat-linux:#1a7a7a;--cat-ai:#6d40a0;
  --cat-mail:#8a5a20;--cat-web:#1a7a94;--cat-server:#404099;--cat-mixed:#6b7280;
  --shadow:rgba(0,0,0,.15);
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;height:100vh;overflow:hidden;display:flex;flex-direction:column;transition:background .2s,color .2s;}

/* topbar */
.topbar{background:var(--s1);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px;padding:0 18px;height:56px;flex-shrink:0;}
.menu-btn,.icon-btn{background:none;border:1px solid var(--border);border-radius:8px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--muted);}
.menu-btn:hover,.icon-btn:hover{color:var(--text);border-color:var(--green);}
.brand{font-size:15px;font-weight:700;white-space:nowrap;}
.brand span{color:var(--muted);font-weight:400;}
.mode-pill{font-size:10px;font-weight:700;letter-spacing:.6px;padding:3px 9px;border-radius:20px;border:1px solid var(--green);color:var(--green);text-transform:uppercase;}
.mode-pill.server{border-color:var(--red-soft);color:var(--red-soft);}
.mode-pill.showcase{border-color:var(--amber,#e0a458);color:var(--amber,#e0a458);}
.sc-banner{background:rgba(224,164,88,.12);border-bottom:1px solid rgba(224,164,88,.4);color:var(--amber,#e0a458);font-size:12px;font-weight:600;padding:7px 16px;text-align:center;letter-spacing:.3px;}
.topnav{display:flex;gap:4px;margin-left:6px;}
.tab{display:flex;align-items:center;gap:8px;padding:8px 14px;border-radius:8px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;transition:background .15s,color .15s;}
.tab:hover{background:var(--s2);color:var(--text);}
.tab.active{background:var(--s2);color:var(--text);box-shadow:inset 0 -2px 0 var(--green);}
.tab svg{width:16px;height:16px;}
.topbar .right{margin-left:auto;display:flex;align-items:center;gap:8px;}
.rbtn{background:none;border:1px solid var(--border);color:var(--muted);padding:7px 12px;border-radius:8px;font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;}
.rbtn:hover{color:var(--text);border-color:var(--green);}

/* main */
.main{flex:1;overflow-y:auto;}
.page{padding:22px 26px;max-width:1500px;margin:0 auto;min-height:100%;}

/* drawer */
.backdrop{position:fixed;inset:0;background:rgba(0,0,0,.5);opacity:0;visibility:hidden;transition:opacity .28s,visibility .28s;z-index:90;}
.backdrop.open{opacity:1;visibility:visible;}
.drawer{position:fixed;top:0;left:0;height:100%;width:320px;background:rgba(20,22,24,.9);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-right:1px solid var(--border);transform:translateX(-100%);transition:transform .28s cubic-bezier(.4,0,.2,1);z-index:91;display:flex;flex-direction:column;padding:18px;overflow-y:auto;}
html.light .drawer{background:rgba(255,255,255,.94);}
.drawer.open{transform:translateX(0);}
.dr-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;}
.dr-head .title{font-size:15px;font-weight:700;}
.dclose{background:none;border:none;color:var(--muted);cursor:pointer;display:flex;}
.dclose:hover{color:var(--text);}
.dr-section{margin-bottom:18px;}
.dr-label{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:10px;}

/* profile card */
.profile-card{background:var(--s2);border-radius:12px;padding:14px;}
.profile-avatar{width:52px;height:52px;border-radius:50%;background:var(--green-dim);border:2px solid var(--green);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px;color:var(--text);cursor:pointer;overflow:hidden;flex-shrink:0;position:relative;}
html.light .profile-avatar{color:var(--green);}
.profile-avatar img{width:100%;height:100%;object-fit:cover;border-radius:50%;}
.profile-row{display:flex;align-items:center;gap:12px;margin-bottom:12px;}
.profile-names{flex:1;}
.profile-names .pn{font-weight:600;font-size:14px;}
.profile-names .pe{font-size:11px;color:var(--muted);}
.profile-fields{display:grid;gap:7px;}
.pfield{display:grid;gap:4px;}
.pfield label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;}
.pfield input{background:var(--s3);border:1px solid var(--border);color:var(--text);padding:6px 9px;border-radius:7px;font-size:12px;outline:none;width:100%;}
.pfield input:focus{border-color:var(--green);}
.pbtn{margin-top:10px;width:100%;padding:8px;border-radius:8px;border:1px solid var(--green);background:transparent;color:var(--green);font-size:12px;font-weight:600;cursor:pointer;}
.pbtn:hover{background:rgba(63,140,95,.12);}
#avatar-input{display:none;}

/* contacts */
.contact{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;}
.contact:hover{background:var(--s2);}
.cdot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.contact .cn{font-size:13px;}
.contact .cr{font-size:11px;color:var(--muted);margin-left:auto;}
.dr-muted{font-size:11px;color:var(--faint);padding:6px 12px;line-height:1.5;}

/* theme toggle */
.theme-toggle{display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--s2);border-radius:10px;}
.theme-toggle span{font-size:13px;flex:1;}
.toggle-track{width:40px;height:22px;border-radius:11px;background:var(--s3);border:1px solid var(--border);cursor:pointer;position:relative;transition:background .2s;}
.toggle-track.on{background:var(--green);}
.toggle-thumb{position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:left .2s;box-shadow:0 1px 3px rgba(0,0,0,.3);}
.toggle-track.on .toggle-thumb{left:20px;}

.dr-note{font-size:11px;color:var(--faint);margin-top:auto;padding-top:14px;line-height:1.5;}

/* kpi */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px;}
.kpi{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:18px 20px;}
.kpi .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;}
.kpi .val{font-size:32px;font-weight:700;}
.kpi.crit .val{color:var(--crit);}
.kpi.high .val{color:var(--high);}

/* cards */
.chart-row{display:grid;grid-template-columns:280px 1fr 1fr;gap:16px;margin-bottom:20px;}
.card{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:18px 20px;}
.card h3{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:16px;}
.donut-wrap{display:flex;align-items:center;gap:18px;}
.dleg .row{display:flex;align-items:center;gap:8px;margin-bottom:7px;font-size:12px;}
.dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
.dv{margin-left:auto;font-weight:700;}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:10px;cursor:pointer;border-radius:6px;padding:2px 4px;transition:background .12s;}
.bar-row:hover{background:var(--s2);}
.bar-lbl{width:96px;font-size:11px;font-weight:600;letter-spacing:.3px;flex-shrink:0;font-family:'Consolas',monospace;}
.bar-track{flex:1;background:var(--s3);border-radius:5px;height:8px;}
.bar-fill{height:8px;border-radius:5px;min-width:4px;}
.bar-cnt{width:26px;text-align:right;font-size:12px;color:var(--muted);flex-shrink:0;}

/* tables */
.tbl-wrap{background:var(--s1);border:1px solid var(--border);border-radius:12px;overflow:hidden;}
.tbl-hdr{display:flex;align-items:center;justify-content:space-between;padding:15px 18px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:10px;}
.tbl-hdr h3{font-size:14px;font-weight:600;}
.scope-note{font-size:11px;color:var(--muted);margin-top:3px;}
.zone-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;}
.zone-card .tk-count{font-size:34px;font-weight:700;margin:6px 0 10px;}
.zone-card .tk-count span{font-size:13px;font-weight:400;color:var(--muted);margin-left:6px;}
.zone-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--faint);margin:8px 0 5px;}
.chips{display:flex;flex-wrap:wrap;gap:7px;}
.sevchip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:14px;padding:3px 10px;font-size:11px;cursor:pointer;transition:background .12s;color:var(--text);}
.sevchip:hover{background:var(--s2);}
.sevchip .sd{width:8px;height:8px;border-radius:50%;display:inline-block;}
.sevchip b{font-weight:700;}
@media(max-width:760px){.zone-row{grid-template-columns:1fr;}}
.filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.chip{display:inline-flex;align-items:center;gap:6px;background:var(--s3);border:1px solid var(--border);border-radius:16px;padding:4px 10px;font-size:11px;color:var(--text);}
.chip b{font-family:'Consolas',monospace;}
.chip .x{cursor:pointer;color:var(--muted);}
.chip .x:hover{color:var(--text);}
select,input[type=text],input:not([type]){background:var(--s2);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:7px;font-size:12px;outline:none;}
select:focus,input:focus{border-color:var(--green);}
select option:disabled{color:var(--faint);font-style:italic;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{background:var(--s2);color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);}
td{padding:11px 14px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tr.clickable{cursor:pointer;transition:background .12s;}
tr.clickable:hover td{background:var(--s2);}
tr.closed{opacity:.5;}

/* signal accordion rows */
tr.sig-exp td{background:var(--s2);padding:0;}
.exp-body{padding:12px 14px;font-size:12px;color:var(--text);line-height:1.6;border-top:1px solid var(--border);}
.exp-body .rec{margin-top:8px;}
.exp-body .rec-item{padding:3px 0;color:var(--muted);}
td.exp-cell{cursor:pointer;max-width:320px;}
td.exp-cell .exp-preview{display:inline-block;max-width:300px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;color:var(--muted);font-size:11px;vertical-align:bottom;}
td.exp-cell .exp-toggle{font-size:10px;color:var(--faint);margin-left:4px;}

/* badges */
.badge{display:inline-block;padding:3px 9px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:.3px;white-space:nowrap;}
.badge.CRITICAL{background:rgba(194,59,70,.18);color:var(--crit);border:1px solid rgba(194,59,70,.4);}
.badge.HIGH{background:rgba(194,122,46,.18);color:var(--high);border:1px solid rgba(194,122,46,.4);}
.badge.MEDIUM{background:rgba(201,176,58,.16);color:var(--med);border:1px solid rgba(201,176,58,.4);}
.badge.LOW{background:rgba(63,140,95,.16);color:var(--low);border:1px solid rgba(63,140,95,.4);}
.badge.INFO{background:rgba(107,114,128,.16);color:var(--info);border:1px solid rgba(107,114,128,.4);}
.stbadge{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;padding:4px 9px;border-radius:7px;display:inline-block;}
.stbadge.open{background:rgba(155,44,58,.22);color:var(--red-soft);}
.stbadge.investigating{background:rgba(194,122,46,.20);color:var(--high);}
.stbadge.resolved{background:rgba(63,140,95,.20);color:var(--low);}
.stbadge.closed{background:var(--s3);color:var(--faint);}
.cat-tag{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-family:'Consolas',monospace;}
.cat-bar{width:3px;height:14px;border-radius:2px;flex-shrink:0;}
.score{font-family:'Consolas',monospace;font-weight:700;}
.stag{background:var(--s3);border-radius:5px;padding:2px 7px;font-size:11px;font-family:'Consolas',monospace;}

/* hash pill */
.hpill{display:inline-flex;align-items:center;gap:5px;background:var(--s3);border-radius:5px;padding:3px 8px;font-size:11px;font-family:'Consolas',monospace;color:var(--cat-ai);margin:0 5px 5px 0;cursor:pointer;border:1px solid transparent;transition:border-color .12s;}
.hpill:hover{border-color:var(--green);}
.hpill .hcopy{font-size:9px;color:var(--muted);}

/* modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;display:flex;align-items:flex-start;justify-content:center;padding-top:48px;opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s;}
.overlay.open{opacity:1;visibility:visible;}
.modal{background:var(--s1);border:1px solid var(--border);border-radius:14px;width:760px;max-width:94vw;max-height:84vh;overflow-y:auto;transform:translateY(18px) scale(.98);opacity:0;transition:transform .22s cubic-bezier(.34,1.2,.64,1),opacity .22s;}
.overlay.open .modal{transform:translateY(0) scale(1);opacity:1;}
.mhdr{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--s1);}
.mhdr h3{font-size:14px;font-weight:600;font-family:'Consolas',monospace;}
.mbody{padding:22px;}
.mclose{background:none;border:none;color:var(--muted);cursor:pointer;display:flex;}
.mclose:hover{color:var(--text);}
.frow{display:grid;grid-template-columns:130px 1fr;gap:8px;margin-bottom:13px;align-items:start;}
.flbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;padding-top:3px;}
.aitem{background:var(--s2);border-radius:8px;padding:9px 12px;margin-bottom:7px;font-size:12px;}
.albl{font-size:10px;color:var(--green);font-weight:700;text-transform:uppercase;margin-bottom:3px;}
textarea{width:100%;background:var(--s2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:9px;font-size:12px;resize:vertical;min-height:72px;outline:none;font-family:inherit;}
textarea:focus{border-color:var(--green);}
.divider{height:1px;background:var(--border);margin:16px 0;}
.btn{display:inline-flex;align-items:center;gap:7px;padding:8px 15px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:background .15s,border-color .15s;}
.btn-p{background:transparent;color:var(--green);border-color:var(--green);}
.btn-p:hover{background:rgba(63,140,95,.14);}
.btn-g{background:var(--s2);color:var(--text);border-color:var(--border);}
.btn-g:hover{background:var(--s3);}

/* run page */
.run-wrap{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.browser{max-height:330px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;background:var(--s2);}
.crumb{display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding:10px 12px;font-size:11px;font-family:'Consolas',monospace;color:var(--muted);border-bottom:1px solid var(--border);}
.crumb span{cursor:pointer;}
.crumb span:hover{color:var(--text);}
.fentry{display:flex;align-items:center;gap:10px;padding:8px 12px;font-size:12px;cursor:pointer;border-bottom:1px solid rgba(42,46,49,.5);}
.fentry:hover{background:var(--s3);}
.fentry.sel{background:rgba(63,140,95,.14);}
.fentry .fn{font-family:'Consolas',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.fentry .fsz{margin-left:auto;font-size:11px;color:var(--faint);}
.fic{width:15px;height:15px;flex-shrink:0;color:var(--muted);}
.fmt-group{display:flex;gap:10px;align-items:center;margin-top:8px;flex-wrap:wrap;}
.fmt-note{font-size:11px;color:var(--faint);margin-top:4px;}
.log-box{background:#0a0c0d;border:1px solid var(--border);border-radius:8px;padding:14px;height:330px;overflow-y:auto;font-family:'Consolas',monospace;font-size:12px;color:var(--low);}
.ll{margin-bottom:3px;word-break:break-all;}
.ll.e{color:var(--red-soft);}.ll.i{color:var(--cat-web);}
.empty{color:var(--muted);text-align:center;padding:44px;font-size:13px;}
.spin{display:inline-block;animation:spin 1s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}
.sel-file{font-size:12px;font-family:'Consolas',monospace;color:var(--green);margin:10px 0;word-break:break-all;}

/* process tree */
.ptree{display:flex;flex-direction:column;gap:4px;margin-top:6px;}
.ptn{display:flex;align-items:center;gap:8px;background:var(--s2);border-radius:7px;padding:6px 10px;font-size:12px;border-left:3px solid var(--border);}
.ptn .ptrole{font-size:9px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);width:52px;flex-shrink:0;}
.ptn .ptimg{font-family:'Consolas',monospace;font-weight:600;}
.ptn .ptpid{font-size:11px;color:var(--faint);}
.ptn .ptcmd{font-family:'Consolas',monospace;font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:340px;}
.ptn:has(.ptrole:empty){opacity:.7;}
.sig-name{cursor:pointer;color:var(--cat-web);font-family:'Consolas',monospace;}
.sig-name:hover{text-decoration:underline;}
.sig-copy{cursor:pointer;color:var(--faint);margin-left:6px;}
.sig-copy:hover{color:var(--text);}

/* toast */
.toast{position:fixed;bottom:24px;right:24px;background:var(--s1);border:1px solid var(--green);color:var(--text);border-radius:10px;padding:10px 16px;font-size:12px;opacity:0;transform:translateY(6px);transition:opacity .2s,transform .2s;z-index:200;display:flex;align-items:center;gap:10px;}
.toast.show{opacity:1;transform:translateY(0);}
.toast-x{cursor:pointer;color:var(--muted);font-weight:700;border:1px solid var(--border);border-radius:50%;width:16px;height:16px;display:flex;align-items:center;justify-content:center;font-size:10px;flex-shrink:0;}
.toast-x:hover{color:var(--text);border-color:var(--red-soft);}
.dleg .row{cursor:pointer;padding:4px 6px;border-radius:6px;transition:background .12s;}
.dleg .row:hover{background:var(--s2);}
.exp-body{overflow-wrap:anywhere;}
.exp-body .exp-full{white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;line-height:1.6;}
</style>
</head>
<body>

<div class="topbar">
  <button class="menu-btn" onclick="openDrawer()" title="Menu">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  </button>
  <div class="brand">Mini SOAR</div>
  <div class="mode-pill" id="mode-pill">LOCAL</div>
  <div class="topnav" id="topnav"></div>
  <div class="right">
    <button class="icon-btn" onclick="histBack()" title="Back">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <button class="rbtn" onclick="refresh()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
      Refresh
    </button>
  </div>
</div>

<div class="main"><div class="page" id="pcontent"></div></div>

<div class="backdrop" id="backdrop" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="dr-head">
    <div class="title">Workspace</div>
    <button class="dclose" onclick="closeDrawer()">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>

  <!-- profile -->
  <div class="dr-section" id="profile-section">
    <div class="dr-label">Account</div>
    <div class="profile-card">
      <div class="profile-row">
        <div class="profile-avatar" onclick="document.getElementById('avatar-input').click()" title="Click to change avatar" id="avatar-el">DD</div>
        <input type="file" id="avatar-input" accept="image/*" onchange="changeAvatar(event)">
        <div class="profile-names">
          <div class="pn" id="p-display-name">Damien Defer</div>
          <div class="pe" id="p-display-email">operator@local</div>
        </div>
      </div>
      <div class="profile-fields">
        <div class="pfield"><label>First name</label><input id="p-first" placeholder="First name"></div>
        <div class="pfield"><label>Last name</label><input id="p-last" placeholder="Last name"></div>
        <div class="pfield"><label>Email</label><input id="p-email" placeholder="email@example.com"></div>
      </div>
      <button class="pbtn" onclick="saveProfile()">Save profile</button>
    </div>
  </div>

  <!-- theme -->
  <div class="dr-section">
    <div class="dr-label">Theme</div>
    <div class="theme-toggle" onclick="toggleTheme()">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      <span id="theme-label">Dark mode</span>
      <div class="toggle-track" id="theme-track"><div class="toggle-thumb"></div></div>
    </div>
  </div>

  <!-- contacts -->
  <div class="dr-section">
    <div class="dr-label">Contacts</div>
    <div class="contact"><div class="cdot" style="background:var(--low)"></div><div class="cn">You</div><div class="cr">owner</div></div>
    <div class="dr-muted">No shared contacts in local mode. Multi user roster arrives with the server skeleton (v10) and real accounts (v11).</div>
  </div>

  <div class="dr-note">Mode is fixed at launch. Use the launcher (python launch.py) to switch; it restarts the app.</div>
  <div class="dr-note" id="dr-version" style="margin-top:6px;font-weight:600;color:var(--muted)"></div>
</div>

<div class="overlay" id="overlay" onmousedown="overlayDown(event)" onclick="closeModal(event)">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="mhdr"><h3 id="mtitle"></h3>
      <button class="mclose" onclick="closeModal()">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="mbody" id="mbody"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
/* -- state -- */
let _cur='dash';
let _tixFilter={};
let _hist=[];

const SEV_C={CRITICAL:'#c23b46',HIGH:'#c27a2e',MEDIUM:'#c9b03a',LOW:'#3f8c5f',INFO:'#6b7280'};
const SEV_O=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

const ABBREV={
  'bash_sigma':'BASH','powershell_sigma':'PWSH','lotl_sigma':'LOTL',
  'auditd.sensitive_file_access':'FILE-ACC','auditd.execve_suspicious':'EXECVE',
  'auditd.user_creation':'USER-ADD','auth.ssh_brute_force':'SSH-BF',
  'auth.root_login':'ROOT-LOG','ai.unexpected_process_on_ai_port':'AI-PORT',
  'ai.model_integrity':'AI-MODEL','ransomware_behavior':'RANSOM',
  'ransomware_behavior_linux':'RANSOM','email_attachments':'MAIL-ATT',
  'email_phishing':'PHISH','recon_sequence':'RECON','merged':'MERGED'
};
const CAT_COLOR={windows:'var(--cat-windows)',linux:'var(--cat-linux)',ai:'var(--cat-ai)',
  mail:'var(--cat-mail)',web:'var(--cat-web)',server:'var(--cat-server)',mixed:'var(--cat-mixed)'};

function baseLabel(t){t=t||'';return t.indexOf('merged[')===0?'merged':t;}
function abbrev(t){const b=baseLabel(t);return ABBREV[b]||b.toUpperCase().slice(0,10);}
function category(t){
  const b=baseLabel(t);
  if(b==='merged')return 'mixed';
  if(b.indexOf('email')===0||b.indexOf('phish')>-1)return 'mail';
  if(b.indexOf('ai')===0)return 'ai';
  if(b.indexOf('auditd')===0||b.indexOf('auth')===0||b.indexOf('bash')===0||b.indexOf('linux')>-1)return 'linux';
  if(b.indexOf('powershell')===0||b.indexOf('lotl')===0||b.indexOf('ps_')===0||b.indexOf('recon')===0)return 'windows';
  return 'mixed';
}
function catColor(t){return CAT_COLOR[category(t)];}

const ICONS={
  dash:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
  tickets:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 8a2 2 0 0 0 0 8v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2a2 2 0 0 1 0-8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2z"/></svg>',
  open:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>',
  mine:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
  signals:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
  run:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
  templates:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/></svg>'
};
const TABS=[['dash','Dashboard'],['open','Open'],['mine','My Tickets'],['signals','Signals'],['run','Run SIEM'],['templates','Templates']];
let SHOWCASE=false;
const VERSION='v9.1';   // single source; bumped on every new build/zip

/* -- api -- */
async function api(path,opts){
  const r=await fetch('/api'+path,Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
  return r.json();
}

/* -- nav -- */
function buildNav(){
  document.getElementById('topnav').innerHTML=TABS.filter(function(t){
    return !(SHOWCASE && t[0]==='run');   // no file pipeline in showcase
  }).map(function(t){
    return '<div class="tab'+(t[0]===_cur?' active':'')+'" onclick="go(\\''+t[0]+'\\')">'+ICONS[t[0]]+t[1]+'</div>';
  }).join('');
}

function go(page,filter,pushH){
  if(SHOWCASE && page==='run')page='dash';   // run pipeline sealed off in showcase
  _cur=page;
  _tixFilter=((page==='open'||page==='mine')&&filter)?filter:{};
  if(pushH!==false){
    history.pushState({page:page,filter:_tixFilter},'','#'+page);
  }
  buildNav();
  renderPage(page);
}

// On-screen button and the mouse/browser back button both route through here.
function histBack(){history.back();}

window.addEventListener('popstate',function(ev){
  const st=ev.state||{page:'dash',filter:{}};
  _cur=st.page||'dash';
  _tixFilter=st.filter||{};
  buildNav();
  renderPage(_cur);
});

function refresh(){renderPage(_cur);}

async function renderPage(p){
  const el=document.getElementById('pcontent');
  el.innerHTML='<div class="empty"><span class="spin"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.2-8.5"/></svg></span></div>';
  if(p==='dash')await renderDash(el);
  else if(p==='open'||p==='mine')await renderTickets(el);
  else if(p==='signals')await renderSignals(el);
  else if(p==='run')renderRun(el);
  else if(p==='templates')renderTemplates(el);
}

/* -- drawer -- */
function openDrawer(){document.getElementById('drawer').classList.add('open');document.getElementById('backdrop').classList.add('open');}
function closeDrawer(){document.getElementById('drawer').classList.remove('open');document.getElementById('backdrop').classList.remove('open');}

/* -- toast -- */
function toast(msg){
  const t=document.getElementById('toast');
  t.innerHTML='<span class="toast-x" onclick="hideToast()">x</span><span>'+msg+'</span>';
  t.classList.add('show');
  clearTimeout(t._to);t._to=setTimeout(function(){t.classList.remove('show');},2600);
}
function hideToast(){const t=document.getElementById('toast');t.classList.remove('show');clearTimeout(t._to);}

/* -- note drafts (hot save): survive modal close and tab changes -- */
function draftKey(tid){return 'soar_note_draft:'+tid;}
function saveDraft(tid,val){
  if(val && val.trim())localStorage.setItem(draftKey(tid),val);
  else localStorage.removeItem(draftKey(tid));
}
function getDraft(tid){return localStorage.getItem(draftKey(tid));}
function clearDraft(tid){localStorage.removeItem(draftKey(tid));}
function myName(){
  const p=JSON.parse(localStorage.getItem('soar_profile')||'{}');
  return ((p.first||'Damien')+' '+(p.last||'Defer')).trim();
}

/* -- clipboard copy -- */
function copyHash(ev,val,el){
  if(ev)ev.stopPropagation();   // copy only, never toggle the row accordion
  navigator.clipboard.writeText(val).then(function(){
    el.querySelector('.hcopy').textContent='copied';
    setTimeout(function(){el.querySelector('.hcopy').textContent='copy';},1500);
    toast('Hash copied to clipboard');
  }).catch(function(){toast('Copy failed - check browser permissions');});
}

function copyId(ev,val){
  if(ev)ev.stopPropagation();
  navigator.clipboard.writeText(val).then(function(){
    toast('Signal ID copied');
  }).catch(function(){toast('Copy failed - check browser permissions');});
}

// Click a signal name -> jump to its ticket if one exists.
async function openTicketForSignal(ev,signalId){
  if(ev)ev.stopPropagation();
  const tix=await api('/tickets');
  const match=tix.find(function(t){return t.signal_id===signalId;});
  if(match){go('open');openTix(match.ticket_id);}
  else toast('No ticket for this signal (below ticketing threshold)');
}

// Render an enriched process ancestry chain + direct children.
function processTreeHtml(ancestors,self_node,children){
  ancestors=ancestors||[];children=children||[];
  if(!ancestors.length && !children.length && !self_node)
    return '<div style="color:var(--faint);font-size:12px">No process tree for this signal. The source events carry no pid linkage.</div>';
  function node(n,role){
    return '<div class="ptn" title="'+(n.command_line||'')+'">'+
      '<span class="ptrole">'+role+'</span>'+
      '<span class="ptimg">'+(n.image||'?')+'</span>'+
      '<span class="ptpid">pid '+(n.pid==null?'?':n.pid)+'</span>'+
      (n.command_line?'<span class="ptcmd">'+n.command_line+'</span>':'')+
      '</div>';
  }
  let html='<div class="ptree">';
  ancestors.forEach(function(a,i){html+=node(a, i===0?'root':'parent');});
  html+=node(self_node||{image:'this process',pid:null,command_line:''},'signal');
  children.forEach(function(c){html+=node(c,'child');});
  html+='</div>';
  return html;
}

const DEFAULT_TEMPLATES={
 open:[
  '=== TRIAGE ===',
  'Date/time (UTC): {date}',
  'Ticket: {ticket_id}',
  'Triaged by: {analyst}',
  '',
  '-- Alert --',
  'Host: {host}',
  'Detection: {signal_type}',
  'MITRE: {mitre}',
  'Severity score: {score}',
  '',
  '-- Initial assessment --',
  'Summary of what fired: ',
  'Looks like (suspicion): ',
  'Priority (P1/P2/P3/P4): ',
  'Assign to: ',
  'Action: [take | watch | dismiss as noise]'
 ].join(String.fromCharCode(10)),
 investigating:[
  '=== INVESTIGATION ===',
  'Date/time (UTC): {date}',
  'Ticket: {ticket_id}',
  'Analyst: {analyst}',
  'Status: {status}',
  '',
  '-- Context --',
  'Host: {host}',
  'Detection: {signal_type}  (MITRE {mitre})',
  'Severity score: {score}',
  '',
  '-- Timeline (UTC) --',
  '  T0  : ',
  '  T+  : ',
  '',
  '-- Process / evidence --',
  'Triggering process: ',
  'Parent chain: ',
  'Child processes: ',
  'File hashes checked (VT/internal): ',
  'Network indicators: ',
  '',
  '-- Scope --',
  'Other hosts affected: ',
  'Accounts involved: ',
  'Lateral movement seen: [yes/no] ',
  '',
  '-- Analysis --',
  'What was confirmed: ',
  'What was ruled out: ',
  'Open questions: ',
  '',
  '-- Containment so far --',
  'Actions taken: ',
  'Next steps: '
 ].join(String.fromCharCode(10)),
 resolved:[
  '=== RESOLUTION ===',
  'Date/time (UTC): {date}',
  'Ticket: {ticket_id}',
  'Analyst: {analyst}',
  'Verdict: {disposition}',
  '',
  '-- What happened --',
  'Root cause: ',
  'Attack stage reached: ',
  'Impact (data/systems): ',
  '',
  '-- Remediation --',
  'Containment: ',
  'Eradication: ',
  'Recovery: ',
  'Verification performed: ',
  '',
  '-- Follow up --',
  'Detections to tune: ',
  'Hardening recommended: '
 ].join(String.fromCharCode(10)),
 closed:[
  '=== CLOSURE REPORT ===',
  'Date/time (UTC): {date}',
  'Ticket: {ticket_id}',
  'Closed by: {analyst}',
  'Final verdict: {disposition}',
  'Detection: {signal_type}  (MITRE {mitre})  on {host}',
  '',
  '-- Summary --',
  'One line: ',
  'Root cause: ',
  '',
  '-- Actions taken --',
  '  1) ',
  '  2) ',
  '',
  '-- Outcome --',
  'Confirmed malicious / benign: ',
  'Data or systems impacted: ',
  'Residual risk: ',
  '',
  '-- If false positive --',
  'Why it fired: ',
  'Rule or baseline to adjust: ',
  '',
  '-- Lessons / handover --',
  'What to watch next: '
 ].join(String.fromCharCode(10))
};

function getTemplates(){
  try{return Object.assign({},DEFAULT_TEMPLATES,JSON.parse(localStorage.getItem('soar_templates')||'{}'));}
  catch(e){return Object.assign({},DEFAULT_TEMPLATES);}
}
function saveTemplates(obj){localStorage.setItem('soar_templates',JSON.stringify(obj));}

function fillTemplate(tpl,t){
  const d=new Date().toISOString().slice(0,16).replace('T',' ');
  const map={
    '{date}':d,'{ticket_id}':t.ticket_id||'','{host}':t.host||'',
    '{signal_type}':t.signal_type||'','{mitre}':t.mitre_technique||'-',
    '{score}':(t.score||0).toFixed(2),'{analyst}':myName(),
    '{status}':document.getElementById('m-st')?document.getElementById('m-st').value:(t.status||''),
    '{disposition}':document.getElementById('m-disp')?document.getElementById('m-disp').value:(t.disposition||'')
  };
  let out=tpl;
  Object.keys(map).forEach(function(k){out=out.split(k).join(map[k]);});
  return out;
}

// Insert the template that matches the ticket's current status into the note.
let _curTicket=null;
function insertTemplate(){
  if(!_curTicket)return;
  const st=document.getElementById('m-st')?document.getElementById('m-st').value:'open';
  const tpls=getTemplates();
  const tpl=tpls[st]||'';
  const ta=document.getElementById('m-notes');
  const filled=fillTemplate(tpl,_curTicket);
  ta.value=ta.value.trim()?(ta.value.replace(/\\s+$/,'')+String.fromCharCode(10)+String.fromCharCode(10)+filled):filled;
  saveDraft(_curTicket.ticket_id,ta.value);
  autoGrow(ta);
  toast('Template for "'+st+'" inserted');
}

// Grow a textarea to fit its content.
function autoGrow(el){
  if(!el)return;
  el.style.height='auto';
  el.style.height=(el.scrollHeight+2)+'px';
}

function clearNote(){
  if(!_curTicket)return;
  const ta=document.getElementById('m-notes');
  ta.value='';
  saveDraft(_curTicket.ticket_id,'');
  autoGrow(ta);
}

function hashPills(hashes){
  const entries=Object.entries(hashes||{});
  if(!entries.length)return '<em style="color:var(--muted)">None</em>';
  return entries.map(function(e){
    return '<span class="hpill" onclick="copyHash(event,\\''+e[1]+'\\',this)" title="'+e[1]+'">'+
      e[0].toUpperCase()+': '+e[1].substring(0,16)+' <span class="hcopy">copy</span></span>';
  }).join('');
}

/* -- theme -- */
function applyTheme(light){
  document.documentElement.classList.toggle('light',!!light);
  const track=document.getElementById('theme-track');
  const lbl=document.getElementById('theme-label');
  if(track){track.classList.toggle('on',!!light);lbl.textContent=light?'Light mode':'Dark mode';}
  localStorage.setItem('soar_theme',light?'light':'dark');
}
function toggleTheme(){
  applyTheme(!document.documentElement.classList.contains('light'));
  // The donut center is painted on a canvas from theme vars; repaint it.
  if(_cur==='dash')renderPage('dash');
}

/* -- profile -- */
function loadProfile(){
  const p=JSON.parse(localStorage.getItem('soar_profile')||'{}');
  const f=p.first||'Damien';const l=p.last||'Defer';const e=p.email||'operator@local';
  document.getElementById('p-first').value=f;
  document.getElementById('p-last').value=l;
  document.getElementById('p-email').value=e;
  document.getElementById('p-display-name').textContent=f+' '+l;
  document.getElementById('p-display-email').textContent=e;
  const av=document.getElementById('avatar-el');
  if(p.avatar){av.innerHTML='<img src="'+p.avatar+'" alt="avatar">';}
  else{av.textContent=(f[0]||'?')+(l[0]||'').toUpperCase();}
}
function saveProfile(){
  const f=document.getElementById('p-first').value.trim()||'Damien';
  const l=document.getElementById('p-last').value.trim()||'Defer';
  const e=document.getElementById('p-email').value.trim()||'operator@local';
  const p=JSON.parse(localStorage.getItem('soar_profile')||'{}');
  p.first=f;p.last=l;p.email=e;
  localStorage.setItem('soar_profile',JSON.stringify(p));
  document.getElementById('p-display-name').textContent=f+' '+l;
  document.getElementById('p-display-email').textContent=e;
  const av=document.getElementById('avatar-el');
  if(!p.avatar)av.textContent=(f[0]||'?')+(l[0]||'').toUpperCase();
  toast('Profile saved');
}
function changeAvatar(ev){
  const file=ev.target.files[0];if(!file)return;
  const reader=new FileReader();
  reader.onload=function(e){
    const data=e.target.result;
    const p=JSON.parse(localStorage.getItem('soar_profile')||'{}');
    p.avatar=data;localStorage.setItem('soar_profile',JSON.stringify(p));
    document.getElementById('avatar-el').innerHTML='<img src="'+data+'" alt="avatar">';
    toast('Avatar updated');
  };
  reader.readAsDataURL(file);
}

/* -- dashboard -- */
function goScope(elm){
  const sc=elm.getAttribute('data-scope');
  const sev=elm.getAttribute('data-sev');
  const ty=elm.getAttribute('data-type');
  if(sev)go(sc,{severity:sev});
  else if(ty)go(sc,{type:ty});
  else go(sc);
}
function scopeCard(title,list,scope){
  const bySev={};const byType={};
  list.forEach(function(t){
    bySev[t.severity]=(bySev[t.severity]||0)+1;
    const key=baseLabel(t.signal_type);
    byType[key]=(byType[key]||0)+1;
  });
  const sevChips=SEV_O.filter(function(k){return bySev[k];}).map(function(k){
    return '<span class="sevchip" data-scope="'+scope+'" data-sev="'+k+'" onclick="goScope(this)" style="border-color:'+SEV_C[k]+'"><span class="sd" style="background:'+SEV_C[k]+'"></span>'+k+' <b>'+bySev[k]+'</b></span>';
  }).join('')||'<span style="color:var(--muted);font-size:12px">None</span>';
  const topTypes=Object.entries(byType).sort(function(a,b){return b[1]-a[1];}).slice(0,5).map(function(e){
    return '<span class="sevchip" data-scope="'+scope+'" data-type="'+e[0]+'" onclick="goScope(this)" style="border-color:'+catColor(e[0])+'"><span class="sd" style="background:'+catColor(e[0])+'"></span>'+abbrev(e[0])+' <b>'+e[1]+'</b></span>';
  }).join('')||'<span style="color:var(--muted);font-size:12px">None</span>';
  const goAll='<span class="x" style="cursor:pointer;font-size:12px;color:var(--green)" onclick="go(\\''+scope+'\\')">open '+(scope==='open'?'queue':'my tickets')+' &rarr;</span>';
  return '<div class="card zone-card">'+
    '<div style="display:flex;align-items:baseline;justify-content:space-between"><h3>'+title+'</h3>'+goAll+'</div>'+
    '<div class="tk-count">'+list.length+'<span> remaining</span></div>'+
    '<div class="zone-lbl">By severity</div><div class="chips">'+sevChips+'</div>'+
    '<div class="zone-lbl">By type</div><div class="chips">'+topTypes+'</div>'+
  '</div>';
}
async function renderDash(el){
  const s=await api('/stats');
  const allTix=await api('/tickets');
  const openList=allTix.filter(function(t){return t.status==='open';});
  const mineList=allTix.filter(function(t){return t.status!=='open';});
  const sev=s.severity||{};
  const total=s.total_tickets||0;
  const did='d'+Date.now();

  const legend=SEV_O.filter(function(k){return sev[k];}).map(function(k){
    return '<div class="row" style="cursor:pointer" title="Filter tickets by '+k+'" onclick="go(\\'open\\',{severity:\\''+k+'\\'})"><div class="dot" style="background:'+SEV_C[k]+'"></div><span>'+k+'</span><span class="dv">'+sev[k]+'</span></div>';
  }).join('');

  const tE=Object.entries(s.types||{}).slice(0,10);
  const tM=Math.max.apply(null,tE.map(function(e){return e[1];}).concat([1]));
  const typeBars=tE.map(function(e){
    return '<div class="bar-row" title="'+e[0]+'" onclick="go(\\'open\\',{type:\\''+baseLabel(e[0])+'\\'})">' +
      '<div class="bar-lbl" style="color:'+catColor(e[0])+'">'+abbrev(e[0])+'</div>'+
      '<div class="bar-track"><div class="bar-fill" style="width:'+Math.round(e[1]/tM*100)+'%;background:'+catColor(e[0])+'"></div></div>'+
      '<div class="bar-cnt">'+e[1]+'</div></div>';
  }).join('');

  const mE=Object.entries(s.mitre||{}).slice(0,10);
  const mM=Math.max.apply(null,mE.map(function(e){return e[1];}).concat([1]));
  const mitreBars=mE.map(function(e){
    return '<div class="bar-row" title="'+e[0]+'" onclick="go(\\'open\\',{mitre:\\''+e[0]+'\\'})">' +
      '<div class="bar-lbl">'+e[0]+'</div>'+
      '<div class="bar-track"><div class="bar-fill" style="width:'+Math.round(e[1]/mM*100)+'%;background:var(--cat-ai)"></div></div>'+
      '<div class="bar-cnt">'+e[1]+'</div></div>';
  }).join('');

  const catLeg=Object.keys(CAT_COLOR).map(function(c){
    return '<span class="cat-tag"><span class="cat-bar" style="background:'+CAT_COLOR[c]+'"></span>'+c+'</span>';
  }).join('');

  el.innerHTML=
  '<div class="kpi-grid">'+
    '<div class="kpi"><div class="lbl">Tickets</div><div class="val">'+total+'</div></div>'+
    '<div class="kpi"><div class="lbl">Signals</div><div class="val">'+(s.total_signals||0)+'</div></div>'+
    '<div class="kpi crit"><div class="lbl">Critical</div><div class="val">'+(sev.CRITICAL||0)+'</div></div>'+
    '<div class="kpi high"><div class="lbl">High</div><div class="val">'+(sev.HIGH||0)+'</div></div>'+
  '</div>'+
  '<div class="zone-row">'+scopeCard('Open queue',openList,'open')+scopeCard('My tickets',mineList,'mine')+'</div>'+
  '<div class="chart-row">'+
    '<div class="card"><h3>Severity</h3><div class="donut-wrap"><canvas id="'+did+'" width="120" height="120"></canvas><div class="dleg">'+(legend||'<span style="color:var(--muted)">No data</span>')+'</div></div></div>'+
    '<div class="card"><h3>Signal Types</h3>'+(typeBars||'<div class="empty">Run SIEM first</div>')+'</div>'+
    '<div class="card"><h3>MITRE Techniques</h3>'+(mitreBars||'<div class="empty">No data</div>')+'</div>'+
  '</div>'+
  '<div class="card"><h3>Category legend - click a bar to filter tickets</h3><div style="display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted)">'+catLeg+'</div></div>';

  if(total){
    const ctx=document.getElementById(did).getContext('2d');
    let start=-Math.PI/2;const cx=60,cy=60,R=52,ir=33;
    SEV_O.forEach(function(k){
      const v=sev[k]||0;if(!v)return;
      const a=(v/total)*2*Math.PI;
      ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,R,start,start+a);ctx.closePath();
      ctx.fillStyle=SEV_C[k];ctx.fill();start+=a;
    });
    ctx.beginPath();ctx.arc(cx,cy,ir,0,2*Math.PI);ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--s1').trim()||'#16181a';ctx.fill();
    ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text').trim()||'#e6e7e8';
    ctx.font='bold 16px Segoe UI';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(total,cx,cy);
  }
}

/* -- tickets -- */
let _tix=[];
let _tixScope='open';
async function renderTickets(el){
  _tixScope=(_cur==='mine')?'mine':'open';
  let qs='';
  if(_tixFilter.type)qs='?type='+encodeURIComponent(_tixFilter.type);
  else if(_tixFilter.mitre)qs='?mitre='+encodeURIComponent(_tixFilter.mitre);
  else if(_tixFilter.severity)qs='?severity='+encodeURIComponent(_tixFilter.severity);
  _tix=await api('/tickets'+qs);
  let chipLabel='';
  if(_tixFilter.type)chipLabel=abbrev(_tixFilter.type);
  else if(_tixFilter.mitre)chipLabel=_tixFilter.mitre;
  else if(_tixFilter.severity)chipLabel=_tixFilter.severity;
  const chip=chipLabel?
    '<div class="chip">filter <b>'+chipLabel+'</b><span class="x" onclick="go(\\''+_cur+'\\')">clear</span></div>':'';
  const presetSev=_tixFilter.severity||'';
  const title=_tixScope==='open'?'Open queue':'My tickets';
  const sub=_tixScope==='open'
    ?'<div class="scope-note">Take a ticket: set it to investigating and add a note. It then moves to My tickets.</div>'
    :'<div class="scope-note">Your tickets in progress. Here you can resolve or close them.</div>';
  const statusOpts=_tixScope==='open'?['investigating','resolved','closed']:['open','investigating','resolved','closed'];
  el.innerHTML=
  '<div class="tbl-wrap"><div class="tbl-hdr"><div><h3>'+title+' (<span id="tix-count">0</span>)</h3>'+sub+'</div>'+
    '<div class="filters">'+chip+
      '<select id="f-sev" onchange="filterTix()"><option value="">All severities</option>'+SEV_O.map(function(s){return '<option'+(s===presetSev?' selected':'')+'>'+s+'</option>';}).join('')+'</select>'+
      (_tixScope==='mine'?'<select id="f-st" onchange="filterTix()"><option value="">All status</option>'+statusOpts.map(function(s){return '<option>'+s+'</option>';}).join('')+'</select>':'')+
      '<input id="f-q" placeholder="Search" oninput="filterTix()" style="width:150px">'+
    '</div></div>'+
    '<table><thead><tr><th>Ticket ID</th><th>Severity</th><th>Score</th><th>Type</th><th>Host</th><th>MITRE</th><th>Status</th></tr></thead>'+
    '<tbody id="tix-body"></tbody></table></div>';
  filterTix();
}

function filterTix(){
  const sev=(document.getElementById('f-sev')||{}).value||'';
  const st=(document.getElementById('f-st')||{}).value||'';
  const q=((document.getElementById('f-q')||{}).value||'').toLowerCase();
  const rows=_tix.filter(function(t){
    const inScope=(_tixScope==='open')?(t.status==='open'):(t.status!=='open');
    return inScope&&(!sev||t.severity===sev)&&(!st||t.status===st)&&
      (!q||[t.host,t.signal_type,t.ticket_id,t.signal_id].some(function(x){return (x||'').toLowerCase().includes(q);}));
  });
  document.getElementById('tix-count').textContent=rows.length;
  const tb=document.getElementById('tix-body');if(!tb)return;
  tb.innerHTML=rows.length?rows.map(function(t){
    return '<tr class="clickable'+(t.status==='closed'?' closed':'')+'" onclick="openTix(\\''+t.ticket_id+'\\')">'+
      '<td><code style="font-family:Consolas,monospace;color:var(--muted)">'+t.ticket_id+'</code></td>'+
      '<td><span class="badge '+t.severity+'">'+t.severity+'</span></td>'+
      '<td class="score" style="color:'+sc(t.score)+'">'+(t.score||0).toFixed(2)+'</td>'+
      '<td><span class="cat-tag"><span class="cat-bar" style="background:'+catColor(t.signal_type)+'"></span>'+abbrev(t.signal_type)+'</span></td>'+
      '<td>'+t.host+'</td>'+
      '<td style="font-size:11px;font-family:Consolas,monospace">'+(t.mitre_technique||'-')+'</td>'+
      '<td><span class="stbadge '+t.status+'">'+t.status+'</span></td></tr>';
  }).join(''):'<tr><td colspan="7" class="empty">'+(_tixScope==='open'?'No open tickets in the queue.':'You have not taken any tickets yet.')+'</td></tr>';
}

function sc(v){if(v>=.9)return'var(--crit)';if(v>=.75)return'var(--high)';if(v>=.55)return'var(--med)';return'var(--muted)';}

async function openTix(tid){
  const t=await api('/tickets/'+tid);
  const hashes=hashPills(t.file_hashes);
  const actions=(t.actions_taken||[]).map(function(a){
    return '<div class="aitem"><div class="albl">'+(a.action||'?')+'</div>'+(a.detail||a.target||'')+'</div>';
  }).join('')||'<div class="empty">No actions.</div>';
  const factors=(t.risk_factors||[]).map(function(f){return '<div style="font-size:12px;margin-bottom:4px">- '+f+'</div>';}).join('');
  document.getElementById('mtitle').textContent=t.ticket_id;
  document.getElementById('mbody').innerHTML=
    '<div class="frow"><div class="flbl">Severity</div><div><span class="badge '+t.severity+'">'+t.severity+'</span></div></div>'+
    '<div class="frow"><div class="flbl">Score</div><div class="score" style="color:'+sc(t.score)+'">'+(t.score||0).toFixed(4)+'</div></div>'+
    '<div class="frow"><div class="flbl">Type</div><div><span class="cat-tag"><span class="cat-bar" style="background:'+catColor(t.signal_type)+'"></span><span class="stag">'+t.signal_type+'</span></span></div></div>'+
    '<div class="frow"><div class="flbl">Host</div><div>'+(t.host||'-')+'</div></div>'+
    '<div class="frow"><div class="flbl">MITRE</div><div>'+(t.mitre_technique||'-')+' <span style="color:var(--muted);font-size:11px">'+(t.mitre_tactic||'')+'</span></div></div>'+
    '<div class="frow"><div class="flbl">Playbook</div><div style="color:var(--green)">'+(t.playbook||'-')+'</div></div>'+
    '<div class="frow"><div class="flbl">Created</div><div style="font-size:12px">'+(t.created_at||'-')+'</div></div>'+
    '<div class="divider"></div>'+
    '<div class="frow"><div class="flbl">File Hashes</div><div>'+hashes+'</div></div>'+
    '<div style="margin-bottom:14px"><div class="flbl" style="margin-bottom:6px">Risk Factors</div>'+(factors||'<em style="color:var(--muted)">None</em>')+'</div>'+
    '<div class="divider"></div>'+
    '<div style="margin-bottom:14px"><div class="flbl" style="margin-bottom:8px">SOAR Actions</div>'+actions+'</div>'+
    '<div class="divider"></div>'+
    '<div style="margin-bottom:14px"><div class="flbl" style="margin-bottom:8px">Process Tree</div>'+processTreeHtml(t.process_ancestors,t.process_self,t.process_children)+'</div>'+
    '<div class="divider"></div>'+
    '<div class="frow"><div class="flbl">Status</div><select id="m-st">'+
      (_tixScope==='open'?['open','investigating']:['open','investigating','resolved','closed'])
        .map(function(s){return '<option'+(t.status===s?' selected':'')+'>'+s+'</option>';}).join('')+'</select>'+
      (_tixScope==='open'?'<span style="font-size:11px;color:var(--muted);margin-left:10px">Set to investigating to take this ticket.</span>':'')+'</div>'+
    '<div class="frow"><div class="flbl">Verdict</div><select id="m-disp">'+
      [['','unset'],['true_positive','true positive'],['false_positive','false positive'],['benign','benign'],['duplicate','duplicate']]
        .map(function(d){return '<option value="'+d[0]+'"'+((t.disposition||'')===d[0]?' selected':'')+'>'+d[1]+'</option>';}).join('')+
      '</select><span style="font-size:11px;color:var(--muted);margin-left:10px">Feeds future auto-triage and informs others.</span></div>'+
    '<div style="margin-bottom:14px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px"><span class="flbl">Notes'+(getDraft(t.ticket_id)?' <span style="color:var(--high)">(unsaved draft)</span>':'')+'</span><span style="display:flex;gap:8px"><button class="btn btn-g" style="padding:4px 10px;font-size:11px" onclick="insertTemplate()">Insert template</button><button class="btn btn-g" style="padding:4px 10px;font-size:11px" onclick="clearNote()">Clear</button></span></div><textarea id="m-notes" style="overflow:hidden" oninput="saveDraft(\\''+t.ticket_id+'\\',this.value);autoGrow(this)">'+(getDraft(t.ticket_id)||t.notes||'')+'</textarea></div>'+
    '<div style="display:flex;gap:10px"><button class="btn btn-p" onclick="saveTix(\\''+t.ticket_id+'\\')">Save</button><button class="btn btn-g" onclick="closeModal()">Cancel</button></div>';
  _curTicket=t;
  document.getElementById('overlay').classList.add('open');
  autoGrow(document.getElementById('m-notes'));
}

async function saveTix(tid){
  const status=document.getElementById('m-st').value;
  const notes=document.getElementById('m-notes').value;
  const body={status:status,notes:notes};
  const disp=document.getElementById('m-disp');
  if(disp)body.disposition=disp.value;
  if(status!=='open')body.assignee=myName();   // taking or working a ticket
  await api('/tickets/'+tid,{method:'PATCH',body:JSON.stringify(body)});
  clearDraft(tid);
  closeModal();
  await renderTickets(document.getElementById('pcontent'));
}

let _ovDown=false;
function overlayDown(e){_ovDown=(e.target===document.getElementById('overlay'));}
function closeModal(e){
  // Only close on a click that both started and ended on the backdrop itself.
  // This avoids closing when a text selection drag is released outside the textarea.
  if(!e || (e.target===document.getElementById('overlay') && _ovDown))
    document.getElementById('overlay').classList.remove('open');
  _ovDown=false;
}

/* -- signals with accordion explanation -- */
let _sigExpanded={};
let _sigs=[];
async function renderSignals(el){
  const sigs=await api('/signals');
  // Hide signals whose correlated ticket is closed.
  let closed=new Set();
  try{
    const tix=await api('/tickets');
    tix.forEach(function(t){if(t.status==='closed'&&t.signal_id)closed.add(t.signal_id);});
  }catch(e){}
  _sigs=sigs.filter(function(s){return !closed.has(s.signal_id);});
  _sigExpanded={};
  _drawSignals(el);
}

function _drawSignals(el){
  const body=_sigs.length?_sigs.map(function(s,i){
    const h=hashPills(s.file_hashes||{});
    const exp=s.explanation||'';
    const isOpen=!!_sigExpanded[i];
    const expRow=isOpen?
      '<tr class="sig-exp"><td colspan="7"><div class="exp-body">'+
        '<div class="exp-full" style="margin-bottom:6px">'+exp+'</div>'+
        (s.recommended_actions&&s.recommended_actions.length?'<div class="rec"><div class="flbl" style="margin-bottom:5px">Recommended actions</div>'+s.recommended_actions.map(function(a){return '<div class="rec-item">- '+a+'</div>';}).join('')+'</div>':'') +
        '<div class="rec"><div class="flbl" style="margin:10px 0 4px">Process tree</div>'+processTreeHtml(s.process_ancestors,s.process_self,s.process_children)+'</div>'+
        '<div style="margin-top:8px">'+h+'</div>'+
      '</div></td></tr>':'';
    return '<tr class="clickable" onclick="toggleSig('+i+',this)">'+
      '<td><span class="sig-name" title="Open the matching ticket" onclick="openTicketForSignal(event,\\''+(s.signal_id||'')+'\\')">'+(s.signal_id||'').substring(0,12)+'</span><span class="sig-copy" title="Copy signal ID" onclick="copyId(event,\\''+(s.signal_id||'')+'\\')">copy</span></td>'+
      '<td><span class="cat-tag"><span class="cat-bar" style="background:'+catColor(s.signal_type)+'"></span>'+abbrev(s.signal_type)+'</span></td>'+
      '<td class="score" style="color:'+sc(s.score)+'">'+(s.score||0).toFixed(2)+'</td>'+
      '<td>'+((s.host&&s.host.hostname)||'-')+'</td>'+
      '<td style="font-size:11px;font-family:Consolas,monospace">'+(s.mitre_technique||'-')+'</td>'+
      '<td>'+hashPills(s.file_hashes||{})+'</td>'+
      '<td class="exp-cell"><span class="exp-preview">'+(exp||'<em style="color:var(--faint)">no explanation</em>')+'</span><span class="exp-toggle">'+(isOpen?' v':' >')+'</span></td></tr>'+expRow;
  }).join(''):'<tr><td colspan="7" class="empty">Run the SIEM first.</td></tr>';
  el.innerHTML='<div class="tbl-wrap"><div class="tbl-hdr"><h3>Signals ('+_sigs.length+')</h3></div>'+
    '<table><thead><tr><th>ID</th><th>Type</th><th>Score</th><th>Host</th><th>MITRE</th><th>File Hashes</th><th>Explanation - click to expand</th></tr></thead>'+
    '<tbody>'+body+'</tbody></table></div>';
}

function toggleSig(i,row){
  _sigExpanded[i]=!_sigExpanded[i];
  _drawSignals(document.getElementById('pcontent'));
}

/* -- run -- */
const FORMATS=[
  {v:'auto',l:'auto (detect)',enabled:true},
  {v:'json',l:'json (SIEM native)',enabled:true},
  {v:'syslog',l:'syslog',enabled:true},
  {v:'csv',l:'Generic CSV',enabled:true},
  {v:'elastic',l:'Elastic / ECS',enabled:true},
  {v:'snort',l:'Snort alerts',enabled:true},
  {v:'auditd',l:'Linux auditd',enabled:true},
  {v:'evtx',l:'Windows EVTX (local)',enabled:true},
  {v:'pcap',l:'PCAP / Wireshark (local)',enabled:true}
];

let _browseData=null;
let _selFile='';

function renderRun(el){
  const fmtOptions=FORMATS.map(function(f){
    return '<option value="'+f.v+'"'+(f.enabled?'':' disabled')+'>'+f.l+'</option>';
  }).join('');
  el.innerHTML=
  '<div class="run-wrap"><div class="card"><h3>Pick an input file</h3>'+
    '<div class="browser" id="browser"></div>'+
    '<div class="sel-file" id="selfile">No file selected</div>'+
    '<div class="fmt-group">'+
      '<select id="fmt">'+fmtOptions+'</select>'+
      '<button class="btn btn-p" id="rbtn" onclick="runSiem()">Run SIEM</button>'+
    '</div>'+
    '<div class="fmt-note">EVTX and PCAP are local-only binary formats and need python-evtx / dpkt installed.</div>'+
  '</div>'+
  '<div class="card"><h3>Live Output</h3><div class="log-box" id="lbox"><div class="ll" style="color:var(--muted)">Ready.</div></div></div></div>';
  loadBrowse('');
}

async function loadBrowse(path){
  const r=await api('/browse?path='+encodeURIComponent(path));
  if(r.error){addLog(document.getElementById('lbox'),r.error,'e');return;}
  _browseData=r;
  const box=document.getElementById('browser');
  const crumb=(r.crumbs||[]).map(function(c,i){return '<span onclick="navCrumb('+i+')">'+c.name+'</span>';}).join(' / ');
  let html='<div class="crumb">'+(crumb||'/')+'</div>';
  if(r.parent!==null)
    html+='<div class="fentry" onclick="navParent()"><svg class="fic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg><span class="fn">..</span></div>';
  (r.entries||[]).forEach(function(e,i){
    if(e.is_dir)
      html+='<div class="fentry" onclick="navEntry('+i+')"><svg class="fic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span class="fn">'+e.name+'</span></div>';
    else
      html+='<div class="fentry" id="fe'+i+'" onclick="navEntry('+i+')"><svg class="fic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><span class="fn">'+e.name+'</span><span class="fsz">'+e.size+'</span></div>';
  });
  box.innerHTML=html;
}

function navCrumb(i){loadBrowse(_browseData.crumbs[i].path);}
function navParent(){if(_browseData&&_browseData.parent!==null)loadBrowse(_browseData.parent);}
function navEntry(i){
  const e=_browseData.entries[i];
  if(e.is_dir){loadBrowse(e.path);return;}
  document.querySelectorAll('.fentry.sel').forEach(function(n){n.classList.remove('sel');});
  const node=document.getElementById('fe'+i);if(node)node.classList.add('sel');
  _selFile=e.path;
  document.getElementById('selfile').textContent=e.path;
}

function runSiem(){
  if(!_selFile){addLog(document.getElementById('lbox'),'Select a file first.','e');return;}
  const fmt=document.getElementById('fmt').value;
  const lbox=document.getElementById('lbox');
  const btn=document.getElementById('rbtn');
  lbox.innerHTML='';btn.disabled=true;btn.textContent='Running';
  const es=new EventSource('/api/run-stream?input='+encodeURIComponent(_selFile)+'&format='+fmt);
  es.onmessage=function(ev){
    let text;try{text=JSON.parse(ev.data);}catch(err){return;}
    if(text==='__DONE__'){es.close();btn.disabled=false;btn.textContent='Run SIEM';addLog(lbox,'Done. Open Dashboard or Tickets.','i');return;}
    addLog(lbox,text,text.indexOf('[!')===0?'e':text.indexOf('[soar]')===0?'i':'');
  };
  es.onerror=function(){es.close();btn.disabled=false;btn.textContent='Run SIEM';addLog(lbox,'Stream closed.','i');};
}

function addLog(el,text,cls){
  const d=document.createElement('div');
  d.className='ll'+(cls?' '+cls:'');d.textContent=text;
  el.appendChild(d);el.scrollTop=el.scrollHeight;
}

/* -- init -- */
function renderTemplates(el){
  const tpls=getTemplates();
  const statuses=[['open','Triage (open)'],['investigating','Investigation'],['resolved','Resolution'],['closed','Closure']];
  el.innerHTML=
  '<div class="card" style="margin-bottom:16px"><h3>Note templates</h3>'+
    '<div style="font-size:12px;color:var(--muted);line-height:1.6">One template per ticket status. The Insert template button in a ticket fills the template that matches its current status and substitutes the variables below. Edits are saved on this machine. In v11 this editing will be limited to roles such as manager or CISO, to keep one writing convention.</div>'+
    '<div style="font-size:11px;color:var(--faint);margin-top:8px">Variables: {date} {ticket_id} {host} {signal_type} {mitre} {score} {analyst} {status} {disposition}</div>'+
  '</div>'+
  statuses.map(function(s){
    return '<div class="card" style="margin-bottom:14px"><h3>'+s[1]+'</h3>'+
      '<textarea id="tpl-'+s[0]+'" style="min-height:150px;font-family:Consolas,monospace">'+(tpls[s[0]]||'')+'</textarea></div>';
  }).join('')+
  (SHOWCASE
    ? '<div class="dr-muted" style="font-size:12px">Templates are read-only in showcase mode.</div>'
    : '<div style="display:flex;gap:10px"><button class="btn btn-p" onclick="saveAllTemplates()">Save templates</button>'+
      '<button class="btn btn-g" onclick="resetTemplates()">Reset to defaults</button></div>');
}

function saveAllTemplates(){
  if(SHOWCASE){toast('Read-only in showcase');return;}
  const obj={};
  ['open','investigating','resolved','closed'].forEach(function(s){
    const ta=document.getElementById('tpl-'+s);if(ta)obj[s]=ta.value;
  });
  saveTemplates(obj);
  toast('Templates saved');
}
function resetTemplates(){
  localStorage.removeItem('soar_templates');
  renderTemplates(document.getElementById('pcontent'));
  toast('Templates reset to defaults');
}

function applyShowcaseLock(){
  // Sealed demo: banner, no profile editing, no file pipeline. View, fill, open and
  // close tickets and browse the site only.
  var b=document.createElement('div');
  b.className='sc-banner';
  b.textContent='SHOWCASE MODE | sealed demo with fake data only. File upload, the run pipeline and the profile are disabled. View, fill, open and close tickets freely.';
  document.body.insertBefore(b, document.body.firstChild);
  var ps=document.getElementById('profile-section');
  if(ps)ps.style.display='none';
  // The demo streams: tickets are revealed progressively. Auto-refresh the current list
  // so they appear without navigating away, but never while a ticket modal is open.
  setInterval(function(){
    var ov=document.getElementById('overlay');
    if(ov&&ov.classList.contains('open'))return;
    if(['dash','open','mine','signals'].indexOf(_cur)>-1)renderPage(_cur);
  }, 7000);
}

async function init(){  // restore theme
  applyTheme(localStorage.getItem('soar_theme')==='light');
  loadProfile();
  var dv=document.getElementById('dr-version');
  if(dv)dv.textContent='Mini SOAR '+VERSION;
  try{
    const c=await api('/config');
    SHOWCASE=((c.mode||'local')==='showcase');
    const pill=document.getElementById('mode-pill');
    pill.textContent=(c.mode||'local').toUpperCase();
    if((c.mode||'local')==='server')pill.classList.add('server');
    if(SHOWCASE){pill.classList.add('showcase');applyShowcaseLock();}
  }catch(e){}
  buildNav();
  history.replaceState({page:'dash',filter:{}},'','#dash');
  renderPage('dash');
}
init();
</script>
</body>
</html>"""
