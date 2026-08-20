"""frontend.py - Embedded SPA for the Mini SOAR web interface."""

FRONTEND_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mini SOAR</title>
<style>
/* -- CSS vars - dark theme (default, locked) -- */
@font-face{font-family:'Space Grotesk';src:url('/assets/fonts/SpaceGrotesk-Regular.woff2') format('woff2');font-weight:400;font-style:normal;font-display:swap;}
@font-face{font-family:'Space Grotesk';src:url('/assets/fonts/SpaceGrotesk-Medium.woff2') format('woff2');font-weight:500;font-style:normal;font-display:swap;}
@font-face{font-family:'Space Grotesk';src:url('/assets/fonts/SpaceGrotesk-Bold.woff2') format('woff2');font-weight:700;font-style:normal;font-display:swap;}
@font-face{font-family:'JetBrains Mono';src:url('/assets/fonts/JetBrainsMono-Regular.woff2') format('woff2');font-weight:400;font-style:normal;font-display:swap;}
@font-face{font-family:'JetBrains Mono';src:url('/assets/fonts/JetBrainsMono-Medium.woff2') format('woff2');font-weight:500;font-style:normal;font-display:swap;}
@font-face{font-family:'JetBrains Mono';src:url('/assets/fonts/JetBrainsMono-Bold.woff2') format('woff2');font-weight:700;font-style:normal;font-display:swap;}
:root{
  --font-sans:'Space Grotesk','Segoe UI',system-ui,sans-serif;
  --font-mono:'JetBrains Mono',Consolas,monospace;
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
body{background:var(--bg);color:var(--text);font-family:var(--font-sans);font-size:14px;height:100vh;overflow:hidden;display:flex;flex-direction:column;transition:background .2s,color .2s;}

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
.btn-shutdown{margin-top:14px;width:100%;background:#2a1d1d;border:1px solid #b5524f;color:#e07a78;border-radius:9px;padding:10px;font-weight:700;cursor:pointer;font-size:13px;}
.btn-shutdown:hover{background:#3a2424;}
.topnav{position:relative;display:flex;gap:4px;margin-left:6px;}
.dock{position:relative;display:inline-flex;align-items:center;gap:3px;padding:5px;border-radius:999px;background:var(--s1);border:1px solid var(--border);}
.dock-item{position:relative;width:38px;height:38px;display:flex;align-items:center;justify-content:center;border-radius:999px;background:transparent;border:none;color:var(--muted);cursor:pointer;transition:background .15s,color .15s,transform .1s;}
.dock-item svg{width:17px;height:17px;}
.dock-item:hover{background:var(--s2);color:var(--text);}
.dock-item:active{transform:scale(.92);background:var(--s2);}
.dock-item.selected{background:var(--green);color:#0a0c0d;}
.dock-item.selected:hover{background:var(--green);color:#0a0c0d;filter:brightness(1.08);}
.dock-tooltip{position:absolute;left:0;top:-34px;pointer-events:none;background:var(--s1);border:1px solid var(--border);border-radius:8px;padding:5px 10px;font-size:12px;font-weight:600;color:var(--text);white-space:nowrap;opacity:0;transition:opacity .12s,transform .12s;z-index:20;}
.dock-tooltip.show{opacity:1;}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}
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
.login-wrap{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg,#15171a);overflow:hidden;}
.login-bg{position:absolute;inset:-20%;background:
  radial-gradient(circle at 30% 30%,rgba(63,174,116,.10),transparent 55%),
  radial-gradient(circle at 70% 70%,rgba(63,174,116,.06),transparent 55%);
  animation:loginDrift 14s ease-in-out infinite alternate;pointer-events:none;}
@keyframes loginDrift{from{transform:translate(0,0) scale(1);}to{transform:translate(-3%,2%) scale(1.05);}}
.login-card{position:relative;z-index:1;width:320px;background:var(--s1,#1d2024);border:1px solid var(--border,#2a2e33);border-radius:14px;padding:28px 26px;box-shadow:0 8px 40px rgba(0,0,0,.4);}
.login-anim{animation:loginSlideIn .35s ease-out;}
@keyframes loginSlideIn{from{opacity:0;transform:translateX(24px);}to{opacity:1;transform:translateX(0);}}
.step-mfa{animation-name:loginSlideIn;}
.login-title{font-size:26px;font-weight:700;color:var(--text,#e6e8ea);margin-bottom:2px;letter-spacing:-.02em;}
.login-sub{font-size:13px;color:var(--muted,#8b9096);margin-bottom:18px;}
.login-err{background:rgba(180,70,70,.15);border:1px solid #b5524f;color:#e07a78;font-size:12px;padding:8px 10px;border-radius:8px;margin-bottom:14px;}
.login-input{width:100%;box-sizing:border-box;background:var(--s2,#24272c);border:1px solid var(--border,#2a2e33);border-radius:9px;padding:11px 12px;color:var(--text,#e6e8ea);font-size:14px;margin-bottom:12px;transition:border-color .15s;}
.login-input:hover{border-color:var(--muted,#8b9096);}
.login-input:focus{outline:none;border-color:var(--green,#3fae74);}
.login-btn{width:100%;background:var(--green,#3fae74);color:#0a0c0d;border:none;border-radius:9px;padding:11px;font-weight:700;font-size:14px;cursor:pointer;transition:filter .12s,transform .08s;}
.login-btn:hover{filter:brightness(1.08);}
.login-btn:active{transform:scale(.98);filter:brightness(.95);}
.login-btn:disabled{opacity:.6;cursor:default;}
.dr-logout{margin-top:14px;padding-top:14px;border-top:1px solid var(--border,#2a2e33);}
.dr-user{font-size:12px;color:var(--text,#e6e8ea);margin-bottom:8px;}
.dr-role{color:var(--muted,#8b9096);text-transform:uppercase;font-size:10px;letter-spacing:.5px;}
.dr-logout-btn{width:100%;background:transparent;border:1px solid var(--border,#2a2e33);color:var(--muted,#8b9096);border-radius:8px;padding:8px;font-size:12px;font-weight:600;cursor:pointer;}
.dr-logout-btn:hover{border-color:#b5524f;color:#e07a78;}
.mfa-modal{max-width:380px;}
.mfa-state{font-size:13px;font-weight:600;padding:10px 12px;border-radius:8px;margin-bottom:12px;}
.mfa-state.on{background:rgba(63,174,116,.15);border:1px solid var(--green,#3fae74);color:var(--green,#3fae74);}
.mfa-state.off{background:var(--s2,#24272c);border:1px solid var(--border,#2a2e33);color:var(--muted,#8b9096);}
.mfa-help{font-size:12px;color:var(--muted,#8b9096);margin:8px 0;line-height:1.5;}
.mfa-qr{display:flex;justify-content:center;padding:12px;background:#fff;border-radius:10px;margin:12px 0;}
.mfa-qr svg{max-width:200px;height:auto;}
.mfa-secret-label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted,#8b9096);margin-top:8px;}
.mfa-secret{font-family:var(--font-mono);font-size:15px;letter-spacing:2px;color:var(--text,#e6e8ea);background:var(--s2,#24272c);padding:10px;border-radius:8px;margin:6px 0 10px;text-align:center;user-select:all;}
.shake{animation:shake .4s;}
@keyframes shake{0%,100%{transform:translateX(0);}25%{transform:translateX(-6px);}75%{transform:translateX(6px);}}
.login-key-btn{width:100%;background:transparent;border:1px solid var(--border,#2a2e33);color:var(--text,#e6e8ea);border-radius:9px;padding:10px;font-size:13px;font-weight:600;cursor:pointer;margin-top:8px;}
.login-key-btn:hover{border-color:var(--green,#3fae74);color:var(--green,#3fae74);}
.mfa-section-title{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted,#8b9096);margin-bottom:8px;}
.mfa-divider{height:1px;background:var(--border,#2a2e33);margin:18px 0;}
.wk-row{display:flex;align-items:center;justify-content:space-between;background:var(--s2,#24272c);border-radius:8px;padding:9px 12px;margin-bottom:6px;}
.wk-info{display:flex;align-items:center;gap:8px;}
.wk-name{font-size:13px;color:var(--text,#e6e8ea);}
.wk-tag{font-size:10px;text-transform:uppercase;letter-spacing:.4px;padding:2px 7px;border-radius:5px;background:var(--s1,#1d2024);color:var(--muted,#8b9096);}
.wk-tag.primary{background:rgba(63,174,116,.15);color:var(--green,#3fae74);}
.wk-del{background:transparent;border:none;color:var(--muted,#8b9096);font-size:11px;cursor:pointer;padding:4px 6px;}
.wk-del:hover{color:#e07a78;}
.mfa-checkbox{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted,#8b9096);margin:4px 0 12px;}
.app-footer{display:flex;align-items:center;gap:10px;justify-content:center;padding:14px 20px;font-size:11px;color:var(--muted,#8b9096);border-top:1px solid var(--border,#2a2e33);}
.app-footer a{color:var(--muted,#8b9096);text-decoration:none;}
.app-footer a:hover{color:var(--text,#e6e8ea);text-decoration:underline;}
.footer-sep{opacity:.4;}
.footer-update-link{color:var(--green,#3fae74) !important;font-weight:600;}
.admin-mode{font-size:13px;font-weight:600;padding:10px 12px;border-radius:8px;}
.admin-mode.degraded{background:rgba(201,176,58,.15);border:1px solid var(--med,#c9b03a);color:var(--med,#c9b03a);}
.admin-mode.dual{background:rgba(63,174,116,.15);border:1px solid var(--green,#3fae74);color:var(--green,#3fae74);}
.admin-newacct{max-width:320px;}
.dash-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.dash-title{font-size:18px;font-weight:700;margin:0;}
.dash-scope{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-left:8px;}
.dash-toggle{display:inline-flex;border:1px solid var(--border);border-radius:9px;overflow:hidden;}
.dtbtn{background:transparent;color:var(--muted);border:none;padding:7px 14px;font-size:12px;font-weight:600;cursor:pointer;transition:background .12s,color .12s;}
.dtbtn:hover{background:var(--s2);}
.dtbtn.on{background:var(--green);color:#0a0c0d;}
.signals-slot .sig-stat{display:flex;align-items:baseline;gap:12px;margin-top:8px;}
.signals-slot .sig-num{font-size:30px;font-weight:700;color:var(--text);}
.signals-slot .sig-lbl{font-size:12px;color:var(--muted);}
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
.bar-lbl{width:96px;font-size:11px;font-weight:600;letter-spacing:.3px;flex-shrink:0;font-family:var(--font-mono);}
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
.chip b{font-family:var(--font-mono);}
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
tr.ticket-new td{animation:ticketFade 2.4s ease-out forwards;}
@keyframes ticketFade{0%{background:rgba(120,150,200,.22);}100%{background:transparent;}}
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
.row-take-btn{margin-left:8px;background:var(--green);color:#0a0c0d;border:none;border-radius:6px;padding:3px 10px;font-size:11px;font-weight:700;cursor:pointer;font-family:var(--font-sans);}
.row-take-btn:hover{filter:brightness(1.08);}
.stbadge.investigating{background:rgba(194,122,46,.20);color:var(--high);}
.stbadge.resolved{background:rgba(63,140,95,.20);color:var(--low);}
.stbadge.closed{background:var(--s3);color:var(--faint);}
.cat-tag{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-family:var(--font-mono);}
.cat-bar{width:3px;height:14px;border-radius:2px;flex-shrink:0;}
.score{font-family:var(--font-mono);font-weight:700;}
.stag{background:var(--s3);border-radius:5px;padding:2px 7px;font-size:11px;font-family:var(--font-mono);}

/* hash pill */
.hpill{display:inline-flex;align-items:center;gap:5px;background:var(--s3);border-radius:5px;padding:3px 8px;font-size:11px;font-family:var(--font-mono);color:var(--cat-ai);margin:0 5px 5px 0;cursor:pointer;border:1px solid transparent;transition:border-color .12s;}
.hpill:hover{border-color:var(--green);}
.hpill .hcopy{font-size:9px;color:var(--muted);}

/* modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;display:flex;align-items:flex-start;justify-content:center;padding-top:48px;opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s;}
.overlay.open{opacity:1;visibility:visible;}
.modal{background:var(--s1);border:1px solid var(--border);border-radius:14px;width:760px;max-width:94vw;max-height:84vh;overflow-y:auto;transform:translateY(18px) scale(.98);opacity:0;transition:transform .22s cubic-bezier(.34,1.2,.64,1),opacity .22s;}
.overlay.open .modal{transform:translateY(0) scale(1);opacity:1;}
.mhdr{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--s1);}
.mhdr h3{font-size:14px;font-weight:600;font-family:var(--font-mono);}
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
.crumb{display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding:10px 12px;font-size:11px;font-family:var(--font-mono);color:var(--muted);border-bottom:1px solid var(--border);}
.crumb span{cursor:pointer;}
.crumb span:hover{color:var(--text);}
.fentry{display:flex;align-items:center;gap:10px;padding:8px 12px;font-size:12px;cursor:pointer;border-bottom:1px solid rgba(42,46,49,.5);}
.fentry:hover{background:var(--s3);}
.fentry.sel{background:rgba(63,140,95,.14);}
.fentry .fn{font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.fentry .fsz{margin-left:auto;font-size:11px;color:var(--faint);}
.fic{width:15px;height:15px;flex-shrink:0;color:var(--muted);}
.fmt-group{display:flex;gap:10px;align-items:center;margin-top:8px;flex-wrap:wrap;}
.fmt-note{font-size:11px;color:var(--faint);margin-top:4px;}
.log-box{background:#0a0c0d;border:1px solid var(--border);border-radius:8px;padding:14px;height:330px;overflow-y:auto;font-family:var(--font-mono);font-size:12px;color:var(--low);}
.ll{margin-bottom:3px;word-break:break-all;}
.ll.e{color:var(--red-soft);}.ll.i{color:var(--cat-web);}
.empty{color:var(--muted);text-align:center;padding:44px;font-size:13px;}
.spin{display:inline-block;animation:spin 1s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}
.sel-file{font-size:12px;font-family:var(--font-mono);color:var(--green);margin:10px 0;word-break:break-all;}

/* process tree */
.ptree{display:flex;flex-direction:column;gap:4px;margin-top:6px;}
.ptn{display:flex;align-items:center;gap:8px;background:var(--s2);border-radius:7px;padding:6px 10px;font-size:12px;border-left:3px solid var(--border);}
.ptn .ptrole{font-size:9px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);width:52px;flex-shrink:0;}
.ptn .ptimg{font-family:var(--font-mono);font-weight:600;}
.ptn .ptpid{font-size:11px;color:var(--faint);}
.ptn .ptcmd{font-family:var(--font-mono);font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:340px;}
.ptn:has(.ptrole:empty){opacity:.7;}
.sig-name{cursor:pointer;color:var(--cat-web);font-family:var(--font-mono);}
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
  <div class="brand" style="cursor:pointer" onclick="go('dash')" title="Go to dashboard">Mini SOAR</div>
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

<div class="main"><div class="page" id="pcontent"></div><div id="app-footer"></div></div>

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
    <div class="contact"><div class="cdot" style="background:var(--low)"></div><div class="cn">You</div><div class="cr" id="you-role">owner</div></div>
    <div class="dr-muted">Shared contacts and privilege levels arrive with the multi-user directory (later v11 increment). Accounts, roles and MFA are already active.</div>
  </div>

  <div class="dr-note">Mode is fixed at launch. Use the launcher (python launch.py) to switch; it restarts the app.</div>
  <div class="dr-note" id="dr-version" style="margin-top:6px;font-weight:600;color:var(--muted)"></div>
  <button class="btn-shutdown" onclick="shutdownApp()" title="Stop the server and close the app">Shut down app</button>
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
let _navigating=false;  // true while a page switch is rendering; blocks auto-refresh races
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
  templates:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/></svg>',
  admin:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 4 6v6c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6z"/></svg>',
  ai:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="7" y="7" width="10" height="10" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>'
};
const TABS=[['dash','Dashboard'],['open','Open'],['mine','My Tickets'],['signals','Signals'],['run','Run SIEM'],['templates','Templates'],['ai','AI'],['admin','Admin']];
let _isAdmin=false;
let _role='operator';
let SHOWCASE=false;
const VERSION='v13.1.08';   // single source; bumped on every new build/zip

/* -- api -- */
async function api(path,opts){
  const r=await fetch('/api'+path,Object.assign({headers:{'Content-Type':'application/json'}},opts||{}));
  return r.json();
}

/* -- nav -- */
function esc(s){
  // Central XSS defense: every log-derived field is escaped before entering the DOM.
  return String(s==null?'':s).replace(/[&<>"']/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function buildNav(){
  const visible=TABS.filter(function(t){
    if(SHOWCASE && t[0]==='run')return false;   // no file pipeline in showcase
    if(t[0]==='admin' && !_isAdmin)return false; // admin panel hidden from non-admins
    if(t[0]==='ai' && !(_role==='manager'||_role==='admin'))return false; // AI tickets: manager+ only
    return true;
  });
  document.getElementById('topnav').innerHTML=
    '<div class="dock-tooltip" id="dock-tip"><span id="dock-tip-label"></span></div>'+
    '<div class="dock" id="dock-items">'+
    visible.map(function(t){
      return '<button type="button" class="dock-item'+(t[0]===_cur?' selected':'')+'" '+
        'data-tab="'+t[0]+'" data-label="'+esc(t[1])+'" '+
        'onmouseenter="dockHover(this)" onmouseleave="dockUnhover()" '+
        'onclick="go(\\''+t[0]+'\\')"><span class="dock-icon">'+ICONS[t[0]]+'</span>'+
        '<span class="sr-only">'+esc(t[1])+'</span></button>';
    }).join('')+
    '</div>';
}

// Dock hover tooltip: measures the hovered item and slides a small label above it,
// translating the 21st.dev bottom-menu interaction (a floating tooltip that tracks the
// hovered icon) into plain JS/CSS, no animation library.
function dockHover(el){
  const dock=document.getElementById('dock-items');
  const tip=document.getElementById('dock-tip');
  const label=document.getElementById('dock-tip-label');
  if(!dock||!tip||!label)return;
  const dockRect=dock.getBoundingClientRect();
  const elRect=el.getBoundingClientRect();
  label.textContent=el.getAttribute('data-label');
  tip.classList.add('show');
  // Center the tooltip over the hovered icon, clamped to stay within the dock's width.
  requestAnimationFrame(function(){
    const tipRect=tip.getBoundingClientRect();
    let left=(elRect.left-dockRect.left)+(elRect.width-tipRect.width)/2;
    left=Math.max(0,Math.min(left,dockRect.width-tipRect.width));
    tip.style.transform='translateX('+left+'px)';
  });
}
function dockUnhover(){
  const tip=document.getElementById('dock-tip');
  if(tip)tip.classList.remove('show');
}

// Generic styled hover tooltip, reusing the same visual language as the nav dock's
// tooltip. Any element with a data-tip attribute and onmouseenter="showTip(this)"
// onmouseleave="hideTip()" gets a small floating bubble instead of the plain unstyled
// native browser title tooltip.
function _genericTip(){
  let el=document.getElementById('generic-tip');
  if(!el){
    el=document.createElement('div');el.id='generic-tip';el.className='dock-tooltip';
    el.style.position='fixed';document.body.appendChild(el);
  }
  return el;
}
function showTip(target){
  const text=target.getAttribute('data-tip');
  if(!text)return;
  const tip=_genericTip();
  tip.textContent=text;
  tip.classList.add('show');
  const r=target.getBoundingClientRect();
  requestAnimationFrame(function(){
    const tr=tip.getBoundingClientRect();
    let left=r.left+(r.width-tr.width)/2;
    left=Math.max(4,Math.min(left,window.innerWidth-tr.width-4));
    tip.style.left=left+'px';
    tip.style.top=(r.top-tr.height-8)+'px';
  });
}
function hideTip(){
  const tip=document.getElementById('generic-tip');
  if(tip)tip.classList.remove('show');
}

// Mark that the user just interacted. For a short window the auto-refresh will not touch
// the DOM, so a click is never queued behind a refresh's synchronous work.
let _actingTimer=null;
function markActing(){
  _userActing=true;
  if(_actingTimer)clearTimeout(_actingTimer);
  _actingTimer=setTimeout(function(){_userActing=false;},350);
}

function go(page,filter,pushH){
  if(SHOWCASE && page==='run')page='dash';   // run pipeline sealed off in showcase
  markActing();
  _navigating=true;
  _cur=page;
  _tixFilter=((page==='open'||page==='mine')&&filter)?filter:{};
  if(pushH!==false){
    history.pushState({page:page,filter:_tixFilter},'','#'+page);
  }
  buildNav();
  Promise.resolve(renderPage(page)).finally(function(){_navigating=false;});
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
  else if(p==='admin')await renderAdmin(el);
  else if(p==='ai')await renderAI(el);
}

async function renderAI(el){
  let proposed=[],pending=[];
  try{proposed=await api('/ai/tickets?view=proposed');}catch(e){}
  try{pending=await api('/ai/tickets?view=pending_verification');}catch(e){}
  function tf(rec){
    return (rec.top_features||[]).slice(0,4).map(function(x){
      return '<span class="wk-tag">'+esc((x[1]!==undefined?x[1]:x))+'</span>';}).join('');
  }
  function confBadge(c){
    if(c==null)return '<span class="wk-tag">conf -</span>';
    var pct=(c*100).toFixed(0);
    var color=c>=0.9?'#4ade80':(c>=0.7?'#fbbf24':'#f87171');
    var note=c>=0.9?'':(c>=0.7?' check':' verify');
    return '<span class="wk-tag" style="border-color:'+color+';color:'+color+'" title="lower confidence needs more analyst verification">conf '+pct+'%'+note+'</span>';
  }
  function row(rec){
    const lab=esc(rec.ai_label||'unknown');
    return '<div class="wk-row" style="flex-wrap:wrap;gap:8px;align-items:center">'+
      '<div class="wk-info" style="min-width:150px"><span class="wk-name">'+esc(rec.ticket_id)+'</span>'+
        '<span class="wk-tag">AI: '+lab+'</span>'+confBadge(rec.confidence)+
        '<span class="wk-tag">'+esc(rec.category)+'</span></div>'+
      '<div style="flex:1;min-width:140px;font-size:11px;color:var(--muted)">analysis: '+(tf(rec)||'<span class="wk-tag">no model / abstained</span>')+'</div>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap">'+
        '<button class="login-btn" style="width:auto;padding:5px 9px;font-size:12px;display:inline-block" onclick="aiVerify('+rec.id+',\\'true_positive\\')">TP</button>'+
        '<button class="login-btn" style="width:auto;padding:5px 9px;font-size:12px;display:inline-block" onclick="aiVerify('+rec.id+',\\'false_positive\\')">FP</button>'+
        '<button class="wk-del" onclick="aiVerify('+rec.id+',\\'benign\\')">benign</button>'+
        '<button class="wk-del" onclick="aiVerify('+rec.id+',\\'duplicate\\')">dup</button>'+
        '<button class="wk-del" onclick="aiExplain('+rec.id+')">Explain</button>'+
      '</div></div>';
  }
  const propRows=proposed.slice().sort(function(a,b){return (a.confidence||0)-(b.confidence||0);}).map(row).join('');
  const pendRows=pending.map(row).join('');
  el.innerHTML=
    '<div class="card"><h3>AI tickets</h3>'+
      '<div class="dr-muted" style="margin-bottom:10px">Manager and admin only. Delegate a ticket to the AI, then confirm or correct its proposed disposition. Your verification is what teaches the model (validated label) and moves its autonomy streak. Auto-closed items still wait here for a human spot-check.</div>'+
      '<div class="wk-row" style="gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px">'+
        '<input id="ai-tid" class="login-input" style="flex:1;min-width:160px;margin:0" placeholder="Ticket ID to delegate">'+
        '<input id="ai-cat" class="login-input" style="flex:1;min-width:140px;margin:0" placeholder="Category (default ticket_triage)">'+
        '<button class="login-btn" style="width:auto;padding:6px 12px;font-size:12px;display:inline-block" onclick="aiDelegate()">Delegate to AI</button>'+
        '<button class="wk-del" onclick="aiAutoInfer()">Auto-triage now</button>'+
        '<button class="wk-del" onclick="aiSeedDemo()">Seed AI demo</button>'+
      '</div>'+
    '</div>'+
    '<div class="card"><h3>Proposed ('+proposed.length+')</h3>'+(propRows||'<div class="empty">No proposals.</div>')+'</div>'+
    '<div class="card"><h3>Auto-closed, pending verification ('+pending.length+')</h3>'+(pendRows||'<div class="empty">Nothing pending.</div>')+'</div>';
}
async function aiExplain(id){
  let r={};
  try{r=await api('/ai/tickets/'+id+'/explain');}catch(e){}
  if(r&&r.explanation){toast('AI explanation: '+r.explanation);}
  else{toast('Explanation unavailable ('+((r&&r.reason)||'LLM off')+'). The verdict stays the deterministic classifier.');}
}
async function aiDelegate(){
  const tid=((document.getElementById('ai-tid')||{}).value||'').trim();
  const cat=((document.getElementById('ai-cat')||{}).value||'').trim();
  if(!tid){toast('Enter a ticket ID.');return;}
  let r={};
  try{r=await api('/ai/tickets/assign',{method:'POST',body:JSON.stringify({ticket_id:tid,category:cat||undefined})});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  toast('Delegated '+tid+' to the AI ('+(r.ai_label||'?')+')');
  renderPage('ai');
}
async function aiAutoInfer(){
  let r={};
  try{r=await api('/ai/auto-infer',{method:'POST',body:JSON.stringify({})});}catch(e){}
  if(r&&r.created!==undefined){
    if(r.created>0){toast('Auto-triaged '+r.created+' ticket(s).');}
    else{toast('Auto-triage: nothing new'+(r.skipped?' ('+r.skipped+')':'')+'.');}
  }else{toast('Auto-triage failed.');}
  renderPage('ai');
}
async function aiSeedDemo(){
  let r={};
  try{r=await api('/ai/seed-demo',{method:'POST',body:JSON.stringify({})});}catch(e){}
  if(r&&r.created!==undefined){
    toast('AI demo seeded (model v'+(r.model_version||'?')+'), auto-triaged '+r.created+' ticket(s).');
  }else{toast('Seed failed'+((r&&r.error)?': '+r.error:'')+'.');}
  renderPage('ai');
}
async function aiVerify(id,label){
  let r={};
  try{r=await api('/ai/tickets/'+id+'/verify',{method:'POST',body:JSON.stringify({human_label:label})});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  const st=(r.autonomy&&r.autonomy.state_name)?', autonomy now '+r.autonomy.state_name:'';
  toast('Verified as '+label+st);
  renderPage('ai');
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
    return '<div class="ptn" title="'+esc(n.command_line||'')+'">'+
      '<span class="ptrole">'+esc(role)+'</span>'+
      '<span class="ptimg">'+esc(n.image||'?')+'</span>'+
      '<span class="ptpid">pid '+(n.pid==null?'?':esc(n.pid))+'</span>'+
      (n.command_line?'<span class="ptcmd">'+esc(n.command_line)+'</span>':'')+
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
  const f=p.first||'';const l=p.last||'';const e=p.email||'';
  document.getElementById('p-first').value=f;
  document.getElementById('p-last').value=l;
  document.getElementById('p-email').value=e;
  document.getElementById('p-display-name').textContent=(f+' '+l).trim();
  document.getElementById('p-display-email').textContent=e;
  const av=document.getElementById('avatar-el');
  if(p.avatar){av.innerHTML='<img src="'+p.avatar+'" alt="avatar">';}
  else{av.textContent=((f[0]||'')+(l[0]||'')).toUpperCase()||'?';}
}
function reflectAccount(user, role){
  // When authenticated, the drawer must show the REAL logged-in account, not the cosmetic
  // localStorage defaults ("operator@local", "owner"). The first/last name stays a personal
  // display alias if the user set one; otherwise it falls back to the account username.
  if(user){
    var sub=document.getElementById('p-display-email');
    if(sub)sub.textContent=user+' | '+(role||'');
  }
  if(role){
    var yr=document.getElementById('you-role');
    if(yr)yr.textContent=role;
  }
  var prof={};try{prof=JSON.parse(localStorage.getItem('soar_profile')||'{}');}catch(e){}
  if(user && !prof.first && !prof.last){
    var dn=document.getElementById('p-display-name');if(dn)dn.textContent=user;
    var av=document.getElementById('avatar-el');
    if(av && !prof.avatar)av.textContent=(user[0]||'?').toUpperCase();
  }
}
function pwChecklistHTML(id){
  var items=[['len','At least 12 characters'],['upper','An uppercase letter'],
    ['lower','A lowercase letter'],['digit','A number'],['special','A special character']];
  return '<div id="'+id+'" class="pwc" style="margin:2px 0 10px 2px;font-size:11px;color:var(--muted);line-height:1.7">'+
    items.map(function(it){
      return '<div data-k="'+it[0]+'" style="display:flex;align-items:center;gap:6px">'+
        '<span class="pwc-mark" style="display:inline-block;width:10px;text-align:center;background:transparent;font-size:8px;line-height:1">.</span>'+
        '<span>'+it[1]+'</span></div>';
    }).join('')+
    '<div style="opacity:.7;margin-top:3px">At least 3 of the 4 character types, enough length, no common patterns.</div>'+
  '</div>';
}
function updatePwChecklist(passId,listId){
  var v=(document.getElementById(passId)||{}).value||'';
  var checks={len:v.length>=12,upper:/[A-Z]/.test(v),lower:/[a-z]/.test(v),
    digit:/[0-9]/.test(v),special:/[^A-Za-z0-9]/.test(v)};
  var list=document.getElementById(listId);if(!list)return;
  Object.keys(checks).forEach(function(k){
    var rowEl=list.querySelector('[data-k="'+k+'"]');if(!rowEl)return;
    var mark=rowEl.querySelector('.pwc-mark');if(!mark)return;
    if(checks[k]){mark.textContent=String.fromCharCode(10003);mark.style.color='#4ade80';}
    else{mark.textContent=String.fromCharCode(10007);mark.style.color='var(--muted)';}
  });
}
function saveProfile(){
  const f=document.getElementById('p-first').value.trim();
  const l=document.getElementById('p-last').value.trim();
  const e=document.getElementById('p-email').value.trim();
  const p=JSON.parse(localStorage.getItem('soar_profile')||'{}');
  p.first=f;p.last=l;p.email=e;
  localStorage.setItem('soar_profile',JSON.stringify(p));
  document.getElementById('p-display-name').textContent=(f+' '+l).trim();
  document.getElementById('p-display-email').textContent=e;
  const av=document.getElementById('avatar-el');
  if(!p.avatar)av.textContent=((f[0]||'')+(l[0]||'')).toUpperCase()||'?';
  // When authenticated (server mode), the profile is stored per-account server-side too,
  // so it follows the account across browsers and an admin can see/edit it.
  if(window._account&&window._account.user){
    api('/account/profile',{method:'PUT',body:JSON.stringify({first_name:f,last_name:l,email:e})})
      .then(function(){toast('Profile saved');})
      .catch(function(){toast('Could not save profile');});
  }else{
    toast('Profile saved');
  }
}
async function loadAccountProfile(){
  // Fill the drawer fields from the server-side per-account profile after login.
  if(!(window._account&&window._account.user))return;
  let pr={};try{pr=await api('/account/profile');}catch(e){return;}
  const fi=document.getElementById('p-first'),li=document.getElementById('p-last'),ei=document.getElementById('p-email');
  if(fi)fi.value=pr.first_name||'';if(li)li.value=pr.last_name||'';if(ei)ei.value=pr.email||'';
  const dn=(((pr.first_name||'')+' '+(pr.last_name||'')).trim())||window._account.user;
  const de=document.getElementById('p-display-name');if(de)de.textContent=dn;
  const p=JSON.parse(localStorage.getItem('soar_profile')||'{}');
  if(!p.avatar){
    const av=document.getElementById('avatar-el');
    if(av)av.textContent=(((pr.first_name||'')[0]||'')+((pr.last_name||'')[0]||'')).toUpperCase()||(window._account.user[0]||'?').toUpperCase();
  }
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
let _dashSig=null;  // last-seen dashboard signature, to skip needless re-renders
let _dashScope='general';  // 'general' = whole open queue; 'mine' = current user's tickets

async function maybeRefreshDash(){
  const scopeAtStart=_cur;
  let tix,stats;
  try{tix=await api('/tickets');}catch(e){return;}
  if(_cur!==scopeAtStart||_cur!=='dash')return;
  // Signature = counts that the dashboard visibly depends on.
  const sig=tix.length+'|'+tix.filter(function(t){return t.status==='open';}).length+
    '|'+tix.filter(function(t){return t.status!=='open';}).length;
  if(sig===_dashSig)return;  // nothing the dashboard shows has changed
  try{stats=await api('/stats');}catch(e){return;}
  if(_cur!==scopeAtStart||_cur!=='dash')return;
  _dashSig=sig;
  const el=document.getElementById('pcontent');
  if(el)renderDash(el,stats,tix);  // reuse already-fetched data, no extra round-trips
}

function setDashScope(s){
  _dashScope=s;
  const el=document.getElementById('pcontent');
  if(el&&_cur==='dash')renderDash(el);
}

async function renderDash(el,preStats,preTix){
  const s=preStats||await api('/stats');
  const allTix=preTix||await api('/tickets');
  const openList=allTix.filter(function(t){return t.status==='open';});
  const mineList=allTix.filter(function(t){return t.status!=='open';});

  // Scope selection (strict): in 'mine' mode every stat reflects the user's tickets only.
  const scoped=(_dashScope==='mine')?mineList:openList;
  const scopeLabel=(_dashScope==='mine')?'my tickets':'open queue';
  const dnav=(_dashScope==='mine')?'mine':'open';  // navigation target for drill-down clicks

  // Severity from the scoped set.
  const sev={};
  scoped.forEach(function(t){if(t.severity)sev[t.severity]=(sev[t.severity]||0)+1;});
  const sevTotal=scoped.length;
  const did='d'+Date.now();

  // Signal Types and MITRE recomputed from the scoped tickets (strict mode), not from the
  // global /api/stats. This keeps every widget consistent with the selected scope.
  const typeCount={};const mitreCount={};
  scoped.forEach(function(t){
    const k=baseLabel(t.signal_type);if(k)typeCount[k]=(typeCount[k]||0)+1;
    const m=t.mitre_technique;if(m)mitreCount[m]=(mitreCount[m]||0)+1;
  });

  const legend=SEV_O.filter(function(k){return sev[k];}).map(function(k){
    return '<div class=\"row\" style=\"cursor:pointer\" title=\"Filter by '+k+'\" onclick=\"go(\\''+dnav+'\\',{severity:\\''+k+'\\'})\"><div class=\"dot\" style=\"background:'+SEV_C[k]+'\"></div><span>'+k+'</span><span class=\"dv\">'+sev[k]+'</span></div>';
  }).join('');

  const tE=Object.entries(typeCount).sort(function(a,b){return b[1]-a[1];}).slice(0,10);
  const tM=Math.max.apply(null,tE.map(function(e){return e[1];}).concat([1]));
  const typeBars=tE.map(function(e){
    return '<div class=\"bar-row\" data-tip=\"'+esc(e[0])+'\" onmouseenter=\"showTip(this)\" onmouseleave=\"hideTip()\" onclick=\"go(\\''+dnav+'\\',{type:\\''+baseLabel(e[0])+'\\'})\">' +
      '<div class=\"bar-lbl\" style=\"color:'+catColor(e[0])+'\">'+abbrev(e[0])+'</div>'+
      '<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:'+Math.round(e[1]/tM*100)+'%;background:'+catColor(e[0])+'\"></div></div>'+
      '<div class=\"bar-cnt\">'+e[1]+'</div></div>';
  }).join('');

  const mE=Object.entries(mitreCount).sort(function(a,b){return b[1]-a[1];}).slice(0,10);
  const mM=Math.max.apply(null,mE.map(function(e){return e[1];}).concat([1]));
  const mitreBars=mE.map(function(e){
    return '<div class=\"bar-row\" data-tip=\"'+esc(e[0])+'\" onmouseenter=\"showTip(this)\" onmouseleave=\"hideTip()\" onclick=\"go(\\''+dnav+'\\',{mitre:\\''+e[0]+'\\'})\">' +
      '<div class=\"bar-lbl\">'+e[0]+'</div>'+
      '<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:'+Math.round(e[1]/mM*100)+'%;background:var(--cat-ai)\"></div></div>'+
      '<div class=\"bar-cnt\">'+e[1]+'</div></div>';
  }).join('');

  const catLeg=Object.keys(CAT_COLOR).map(function(c){
    return '<span class="cat-tag"><span class="cat-bar" style="background:'+CAT_COLOR[c]+'"></span>'+c+'</span>';
  }).join('');

  // View toggle: general (open queue) vs my tickets. Top-right of the dashboard.
  const toggle=
    '<div class=\"dash-toggle\">'+
      '<button class=\"dtbtn'+(_dashScope==='general'?' on':'')+'\" onclick=\"setDashScope(\\'general\\')\">General view</button>'+
      '<button class=\"dtbtn'+(_dashScope==='mine'?' on':'')+'\" onclick=\"setDashScope(\\'mine\\')\">My tickets</button>'+
    '</div>';

  el.innerHTML=
  '<div class="dash-head"><h2 class="dash-title">Dashboard <span class="dash-scope">'+scopeLabel+'</span></h2>'+toggle+'</div>'+
  '<div class="kpi-grid">'+
    '<div class="kpi"><div class="lbl">Tickets ('+scopeLabel+')</div><div class="val">'+sevTotal+'</div></div>'+
    '<div class="kpi crit"><div class="lbl">Critical</div><div class="val">'+(sev.CRITICAL||0)+'</div></div>'+
    '<div class="kpi high"><div class="lbl">High</div><div class="val">'+(sev.HIGH||0)+'</div></div>'+
    '<div class="kpi"><div class="lbl">Medium</div><div class="val">'+(sev.MEDIUM||0)+'</div></div>'+
  '</div>'+
  '<div class="zone-row">'+scopeCard('Open queue',openList,'open')+scopeCard('My tickets',mineList,'mine')+'</div>'+
  '<div class="chart-row">'+
    '<div class="card"><h3>Severity ('+scopeLabel+')</h3><div class="donut-wrap"><canvas id="'+did+'" width="120" height="120"></canvas><div class="dleg">'+(legend||'<span style="color:var(--muted)">No data</span>')+'</div></div></div>'+
    '<div class="card"><h3>Signal Types ('+scopeLabel+')</h3>'+(typeBars||'<div class="empty">No tickets in scope</div>')+'</div>'+
    '<div class="card"><h3>MITRE Techniques ('+scopeLabel+')</h3>'+(mitreBars||'<div class="empty">No data</div>')+'</div>'+
  '</div>'+
  // Signals: its own separate slot, NOT mixed into the ticket-based widgets above.
  // Signals are raw detections, conceptually distinct from tickets; they get a dedicated row.
  '<div class="card signals-slot"><div style="display:flex;align-items:baseline;justify-content:space-between"><h3>Signals (global)</h3><span class="x" style="cursor:pointer;font-size:12px;color:var(--green)" onclick="go(\\'signals\\')">open signals &rarr;</span></div>'+
    '<div class="sig-stat"><span class="sig-num">'+(s.total_signals||0)+'</span><span class="sig-lbl">raw detections across all sources, independent of ticket scope</span></div></div>'+
  '<div class="card"><h3>Category legend - click a bar to filter tickets</h3><div style="display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted)">'+catLeg+'</div></div>';

  if(sevTotal){
    const ctx=document.getElementById(did).getContext('2d');
    let start=-Math.PI/2;const cx=60,cy=60,R=52,ir=33;
    SEV_O.forEach(function(k){
      const v=sev[k]||0;if(!v)return;
      const a=(v/sevTotal)*2*Math.PI;
      ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,R,start,start+a);ctx.closePath();
      ctx.fillStyle=SEV_C[k];ctx.fill();start+=a;
    });
    ctx.beginPath();ctx.arc(cx,cy,ir,0,2*Math.PI);ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--s1').trim()||'#16181a';ctx.fill();
    ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--text').trim()||'#e6e7e8';
    ctx.font='bold 16px Segoe UI';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(sevTotal,cx,cy);
  }
}
/* -- tickets -- */
let _tix=[];
let _tixScope='open';
let _tixFetching=false;   // true while any /tickets request is in flight
let _tixLastFetch=0;      // timestamp of the last successful /tickets fetch
let _pendingInsert=false; // true while a deferred ticket insertion is scheduled
let _userActing=false;    // true briefly after a user interaction; refresh yields to it
async function renderTickets(el){
  _tixScope=(_cur==='mine')?'mine':'open';
  let qs='';
  if(_tixFilter.type)qs='?type='+encodeURIComponent(_tixFilter.type);
  else if(_tixFilter.mitre)qs='?mitre='+encodeURIComponent(_tixFilter.mitre);
  else if(_tixFilter.severity)qs='?severity='+encodeURIComponent(_tixFilter.severity);
  _tixFetching=true;
  _tix=await api('/tickets'+qs);
  _tixFetching=false;
  _tixLastFetch=Date.now();
  let chipLabel='';
  if(_tixFilter.type)chipLabel=abbrev(_tixFilter.type);
  else if(_tixFilter.mitre)chipLabel=_tixFilter.mitre;
  else if(_tixFilter.severity)chipLabel=_tixFilter.severity;
  const chip=chipLabel?
    '<div class="chip">filter <b>'+esc(chipLabel)+'</b><span class="x" onclick="go(\\''+_cur+'\\')">clear</span></div>':'';
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

function visibleRows(){
  const sev=(document.getElementById('f-sev')||{}).value||'';
  const st=(document.getElementById('f-st')||{}).value||'';
  const q=((document.getElementById('f-q')||{}).value||'').toLowerCase();
  return _tix.filter(function(t){
    const inScope=(_tixScope==='open')?(t.status==='open'):(t.status!=='open');
    return inScope&&(!sev||t.severity===sev)&&(!st||t.status===st)&&
      (!q||[t.host,t.signal_type,t.ticket_id,t.signal_id].some(function(x){return (x||'').toLowerCase().includes(q);}));
  });
}

function tixRowHtml(t,isNew){
  const canTake=(t.status==='open');
  const takeBtn=canTake
    ?'<button class="row-take-btn" onclick="event.stopPropagation();quickTakeTix(\\''+t.ticket_id+'\\')" title="Take this ticket without opening it">Take</button>'
    :'';
  return '<tr class="clickable'+(t.status==='closed'?' closed':'')+(isNew?' ticket-new':'')+'" data-tid="'+t.ticket_id+'" onclick="openTix(\\''+t.ticket_id+'\\')">'+
    '<td><code style="font-family:var(--font-mono);color:var(--muted)">'+t.ticket_id+'</code></td>'+
    '<td><span class="badge '+t.severity+'">'+t.severity+'</span></td>'+
    '<td class="score" style="color:'+sc(t.score)+'">'+(t.score||0).toFixed(2)+'</td>'+
    '<td><span class="cat-tag"><span class="cat-bar" style="background:'+catColor(t.signal_type)+'"></span>'+abbrev(t.signal_type)+'</span></td>'+
    '<td>'+esc(t.host)+'</td>'+
    '<td style="font-size:11px;font-family:var(--font-mono)">'+esc(t.mitre_technique||'-')+'</td>'+
    '<td><span class="stbadge '+t.status+'">'+t.status+'</span>'+takeBtn+'</td></tr>';
}

async function quickTakeTix(tid){
  // Take a ticket directly from the row: same PATCH the modal's save button would send
  // (status=investigating, assignee=me), without ever opening the modal.
  try{
    await api('/tickets/'+tid,{method:'PATCH',
      body:JSON.stringify({status:'investigating',assignee:myName()})});
  }catch(e){toast('Could not take ticket '+tid+'.');return;}
  toast('Took ticket '+tid+'.');
  const el=document.getElementById('pcontent');
  if(el)await renderTickets(el);
}

function filterTix(){
  markActing();
  const rows=visibleRows();
  document.getElementById('tix-count').textContent=rows.length;
  const tb=document.getElementById('tix-body');if(!tb)return;
  tb.innerHTML=rows.length?rows.map(function(t){return tixRowHtml(t,false);}).join('')
    :'<tr><td colspan="7" class="empty">'+(_tixScope==='open'?'No open tickets in the queue.':'You have not taken any tickets yet.')+'</td></tr>';
}

// Additive refresh: pulls fresh tickets, inserts only new ones into the existing DOM in
// sorted position, compensating scroll so the analyst's current view never jumps.
async function refreshTicketsAdditive(){
  const tb=document.getElementById('tix-body');if(!tb)return;
  // Skip if a fetch is in flight or one completed within the last 2s (data already fresh).
  if(_tixFetching||(Date.now()-_tixLastFetch)<2000)return;
  const scopeAtStart=_cur;
  let qs='';
  if(_tixFilter.type)qs='?type='+encodeURIComponent(_tixFilter.type);
  else if(_tixFilter.mitre)qs='?mitre='+encodeURIComponent(_tixFilter.mitre);
  else if(_tixFilter.severity)qs='?severity='+encodeURIComponent(_tixFilter.severity);
  let fresh;
  _tixFetching=true;
  try{fresh=await api('/tickets'+qs);}catch(e){_tixFetching=false;return;}
  _tixFetching=false;
  _tixLastFetch=Date.now();
  if(_cur!==scopeAtStart||(_cur!=='open'&&_cur!=='mine'))return;
  if(!document.getElementById('tix-body'))return;
  const oldById={};_tix.forEach(function(t){oldById[t.ticket_id]=t;});
  const newcomers=fresh.filter(function(t){return !oldById[t.ticket_id];});
  const statusChanged=fresh.some(function(t){return oldById[t.ticket_id]&&oldById[t.ticket_id].status!==t.status;});
  _tix=fresh;
  const vis=visibleRows();
  const cnt=document.getElementById('tix-count');if(cnt)cnt.textContent=vis.length;
  if(!newcomers.length){
    if(statusChanged)filterTix();
    return;
  }
  // CRITICAL: never run the DOM insertion synchronously here. If the user is mid-click,
  // a synchronous block (filter + measure + insert + reflow) holds the main thread and the
  // click waits behind it (the ~1s freeze). Defer to the next animation frame, and if the
  // user starts acting before it runs, skip this cycle (the next refresh will catch up).
  if(_pendingInsert)return;  // an insert is already scheduled
  _pendingInsert=true;
  requestAnimationFrame(function(){
    _pendingInsert=false;
    // Re-check: user may have switched pages or started interacting since we scheduled.
    if(_cur!==scopeAtStart||(_cur!=='open'&&_cur!=='mine'))return;
    if(_userActing){return;}  // user is interacting; do not steal the thread, retry next cycle
    const body=document.getElementById('tix-body');if(!body)return;
    const visNow=visibleRows();
    // Precompute sort positions once (O(n)) instead of indexOf inside loops (O(n^2)).
    const posById={};visNow.forEach(function(t,i){posById[t.ticket_id]=i;});
    const showNow=newcomers.filter(function(t){return posById[t.ticket_id]!==undefined;});
    if(!showNow.length)return;
    const scroller=document.scrollingElement||document.documentElement;
    const empty=body.querySelector('td.empty');if(empty&&empty.parentNode)empty.parentNode.remove();
    // Anchor measurement: read layout ONCE before any mutation.
    let anchorRow=null,anchorOffset=0;
    const rows0=body.children;
    for(let i=0;i<rows0.length;i++){
      const r=rows0[i].getBoundingClientRect();
      if(r.bottom>0){anchorRow=rows0[i];anchorOffset=r.top;break;}
    }
    // Build a fragment, then do all inserts (writes only, no interleaved reads = no thrashing).
    showNow.forEach(function(t){
      const pos=posById[t.ticket_id];
      const tmp=document.createElement('tbody');tmp.innerHTML=tixRowHtml(t,true);
      const tr=tmp.firstChild;
      const existing=body.children;
      let refNode=null;
      for(let i=0;i<existing.length;i++){
        const eid=existing[i].getAttribute('data-tid');
        const ep=posById[eid];
        if(ep!==undefined&&ep>pos){refNode=existing[i];break;}
      }
      body.insertBefore(tr,refNode);
    });
    // Single layout read AFTER all writes, then one scroll write to keep the view fixed.
    if(anchorRow){
      const delta=anchorRow.getBoundingClientRect().top-anchorOffset;
      if(delta!==0)scroller.scrollTop+=delta;
    }
  });
}
async function renderAdmin(el){
  let status={},accounts=[],pending=[],audit=[],ai={};
  try{status=await api('/admin/status');}catch(e){}
  try{accounts=await api('/admin/accounts');}catch(e){}
  try{pending=await api('/admin/requests');}catch(e){}
  try{audit=await api('/admin/audit');}catch(e){}
  try{ai=await api('/admin/ai/status');}catch(e){}

  const modeNote=status.dual_control_active
    ? '<div class="admin-mode dual">Dual control ACTIVE ('+status.admin_count+' admins). Sensitive actions require a second admin\\'s approval.</div>'
    : '<div class="admin-mode degraded">Degraded mode ('+status.admin_count+' admin'+(status.admin_count===1?'':'s')+'). Sensitive actions apply immediately and are audited as degraded. Add a second admin to enable four-eyes control.</div>';

  const LEVELS=['shadow','supervised','auto_triage','auto_close'];
  function levelSelect(cat,current){
    return '<select onchange="aiSetCeiling(\\''+esc(cat)+'\\',this.value)" style="padding:4px 6px;background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:6px">'+
      LEVELS.map(function(lv){return '<option value="'+lv+'"'+(lv===current?' selected':'')+'>'+lv+'</option>';}).join('')+'</select>';
  }
  const aiCats=(ai.categories||[]);
  const aiRows=aiCats.map(function(c){
    return '<div class="wk-row" style="flex-wrap:wrap;gap:8px;align-items:center">'+
      '<div class="wk-info" style="min-width:150px"><span class="wk-name">'+esc(c.category)+'</span>'+
        '<span class="wk-tag">state: '+esc(c.effective_state_name)+'</span>'+
        '<span class="wk-tag">streak: '+(c.streak||0)+'</span></div>'+
      '<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">'+
        '<span style="font-size:11px;color:var(--muted)">ceiling</span>'+levelSelect(c.category,c.ceiling_name)+
        '<button class="login-btn" style="width:auto;padding:6px 10px;font-size:12px;display:inline-block" onclick="aiTrain(\\''+esc(c.category)+'\\')">Train</button>'+
        '<button class="wk-del" onclick="aiMetrics(\\''+esc(c.category)+'\\')">Metrics</button>'+
        '<button class="wk-del" onclick="aiRollback(\\''+esc(c.category)+'\\')">Rollback model</button>'+
      '</div></div>';
  }).join('');
  const killNote=ai.kill_switch_engaged
    ? '<span class="admin-mode degraded" style="display:inline-block;padding:4px 10px;margin:0">KILL SWITCH ENGAGED, all categories forced to supervised</span>'
    : '<span style="color:var(--muted);font-size:12px">Kill switch off</span>';
  const aiEnabledNote=ai.ai_enabled
    ? '<span class="wk-tag">classifier enabled</span>'
    : '<span class="wk-tag">classifier OFF (set SIEM_AI_ENABLED=1 to run inference; policy can still be configured now)</span>';
  const aiCard='<div class="card"><h3>AI autonomy</h3>'+
    '<div class="dr-muted" style="margin-bottom:10px">Ladder: shadow -> supervised -> auto_triage -> auto_close. The ceiling is the admin-approved authority; the AI never acts above it. Raising a ceiling to auto_close, disengaging the kill switch, or retraining are four-eyes actions. Lowering a ceiling and engaging the kill switch are immediate. '+aiEnabledNote+'</div>'+
    '<div class="wk-row" style="gap:8px;flex-wrap:wrap;align-items:center;background:var(--s2);border-radius:8px;padding:10px;margin-bottom:12px">'+
      '<div style="flex:1;min-width:220px">'+
        '<div class="wk-name">Training and tuning</div>'+
        '<div class="dr-muted" style="font-size:11px">Train the model on the current training data (the bundled SOC corpus plus any imported datasets and verified tickets), then tune how hard it leans toward calling a borderline ticket a threat.</div>'+
      '</div>'+
      '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
        '<label class="dr-muted" style="font-size:11px">Recall bias</label>'+
        '<input id="ai-bias" type="number" step="0.5" min="0" max="20" value="'+esc(String((ai.recall_bias!=null?ai.recall_bias:4)))+'" class="login-input" style="width:70px;margin:0">'+
        '<button class="wk-del" onclick="aiSetBias()">Set</button>'+
        '<button class="login-btn" style="width:auto;padding:6px 12px;font-size:12px;display:inline-block" onclick="aiTrainDatasets()">Train on training data</button>'+
      '</div>'+
    '</div>'+
    '<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">'+killNote+
      '<button class="wk-del" onclick="aiKillSwitch(true)">Engage kill switch</button>'+
      '<button class="login-btn" style="width:auto;padding:6px 10px;font-size:12px;display:inline-block" onclick="aiKillSwitch(false)">Disengage</button></div>'+
    (aiRows||'<div class="empty">No category configured yet. Add one below to opt it in.</div>')+
    '<div class="wk-row" style="gap:8px;margin-top:12px;flex-wrap:wrap;align-items:flex-start;border-top:1px solid var(--border);padding-top:12px">'+
      '<div style="flex:1;min-width:220px">'+
        '<div class="dr-muted" style="margin-bottom:6px">Import a classifier (our JSON params only; pickle/executables refused structurally). Imported models are quarantined as an INACTIVE version. Review, then activate via the version controls. Semantic quality is your risk.</div>'+
        '<input id="ai-imp-cat" class="login-input" style="margin:0 0 6px 0" placeholder="Category for the imported model">'+
        '<textarea id="ai-imp-json" class="login-input" style="margin:0;min-height:70px;font-family:monospace;font-size:11px" placeholder=\\'{"kind":"naive_bayes", ...}\\'></textarea>'+
        '<button class="login-btn" style="width:auto;padding:6px 12px;font-size:12px;display:inline-block;margin-top:6px" onclick="aiImportModel()">Import model (inactive)</button>'+
      '</div>'+
      '<div style="flex:1;min-width:220px">'+
        '<div class="dr-muted" style="margin-bottom:6px">Import a labeled training dataset (JSON array of {features:[...] or ticket:{...}, label}). Tagged as a distinct source, influence-capped, and rollback-able by name. Retraining still needs four-eyes.</div>'+
        '<input id="ai-ds-cat" class="login-input" style="margin:0 0 6px 0" placeholder="Category">'+
        '<input id="ai-ds-name" class="login-input" style="margin:0 0 6px 0" placeholder="Dataset name (e.g. vendorA)">'+
        '<textarea id="ai-ds-json" class="login-input" style="margin:0;min-height:60px;font-family:monospace;font-size:11px" placeholder=\\'[{"features":["stype=powershell"],"label":"true_positive"}]\\'></textarea>'+
        '<div style="display:flex;gap:6px;margin-top:6px">'+
          '<button class="login-btn" style="width:auto;padding:6px 12px;font-size:12px;display:inline-block" onclick="aiImportDataset()">Import dataset</button>'+
          '<button class="wk-del" onclick="aiRollbackDataset()">Rollback dataset</button>'+
        '</div>'+
      '</div>'+
    '</div>'+
    '<div class="wk-row" style="gap:8px;margin-top:10px;flex-wrap:wrap;align-items:center">'+
      '<input id="ai-newcat" class="login-input" style="flex:1;min-width:160px;margin:0" placeholder="Category name (e.g. microsoft_service_noise)">'+
      '<select id="ai-newcat-level" style="padding:4px 6px;background:var(--panel);color:var(--fg);border:1px solid var(--border);border-radius:6px">'+
        LEVELS.map(function(lv){return '<option value="'+lv+'">'+lv+'</option>';}).join('')+'</select>'+
      '<button class="login-btn" style="width:auto;padding:6px 12px;font-size:12px;display:inline-block" onclick="aiAddCategory()">Configure category</button>'+
    '</div>'+
  '</div>';

  const acctRows=accounts.map(function(a){
    return '<tr><td>'+esc(a.username)+'</td><td><span class="stbadge '+esc(a.role)+'">'+esc(a.role)+'</span></td>'+
      '<td style="font-size:11px;color:var(--muted)">'+esc((a.last_login||'never').slice(0,19))+'</td>'+
      '<td><button class="wk-del" style="margin-right:8px" onclick="adminForceLogout(\\''+esc(a.username)+'\\')" title="Immediately kill every active session for this account">force logout</button>'+
      '<button class="wk-del" onclick="adminDeleteAccount(\\''+esc(a.username)+'\\')">delete</button></td></tr>';
  }).join('');

  const profRows=accounts.map(function(a,i){
    return '<div class="wk-row" style="flex-wrap:wrap;gap:6px;align-items:center">'+
      '<div class="wk-info" style="min-width:110px"><span class="wk-name">'+esc(a.username)+'</span>'+
        '<span class="wk-tag">'+esc(a.role)+'</span></div>'+
      '<input id="pf-f-'+i+'" class="login-input" style="flex:1;min-width:90px;margin:0" placeholder="First name" value="'+esc(a.first_name||'')+'">'+
      '<input id="pf-l-'+i+'" class="login-input" style="flex:1;min-width:90px;margin:0" placeholder="Last name" value="'+esc(a.last_name||'')+'">'+
      '<input id="pf-e-'+i+'" class="login-input" style="flex:1;min-width:120px;margin:0" placeholder="Email" value="'+esc(a.email||'')+'">'+
      '<button class="login-btn" style="width:auto;padding:6px 12px;font-size:12px;display:inline-block" onclick="adminSaveProfile(\\''+esc(a.username)+'\\','+i+')">Save</button>'+
    '</div>';
  }).join('');

  const pendingRows=pending.map(function(r){
    return '<div class="wk-row"><div class="wk-info"><span class="wk-name">'+esc(r.action)+'</span>'+
      '<span class="wk-tag">by '+esc(r.requested_by)+'</span></div>'+
      '<div><button class="login-btn" style="width:auto;padding:6px 12px;font-size:12px;display:inline-block" onclick="adminDecide('+r.id+',true)">Approve</button> '+
      '<button class="wk-del" onclick="adminDecide('+r.id+',false)">Reject</button></div></div>';
  }).join('');

  const auditRows=audit.slice(0,50).map(function(e){
    return '<tr><td style="font-size:11px;color:var(--muted)">'+esc((e.at||'').slice(0,19))+'</td>'+
      '<td>'+esc(e.actor)+'</td><td>'+esc(e.action)+'</td>'+
      '<td>'+(e.degraded?'<span class="wk-tag">degraded</span>':'')+'</td></tr>';
  }).join('');

  el.innerHTML=
    '<div class="card">'+modeNote+'</div>'+
    aiCard+
    '<div class="card"><h3>Accounts</h3>'+
      '<div class="admin-newacct">'+
        '<input id="na-user" class="login-input" placeholder="Username" style="margin-bottom:8px">'+
        '<input id="na-pass" type="password" class="login-input" placeholder="Password" style="margin-bottom:8px" oninput="updatePwChecklist(\\'na-pass\\',\\'na-pwc\\')">'+
        pwChecklistHTML('na-pwc')+
        '<select id="na-role" class="login-input" style="margin-bottom:8px">'+
          '<option value="operator">operator</option><option value="manager">manager</option><option value="admin">admin</option>'+
        '</select>'+
        '<button class="login-btn" onclick="adminCreateAccount()">Create account</button>'+
      '</div>'+
      '<table style="width:100%;margin-top:14px"><thead><tr><th>User</th><th>Role</th><th>Last login</th><th></th></tr></thead>'+
      '<tbody>'+(acctRows||'<tr><td colspan="4" class="empty">No accounts.</td></tr>')+'</tbody></table>'+
    '</div>'+
    '<div class="card"><h3>Profiles</h3>'+
      '<div class="dr-muted" style="margin-bottom:10px">Edit any account\\'s display name and email. Cosmetic metadata, not role or password, so it is not four-eyes gated. Each user can also edit their own from the left drawer.</div>'+
      (profRows||'<div class="empty">No accounts.</div>')+
    '</div>'+
    '<div class="card"><h3>Pending approvals</h3>'+(pendingRows||'<div class="empty">No pending requests.</div>')+'</div>'+
    '<div class="card"><h3>Audit log</h3><table style="width:100%">'+
      '<thead><tr><th>When</th><th>Actor</th><th>Action</th><th></th></tr></thead>'+
      '<tbody>'+(auditRows||'<tr><td colspan="4" class="empty">No audit entries yet.</td></tr>')+'</tbody></table></div>';
  updatePwChecklist('na-pass','na-pwc');
}

async function adminSaveProfile(username,i){
  const f=(document.getElementById('pf-f-'+i)||{}).value||'';
  const l=(document.getElementById('pf-l-'+i)||{}).value||'';
  const e=(document.getElementById('pf-e-'+i)||{}).value||'';
  let r={};
  try{r=await api('/admin/accounts/'+encodeURIComponent(username)+'/profile',
    {method:'PUT',body:JSON.stringify({first_name:f,last_name:l,email:e})});}catch(err){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  toast('Profile updated for '+username);
}

async function aiSetCeiling(category,level){
  let r={};
  try{r=await api('/admin/ai/categories/'+encodeURIComponent(category)+'/ceiling',
    {method:'POST',body:JSON.stringify({level:level})});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);renderPage('admin');return;}
  if(r&&r.status==='pending_approval'){toast('Raising to auto_close submitted, awaiting a second admin.');}
  else{toast('Ceiling updated for '+category);}
  renderPage('admin');
}
async function aiKillSwitch(engage){
  if(!engage&&!confirm('Disengage the kill switch? This restores AI autonomy and needs a second admin when dual control is active.'))return;
  let r={};
  try{r=await api('/admin/ai/kill-switch',{method:'POST',body:JSON.stringify({engage:engage})});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  if(r&&r.status==='pending_approval'){toast('Disengage submitted, awaiting a second admin.');}
  else{toast(engage?'Kill switch engaged.':'Kill switch disengaged.');}
  renderPage('admin');
}
async function aiTrain(category){
  let r={};
  try{r=await api('/admin/ai/train/'+encodeURIComponent(category),{method:'POST'});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  if(r&&r.status==='pending_approval'){toast('Retrain submitted, awaiting a second admin.');}
  else{toast('Model retrained for '+category);}
  renderPage('admin');
}
async function aiRollback(category){
  if(!confirm('Roll back '+category+' to the previous model version?'))return;
  let r={};
  try{r=await api('/admin/ai/models/'+encodeURIComponent(category)+'/rollback',{method:'POST'});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  toast('Rolled back to version '+r.active_version);
  renderPage('admin');
}
async function aiAddCategory(){
  const cat=((document.getElementById('ai-newcat')||{}).value||'').trim();
  const level=(document.getElementById('ai-newcat-level')||{}).value||'shadow';
  if(!cat){toast('Enter a category name.');return;}
  await aiSetCeiling(cat,level);
}
async function aiMetrics(category){
  let r={};
  try{r=await api('/admin/ai/metrics/'+encodeURIComponent(category));}catch(e){}
  if(!r||r.enough_data===false){toast('Metrics: '+((r&&r.note)||'not enough validated data yet'));return;}
  var pc=r.per_class||{};
  var parts=Object.keys(pc).map(function(k){return k+' P'+(pc[k].precision*100).toFixed(0)+'/R'+(pc[k].recall*100).toFixed(0);});
  toast('Held-out ('+r.n_test+' test): accuracy '+(r.accuracy*100).toFixed(0)+'% | '+parts.join('  '));
}
async function aiImportDataset(){
  const cat=((document.getElementById('ai-ds-cat')||{}).value||'').trim();
  const name=((document.getElementById('ai-ds-name')||{}).value||'').trim();
  const raw=((document.getElementById('ai-ds-json')||{}).value||'').trim();
  if(!cat||!name||!raw){toast('Provide category, dataset name and JSON records.');return;}
  var records;
  try{records=JSON.parse(raw);}catch(e){toast('Records must be valid JSON array.');return;}
  let r={};
  try{r=await api('/admin/ai/datasets/'+encodeURIComponent(cat)+'/import',
    {method:'POST',body:JSON.stringify({name:name,records:records})});}catch(e){}
  if(r&&r.error){toast('Import refused: '+r.error);return;}
  toast('Imported '+r.imported+' labels as '+r.source+' (influence-capped, rollback-able).');
}
async function aiRollbackDataset(){
  const cat=((document.getElementById('ai-ds-cat')||{}).value||'').trim();
  const name=((document.getElementById('ai-ds-name')||{}).value||'').trim();
  if(!cat||!name){toast('Provide category and dataset name to roll back.');return;}
  if(!confirm('Roll back dataset "'+name+'" from '+cat+'? Removes only that imported batch.'))return;
  let r={};
  try{r=await api('/admin/ai/datasets/'+encodeURIComponent(cat)+'/rollback',
    {method:'POST',body:JSON.stringify({name:name})});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  toast('Removed '+r.removed+' imported labels.');
}
async function aiSetBias(){
  const v=((document.getElementById('ai-bias')||{}).value||'').trim();
  let r={};
  try{r=await api('/admin/ai/recall-bias',{method:'POST',body:JSON.stringify({recall_bias:parseFloat(v)})});}catch(e){}
  if(r&&r.error){toast('Error: '+r.error);return;}
  toast('Recall bias set to '+r.recall_bias+' (higher = catches more threats, more false alarms).');
}
async function aiTrainDatasets(){
  toast('Training on the current data...');
  let r={};
  try{r=await api('/admin/ai/train-datasets',{method:'POST',body:JSON.stringify({})});}catch(e){}
  if(r&&r.error){toast('Training failed: '+r.error);return;}
  var m=r.metrics||{};
  var tp=(m.per_class&&m.per_class.true_positive)||{};
  var acc=(m.accuracy!=null?(m.accuracy*100).toFixed(0)+'%':'?');
  var rec=(tp.recall!=null?(tp.recall*100).toFixed(0)+'%':'?');
  toast('Trained model v'+(r.model_version||'?')+'. Held-out accuracy '+acc+', threat recall '+rec+'. Auto-triaged '+(r.created||0)+' ticket(s).');
  renderPage('admin');
}
async function aiImportModel(){
  const cat=((document.getElementById('ai-imp-cat')||{}).value||'').trim();
  const content=((document.getElementById('ai-imp-json')||{}).value||'').trim();
  if(!cat||!content){toast('Provide a category and the JSON classifier params.');return;}
  let r={};
  try{r=await api('/admin/ai/models/'+encodeURIComponent(cat)+'/import',
    {method:'POST',body:JSON.stringify({format:'json',content:content})});}catch(e){}
  if(r&&r.error){toast('Import refused: '+r.error);return;}
  toast('Imported as inactive version '+r.imported_version+'. Activate it after review.');
  renderPage('admin');
}
async function adminCreateAccount(){
  const username=(document.getElementById('na-user')||{}).value||'';
  const password=(document.getElementById('na-pass')||{}).value||'';
  const role=(document.getElementById('na-role')||{}).value||'operator';
  let r={};
  try{r=await api('/admin/accounts',{method:'POST',body:JSON.stringify({username:username,password:password,role:role})});}catch(e){}
  if(r.error){toast('Error: '+r.error);return;}
  toast(r.status==='pending_approval'?'Request submitted, awaiting a second admin.':'Account created.');
  renderPage('admin');
}

async function adminDeleteAccount(username){
  let r={};
  try{r=await api('/admin/accounts/'+encodeURIComponent(username),{method:'DELETE'});}catch(e){}
  if(r.error){toast('Error: '+r.error);return;}
  toast(r.status==='pending_approval'?'Deletion submitted, awaiting a second admin.':'Account deleted.');
  renderPage('admin');
}

async function adminForceLogout(username){
  let r={};
  try{r=await api('/admin/accounts/'+encodeURIComponent(username)+'/force-logout',{method:'POST'});}catch(e){}
  if(r.error){toast('Error: '+r.error);return;}
  toast('Signed out '+(r.sessions_revoked||0)+' active session(s) for '+username+'.');
}

async function adminDecide(requestId,approve){
  let r={};
  try{r=await api('/admin/requests/'+requestId+'/decide',{method:'POST',body:JSON.stringify({approve:approve})});}catch(e){}
  if(r.error){toast('Error: '+r.error);return;}
  toast(approve?'Approved and applied.':'Rejected.');
  renderPage('admin');
}
function sc(v){if(v>=.9)return'var(--crit)';if(v>=.75)return'var(--high)';if(v>=.55)return'var(--med)';return'var(--muted)';}

async function openTix(tid){
  const t=await api('/tickets/'+tid);
  const hashes=hashPills(t.file_hashes);
  const actions=(t.actions_taken||[]).map(function(a){
    return '<div class="aitem"><div class="albl">'+esc(a.action||'?')+'</div>'+esc(a.detail||a.target||'')+'</div>';
  }).join('')||'<div class="empty">No actions.</div>';
  const factors=(t.risk_factors||[]).map(function(f){return '<div style="font-size:12px;margin-bottom:4px">- '+esc(f)+'</div>';}).join('');
  document.getElementById('mtitle').textContent=t.ticket_id;
  document.getElementById('mbody').innerHTML=
    '<div class="frow"><div class="flbl">Severity</div><div><span class="badge '+t.severity+'">'+t.severity+'</span></div></div>'+
    '<div class="frow"><div class="flbl">Score</div><div class="score" style="color:'+sc(t.score)+'">'+(t.score||0).toFixed(4)+'</div></div>'+
    '<div class="frow"><div class="flbl">Type</div><div><span class="cat-tag"><span class="cat-bar" style="background:'+catColor(t.signal_type)+'"></span><span class="stag">'+esc(t.signal_type)+'</span></span></div></div>'+
    '<div class="frow"><div class="flbl">Host</div><div>'+esc(t.host||'-')+'</div></div>'+
    '<div class="frow"><div class="flbl">MITRE</div><div>'+esc(t.mitre_technique||'-')+' <span style="color:var(--muted);font-size:11px">'+esc(t.mitre_tactic||'')+'</span></div></div>'+
    '<div class="frow"><div class="flbl">Playbook</div><div style="color:var(--green)">'+esc(t.playbook||'-')+'</div></div>'+
    '<div class="frow"><div class="flbl">Created</div><div style="font-size:12px">'+esc(t.created_at||'-')+'</div></div>'+
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
    '<div style="margin-bottom:14px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px"><span class="flbl">Notes'+(getDraft(t.ticket_id)?' <span style="color:var(--high)">(unsaved draft)</span>':'')+'</span><span style="display:flex;gap:8px"><button class="btn btn-g" style="padding:4px 10px;font-size:11px" onclick="insertTemplate()">Insert template</button><button class="btn btn-g" style="padding:4px 10px;font-size:11px" onclick="clearNote()">Clear</button></span></div><textarea id="m-notes" style="overflow:hidden" oninput="saveDraft(\\''+t.ticket_id+'\\',this.value);autoGrow(this)">'+esc(getDraft(t.ticket_id)||t.notes||'')+'</textarea></div>'+
    '<div style="display:flex;gap:10px"><button class="btn btn-p" onclick="saveTix(\\''+t.ticket_id+'\\')">Save</button><button class="btn btn-g" onclick="closeModal()">Cancel</button></div>';
  _curTicket=t;
  document.getElementById('overlay').classList.add('open');
  _modalOpen=true;
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
let _modalOpen=false;   // explicit modal state; the auto-refresh pauses only while true
function overlayDown(e){_ovDown=(e.target===document.getElementById('overlay'));}
function closeModal(e){
  // Only close on a click that both started and ended on the backdrop itself, or on an
  // explicit close call (no event, e.g. Cancel/X button or after Save).
  if(!e || (e.target===document.getElementById('overlay') && _ovDown)){
    document.getElementById('overlay').classList.remove('open');
    _modalOpen=false;  // refresh can resume; cleared on every real close path
  }
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

// Periodic signals refresh that does NOT yank the view to the top and does NOT collapse
// rows the analyst has expanded. Only repaints when the visible set actually changed,
// then restores scroll position.
async function refreshSignals(){
  const el=document.getElementById('pcontent');if(!el)return;
  const scopeAtStart=_cur;
  let sigs;
  try{sigs=await api('/signals');}catch(e){return;}
  if(_cur!==scopeAtStart||_cur!=='signals')return;
  let closed=new Set();
  try{
    const tix=await api('/tickets');
    tix.forEach(function(t){if(t.status==='closed'&&t.signal_id)closed.add(t.signal_id);});
  }catch(e){}
  if(_cur!==scopeAtStart||_cur!=='signals')return;
  const filtered=sigs.filter(function(s){return !closed.has(s.signal_id);});
  // Signature = the ordered list of signal ids currently shown. No change -> do nothing.
  const oldSig=_sigs.map(function(s){return s.signal_id;}).join('|');
  const newSig=filtered.map(function(s){return s.signal_id;}).join('|');
  if(oldSig===newSig)return;
  const scroller=document.scrollingElement||document.documentElement;
  const savedTop=scroller.scrollTop;
  _sigs=filtered;
  // Keep expansion state for signals that still exist (keyed by index is fragile, so we
  // rebuild expansion against signal_id presence).
  _drawSignals(el);
  scroller.scrollTop=savedTop;  // restore the analyst's reading position
}

function _drawSignals(el){
  const body=_sigs.length?_sigs.map(function(s,i){
    const h=hashPills(s.file_hashes||{});
    const exp=s.explanation||'';
    const isOpen=!!_sigExpanded[i];
    const expRow=isOpen?
      '<tr class="sig-exp"><td colspan="7"><div class="exp-body">'+
        '<div class="exp-full" style="margin-bottom:6px">'+esc(exp)+'</div>'+
        (s.recommended_actions&&s.recommended_actions.length?'<div class="rec"><div class="flbl" style="margin-bottom:5px">Recommended actions</div>'+s.recommended_actions.map(function(a){return '<div class="rec-item">- '+esc(a)+'</div>';}).join('')+'</div>':'') +
        '<div class="rec"><div class="flbl" style="margin:10px 0 4px">Process tree</div>'+processTreeHtml(s.process_ancestors,s.process_self,s.process_children)+'</div>'+
        '<div style="margin-top:8px">'+h+'</div>'+
      '</div></td></tr>':'';
    return '<tr class="clickable" onclick="toggleSig('+i+',this)">'+
      '<td><span class="sig-name" title="Open the matching ticket" onclick="openTicketForSignal(event,\\''+(s.signal_id||'')+'\\')">'+(s.signal_id||'').substring(0,12)+'</span><span class="sig-copy" title="Copy signal ID" onclick="copyId(event,\\''+(s.signal_id||'')+'\\')">copy</span></td>'+
      '<td><span class="cat-tag"><span class="cat-bar" style="background:'+catColor(s.signal_type)+'"></span>'+abbrev(s.signal_type)+'</span></td>'+
      '<td class="score" style="color:'+sc(s.score)+'">'+(s.score||0).toFixed(2)+'</td>'+
      '<td>'+esc((s.host&&s.host.hostname)||'-')+'</td>'+
      '<td style="font-size:11px;font-family:var(--font-mono)">'+esc(s.mitre_technique||'-')+'</td>'+
      '<td>'+hashPills(s.file_hashes||{})+'</td>'+
      '<td class="exp-cell"><span class="exp-preview">'+(exp?esc(exp):'<em style="color:var(--faint)">no explanation</em>')+'</span><span class="exp-toggle">'+(isOpen?' v':' >')+'</span></td></tr>'+expRow;
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
  const crumb=(r.crumbs||[]).map(function(c,i){return '<span onclick="navCrumb('+i+')">'+esc(c.name)+'</span>';}).join(' / ');
  let html='<div class="crumb">'+(crumb||'/')+'</div>';
  if(r.parent!==null)
    html+='<div class="fentry" onclick="navParent()"><svg class="fic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg><span class="fn">..</span></div>';
  (r.entries||[]).forEach(function(e,i){
    if(e.is_dir)
      html+='<div class="fentry" onclick="navEntry('+i+')"><svg class="fic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span class="fn">'+esc(e.name)+'</span></div>';
    else
      html+='<div class="fentry" id="fe'+i+'" onclick="navEntry('+i+')"><svg class="fic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg><span class="fn">'+esc(e.name)+'</span><span class="fsz">'+esc(e.size)+'</span></div>';
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
      '<textarea id="tpl-'+s[0]+'" style="min-height:150px;font-family:var(--font-mono)">'+(tpls[s[0]]||'')+'</textarea></div>';
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

function showServerBanner(){
  // init() re-runs after setup, login and MFA; without this guard each re-entry in
  // server mode would insert another banner. Stable id makes the insert idempotent.
  if(document.getElementById('server-mode-banner'))return;
  var b=document.createElement('div');
  b.id='server-mode-banner';
  b.className='sc-banner';
  b.style.background='rgba(181,82,79,.12)';b.style.borderBottom='1px solid rgba(181,82,79,.4)';b.style.color='#e07a78';
  b.textContent='SERVER MODE | authentication required, read-only host posture unless active response is explicitly armed.';
  document.body.insertBefore(b, document.body.firstChild);
}

function shutdownApp(){
  if(!confirm('Stop the server and close the app?'))return;
  fetch('/api/shutdown',{method:'POST'}).catch(function(){});
  document.body.innerHTML='<div style="font-family:system-ui;color:#8b9096;padding:48px;font-size:15px">App stopped. You can close this tab.</div>';
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
  document.addEventListener('keydown',function(ev){
    if(ev.key==='Escape'&&_modalOpen){
      document.getElementById('overlay').classList.remove('open');
      _modalOpen=false;
    }
  });
  setInterval(function(){
    // Refresh pauses only while a ticket modal is genuinely open. We track this with an
    // explicit flag rather than a CSS class, because a stuck 'open' class would freeze
    // the refresh forever (the bug where the list stopped updating after closing a ticket).
    if(_modalOpen)return;
    // Never refresh while a navigation/page switch is in flight (prevents race conditions
    // where the auto-refresh reads a scope that is mid-change).
    if(_navigating)return;
    // Ticket lists: additive refresh, never a full re-render (preserves scroll and order).
    if(_cur==='open'||_cur==='mine'){refreshTicketsAdditive();return;}
    // Dashboard: re-render only if the ticket counts actually changed.
    if(_cur==='dash'){maybeRefreshDash();return;}
    // Signals: scroll-safe refresh that preserves scroll position and expanded rows.
    if(_cur==='signals')refreshSignals();
  }, 7000);
}

async function init(){  // restore theme
  applyTheme(localStorage.getItem('soar_theme')==='light');
  loadProfile();
  var dv=document.getElementById('dr-version');
  if(dv)dv.textContent='Mini SOAR '+VERSION;
  let c={};
  try{
    c=await api('/config');
    SHOWCASE=((c.mode||'local')==='showcase');
    const pill=document.getElementById('mode-pill');
    pill.textContent=(c.mode||'local').toUpperCase();
    if((c.mode||'local')==='server'){pill.classList.add('server');showServerBanner();}
    if(SHOWCASE){pill.classList.add('showcase');applyShowcaseLock();}
    var dv2=document.getElementById('dr-version');
    if(dv2)dv2.textContent='Mini SOAR '+VERSION+(c.encrypted?' | encrypted at rest':'');
  }catch(e){}
  // Bootstrap gate: only relevant when the server requires login (server mode). Local and
  // showcase modes have no accounts, so they must never show the setup or login screens.
  if(c.require_login){
    try{
      const su=await fetch('/api/setup/status');
      if(su.status===200){
        const suj=await su.json();
        if(suj.setup_required){showSetup();return;}
      }
    }catch(e){}
    // Login gate: if we are not authenticated, show the login screen and stop here. The
    // rest of the app boots only after a successful login.
    if(!c.authenticated){
      showLogin();
      return;
    }
  }
  if(c.authenticated){_isAdmin=(c.role==='admin');_role=c.role||'operator';window._account={user:c.user,role:c.role};showLogoutControl(c.user,c.role);reflectAccount(c.user,c.role);await loadAccountProfile();}
  renderFooter();
  checkUpdateStatus();
  buildNav();
  history.replaceState({page:'dash',filter:{}},'','#dash');
  renderPage('dash');
}

function showSetup(err){
  let host=document.getElementById('login-host');
  if(!host){host=document.createElement('div');host.id='login-host';document.body.appendChild(host);}
  host.innerHTML=
    '<div class="login-wrap"><div class="login-card">'+
      '<div class="login-title">Mini SOAR</div>'+
      '<div class="login-sub">First-run setup &mdash; create the admin account</div>'+
      '<div id="su-err" class="login-err" style="display:'+(err?'block':'none')+'">'+esc(err||'')+'</div>'+
      '<p class="mfa-help">Enter the one-time token shown on the server\\'s own terminal '+
        'when it started, then choose an admin username and password.</p>'+
      '<input id="su-token" type="password" class="login-input" placeholder="Setup token" autocomplete="off">'+
      '<input id="su-user" class="login-input" placeholder="Admin username" autocomplete="username">'+
      '<input id="su-pass" type="password" class="login-input" placeholder="Password" autocomplete="new-password" oninput="updatePwChecklist(\\'su-pass\\',\\'su-pwc\\')">'+
      pwChecklistHTML('su-pwc')+
      '<input id="su-pass2" type="password" class="login-input" placeholder="Repeat password" autocomplete="new-password">'+
      '<button id="su-btn" class="login-btn" onclick="doSetup()">Create admin account</button>'+
    '</div></div>';
  const t=document.getElementById('su-token');if(t)t.focus();
  updatePwChecklist('su-pass','su-pwc');
}
function setSetupError(msg){
  // Show an error WITHOUT rebuilding the form, so token/username the operator already
  // typed are preserved. Only used for retryable failures (password mismatch, rejected
  // token/credentials); a hard reset back to showSetup() is reserved for cases where the
  // form itself must start over.
  const e=document.getElementById('su-err');
  if(e){e.textContent=msg;e.style.display='block';}
}
function clearSetupPasswords(focusFirst){
  // On a password problem, clear ONLY the password fields, never token or username: the
  // operator should not have to retype the one-time token because of a typo in the confirm
  // field.
  const p1=document.getElementById('su-pass'),p2=document.getElementById('su-pass2');
  if(p1)p1.value='';if(p2)p2.value='';
  if(focusFirst&&p1)p1.focus();
}

async function doSetup(){
  const token=(document.getElementById('su-token')||{}).value||'';
  const username=(document.getElementById('su-user')||{}).value||'';
  const pass=(document.getElementById('su-pass')||{}).value||'';
  const pass2=(document.getElementById('su-pass2')||{}).value||'';
  if(pass!==pass2){setSetupError('Passwords do not match.');clearSetupPasswords(true);return;}
  const btn=document.getElementById('su-btn');if(btn){btn.disabled=true;btn.textContent='Creating...';}
  let r;
  try{
    r=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token:token,username:username,password:pass})});
  }catch(e){
    setSetupError('Network error. Try again.');
    if(btn){btn.disabled=false;btn.textContent='Create admin account';}
    return;
  }
  if(!r.ok){
    let data={};try{data=await r.json();}catch(e){}
    // A rejected password (weak, or reused token) is a password problem: keep the token
    // and username the operator already typed, only clear the password fields. A rejected
    // token is not a password problem, so the token itself is left for the operator to fix.
    setSetupError(data.error||'Setup failed. Check the token and try again.');
    clearSetupPasswords(true);
    if(btn){btn.disabled=false;btn.textContent='Create admin account';}
    return;
  }
  // Account created, but /api/setup does not open a session by itself: chain into a
  // real login with the same credentials so the operator lands in the app directly.
  let lr;
  try{
    lr=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:username,password:pass})});
  }catch(e){showLogin('Admin created. Please sign in.');return;}
  if(lr.ok){
    const host=document.getElementById('login-host');if(host)host.remove();
    await init();
    return;
  }
  showLogin('Admin account created. Please sign in.');
}

function showLogin(err,mfa,user,pass){
  let host=document.getElementById('login-host');
  if(!host){host=document.createElement('div');host.id='login-host';document.body.appendChild(host);}
  const userVal=user!==undefined?user:'';
  const passVal=pass!==undefined?pass:'';
  host.innerHTML=
    '<div class="login-wrap"><div class="login-bg"></div>'+
      '<div class="login-card login-anim'+(mfa?' step-mfa':' step-pass')+'">'+
      '<div class="login-title">Mini SOAR</div>'+
      '<div class="login-sub">'+(mfa?'Enter your authenticator code':'Sign in to continue')+'</div>'+
      (err?'<div class="login-err">'+esc(err)+'</div>':'')+
      (mfa
        ? '<input id="lg-user" type="hidden" value="'+esc(userVal)+'">'+
          '<input id="lg-pass" type="hidden" value="'+esc(passVal)+'">'+
          '<input id="lg-totp" class="login-input" placeholder="6-digit code" '+
            'inputmode="numeric" autocomplete="one-time-code" maxlength="6">'+
          '<button id="lg-btn" class="login-btn" onclick="doLogin()">Verify</button>'+
          '<button type="button" class="login-key-btn" onclick="doWebauthnLogin()">'+
            'Use a security key instead</button>'
        : '<input id="lg-user" class="login-input" placeholder="Username" autocomplete="username">'+
          '<input id="lg-pass" type="password" class="login-input" placeholder="Password" autocomplete="current-password">'+
          '<button id="lg-btn" class="login-btn" onclick="doLogin()">Sign in</button>')+
    '</div></div>';
  const focusId=mfa?'lg-totp':'lg-user';
  const f=document.getElementById(focusId);if(f)f.focus();
  const enterEl=document.getElementById(mfa?'lg-totp':'lg-pass');
  if(enterEl)enterEl.addEventListener('keydown',function(e){if(e.key==='Enter')doLogin();});
}

async function doLogin(){
  const user=(document.getElementById('lg-user')||{}).value||'';
  const pass=(document.getElementById('lg-pass')||{}).value||'';
  const totpEl=document.getElementById('lg-totp');
  const totpVal=totpEl?(totpEl.value||''):'';
  const btn=document.getElementById('lg-btn');if(btn){btn.disabled=true;btn.textContent='Signing in...';}
  try{
    const payload={username:user,password:pass};
    if(totpVal)payload.totp=totpVal;
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)});
    if(r.ok){
      const host=document.getElementById('login-host');if(host)host.remove();
      await init();
      return;
    }
    let data={};try{data=await r.json();}catch(e){}
    if(data.mfa_required){
      // Password accepted; ask for the 6-digit code (keep username/password filled).
      showLogin(totpVal?'Invalid code. Try again.':'', true, user, pass);
      return;
    }
    let msg='Invalid username or password.';
    if(r.status===429)msg='Too many attempts. Wait a few minutes and try again.';
    showLogin(msg);
  }catch(e){showLogin('Network error. Try again.');}
}

// -- WebAuthn helpers: python-fido2 exchanges base64url-encoded buffers over JSON, but
// navigator.credentials expects real ArrayBuffers. These convert both ways.
function b64urlToBuf(s){
  s=s.replace(/-/g,'+').replace(/_/g,'/');
  while(s.length%4)s+='=';
  const bin=atob(s);const buf=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf){
  const bytes=new Uint8Array(buf);let bin='';
  for(let i=0;i<bytes.length;i++)bin+=String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
}

function _decodeCreationOptions(o){
  const pk=o.publicKey||o;
  pk.challenge=b64urlToBuf(pk.challenge);
  if(pk.user&&pk.user.id)pk.user.id=b64urlToBuf(pk.user.id);
  if(pk.excludeCredentials)pk.excludeCredentials=pk.excludeCredentials.map(function(c){
    return Object.assign({},c,{id:b64urlToBuf(c.id)});
  });
  return pk;
}
function _decodeRequestOptions(o){
  const pk=o.publicKey||o;
  pk.challenge=b64urlToBuf(pk.challenge);
  if(pk.allowCredentials)pk.allowCredentials=pk.allowCredentials.map(function(c){
    return Object.assign({},c,{id:b64urlToBuf(c.id)});
  });
  return pk;
}

async function doWebauthnLogin(){
  const user=(document.getElementById('lg-user')||{}).value||'';
  const pass=(document.getElementById('lg-pass')||{}).value||'';
  if(!('credentials' in navigator)){
    showLogin('Security keys are not supported by this browser.',true,user,pass);
    return;
  }
  let begin;
  try{
    const r=await fetch('/api/webauthn/login/begin',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:user,password:pass})});
    begin=await r.json();
    if(!r.ok)throw new Error(begin.error||'failed');
  }catch(e){showLogin('Could not start key verification.',true,user,pass);return;}

  let assertion;
  try{
    const pk=_decodeRequestOptions(begin.options);
    assertion=await navigator.credentials.get({publicKey:pk});
  }catch(e){
    showLogin('Key verification was cancelled or failed.',true,user,pass);
    return;
  }

  const response={
    id:assertion.id,
    rawId:bufToB64url(assertion.rawId),
    type:assertion.type,
    response:{
      clientDataJSON:bufToB64url(assertion.response.clientDataJSON),
      authenticatorData:bufToB64url(assertion.response.authenticatorData),
      signature:bufToB64url(assertion.response.signature),
      userHandle:assertion.response.userHandle?bufToB64url(assertion.response.userHandle):null
    }
  };
  try{
    const r=await fetch('/api/webauthn/login/complete',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ceremony_id:begin.ceremony_id,response:response})});
    if(r.ok){
      const host=document.getElementById('login-host');if(host)host.remove();
      await init();
      return;
    }
  }catch(e){}
  showLogin('Key verification failed.',true,user,pass);
}

async function mfaBeginWebauthnEnroll(){
  if(!('credentials' in navigator)){
    document.getElementById('mfa-body').innerHTML=
      '<div class="login-err">Security keys are not supported by this browser.</div>';
    return;
  }
  let begin;
  try{
    const r=await api('/webauthn/register/begin',{method:'POST'});
    begin=r;
  }catch(e){
    document.getElementById('mfa-body').innerHTML='<div class="login-err">Could not start enrollment.</div>';
    return;
  }
  let credential;
  try{
    const pk=_decodeCreationOptions(begin.options);
    credential=await navigator.credentials.create({publicKey:pk});
  }catch(e){
    document.getElementById('mfa-body').innerHTML=
      '<div class="login-err">Key enrollment was cancelled or failed.</div>'+
      '<button class="login-btn" onclick="openMfaPanel()">Back</button>';
    return;
  }
  const response={
    id:credential.id,
    rawId:bufToB64url(credential.rawId),
    type:credential.type,
    response:{
      clientDataJSON:bufToB64url(credential.response.clientDataJSON),
      attestationObject:bufToB64url(credential.response.attestationObject)
    }
  };
  const body=document.getElementById('mfa-body');
  body.innerHTML=
    '<p class="mfa-help">Key detected. Give it a name so you can recognize it later.</p>'+
    '<input id="wk-name" class="login-input" placeholder="e.g. office key, vault key">'+
    '<label class="mfa-checkbox"><input type="checkbox" id="wk-backup"> Mark as backup key</label>'+
    '<button class="login-btn" onclick="mfaFinishWebauthnEnroll('+
      JSON.stringify(begin.ceremony_id)+','+JSON.stringify(response)+')">Save key</button>';
  const ni=document.getElementById('wk-name');if(ni)ni.focus();
}

async function mfaFinishWebauthnEnroll(ceremonyId,response){
  const name=(document.getElementById('wk-name')||{}).value||'';
  const isBackup=(document.getElementById('wk-backup')||{}).checked||false;
  if(!name.trim()){
    let e=document.getElementById('wk-name-err');
    const ni=document.getElementById('wk-name');
    if(!e){e=document.createElement('div');e.id='wk-name-err';e.className='login-err';ni.parentNode.insertBefore(e,ni);}
    e.textContent='Please name this key.';
    return;
  }
  let r={};
  try{
    r=await api('/webauthn/register/complete',{method:'POST',body:JSON.stringify(
      {ceremony_id:ceremonyId,name:name.trim(),is_backup:isBackup,response:response})});
  }catch(e){}
  const body=document.getElementById('mfa-body');
  if(r.ok){
    body.innerHTML='<div class="mfa-state on">Key "'+esc(name.trim())+'" enrolled.</div>'+
      '<p class="mfa-help">Consider adding a second key as backup, in case you lose this one.</p>'+
      '<button class="login-btn" onclick="openMfaPanel()">Done</button>';
  }else{
    body.innerHTML='<div class="login-err">'+esc(r.error||'Could not save the key.')+'</div>'+
      '<button class="login-btn" onclick="openMfaPanel()">Back</button>';
  }
}

async function webauthnDeleteKey(rowId){
  let r={};
  try{r=await api('/webauthn/keys/'+rowId,{method:'DELETE'});}catch(e){}
  if(r.ok){openMfaPanel();}
  else{
    const body=document.getElementById('mfa-body');
    if(body){
      let e=document.getElementById('wk-del-err');
      if(!e){e=document.createElement('div');e.id='wk-del-err';e.className='login-err';body.insertBefore(e,body.firstChild);}
      e.textContent=r.error||'Could not remove this key.';
    }
  }
}

function showLogoutControl(user,role){
  const dr=document.getElementById('drawer')||document.body;
  let el=document.getElementById('dr-logout');
  if(!el){
    el=document.createElement('div');el.id='dr-logout';el.className='dr-logout';
    dr.appendChild(el);
  }
  el.innerHTML='<div class="dr-user">'+esc(user)+' <span class="dr-role">'+esc(role)+'</span></div>'+
    '<button class="dr-logout-btn" onclick="openMfaPanel()" style="margin-bottom:8px">Two-factor (MFA)</button>'+
    '<button class="dr-logout-btn" onclick="doLogout()">Sign out</button>';
}

// Minimal footer, reduced to what a purchased desktop tool actually needs now (EULA and
// privacy notice), with placeholders reserved for later: company contact, certifications,
// documentation links, a bug/suggestion ticket slot, and an app rating slot.
function renderFooter(){
  const el=document.getElementById('app-footer');
  if(!el)return;
  el.innerHTML=
    '<div class="app-footer">'+
      '<span>&copy; '+new Date().getFullYear()+' Mini SOAR</span>'+
      '<span class="footer-sep">|</span>'+
      '<a href="#" onclick="showLegalPanel(\\'eula\\');return false;">End User License Agreement</a>'+
      '<span class="footer-sep">|</span>'+
      '<a href="#" onclick="showLegalPanel(\\'privacy\\');return false;">Privacy notice</a>'+
      '<span class="footer-sep">|</span>'+
      '<span id="footer-update-slot"></span>'+
    '</div>';
}

// EULA / privacy notice content lives here, reduced to what a locally-installed desktop
// tool needs: no public-facing Terms of Service, since there is no public sign-up. A real
// legal review should replace this placeholder text before any real distribution.
const LEGAL_TEXT={
  eula:{title:'End User License Agreement',
    body:'This software is licensed, not sold, for use on machines you are authorized '+
      'to operate. You may not redistribute, reverse engineer for competing purposes, '+
      'or remove security controls. Provided as-is; see your organization\\'s purchase '+
      'agreement for warranty and support terms. (Placeholder text: replace with '+
      'reviewed legal copy before real distribution.)'},
  privacy:{title:'Privacy notice',
    body:'This application processes security logs, account records, and IP addresses '+
      'as part of its normal operation. Data stays on this machine unless explicitly '+
      'exported by an operator. No telemetry is sent to any third party. See your '+
      'organization\\'s data protection policy for retention and access rules. '+
      '(Placeholder text: replace with reviewed legal copy before real distribution.)'}
};

function showLegalPanel(kind){
  const info=LEGAL_TEXT[kind];if(!info)return;
  const host=document.getElementById('overlay');if(!host)return;
  host.innerHTML='<div class="modal mfa-modal"><div class="modal-head"><h3>'+esc(info.title)+'</h3>'+
    '<span class="x" onclick="closeModal()">close</span></div>'+
    '<div style="font-size:13px;line-height:1.6;color:var(--muted)">'+esc(info.body)+'</div></div>';
  host.classList.add('open');_modalOpen=true;
}

// Weekly update check display: reads the last result from the server's own schedule
// (Monday 17:00 by default). Never triggers a download; only ever links to the repo's
// Releases page for the operator to inspect and fetch manually.
async function checkUpdateStatus(){
  let r={};
  try{r=await api('/update-status');}catch(e){return;}
  const slot=document.getElementById('footer-update-slot');
  if(!slot||!r.checked)return;
  if(r.update_available){
    slot.innerHTML='<a href="'+esc(r.releases_url)+'" target="_blank" rel="noopener" '+
      'class="footer-update-link">Update available ('+esc(r.latest)+') &rarr;</a>';
  }else{
    slot.textContent='Up to date';
  }
}

async function openMfaPanel(){
  let st={};let keys=[];let recov={};
  try{st=await api('/mfa/status');}catch(e){}
  try{keys=await api('/webauthn/keys');}catch(e){}
  try{recov=await api('/mfa/recovery-codes/status');}catch(e){}
  const host=document.getElementById('overlay');
  if(!host)return;

  const keyRows=keys.map(function(k){
    return '<div class="wk-row"><div class="wk-info"><span class="wk-name">'+esc(k.name)+'</span>'+
      (k.is_backup?'<span class="wk-tag">backup</span>':'<span class="wk-tag primary">primary</span>')+
      '</div><button class="wk-del" onclick="webauthnDeleteKey('+k.id+')" title="Remove key">remove</button></div>';
  }).join('');
  const keysBlock=
    '<div class="mfa-section-title">Security keys</div>'+
    (keyRows||'<p class="mfa-help">No security key enrolled yet.</p>')+
    (keys.length?'<p class="mfa-help">A backup key stored somewhere else protects you if you lose the primary one.</p>':'')+
    '<button class="login-btn" style="margin-top:6px" onclick="mfaBeginWebauthnEnroll()">'+
      (keys.length?'Add another key':'Set up a security key')+'</button>';

  let totpBlock;
  if(st.enabled){
    totpBlock='<div class="mfa-state on">Authenticator app codes: ENABLED.</div>'+
      '<p class="mfa-help">To turn it off, enter a current code from your authenticator app.</p>'+
      '<input id="mfa-disable-code" class="login-input" placeholder="6-digit code" inputmode="numeric" maxlength="6">'+
      '<button class="login-btn" style="background:#b5524f;color:#fff" onclick="mfaDisable()">Disable authenticator app</button>';
  }else{
    totpBlock='<div class="mfa-state off">Authenticator app codes: OFF.</div>'+
      '<p class="mfa-help">Add a second factor with any authenticator app (Google Authenticator, Aegis, FreeOTP).</p>'+
      '<button class="login-btn" onclick="mfaBeginEnroll()">Set up authenticator app</button>';
  }

  // Recovery codes only make sense once a second factor exists; they are a fallback,
  // not a replacement, for when TOTP or a key is unavailable.
  const hasMfa=st.enabled||keys.length>0;
  const recovBlock=!hasMfa?'':
    '<div class="mfa-section-title">Recovery codes</div>'+
    '<p class="mfa-help">'+(typeof recov.remaining==='number'?recov.remaining:0)+
      ' unused code(s) remaining. Generating a new set invalidates any previous codes.</p>'+
    '<button class="login-btn" onclick="mfaGenerateRecoveryCodes()">Generate recovery codes</button>'+
    '<div id="mfa-recovery-codes"></div>';

  host.innerHTML='<div class="modal mfa-modal"><div class="modal-head"><h3>Two-factor authentication</h3>'+
    '<span class="x" onclick="closeModal()">close</span></div>'+
    '<div id="mfa-body">'+keysBlock+'<div class="mfa-divider"></div>'+totpBlock+
    (hasMfa?'<div class="mfa-divider"></div>'+recovBlock:'')+'</div></div>';
  host.classList.add('open');_modalOpen=true;
}

async function mfaGenerateRecoveryCodes(){
  let r={};
  try{r=await api('/mfa/recovery-codes/generate',{method:'POST'});}catch(e){}
  const box=document.getElementById('mfa-recovery-codes');
  if(!box)return;
  if(r.error){box.innerHTML='<div class="login-err">'+esc(r.error)+'</div>';return;}
  const codes=r.codes||[];
  box.innerHTML='<p class="mfa-help">Save these somewhere safe now; they will not be shown again. '+
    'Each code works once.</p>'+
    '<div class="mfa-secret" style="text-align:left;line-height:1.8">'+
    codes.map(function(c){return esc(c);}).join('<br>')+'</div>';
}

async function mfaBeginEnroll(){
  let data={};
  try{data=await api('/mfa/enroll',{method:'POST'});}catch(e){}
  if(!data.secret){document.getElementById('mfa-body').innerHTML='<div class="login-err">Could not start enrollment.</div>';return;}
  // Group the secret in 4-char blocks for easier manual entry.
  const grouped=data.secret.replace(/(.{4})/g,'$1 ').trim();
  const body=document.getElementById('mfa-body');
  body.innerHTML=
    '<p class="mfa-help">Scan this QR code with your authenticator app, or enter the key manually.</p>'+
    '<div id="mfa-qr" class="mfa-qr"></div>'+
    '<div class="mfa-secret-label">Manual entry key</div>'+
    '<div class="mfa-secret">'+esc(grouped)+'</div>'+
    '<p class="mfa-help">Then enter the 6-digit code it shows to confirm.</p>'+
    '<input id="mfa-confirm-code" class="login-input" placeholder="6-digit code" inputmode="numeric" maxlength="6">'+
    '<button class="login-btn" onclick="mfaConfirm()">Confirm and enable</button>';
  renderQR(document.getElementById('mfa-qr'), data.otpauth_uri);
  const ci=document.getElementById('mfa-confirm-code');if(ci)ci.focus();
}

async function mfaConfirm(){
  const code=(document.getElementById('mfa-confirm-code')||{}).value||'';
  let r={};
  try{r=await api('/mfa/confirm',{method:'POST',body:JSON.stringify({code:code})});}catch(e){}
  const body=document.getElementById('mfa-body');
  if(r.enabled){
    body.innerHTML='<div class="mfa-state on">Two-factor is now enabled. You will need a code at your next sign-in.</div>'+
      '<button class="login-btn" onclick="closeModal()">Done</button>';
  }else{
    const ci=document.getElementById('mfa-confirm-code');
    if(ci){ci.classList.add('shake');setTimeout(function(){ci.classList.remove('shake');},400);}
    let e=document.getElementById('mfa-confirm-err');
    if(!e){e=document.createElement('div');e.id='mfa-confirm-err';e.className='login-err';body.insertBefore(e,ci);}
    e.textContent='Invalid code. Make sure your phone time is correct and try again.';
  }
}

async function mfaDisable(){
  const code=(document.getElementById('mfa-disable-code')||{}).value||'';
  let r={};
  try{r=await api('/mfa/disable',{method:'POST',body:JSON.stringify({code:code})});}catch(e){}
  const body=document.getElementById('mfa-body');
  if(r.enabled===false){
    body.innerHTML='<div class="mfa-state off">Two-factor has been disabled.</div>'+
      '<button class="login-btn" onclick="closeModal()">Done</button>';
  }else{
    let e=document.getElementById('mfa-disable-err');
    const ci=document.getElementById('mfa-disable-code');
    if(!e){e=document.createElement('div');e.id='mfa-disable-err';e.className='login-err';body.insertBefore(e,ci);}
    e.textContent='Invalid code.';
  }
}

async function doLogout(){
  try{await fetch('/api/logout',{method:'POST'});}catch(e){}
  location.reload();
}

// -- Compact QR encoder (byte mode, EC level M), public-domain algorithm by Kazuhiko
// Arase, trimmed to what an otpauth URI needs. Renders into a container as an SVG grid.
// If anything fails, the caller still shows the manual-entry key, so QR is best-effort.
var QRCodeLite=(function(){
  function QR8bitByte(data){this.data=data;this.parsedData=[];for(var i=0,l=data.length;i<l;i++){var b=[],c=data.charCodeAt(i);if(c>0x10000){b[0]=0xF0|((c&0x1C0000)>>>18);b[1]=0x80|((c&0x3F000)>>>12);b[2]=0x80|((c&0xFC0)>>>6);b[3]=0x80|(c&0x3F);}else if(c>0x800){b[0]=0xE0|((c&0xF000)>>>12);b[1]=0x80|((c&0xFC0)>>>6);b[2]=0x80|(c&0x3F);}else if(c>0x80){b[0]=0xC0|((c&0x7C0)>>>6);b[1]=0x80|(c&0x3F);}else{b[0]=c;}this.parsedData.push(b);}this.parsedData=Array.prototype.concat.apply([],this.parsedData);if(this.parsedData.length!=this.data.length){this.parsedData.unshift(191);this.parsedData.unshift(187);this.parsedData.unshift(239);}}
  QR8bitByte.prototype={getLength:function(){return this.parsedData.length;},write:function(buf){for(var i=0,l=this.parsedData.length;i<l;i++){buf.put(this.parsedData[i],8);}}};
  function QRCodeModel(typeNumber,errorCorrectLevel){this.typeNumber=typeNumber;this.errorCorrectLevel=errorCorrectLevel;this.modules=null;this.moduleCount=0;this.dataCache=null;this.dataList=[];}
  QRCodeModel.prototype={addData:function(data){var newData=new QR8bitByte(data);this.dataList.push(newData);this.dataCache=null;},isDark:function(row,col){return this.modules[row][col];},getModuleCount:function(){return this.moduleCount;},make:function(){this.makeImpl(false,this.getBestMaskPattern());},makeImpl:function(test,maskPattern){this.moduleCount=this.typeNumber*4+17;this.modules=new Array(this.moduleCount);for(var row=0;row<this.moduleCount;row++){this.modules[row]=new Array(this.moduleCount);for(var col=0;col<this.moduleCount;col++){this.modules[row][col]=null;}}this.setupPositionProbePattern(0,0);this.setupPositionProbePattern(this.moduleCount-7,0);this.setupPositionProbePattern(0,this.moduleCount-7);this.setupPositionAdjustPattern();this.setupTimingPattern();this.setupTypeInfo(test,maskPattern);if(this.typeNumber>=7){this.setupTypeNumber(test);}if(this.dataCache==null){this.dataCache=QRCodeModel.createData(this.typeNumber,this.errorCorrectLevel,this.dataList);}this.mapData(this.dataCache,maskPattern);},setupPositionProbePattern:function(row,col){for(var r=-1;r<=7;r++){if(row+r<=-1||this.moduleCount<=row+r)continue;for(var c=-1;c<=7;c++){if(col+c<=-1||this.moduleCount<=col+c)continue;if((0<=r&&r<=6&&(c==0||c==6))||(0<=c&&c<=6&&(r==0||r==6))||(2<=r&&r<=4&&2<=c&&c<=4)){this.modules[row+r][col+c]=true;}else{this.modules[row+r][col+c]=false;}}}},getBestMaskPattern:function(){var minLostPoint=0,pattern=0;for(var i=0;i<8;i++){this.makeImpl(true,i);var lostPoint=QRUtil.getLostPoint(this);if(i==0||minLostPoint>lostPoint){minLostPoint=lostPoint;pattern=i;}}return pattern;},setupTimingPattern:function(){for(var r=8;r<this.moduleCount-8;r++){if(this.modules[r][6]!=null)continue;this.modules[r][6]=(r%2==0);}for(var c=8;c<this.moduleCount-8;c++){if(this.modules[6][c]!=null)continue;this.modules[6][c]=(c%2==0);}},setupPositionAdjustPattern:function(){var pos=QRUtil.getPatternPosition(this.typeNumber);for(var i=0;i<pos.length;i++){for(var j=0;j<pos.length;j++){var row=pos[i],col=pos[j];if(this.modules[row][col]!=null)continue;for(var r=-2;r<=2;r++){for(var c=-2;c<=2;c++){if(r==-2||r==2||c==-2||c==2||(r==0&&c==0)){this.modules[row+r][col+c]=true;}else{this.modules[row+r][col+c]=false;}}}}}},setupTypeNumber:function(test){var bits=QRUtil.getBCHTypeNumber(this.typeNumber);for(var i=0;i<18;i++){var mod=(!test&&((bits>>i)&1)==1);this.modules[Math.floor(i/3)][i%3+this.moduleCount-8-3]=mod;}for(var i=0;i<18;i++){var mod=(!test&&((bits>>i)&1)==1);this.modules[i%3+this.moduleCount-8-3][Math.floor(i/3)]=mod;}},setupTypeInfo:function(test,maskPattern){var data=(this.errorCorrectLevel<<3)|maskPattern;var bits=QRUtil.getBCHTypeInfo(data);for(var i=0;i<15;i++){var mod=(!test&&((bits>>i)&1)==1);if(i<6){this.modules[i][8]=mod;}else if(i<8){this.modules[i+1][8]=mod;}else{this.modules[this.moduleCount-15+i][8]=mod;}}for(var i=0;i<15;i++){var mod=(!test&&((bits>>i)&1)==1);if(i<8){this.modules[8][this.moduleCount-i-1]=mod;}else if(i<9){this.modules[8][15-i-1+1]=mod;}else{this.modules[8][15-i-1]=mod;}}this.modules[this.moduleCount-8][8]=(!test);},mapData:function(data,maskPattern){var inc=-1,row=this.moduleCount-1,bitIndex=7,byteIndex=0;for(var col=this.moduleCount-1;col>0;col-=2){if(col==6)col--;while(true){for(var c=0;c<2;c++){if(this.modules[row][col-c]==null){var dark=false;if(byteIndex<data.length){dark=(((data[byteIndex]>>>bitIndex)&1)==1);}var mask=QRUtil.getMask(maskPattern,row,col-c);if(mask){dark=!dark;}this.modules[row][col-c]=dark;bitIndex--;if(bitIndex==-1){byteIndex++;bitIndex=7;}}}row+=inc;if(row<0||this.moduleCount<=row){row-=inc;inc=-inc;break;}}}}};
  QRCodeModel.PAD0=0xEC;QRCodeModel.PAD1=0x11;
  QRCodeModel.createData=function(typeNumber,errorCorrectLevel,dataList){var rsBlocks=QRRSBlock.getRSBlocks(typeNumber,errorCorrectLevel);var buffer=new QRBitBuffer();for(var i=0;i<dataList.length;i++){var data=dataList[i];buffer.put(4,4);buffer.put(data.getLength(),QRUtil.getLengthInBits(4,typeNumber));data.write(buffer);}var totalDataCount=0;for(var i=0;i<rsBlocks.length;i++){totalDataCount+=rsBlocks[i].dataCount;}if(buffer.getLengthInBits()>totalDataCount*8){throw new Error("code length overflow.");}if(buffer.getLengthInBits()+4<=totalDataCount*8){buffer.put(0,4);}while(buffer.getLengthInBits()%8!=0){buffer.putBit(false);}while(true){if(buffer.getLengthInBits()>=totalDataCount*8)break;buffer.put(QRCodeModel.PAD0,8);if(buffer.getLengthInBits()>=totalDataCount*8)break;buffer.put(QRCodeModel.PAD1,8);}return QRCodeModel.createBytes(buffer,rsBlocks);};
  QRCodeModel.createBytes=function(buffer,rsBlocks){var offset=0,maxDcCount=0,maxEcCount=0;var dcdata=new Array(rsBlocks.length),ecdata=new Array(rsBlocks.length);for(var r=0;r<rsBlocks.length;r++){var dcCount=rsBlocks[r].dataCount,ecCount=rsBlocks[r].totalCount-dcCount;maxDcCount=Math.max(maxDcCount,dcCount);maxEcCount=Math.max(maxEcCount,ecCount);dcdata[r]=new Array(dcCount);for(var i=0;i<dcdata[r].length;i++){dcdata[r][i]=0xff&buffer.buffer[i+offset];}offset+=dcCount;var rsPoly=QRUtil.getErrorCorrectPolynomial(ecCount);var rawPoly=new QRPolynomial(dcdata[r],rsPoly.getLength()-1);var modPoly=rawPoly.mod(rsPoly);ecdata[r]=new Array(rsPoly.getLength()-1);for(var i=0;i<ecdata[r].length;i++){var modIndex=i+modPoly.getLength()-ecdata[r].length;ecdata[r][i]=(modIndex>=0)?modPoly.get(modIndex):0;}}var totalCodeCount=0;for(var i=0;i<rsBlocks.length;i++){totalCodeCount+=rsBlocks[i].totalCount;}var data=new Array(totalCodeCount),index=0;for(var i=0;i<maxDcCount;i++){for(var r=0;r<rsBlocks.length;r++){if(i<dcdata[r].length){data[index++]=dcdata[r][i];}}}for(var i=0;i<maxEcCount;i++){for(var r=0;r<rsBlocks.length;r++){if(i<ecdata[r].length){data[index++]=ecdata[r][i];}}}return data;};
  var QRMode={MODE_8BIT_BYTE:1<<2};var QRErrorCorrectLevel={M:0};
  var QRUtil={PATTERN_POSITION_TABLE:[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],G15:(1<<10)|(1<<8)|(1<<5)|(1<<4)|(1<<2)|(1<<1)|(1<<0),G18:(1<<12)|(1<<11)|(1<<10)|(1<<9)|(1<<8)|(1<<5)|(1<<2)|(1<<0),G15_MASK:(1<<14)|(1<<12)|(1<<10)|(1<<4)|(1<<1),getBCHTypeInfo:function(data){var d=data<<10;while(QRUtil.getBCHDigit(d)-QRUtil.getBCHDigit(QRUtil.G15)>=0){d^=(QRUtil.G15<<(QRUtil.getBCHDigit(d)-QRUtil.getBCHDigit(QRUtil.G15)));}return((data<<10)|d)^QRUtil.G15_MASK;},getBCHTypeNumber:function(data){var d=data<<12;while(QRUtil.getBCHDigit(d)-QRUtil.getBCHDigit(QRUtil.G18)>=0){d^=(QRUtil.G18<<(QRUtil.getBCHDigit(d)-QRUtil.getBCHDigit(QRUtil.G18)));}return(data<<12)|d;},getBCHDigit:function(data){var digit=0;while(data!=0){digit++;data>>>=1;}return digit;},getPatternPosition:function(typeNumber){return QRUtil.PATTERN_POSITION_TABLE[typeNumber-1];},getMask:function(maskPattern,i,j){switch(maskPattern){case 0:return(i+j)%2==0;case 1:return i%2==0;case 2:return j%3==0;case 3:return(i+j)%3==0;case 4:return(Math.floor(i/2)+Math.floor(j/3))%2==0;case 5:return(i*j)%2+(i*j)%3==0;case 6:return((i*j)%2+(i*j)%3)%2==0;case 7:return((i*j)%3+(i+j)%2)%2==0;default:throw new Error("bad maskPattern:"+maskPattern);}},getErrorCorrectPolynomial:function(errorCorrectLength){var a=new QRPolynomial([1],0);for(var i=0;i<errorCorrectLength;i++){a=a.multiply(new QRPolynomial([1,QRMath.gexp(i)],0));}return a;},getLengthInBits:function(mode,type){if(1<=type&&type<10){return 8;}else if(type<27){return 16;}else{return 16;}},getLostPoint:function(qrCode){var moduleCount=qrCode.getModuleCount(),lostPoint=0;for(var row=0;row<moduleCount;row++){for(var col=0;col<moduleCount;col++){var sameCount=0,dark=qrCode.isDark(row,col);for(var r=-1;r<=1;r++){if(row+r<0||moduleCount<=row+r)continue;for(var c=-1;c<=1;c++){if(col+c<0||moduleCount<=col+c)continue;if(r==0&&c==0)continue;if(dark==qrCode.isDark(row+r,col+c)){sameCount++;}}}if(sameCount>5){lostPoint+=(3+sameCount-5);}}}for(var row=0;row<moduleCount-1;row++){for(var col=0;col<moduleCount-1;col++){var count=0;if(qrCode.isDark(row,col))count++;if(qrCode.isDark(row+1,col))count++;if(qrCode.isDark(row,col+1))count++;if(qrCode.isDark(row+1,col+1))count++;if(count==0||count==4){lostPoint+=3;}}}for(var row=0;row<moduleCount;row++){for(var col=0;col<moduleCount-6;col++){if(qrCode.isDark(row,col)&&!qrCode.isDark(row,col+1)&&qrCode.isDark(row,col+2)&&qrCode.isDark(row,col+3)&&qrCode.isDark(row,col+4)&&!qrCode.isDark(row,col+5)&&qrCode.isDark(row,col+6)){lostPoint+=40;}}}for(var col=0;col<moduleCount;col++){for(var row=0;row<moduleCount-6;row++){if(qrCode.isDark(row,col)&&!qrCode.isDark(row+1,col)&&qrCode.isDark(row+2,col)&&qrCode.isDark(row+3,col)&&qrCode.isDark(row+4,col)&&!qrCode.isDark(row+5,col)&&qrCode.isDark(row+6,col)){lostPoint+=40;}}}var darkCount=0;for(var col=0;col<moduleCount;col++){for(var row=0;row<moduleCount;row++){if(qrCode.isDark(row,col)){darkCount++;}}}var ratio=Math.abs(100*darkCount/moduleCount/moduleCount-50)/5;lostPoint+=ratio*10;return lostPoint;}};
  var QRMath={glog:function(n){if(n<1){throw new Error("glog("+n+")");}return QRMath.LOG_TABLE[n];},gexp:function(n){while(n<0){n+=255;}while(n>=256){n-=255;}return QRMath.EXP_TABLE[n];},EXP_TABLE:new Array(256),LOG_TABLE:new Array(256)};
  for(var i=0;i<8;i++){QRMath.EXP_TABLE[i]=1<<i;}for(var i=8;i<256;i++){QRMath.EXP_TABLE[i]=QRMath.EXP_TABLE[i-4]^QRMath.EXP_TABLE[i-5]^QRMath.EXP_TABLE[i-6]^QRMath.EXP_TABLE[i-8];}for(var i=0;i<255;i++){QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]]=i;}
  function QRPolynomial(num,shift){if(num.length==undefined){throw new Error(num.length+"/"+shift);}var offset=0;while(offset<num.length&&num[offset]==0){offset++;}this.num=new Array(num.length-offset+shift);for(var i=0;i<num.length-offset;i++){this.num[i]=num[i+offset];}}
  QRPolynomial.prototype={get:function(index){return this.num[index];},getLength:function(){return this.num.length;},multiply:function(e){var num=new Array(this.getLength()+e.getLength()-1);for(var i=0;i<this.getLength();i++){for(var j=0;j<e.getLength();j++){num[i+j]^=QRMath.gexp(QRMath.glog(this.get(i))+QRMath.glog(e.get(j)));}}return new QRPolynomial(num,0);},mod:function(e){if(this.getLength()-e.getLength()<0){return this;}var ratio=QRMath.glog(this.get(0))-QRMath.glog(e.get(0));var num=new Array(this.getLength());for(var i=0;i<this.getLength();i++){num[i]=this.get(i);}for(var i=0;i<e.getLength();i++){num[i]^=QRMath.gexp(QRMath.glog(e.get(i))+ratio);}return new QRPolynomial(num,0).mod(e);}};
  function QRRSBlock(totalCount,dataCount){this.totalCount=totalCount;this.dataCount=dataCount;}
  QRRSBlock.RS_BLOCK_TABLE=[[1,26,16],[1,44,28],[1,70,44],[2,50,32],[2,67,43],[4,43,27],[4,49,31],[2,60,38,2,61,39],[3,58,36,2,59,37],[4,69,43,1,70,44],[1,80,50,4,81,51],[6,58,36,2,59,37],[8,59,37,1,60,38],[4,64,40,5,65,41],[5,65,41,5,66,42],[7,73,45,3,74,46],[10,74,46,1,75,47],[9,69,43,4,70,44],[3,70,44,11,71,45],[3,67,41,13,68,42],[17,68,42],[17,74,46],[4,75,47,14,76,48],[6,73,45,14,74,46],[8,75,47,13,76,48],[19,74,46,4,75,47],[22,73,45,3,74,46],[3,73,45,23,74,46],[21,73,45,7,74,46],[19,75,47,10,76,48],[2,74,46,29,75,47],[10,74,46,23,75,47],[14,74,46,21,75,47],[14,74,46,23,75,47],[12,75,47,26,76,48],[6,75,47,34,76,48],[29,74,46,14,75,47],[13,74,46,32,75,47],[40,75,47,7,76,48],[18,75,47,31,76,48]];
  QRRSBlock.getRSBlocks=function(typeNumber,errorCorrectLevel){var rsBlock=QRRSBlock.RS_BLOCK_TABLE[(typeNumber-1)];if(rsBlock==undefined){throw new Error("bad rs block");}var length=rsBlock.length/3,list=[];for(var i=0;i<length;i++){var count=rsBlock[i*3+0],totalCount=rsBlock[i*3+1],dataCount=rsBlock[i*3+2];for(var j=0;j<count;j++){list.push(new QRRSBlock(totalCount,dataCount));}}return list;};
  function QRBitBuffer(){this.buffer=[];this.length=0;}
  QRBitBuffer.prototype={get:function(index){var bufIndex=Math.floor(index/8);return((this.buffer[bufIndex]>>>(7-index%8))&1)==1;},put:function(num,length){for(var i=0;i<length;i++){this.putBit(((num>>>(length-i-1))&1)==1);}},getLengthInBits:function(){return this.length;},putBit:function(bit){var bufIndex=Math.floor(this.length/8);if(this.buffer.length<=bufIndex){this.buffer.push(0);}if(bit){this.buffer[bufIndex]|=(0x80>>>(this.length%8));}this.length++;}};
  return {render:function(container,text){try{var type=0;for(var t=1;t<=20;t++){try{var test=new QRCodeModel(t,QRErrorCorrectLevel.M);test.addData(text);test.make();type=t;break;}catch(e){}}if(!type)throw new Error("no fit");var qr=new QRCodeModel(type,QRErrorCorrectLevel.M);qr.addData(text);qr.make();var n=qr.getModuleCount(),cell=5,pad=4,size=(n+pad*2)*cell;var svg='<svg xmlns="http://www.w3.org/2000/svg" width="'+size+'" height="'+size+'" viewBox="0 0 '+size+' '+size+'" shape-rendering="crispEdges"><rect width="'+size+'" height="'+size+'" fill="#fff"/>';for(var r=0;r<n;r++){for(var c=0;c<n;c++){if(qr.isDark(r,c)){svg+='<rect x="'+((c+pad)*cell)+'" y="'+((r+pad)*cell)+'" width="'+cell+'" height="'+cell+'" fill="#000"/>';}}}svg+='</svg>';container.innerHTML=svg;return true;}catch(e){container.innerHTML='<div style="font-size:12px;color:var(--muted)">QR unavailable; use the manual key below.</div>';return false;}}};
})();
function renderQR(el,text){if(el)QRCodeLite.render(el,text);}
init();
</script>
</body>
</html>"""
