(function(){
"use strict";
const Q = window.SOC_QDATA;
const TOPICS = [["all","Todos"],["phishing","Phishing"],["smb","Brute force SMB"],["powershell","PowerShell"],["soc","Wazuh e SOC"]];
const LEVELS = [["all","Todos"],["conceito","Conceito"],["investigacao","Investigação"],["entrevista","Entrevista"]];
const MODES = [["all","Todas"],["new","Não respondidas"],["wrong","Que errei"]];
const LVNAME = {conceito:"Conceito",investigacao:"Investigação",entrevista:"Entrevista"};
const TPNAME = Object.fromEntries(TOPICS);
const KEY = "simulado-soc-n1-v1";
const $ = s => document.querySelector(s);

let prog = {};
try { prog = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch(e) { prog = {}; }
const save = () => { try { localStorage.setItem(KEY, JSON.stringify(prog)); } catch(e) {} };

const st = { topic:"all", level:"all", mode:"all", shuffle:false, list:[], pos:0, seed:1, search:"" };
const norm = s => String(s).toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");

function esc(s){ return String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
// `code` em crase vira <code>
function rich(s){ return esc(s).replace(/`([^`]+)`/g, "<code>$1</code>"); }

function rng(seed){ let x = seed >>> 0 || 1; return () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return (x >>> 0) / 4294967296; }; }

function buildList(keepId){
  let l = Q.filter(q => (st.topic==="all"||q.topic===st.topic) && (st.level==="all"||q.level===st.level));
  if (st.mode==="new") l = l.filter(q => !prog[q.id]);
  if (st.mode==="wrong") l = l.filter(q => prog[q.id] && !prog[q.id].ok);
  if (st.search){ const k = norm(st.search); l = l.filter(q => norm([q.id,q.q,q.why].concat(q.options).join(" ")).includes(k)); }
  if (st.shuffle){ const r = rng(st.seed); for (let i=l.length-1;i>0;i--){ const j=Math.floor(r()*(i+1)); [l[i],l[j]]=[l[j],l[i]]; } }
  st.list = l;
  const i = keepId ? l.findIndex(q => q.id===keepId) : -1;
  st.pos = i >= 0 ? i : 0;
}

function chips(el, items, key){
  el.innerHTML = "";
  items.forEach(([v,label]) => {
    const b = document.createElement("button");
    b.type="button"; b.className="chip"; b.setAttribute("aria-pressed", String(st[key]===v));
    let n;
    if (key==="topic") n = v==="all" ? Q.length : Q.filter(q=>q.topic===v).length;
    if (key==="level") n = Q.filter(q=>(st.topic==="all"||q.topic===st.topic)&&(v==="all"||q.level===v)).length;
    if (key==="mode"){ const base=Q.filter(q=>(st.topic==="all"||q.topic===st.topic)&&(st.level==="all"||q.level===st.level));
      n = v==="all"?base.length : v==="new"?base.filter(q=>!prog[q.id]).length : base.filter(q=>prog[q.id]&&!prog[q.id].ok).length; }
    b.innerHTML = esc(label) + ` <small>${n}</small>`;
    b.onclick = () => { st[key]=v; buildList(); renderAll(); };
    el.appendChild(b);
  });
}

function renderStats(){
  const done = Object.keys(prog).filter(id => Q.some(q=>q.id===id));
  const ok = done.filter(id => prog[id].ok).length;
  $("#sDone").textContent = `${done.length}/${Q.length}`;
  $("#sPct").textContent = done.length ? Math.round(ok*100/done.length)+"%" : "—";
  $("#sWrong").textContent = done.length - ok;
  const bars = $("#bars"); bars.innerHTML = "";
  TOPICS.slice(1).forEach(([t,name]) => {
    const qs = Q.filter(q=>q.topic===t), d = qs.filter(q=>prog[q.id]), o = d.filter(q=>prog[q.id].ok);
    const pct = d.length ? Math.round(o.length*100/d.length) : 0;
    const row = document.createElement("div"); row.className="bar";
    row.innerHTML = `<span>${esc(name)}</span><i title="${d.length} de ${qs.length} respondidas"><em style="width:${d.length?pct:0}%"></em></i><code>${d.length?pct+"%":"—"}</code>`;
    bars.appendChild(row);
  });
}

function renderMap(){
  const m = $("#map"); m.innerHTML = "";
  $("#mapTitle").textContent = `Questões (${st.list.length})`;
  st.list.forEach((q,i) => {
    const b = document.createElement("button");
    b.type="button"; b.className = "dot" + (prog[q.id] ? (prog[q.id].ok?" ok":" bad") : "") + (i===st.pos?" cur":"");
    b.title = `${i+1}. ${q.q.slice(0,80)}`; b.setAttribute("aria-label", `Questão ${i+1}`);
    b.onclick = () => { st.pos=i; renderAll(); $("#card").scrollIntoView({block:"nearest"}); };
    m.appendChild(b);
  });
}

function renderCard(){
  const c = $("#card");
  const q = st.list[st.pos];
  if (!q){
    c.innerHTML = `<div class="empty">${st.mode==="wrong"?"Nenhuma questão errada com esses filtros. Bom sinal.":st.mode==="new"?"Você já respondeu todas as questões desses filtros.":"Nenhuma questão com esses filtros."}</div>`;
    Viz.idle("Sem questão selecionada."); renderSteps(null); return;
  }
  const p = prog[q.id];
  const answered = !!p;
  c.innerHTML = `
    <div class="meta"><span>${st.pos+1} / ${st.list.length}</span><span class="tag">${esc(TPNAME[q.topic]||q.topic)}</span><span class="tag lv-${q.level}">${esc(LVNAME[q.level]||q.level)}</span><span>${esc(q.id)}</span></div>
    <h2 class="qtext">${rich(q.q)}</h2>
    <div class="opts" role="group" aria-label="Alternativas"></div>
    <div id="fb"></div>
    <div class="nav">
      <button class="btn" id="prev" type="button" ${st.pos===0?"disabled":""}>← Anterior</button>
      <span class="kbd"><kbd>1</kbd>–<kbd>4</kbd> responde · <kbd>→</kbd> próxima</span>
      <button class="btn primary" id="next" type="button" ${st.pos>=st.list.length-1?"disabled":""}>Próxima →</button>
    </div>`;
  const box = c.querySelector(".opts");
  q.options.forEach((o,i) => {
    const b = document.createElement("button");
    b.type="button"; b.className="opt"; b.dataset.i=i;
    b.innerHTML = `<span class="k">${"ABCD"[i]}</span><span>${rich(o)}</span>`;
    b.onclick = () => answer(i);
    box.appendChild(b);
  });
  $("#prev").onclick = () => go(-1);
  $("#next").onclick = () => go(1);
  if (answered) showResult(q, p.pick, false); else { Viz.idle("Responda para ver a ilustração da resposta.", q); renderSteps(q, false); }
}

// Passo a passo prático (assets/data/passos.js), revelado depois de responder para não entregar a resposta
function richSteps(s){ return rich(s).replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>"); }
function renderSteps(q, show){
  const el = $("#steps"); if (!el) return;
  const P = window.SOC_PASSOS;
  if (!q){ el.innerHTML = `<p class="steps-wait">Sem questão selecionada.</p>`; return; }
  if (!P){ el.innerHTML = `<p class="steps-wait">O passo a passo não carregou.</p>`; return; }
  const keys = (P.map[q.id] || []).filter(k => P.proc[k]);
  if (!show){ el.innerHTML = `<p class="steps-wait">Responda para ver como fazer, na prática, cada ação desta questão (${keys.length} ${keys.length===1?"procedimento":"procedimentos"}).</p>`; return; }
  el.innerHTML = keys.map(k => { const p = P.proc[k];
    return `<div class="proc"><h3>${esc(p.t)}</h3>${p.onde?`<p class="onde">${esc(p.onde)}</p>`:""}<ol>${p.s.map(s => `<li><span>${richSteps(s)}</span></li>`).join("")}</ol>${p.dica?`<p class="dica">${richSteps(p.dica)}</p>`:""}</div>`; }).join("")
    + `<p class="steps-foot">Nomes de menus podem mudar conforme a versão do programa.</p>`;
  el.closest("aside").scrollTop = 0;
}

function showResult(q, pick, fresh){
  const ok = pick === q.answer;
  document.querySelectorAll(".opt").forEach(b => {
    const i = +b.dataset.i; b.disabled = true;
    if (i===q.answer) b.classList.add("right");
    else if (i===pick) b.classList.add("wrong");
    else b.classList.add("dim");
  });
  if (window.SOCExplain) SOCExplain.render($("#fb"), q, pick, { auto:fresh }); else $("#fb").innerHTML = `<div class="verdict"><span class="pill ${ok?"ok":"bad"}">${ok?"Correta":"Incorreta"}</span><span>${ok?"Isso mesmo.":"Resposta certa: "+"ABCD"[q.answer]+"."}</span></div><p class="why">${rich(q.why)}</p>`;
  Viz.show(q);
  renderSteps(q, true);
  if (fresh) $("#next") && !$("#next").disabled && $("#next").focus({preventScroll:true});
}

function answer(i){
  const q = st.list[st.pos]; if (!q || prog[q.id]) return;
  prog[q.id] = { pick:i, ok: i===q.answer, t: Date.now() }; save();
  showResult(q, i, true); renderStats(); renderMap(); renderFilters();
}
function go(d){ const n = st.pos + d; if (n<0 || n>=st.list.length) return; st.pos=n; renderAll(); }

function renderFilters(){
  chips($("#fTopic"), TOPICS, "topic"); chips($("#fLevel"), LEVELS, "level"); chips($("#fMode"), MODES, "mode");
  $("#shuffleBtn").setAttribute("aria-pressed", String(st.shuffle));
}
function renderAll(){ renderFilters(); renderStats(); renderMap(); renderCard(); }

$("#shuffleBtn").onclick = () => { const id = st.list[st.pos]&&st.list[st.pos].id; st.shuffle=!st.shuffle; st.seed = (Date.now() & 0xffff) || 7; buildList(id); renderAll(); };
$("#resetBtn").onclick = () => { $("#resetConfirm").hidden=false; $("#resetBtn").hidden=true; };
$("#resetNo").onclick = () => { $("#resetConfirm").hidden=true; $("#resetBtn").hidden=false; };
$("#resetYes").onclick = () => { prog={}; save(); $("#resetConfirm").hidden=true; $("#resetBtn").hidden=false; buildList(); renderAll(); };
$("#qSearch").addEventListener("input", e => { const id = st.list[st.pos]&&st.list[st.pos].id; st.search = e.target.value.trim(); buildList(id); renderMap(); renderCard(); });
document.addEventListener("keydown", e => {
  if (document.body.dataset.view && document.body.dataset.view !== "sim") return;
  if (e.target.closest && e.target.closest("input,textarea,select")) return;
  const q = st.list[st.pos]; if (!q) return;
  const k = e.key.toLowerCase();
  const idx = "1234".indexOf(k) >= 0 ? "1234".indexOf(k) : "abcd".indexOf(k);
  if (idx >= 0 && !prog[q.id] && !e.ctrlKey && !e.metaKey) { answer(idx); e.preventDefault(); }
  else if (e.key==="ArrowRight") { go(1); }
  else if (e.key==="ArrowLeft") { go(-1); }
});

/* ===================== 3D ===================== */
const Viz = (function(){
  const canvas = $("#cv"), veil = $("#veil"), stage = $("#stage");
  const ok3d = typeof THREE !== "undefined";
  if (!ok3d){ veil.textContent = "A ilustração 3D não carregou neste navegador."; return { show(){}, idle(){} }; }
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const renderer = new THREE.WebGLRenderer({ canvas, antialias:true, alpha:false });
  renderer.setPixelRatio(Math.min(devicePixelRatio||1, 2));
  const camera = new THREE.PerspectiveCamera(42, 16/9, 0.1, 200);
  const controls = new THREE.OrbitControls(camera, canvas);
  controls.enableDamping = true; controls.dampingFactor = .08; controls.minDistance = 4; controls.maxDistance = 40;
  controls.autoRotate = false; controls.enablePan = false;
  controls.minAzimuthAngle = -Math.PI/3.2; controls.maxAzimuthAngle = Math.PI/3.2; controls.minPolarAngle = .35; controls.maxPolarAngle = Math.PI/2.1;
  let scene = new THREE.Scene(), anims = [], current = null, visible = true;

  function css(v){ return getComputedStyle(document.documentElement).getPropertyValue(v).trim() || "#888"; }
  function col(v){ return new THREE.Color(css(v)); }
  function pal(){ return { bg:css("--panel-2"), ink:css("--ink"), muted:css("--muted"), line:css("--line"), panel:css("--panel"), accent:css("--accent"),
    ok:css("--ok"), bad:css("--bad"), recon:css("--recon"), fail:css("--fail"), alert:css("--alert"), success:css("--success"), noise:css("--noise"), info:css("--info") }; }
  const KIND = { recon:"recon", fail:"fail", alert:"alert", success:"success", noise:"noise", info:"info", suspicious:"alert", benign:"ok", normal:"info" };

  function label(text, o={}){
    const P = pal(), size = o.size || 44, pad = 18;
    const c = document.createElement("canvas"), g = c.getContext("2d");
    const font = `${o.weight||600} ${size}px ${o.mono?'"JetBrains Mono",Consolas,monospace':'"IBM Plex Sans","Segoe UI",sans-serif'}`;
    g.font = font;
    const lines = String(text).split("\n");
    const w = Math.ceil(Math.max(...lines.map(l => g.measureText(l).width))) + pad*2;
    const h = Math.ceil(size*1.3*lines.length) + pad*1.4;
    c.width = Math.max(8,w); c.height = h;
    g.font = font; g.textBaseline = "middle";
    if (o.bg !== false){ g.fillStyle = o.bg || P.panel; roundRect(g,0,0,c.width,c.height,16); g.fill();
      g.strokeStyle = o.border || P.line; g.lineWidth = 3; roundRect(g,1.5,1.5,c.width-3,c.height-3,15); g.stroke(); }
    g.fillStyle = o.color || P.ink;
    lines.forEach((l,i) => g.fillText(l, pad, pad*0.7 + size*0.65 + i*size*1.3));
    const tex = new THREE.CanvasTexture(c); tex.anisotropy = 4;
    const m = new THREE.SpriteMaterial({ map:tex, transparent:true, depthWrite:false, depthTest:false });
    const s = new THREE.Sprite(m); const sc = (o.scale||1) * 0.0105;
    s.scale.set(c.width*sc, c.height*sc, 1); s.renderOrder = 10;
    return s;
  }
  function roundRect(g,x,y,w,h,r){ g.beginPath(); g.moveTo(x+r,y); g.arcTo(x+w,y,x+w,y+h,r); g.arcTo(x+w,y+h,x,y+h,r); g.arcTo(x,y+h,x,y,r); g.arcTo(x,y,x+w,y,r); g.closePath(); }
  function mat(color, o={}){ return new THREE.MeshStandardMaterial({ color, roughness:o.rough??.55, metalness:o.metal??.05, emissive:o.emissive||0x000000, emissiveIntensity:o.ei??0, transparent:o.opacity!=null, opacity:o.opacity??1 }); }
  function box(w,h,d,color,o){ return new THREE.Mesh(new THREE.BoxGeometry(w,h,d), mat(color,o)); }
  function glow(m, color){ m.material.emissive = new THREE.Color(color); m.material.emissiveIntensity = .45; }
  function arc(a, b, color, lift=1.6){
    const mid = a.clone().add(b).multiplyScalar(.5); mid.y += lift;
    const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
    const tube = new THREE.Mesh(new THREE.TubeGeometry(curve, 48, .05, 8, false), mat(color, {emissive:color, ei:.35}));
    const ball = new THREE.Mesh(new THREE.SphereGeometry(.14, 16, 16), mat(color, {emissive:color, ei:.9}));
    const head = new THREE.Mesh(new THREE.ConeGeometry(.16,.4,16), mat(color,{emissive:color,ei:.5}));
    const end = curve.getPoint(1), pre = curve.getPoint(.94); head.position.copy(end); head.lookAt(pre); head.rotateX(-Math.PI/2);
    const g = new THREE.Group(); g.add(tube, ball, head);
    anims.push(t => { if (reduce) { ball.position.copy(curve.getPoint(.5)); return; } ball.position.copy(curve.getPoint((t*0.35)%1)); });
    return { group:g, mid:curve.getPoint(.5) };
  }
  function line(a,b,color){ const g = new THREE.BufferGeometry().setFromPoints([a,b]); return new THREE.Line(g, new THREE.LineBasicMaterial({ color })); }
  function floor(P, size=24){
    const grid = new THREE.GridHelper(size, size, new THREE.Color(P.line), new THREE.Color(P.line));
    grid.material.transparent = true; grid.material.opacity = .55; grid.position.y = -0.01; return grid;
  }
  function fresh(){
    scene.traverse(o => { if (o.geometry) o.geometry.dispose(); if (o.material){ (Array.isArray(o.material)?o.material:[o.material]).forEach(m => { if (m.map) m.map.dispose(); m.dispose(); }); } });
    scene = new THREE.Scene(); anims = [];
    const P = pal(); scene.background = new THREE.Color(P.bg);
    scene.add(new THREE.HemisphereLight(0xffffff, new THREE.Color(P.line), .85));
    const d = new THREE.DirectionalLight(0xffffff, .75); d.position.set(5,10,7); scene.add(d);
    return P;
  }
  function frame(pos, target){ camera.position.set(...pos); controls.target.set(...target); controls.update(); }
  function short(s, n=30){ s = String(s); return s.length > n ? s.slice(0,n-1)+"…" : s; }

  /* ---------- builders ---------- */
  const B = {};
  B.network = (s, P) => {
    const N = { kali:{p:[-5,0,0], c:P.alert, t:"SOC-Kali\n10.0.10.30", r:"atacante"}, win:{p:[0,0,0], c:P.info, t:"SOC-Win11\n10.0.10.20", r:"vítima"},
                wazuh:{p:[5,0,0], c:P.ok, t:"SOC-Wazuh\n10.0.10.10", r:"SIEM"}, host:{p:[0,0,5], c:P.muted, t:"Seu PC\n127.0.0.1", r:"navegador"} };
    const hi = new Set(s.highlight||[]);
    scene.add(floor(P));
    const net = new THREE.Mesh(new THREE.PlaneGeometry(13.5,4.4), mat(P.accent,{opacity:.1})); net.rotation.x=-Math.PI/2; net.position.y=.005; scene.add(net);
    const nl = label("NAT Network 10.0.10.0/24",{size:30,mono:true,bg:false,color:P.muted,scale:.9}); nl.position.set(0,.25,-2.4); scene.add(nl);
    Object.entries(N).forEach(([k,n]) => {
      const on = hi.size===0 || hi.has(k);
      const m = box(1.7,1.1,1.2, n.c, {opacity: on?1:.28}); m.position.set(n.p[0],.6,n.p[2]); if (hi.has(k)) glow(m, n.c); scene.add(m);
      const scr = box(1.3,.08,.9, P.panel, {opacity:on?1:.3}); scr.position.set(n.p[0],1.2,n.p[2]); scene.add(scr);
      const l = label(n.t,{size:34, mono:true, scale:on?1:.8}); l.position.set(n.p[0],2.1,n.p[2]); l.material.opacity = on?1:.45; scene.add(l);
      if (hi.has(k)){ const ring = new THREE.Mesh(new THREE.TorusGeometry(1.25,.04,8,48), mat(n.c,{emissive:n.c,ei:.8})); ring.rotation.x=Math.PI/2; ring.position.set(n.p[0],.03,n.p[2]); scene.add(ring);
        anims.push(t => { const k2 = 1 + .08*Math.sin(t*3); ring.scale.set(k2,k2,k2); }); }
    });
    (s.arrows||[]).forEach(a => {
      const A = N[a.from], Bn = N[a.to]; if (!A||!Bn) return;
      const r = arc(new THREE.Vector3(A.p[0],1.25,A.p[2]), new THREE.Vector3(Bn.p[0],1.25,Bn.p[2]), P.accent, 2);
      scene.add(r.group);
      if (a.label){ const l = label(short(a.label,28),{size:30,mono:true,border:P.accent}); l.position.copy(r.mid).add(new THREE.Vector3(0,.55,0)); scene.add(l); }
    });
    frame([0,7.5,11],[0,.8,.8]);
  };
  B.timeline = (s, P) => {
    const ev = (s.events||[]).slice(0,8), n = ev.length || 1, gap = 2.5, x0 = -(n-1)*gap/2;
    scene.add(floor(P));
    const rail = box((n-1)*gap+1.6,.08,.3,P.line); rail.position.set(0,.04,1.2); scene.add(rail);
    const H = { recon:1.4, fail:1.1, alert:2.6, success:2.1, noise:.6, info:1 };
    ev.forEach((e,i) => {
      const k = KIND[e.kind] || "info", c = P[k] || P.info, h = H[e.kind] || 1;
      const m = box(1,h,1,c); m.position.set(x0+i*gap,h/2,0); if (e.kind==="alert"||e.kind==="success") glow(m,c); scene.add(m);
      const lt = label(e.t||"",{size:28,mono:true,bg:false,color:P.muted}); lt.position.set(x0+i*gap,.25,1.65); scene.add(lt);
      const lb = label(short(e.label||"",24),{size:30,border:c}); lb.position.set(x0+i*gap,h+.6+(i%2)*.85,0); scene.add(lb);
      if (!reduce) anims.push(t => { m.scale.y = Math.min(1, Math.max(.02, (t*1.6) - i*0.25)); m.position.y = h*m.scale.y/2; });
    });
    const head = box(.06,3.4,.06,P.accent,{emissive:P.accent,ei:.8}); head.position.set(x0,1.7,1.2); scene.add(head);
    anims.push(t => { head.position.x = x0 + (((t*0.4)%1) * (n-1+.0001))*gap; });
    frame([0,4.6,Math.max(9, n*2.1)],[0,1.4,0]);
  };
  function tree(nodes, P, kindOf, textOf){
    const byId = {}; nodes.forEach(n => byId[n.id] = n);
    const depth = n => { let d=0, c=n; const seen=new Set(); while (c && c.parent && byId[c.parent] && !seen.has(c.id)){ seen.add(c.id); c = byId[c.parent]; d++; } return d; };
    const levels = {}; nodes.forEach(n => { const d = depth(n); (levels[d] = levels[d] || []).push(n); });
    const pos = {}, maxD = Math.max(0, ...Object.keys(levels).map(Number)), step = maxD ? Math.min(2.2, 6.4/maxD) : 2.2, top = .6 + maxD*step;
    Object.entries(levels).forEach(([d,arr]) => arr.forEach((n,i) => { pos[n.id] = new THREE.Vector3((i-(arr.length-1)/2)*3.8, top - d*step, (i%2)*.6); }));
    scene.add(floor(P));
    nodes.forEach(n => {
      const c = kindOf(n), p = pos[n.id];
      const m = new THREE.Mesh(new THREE.CylinderGeometry(.62,.62,.5,32), mat(c)); m.position.copy(p); if (n.highlight || n.kind==="suspicious") glow(m,c); scene.add(m);
      const l = label(textOf(n),{size:30,mono:true,border:c}); l.position.copy(p).add(new THREE.Vector3(0,.95,0)); scene.add(l);
      if (n.parent && pos[n.parent]){ scene.add(line(pos[n.parent].clone().add(new THREE.Vector3(0,-.25,0)), p.clone().add(new THREE.Vector3(0,.25,0)), new THREE.Color(P.muted)));
        const dotm = new THREE.Mesh(new THREE.SphereGeometry(.09,12,12), mat(P.accent,{emissive:P.accent,ei:1})); scene.add(dotm);
        const a = pos[n.parent].clone(), b = p.clone();
        anims.push(t => { const f = reduce ? .5 : (t*0.5)%1; dotm.position.lerpVectors(a,b,f); }); }
    });
    frame([0, top/2 + 1, 7 + top*.9],[0, top/2 + .3, 0]);
  }
  B.processTree = (s,P) => tree((s.nodes||[]).slice(0,6), P, n => P[KIND[n.kind]||"info"] || P.info, n => short(n.label||"",24) + (n.sub ? "\n"+short(n.sub,24) : ""));
  B.ruleTree = (s,P) => tree((s.nodes||[]).slice(0,6), P, n => { const lv = +n.level||0; return lv===0 ? P.noise : lv>=12 ? P.alert : lv>=8 ? P.fail : lv>=4 ? P.info : P.muted; },
    n => `regra ${n.id} · nível ${n.level}` + (n.label ? "\n"+short(n.label,26) : ""));
  B.emailPath = (s,P) => {
    const hops = (s.hops||[]).slice(0,6), n = hops.length || 1; scene.add(floor(P));
    const pts = hops.map((h,i) => new THREE.Vector3(-((n-1)*2.4)/2 + i*2.4, .3 + i*.45, (i%2?-.5:.5)));
    hops.forEach((h,i) => {
      const on = i === s.highlight; const c = i===0 ? P.alert : i===n-1 ? P.info : P.muted;
      const m = box(1.5,.3,1.5, on ? P.accent : c); m.position.copy(pts[i]); if (on) glow(m,P.accent); scene.add(m);
      const l = label(`${i+1}. ${short(h,26)}`,{size:28,mono:true,border:on?P.accent:P.line}); l.position.copy(pts[i]).add(new THREE.Vector3(0,.9,0)); scene.add(l);
    });
    if (pts.length > 1){
      const curve = new THREE.CatmullRomCurve3(pts.map(p => p.clone().add(new THREE.Vector3(0,.35,0))));
      scene.add(new THREE.Mesh(new THREE.TubeGeometry(curve, 80, .04, 8, false), mat(P.accent,{emissive:P.accent,ei:.3})));
      const env = new THREE.Mesh(new THREE.BoxGeometry(.5,.32,.04), mat(P.panel,{emissive:P.accent,ei:.25}));
      scene.add(env); anims.push(t => { const f = reduce?.5:(t*.18)%1; env.position.copy(curve.getPoint(f)).add(new THREE.Vector3(0,.25,0)); env.rotation.y = t; });
    }
    const cap = label("leitura do Received: de baixo para cima",{size:26,bg:false,color:P.muted}); cap.position.set(0,-.1,2.4); scene.add(cap);
    frame([0,5,Math.max(9, n*2)],[0,1.2,0]);
  };
  B.decode = (s,P) => {
    scene.add(floor(P));
    const steps = (s.steps||[]).slice(0,3);
    const total = steps.length + 2, gap = 3.4, x0 = -(total-1)*gap/2;
    const inp = box(2.4,1.4,.4,P.noise); inp.position.set(x0,.9,0); scene.add(inp);
    const li = label(short(s.input||"",26),{size:28,mono:true}); li.position.set(x0,2.1,0); scene.add(li);
    const lt = label(s.inLabel || "entrada",{size:24,bg:false,color:P.muted}); lt.position.set(x0,-.05,1); scene.add(lt);
    steps.forEach((st,i) => { const x = x0+(i+1)*gap;
      const g = new THREE.Mesh(new THREE.TorusGeometry(.7,.14,16,48), mat(P.accent,{emissive:P.accent,ei:.4})); g.position.set(x,.95,0); scene.add(g);
      anims.push(t => { g.rotation.y = t*1.2; g.rotation.x = .3; });
      const l = label(short(st,20),{size:28,border:P.accent}); l.position.set(x,2.1,0); scene.add(l); });
    const xo = x0+(total-1)*gap;
    const out = box(2.4,1.4,.4,P.ok); out.position.set(xo,.9,0); glow(out,P.ok); scene.add(out);
    const lo = label(short(s.output||"",28),{size:28,mono:true,border:P.ok}); lo.position.set(xo,2.1,0); scene.add(lo);
    const lt2 = label(s.outLabel || "resultado",{size:24,bg:false,color:P.muted}); lt2.position.set(xo,-.05,1); scene.add(lt2);
    for (let k=0;k<6;k++){ const p = new THREE.Mesh(new THREE.BoxGeometry(.16,.16,.16), mat(P.accent,{emissive:P.accent,ei:.8})); scene.add(p);
      anims.push(t => { const f = reduce ? k/6 : ((t*.25)+k/6)%1; p.position.set(x0+f*(xo-x0), .95+Math.sin(f*Math.PI*4)*.25, 0); p.rotation.set(t,t,0); }); }
    frame([0,3.8,Math.max(10,total*3.1)],[0,1,0]);
  };
  B.url = (s,P) => {
    scene.add(floor(P));
    const parts = (s.parts||[]).slice(0,6);
    const W = parts.map(p => Math.max(.7, Math.min(4.2, String(p.text).length*.13)));
    const tot = W.reduce((a,b)=>a+b,0) + (parts.length-1)*.25; let x = -tot/2;
    parts.forEach((p,i) => {
      const w = W[i], cx = x + w/2; x += w + .25;
      const role = p.role; const c = role==="host" ? P.ok : role==="userinfo" ? P.noise : role==="at" ? P.alert : role==="scheme" ? P.info : P.muted;
      const h = role==="host" ? 1.3 : role==="at" ? 1 : .6;
      const m = box(w,h,1,c,{opacity: role==="userinfo" ? .45 : 1}); m.position.set(cx,h/2,0); if (role==="host"||role==="at") glow(m,c); scene.add(m);
      const l = label(short(p.text,30),{size:28,mono:true,border:c}); l.position.set(cx,h+.5+(i%2)*.5,0); scene.add(l);
      const tag = {host:"host REAL (destino)",userinfo:"userinfo: ignorado",at:"separador @",scheme:"esquema",path:"caminho"}[role] || role;
      const lt = label(tag,{size:24,bg:false,color:P.muted}); lt.position.set(cx,-.05,1.1); scene.add(lt);
      if (role==="userinfo" && !reduce) anims.push(t => { m.material.opacity = .25 + .2*(1+Math.sin(t*2))/2; });
    });
    frame([0,3.8,Math.max(8,tot*1.1)],[0,.9,0]);
  };
  B.funnel = (s,P) => {
    const st = (s.stages||[]).slice(0,5), n = st.length || 1, max = Math.max(1, ...st.map(x=>+x.value||0));
    scene.add(floor(P));
    st.forEach((x,i) => {
      const r = .5 + 2.6*Math.sqrt((+x.value||0)/max), r2 = i < n-1 ? .5 + 2.6*Math.sqrt((+st[i+1].value||0)/max) : r*.8;
      const y = (n-1-i)*1.15 + .5;
      const c = i===n-1 ? P.alert : i===0 ? P.noise : P.fail;
      const m = new THREE.Mesh(new THREE.CylinderGeometry(r, r2, .9, 48, 1, true), mat(c,{opacity:.85})); m.material.side = THREE.DoubleSide; m.position.y = y; if (i===n-1) glow(m,c); scene.add(m);
      const l = label(`${x.value} · ${short(x.label,22)}`,{size:30,mono:true,border:c}); l.position.set(r+1.9, y, 0); scene.add(l);
      if (!reduce) anims.push(t => { m.rotation.y = t*.3*(i%2?1:-1); });
    });
    frame([2,3.5,10],[1.2,(n*1.15)/2,0]);
  };
  B.fields = (s,P) => {
    scene.add(floor(P));
    // tabela desenhada numa única textura: gira como um objeto sólido e os textos nunca se sobrepõem
    const rows = (s.rows||[]).slice(0,6), W = 1100, rh = 92, head = 116, pad = 40;
    const c = document.createElement("canvas"); c.width = W; c.height = head + rows.length*rh + 28;
    const g = c.getContext("2d");
    const fit = (txt, x, y, max) => { let t = String(txt); while (t.length > 1 && g.measureText(t).width > max) t = t.slice(0,-2) + "…"; g.fillText(t, x, y); };
    g.fillStyle = P.panel; roundRect(g,0,0,W,c.height,28); g.fill();
    g.strokeStyle = P.line; g.lineWidth = 4; roundRect(g,2,2,W-4,c.height-4,26); g.stroke();
    g.fillStyle = P.accent; roundRect(g,pad,head/2-22,12,44,6); g.fill();
    g.textBaseline = "middle"; g.fillStyle = P.ink; g.font = '700 46px "Archivo","Segoe UI",sans-serif';
    fit(s.title || "Documento", pad + 30, head/2 + 2, W - pad*2 - 30);
    g.fillStyle = P.line; g.fillRect(pad, head - 6, W - pad*2, 3);
    rows.forEach((r,i) => {
      const y = head + i*rh, on = i === s.highlight, cy = y + rh/2;
      if (on){ g.globalAlpha = .16; g.fillStyle = P.accent; roundRect(g,16,y+8,W-32,rh-16,16); g.fill(); g.globalAlpha = 1;
        g.strokeStyle = P.accent; g.lineWidth = 4; roundRect(g,16,y+8,W-32,rh-16,16); g.stroke(); }
      else if (i){ g.fillStyle = P.line; g.globalAlpha = .6; g.fillRect(pad, y, W - pad*2, 2); g.globalAlpha = 1; }
      g.font = '500 34px "JetBrains Mono",Consolas,monospace'; g.fillStyle = on ? P.ink : P.muted; fit(r[0], pad, cy, W*.36);
      g.font = (on ? '700 ' : '400 ') + '36px "JetBrains Mono",Consolas,monospace'; g.fillStyle = on ? P.accent : P.ink; fit(r[1], W*.42, cy, W*.58 - pad);
    });
    const tex = new THREE.CanvasTexture(c); tex.anisotropy = renderer.capabilities.getMaxAnisotropy ? renderer.capabilities.getMaxAnisotropy() : 4;
    const w = 8, h = w * c.height / W, base = .45;
    const back = box(w + .3, h + .3, .22, P.line); back.position.set(0, h/2 + base, -.14); scene.add(back);
    const face = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ map:tex })); face.position.set(0, h/2 + base, 0); scene.add(face);
    const stand = box(1.4, base, .8, P.line); stand.position.set(0, base/2, -.14); scene.add(stand);
    if (typeof s.highlight === "number" && rows[s.highlight]){
      const ry = base + h - (head + (s.highlight + .5)*rh) / c.height * h;
      const arrow = new THREE.Mesh(new THREE.ConeGeometry(.2, .5, 16), mat(P.accent, { emissive:P.accent, ei:.7 }));
      arrow.rotation.z = -Math.PI/2; scene.add(arrow);
      anims.push(t => { arrow.position.set(-w/2 - .55 - (reduce ? 0 : .12*Math.sin(t*4)), ry, .1); });
    }
    frame([1.6, h/2 + base + .8, 9.6], [0, h/2 + base, 0]);
  };
  B.shields = (s,P) => {
    scene.add(floor(P));
    const it = (s.items||[]).slice(0,4), n = it.length || 1, gap = 3;
    const shape = new THREE.Shape(); shape.moveTo(0,1.2); shape.quadraticCurveTo(.9,1.15,1,.9); shape.lineTo(.95,0); shape.quadraticCurveTo(.8,-.9,0,-1.25);
    shape.quadraticCurveTo(-.8,-.9,-.95,0); shape.lineTo(-1,.9); shape.quadraticCurveTo(-.9,1.15,0,1.2);
    const geo = new THREE.ExtrudeGeometry(shape,{depth:.25,bevelEnabled:true,bevelSize:.05,bevelThickness:.05,bevelSegments:2});
    it.forEach((x,i) => {
      const c = x.status==="pass" ? P.ok : x.status==="fail" ? P.alert : P.noise;
      const m = new THREE.Mesh(geo, mat(c,{opacity: x.status==="none"?.55:1})); m.position.set((i-(n-1)/2)*gap,1.6,0); if (x.status!=="none") glow(m,c); scene.add(m);
      const l = label(`${short(x.label,14)}: ${x.status}`,{size:32,mono:true,border:c}); l.position.set((i-(n-1)/2)*gap,3.4,0); scene.add(l);
      anims.push(t => { m.rotation.y = reduce ? .3 : Math.sin(t*.8+i)*.5; });
    });
    frame([0,3,8.5],[0,1.6,0]);
  };

  /* ---------- demonstrações conceituais (uma ideia por cena) ---------- */
  const V3 = (x,y,z) => new THREE.Vector3(x,y,z);
  function tag(text, pos, o={}){ const l = label(text, Object.assign({size:28}, o)); l.position.copy(pos); scene.add(l); return l; }
  function hexColor(ch, P){ const v = parseInt(ch,16); if (isNaN(v)) return new THREE.Color(P.muted); return new THREE.Color().setHSL(v/16, .6, .52); }
  function dyn(w, o={}){
    const P = pal(), c = document.createElement("canvas"); c.width = w; c.height = o.h || 84; const g = c.getContext("2d");
    const tex = new THREE.CanvasTexture(c);
    const s = new THREE.Sprite(new THREE.SpriteMaterial({ map:tex, transparent:true, depthWrite:false, depthTest:false })); const k = .0105*(o.scale||1);
    s.scale.set(c.width*k, c.height*k, 1); s.renderOrder = 10; let last = null;
    s.set = (txt, color) => { const key = txt + "|" + (color||""); if (key === last) return; last = key;
      g.clearRect(0,0,c.width,c.height); g.fillStyle = P.panel; roundRect(g,0,0,c.width,c.height,16); g.fill();
      g.strokeStyle = color || P.line; g.lineWidth = 4; roundRect(g,2,2,c.width-4,c.height-4,14); g.stroke();
      g.fillStyle = color || P.ink; g.font = `600 ${o.size||34}px "JetBrains Mono",Consolas,monospace`; g.textBaseline = "middle"; g.textAlign = "center";
      let t = String(txt); while (t.length > 1 && g.measureText(t).width > c.width - 28) t = t.slice(0,-2) + "…";
      g.fillText(t, c.width/2, c.height/2 + 2); tex.needsUpdate = true; };
    scene.add(s); return s;
  }
  function card(title, lines, accent, w){
    const P = pal(), W = 900, lh = 76, head = 108, pad = 36; w = w || 4.6;
    const c = document.createElement("canvas"); c.width = W; c.height = head + Math.max(1,lines.length)*lh + 26; const g = c.getContext("2d");
    const fit = (t,x,y,max) => { t = String(t); while (t.length > 1 && g.measureText(t).width > max) t = t.slice(0,-2) + "…"; g.fillText(t,x,y); };
    g.fillStyle = P.panel; roundRect(g,0,0,W,c.height,26); g.fill();
    g.strokeStyle = accent || P.line; g.lineWidth = 7; roundRect(g,4,4,W-8,c.height-8,23); g.stroke();
    g.textBaseline = "middle"; g.fillStyle = accent || P.ink; g.font = '700 46px "Archivo","Segoe UI",sans-serif'; fit(title, pad, head/2+2, W-pad*2);
    g.font = '400 36px "JetBrains Mono",Consolas,monospace'; g.fillStyle = P.ink; lines.forEach((l,i) => fit(l, pad, head + i*lh + lh/2, W-pad*2));
    const tex = new THREE.CanvasTexture(c), h = w*c.height/W;
    const m = new THREE.Mesh(new THREE.PlaneGeometry(w,h), new THREE.MeshBasicMaterial({ map:tex, transparent:true, side:THREE.DoubleSide }));
    m.userData.h = h; return m;
  }
  const RAINBOW = P => [P.info, P.ok, P.fail, P.recon, P.alert, P.noise];

  B.hash = (s,P) => {
    scene.add(floor(P));
    const bytes = [];
    for (let r=0;r<4;r++) for (let c=0;c<4;c++){ const b = box(.42,.42,.42,P.info); b.position.set(-4.2+(c-1.5)*.5, .35 + r*.5, 0); scene.add(b); bytes.push(b); }
    tag(short(s.input||"arquivo",24), V3(-4.2,2.75,0), {mono:true});
    const mach = new THREE.Mesh(new THREE.CylinderGeometry(1,1,1.2,6), mat(P.accent,{emissive:P.accent,ei:.25})); mach.position.set(0,.9,0); scene.add(mach);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(1.25,.06,8,48), mat(P.accent,{emissive:P.accent,ei:.8})); ring.position.set(0,.9,0); ring.rotation.x = Math.PI/2; scene.add(ring);
    tag(short(s.algo||"SHA-256",16), V3(0,2.35,0), {mono:true, border:P.accent});
    const clean = x => String(x||"").replace(/[^0-9a-f]/gi,"").toLowerCase();
    const dig = (clean(s.digest) || "3f57a838943fe82a").slice(0,16).padEnd(16,"0");
    const alt = dig.split("").map((ch,i) => ((parseInt(ch,16)*7 + i*5 + 3) % 16).toString(16)).join("");
    const cells = [];
    for (let i=0;i<16;i++){ const m = box(.32,.32,.32,hexColor(dig[i],P)); m.position.set(3 + (i%8)*.38, .6 + Math.floor(i/8)*.42, 0); scene.add(m); cells.push(m); }
    const out = dyn(520,{size:30}); out.position.set(4.33,1.85,0);
    const flip = s.flip !== false, sample = bytes[5];
    if (s.note) tag(short(s.note,46), V3(0,-.1,2.2), {bg:false,color:P.muted,size:26});
    if (flip) tag("1 byte muda → o hash muda inteiro", V3(0,3.4,0), {size:26,bg:false,color:P.muted});
    for (let k=0;k<5;k++){ const p = box(.14,.14,.14,P.accent,{emissive:P.accent,ei:.8}); scene.add(p);
      anims.push(t => { const f = reduce ? k/5 : ((t*.3)+k/5)%1; p.position.set(-3 + f*5.6, .9 + Math.sin(f*Math.PI)*.4, 0); }); }
    anims.push(t => { mach.rotation.y = t*.8;
      const ph = flip && !reduce ? Math.floor(t/2.6)%2 : 0;
      sample.material.color.set(ph ? P.alert : P.info); sample.material.emissive.set(ph ? P.alert : "#000000"); sample.material.emissiveIntensity = ph ? .6 : 0;
      cells.forEach((m,i) => { m.material.color.copy(hexColor((ph?alt:dig)[i],P)); m.position.y = .6 + Math.floor(i/8)*.42 + (reduce?0:.05*Math.sin(t*4+i)); });
      out.set(ph ? alt.slice(0,6)+"…"+alt.slice(-6) : (s.digest ? short(s.digest,20) : dig.slice(0,6)+"…"+dig.slice(-6)), ph ? P.alert : P.ok);
    });
    frame([0,3.3,10.5],[0,1.2,0]);
  };

  B.envelope = (s,P) => {
    scene.add(floor(P));
    const body = box(4,.25,2.6,P.panel); body.position.set(0,.15,0); scene.add(body);
    const flap = new THREE.Mesh(new THREE.ConeGeometry(1.9,1,4), mat(P.line)); flap.rotation.y = Math.PI/4; flap.scale.set(1.45,.22,.95); flap.position.set(0,.38,0); scene.add(flap);
    const L = (s.layers||[]).slice(0,6), n = L.length;
    L.forEach((r,i) => {
      const on = i === s.highlight, c = on ? P.accent : (r[2]==="bad" ? P.alert : r[2]==="ok" ? P.ok : P.info);
      const pl = box(3.6,.06,2.2,c,{opacity:on?.95:.5}); if (on) glow(pl,c); scene.add(pl);
      const y = 1 + i*.78;
      const l = label(`${short(r[0],16)}: ${short(r[1],30)}`,{size:28,mono:true,border:c}); scene.add(l);
      anims.push(t => { const f = reduce ? 1 : Math.min(1, Math.max(0, t*.9 - i*.18)); const yy = .35 + (y-.35)*f;
        pl.position.set(on ? (reduce?0:.12*Math.sin(t*2.5)) : 0, yy, 0); l.position.set(4.1, yy, 0); l.material.opacity = Math.max(.05,f); });
    });
    if (s.title) tag(short(s.title,34), V3(0,1.35+n*.78,0), {size:32,border:P.accent});
    frame([2.4,2.8+n*.3,10],[1.5,.7+n*.38,0]);
  };

  B.bruteforce = (s,P) => {
    scene.add(floor(P));
    const n = Math.max(1, Math.min(12, +s.attempts||6)), win = s.success !== false;
    const lockC = box(1.6,1.4,.8,P.muted); lockC.position.set(2.6,.75,0); scene.add(lockC);
    const sh = new THREE.Mesh(new THREE.TorusGeometry(.55,.13,12,32,Math.PI), mat(P.muted,{metal:.5})); sh.position.set(2.6,1.45,0); scene.add(sh);
    tag(short(s.target||"conta",24), V3(2.6,2.75,0), {mono:true});
    const src = box(1.3,.8,1,P.alert); src.position.set(-4,.4,0); scene.add(src);
    tag(short(s.source||"atacante",24), V3(-4,1.45,0), {mono:true,border:P.alert});
    const key = new THREE.Mesh(new THREE.SphereGeometry(.2,16,16), mat(P.fail,{emissive:P.fail,ei:.8})); scene.add(key);
    const cnt = dyn(620,{size:30}); cnt.position.set(-.8,3.9,0);
    if (s.secret) tag(short(s.secret,30), V3(2.6,-.1,1.2), {mono:true,bg:false,color:P.muted,size:26});
    if (s.note) tag(short(s.note,44), V3(-1,-.1,2.1), {bg:false,color:P.muted,size:26});
    const per = .85, T = n*per + 2.6;
    anims.push(t => {
      const tt = reduce ? T - .5 : t % T, done = tt >= n*per, k = Math.min(n-1, Math.floor(tt/per)), f = done ? 1 : Math.min(1, (tt - k*per)/(per*.7));
      key.position.set(-3.3 + 5.2*f, .75 + Math.sin(f*Math.PI)*.9, 0); key.visible = !done;
      const okNow = win && (done || (k === n-1 && f >= 1)), bad = !okNow && (done || f >= 1);
      const c = okNow ? P.ok : bad ? P.alert : P.muted;
      lockC.material.color.set(c); sh.material.color.set(c); sh.position.y = okNow ? 1.85 : 1.45;
      cnt.set(done ? (win ? `${n} tentativas → acesso` : `${n} tentativas → negado`) : `tentativa ${k+1}/${n}${bad ? " ✗" : ""}`, okNow ? P.ok : bad ? P.alert : null);
    });
    frame([0,3.2,10],[0,1.7,0]);
  };

  B.threshold = (s,P) => {
    scene.add(floor(P));
    const v = (s.values && s.values.length ? s.values : [1,2,3,4,5,6,7,8]).slice(0,12).map(Number), n = v.length, lim = +s.limit || 8;
    const max = Math.max(lim*1.2, ...v), H = 4, gap = .8, x0 = -(n-1)*gap/2, ly = lim/max*H;
    const pl = new THREE.Mesh(new THREE.BoxGeometry(n*gap+1.2,.04,1.4), mat(P.alert,{opacity:.3})); pl.position.set(0,ly,0); scene.add(pl);
    tag(`limite: ${short(s.limitLabel||lim,18)}`, V3(x0-2.1, ly, 0), {size:26,mono:true,border:P.alert});
    const bars = v.map((val,i) => { const h = Math.max(.08, val/max*H); const m = box(.55,h,.55, val >= lim ? P.alert : P.fail); m.position.set(x0+i*gap,h/2,0); scene.add(m); return {m,h}; });
    const siren = new THREE.Mesh(new THREE.SphereGeometry(.42,24,24), mat(P.alert,{emissive:P.alert,ei:.1})); siren.position.set(x0+(n-1)*gap+1.6, H*.85, 0); scene.add(siren);
    if (s.rule) tag(short(s.rule,30), V3(siren.position.x, H*.85+1, 0), {mono:true,border:P.alert});
    if (s.label) tag(short(s.label,44), V3(0,-.1,1.5), {bg:false,color:P.muted,size:26});
    const cross = v.findIndex(x => x >= lim), step = .45, T = n*step + 2.6;
    anims.push(t => { const tt = reduce ? T : t % T;
      bars.forEach((b,i) => { const f = Math.min(1, Math.max(.02, (tt - i*step)/.4)); b.m.scale.y = f; b.m.position.y = b.h*f/2; });
      const fired = cross >= 0 && tt >= cross*step + .4; siren.material.emissiveIntensity = fired ? (reduce ? .8 : .45 + .5*Math.abs(Math.sin(t*6))) : .05; });
    frame([0,H*.6+1.8,Math.max(8.5,n*.95+4)],[0,H/2,0]);
  };

  B.gauge = (s,P) => {
    scene.add(floor(P));
    const max = +s.max || 15, lv = Math.max(0, Math.min(max, +s.level||0)), R = 3, cy = .5;
    const lvColor = i => i===0 ? P.noise : i>=12 ? P.alert : i>=8 ? P.fail : i>=4 ? P.info : P.muted;
    for (let i=0;i<=max;i++){ const a = Math.PI - i/max*Math.PI, c = lvColor(i);
      const seg = box(.36, i===lv ? .9 : .5, .5, c, {opacity: i<=lv ? 1 : .28}); seg.position.set(Math.cos(a)*R, cy+Math.sin(a)*R, 0); seg.rotation.z = a - Math.PI/2; if (i===lv) glow(seg,c); scene.add(seg);
      if (i%3===0 || i===lv || i===max){ const l = label(String(i),{size:26,mono:true,bg:false,color:i===lv?P.ink:P.muted}); l.position.set(Math.cos(a)*(R+.85), cy+Math.sin(a)*(R+.85), 0); scene.add(l); } }
    const piv = new THREE.Group(); piv.position.set(0,cy,.32); scene.add(piv);
    const nd = box(.09,R-.5,.09,P.accent,{emissive:P.accent,ei:.6}); nd.position.y = (R-.5)/2; piv.add(nd);
    const hub = new THREE.Mesh(new THREE.SphereGeometry(.24,16,16), mat(P.accent)); hub.position.set(0,cy,.32); scene.add(hub);
    const target = Math.PI/2 - lv/max*Math.PI;
    tag(short(s.label || `nível ${lv}`,32), V3(0,cy+R+1.25,0), {size:32,mono:true,border:lvColor(lv)});
    if (s.note) tag(short(s.note,46), V3(0,-.1,1.6), {bg:false,color:P.muted,size:26});
    anims.push(t => { const f = reduce ? 1 : Math.min(1, (t % 6)/1.6); const e = 1 - Math.pow(1-f,3); piv.rotation.z = Math.PI/2 + (target - Math.PI/2)*e + (reduce||f<1 ? 0 : .02*Math.sin(t*5)); });
    frame([0,2.8,10.5],[0,2.3,0]);
  };

  B.mitre = (s,P) => {
    scene.add(floor(P));
    const tac = (s.tactics||[]).slice(0,6), n = tac.length || 1, hi = +s.col||0, row = s.row != null ? +s.row : 1, gap = 2.3, x0 = -(n-1)*gap/2;
    tac.forEach((tn,i) => { const on = i === hi, x = x0+i*gap;
      const head = box(2,.35,.9,on?P.accent:P.line); head.position.set(x,3.4,0); if (on) glow(head,P.accent); scene.add(head);
      tag(short(tn,15), V3(x,4.05,0), {size:24,border:on?P.accent:P.line});
      for (let r=0;r<4;r++){ const hit = on && r === row; const cell = box(2,.5,.9, hit ? P.alert : P.panel, {opacity: hit ? 1 : .75}); cell.position.set(x,2.7-r*.65,0); scene.add(cell);
        if (hit){ glow(cell,P.alert); const l = tag(short(s.technique||"técnica",30), V3(x,2.7-r*.65,1.4), {mono:true,border:P.alert,size:28});
          anims.push(t => { const z = reduce ? .6 : .35 + .3*Math.sin(t*2); cell.position.z = z; l.position.z = z + 1; }); } } });
    if (s.note) tag(short(s.note,46), V3(0,-.1,1.6), {bg:false,color:P.muted,size:26});
    frame([0,3,Math.max(9,n*2.2)],[0,2.2,0]);
  };

  B.pipeline = (s,P) => {
    scene.add(floor(P));
    const st = (s.stages||[]).slice(0,6), n = st.length || 1, gap = 2.6, x0 = -(n-1)*gap/2, hi = s.highlight, stop = typeof s.stop === "number" ? s.stop : null;
    st.forEach((name,i) => { const on = i === hi, c = on ? P.accent : i === stop ? P.alert : P.info;
      const m = i%2 ? new THREE.Mesh(new THREE.CylinderGeometry(.62,.62,1,28), mat(c)) : box(1.2,1,1.2,c); m.position.set(x0+i*gap,.6,0); if (on || i===stop) glow(m,c); scene.add(m);
      tag(short(name,20), V3(x0+i*gap,1.75+(i%2)*.55,0), {mono:true,border:on?P.accent:i===stop?P.alert:P.line,size:28}); });
    if (n > 1){ const rail = box((n-1)*gap,.06,.06,P.muted); rail.position.set(0,.6,0); scene.add(rail);
      const endF = stop != null ? stop/(n-1) : 1;
      for (let k=0;k<4;k++){ const pk = box(.26,.26,.26,P.accent,{emissive:P.accent,ei:.8}); scene.add(pk);
        anims.push(t => { const f = (reduce ? (k+.5)/4 : ((t*.2)+k/4)%1) * endF; pk.position.set(x0+f*(n-1)*gap, .6 + .7, 0); pk.rotation.set(t,t,0);
          const blocked = stop != null && f >= endF - .03; pk.material.color.set(blocked ? P.alert : P.accent); pk.material.emissive.set(blocked ? P.alert : P.accent); }); } }
    if (s.packet) tag(short(s.packet,40), V3(0,-.1,1.4), {bg:false,color:P.muted,size:26});
    frame([0,3.4,Math.max(8.5,n*2.2)],[0,1,0]);
  };

  B.compare = (s,P) => {
    scene.add(floor(P));
    ["left","right"].forEach((side,i) => { const d = s[side] || {}, c = d.good ? P.ok : P.alert, x = i ? 2.75 : -2.75;
      const m = card(short(d.title||"",30), (d.lines||[]).slice(0,5).map(l => short(l,40)), c, 4.7); m.position.set(x, m.userData.h/2+.75, 0); m.rotation.y = i ? -.16 : .16; scene.add(m);
      const ped = box(3,.45,1.2,c); ped.position.set(x,.22,0); scene.add(ped);
      const sym = new THREE.Group();
      if (d.good){ const a = box(.2,.55,.2,c,{emissive:c,ei:.6}); a.position.set(-.2,-.08,0); a.rotation.z = .8; const b = box(.2,1.05,.2,c,{emissive:c,ei:.6}); b.position.set(.2,.14,0); b.rotation.z = -.6; sym.add(a,b); }
      else { const a = box(.2,1.1,.2,c,{emissive:c,ei:.6}); a.rotation.z = .785; const b = box(.2,1.1,.2,c,{emissive:c,ei:.6}); b.rotation.z = -.785; sym.add(a,b); }
      sym.position.set(x, m.userData.h+1.55, 0); scene.add(sym); anims.push(t => { sym.rotation.y = reduce ? 0 : t*1.2; }); });
    if (s.verdict) tag(short(s.verdict,48), V3(0,-.1,1.7), {size:28,border:P.accent});
    frame([0,2.8,10.5],[0,1.9,0]);
  };

  B.terminal = (s,P) => {
    scene.add(floor(P));
    const lines = (s.lines||[]).slice(0,7).map(l => short(l,58)), W = 1100, lh = 70, head = 90, H = head + Math.max(4,lines.length)*lh + 36;
    const c = document.createElement("canvas"); c.width = W; c.height = H; const g = c.getContext("2d"); const tex = new THREE.CanvasTexture(c);
    const total = lines.reduce((a,l) => a + l.length, 0);
    function draw(nc){ g.fillStyle = "#0d1117"; g.fillRect(0,0,W,H); g.fillStyle = "#1f2a36"; g.fillRect(0,0,W,head-20);
      ["#ff5f56","#ffbd2e","#27c93f"].forEach((cc,i) => { g.fillStyle = cc; g.beginPath(); g.arc(40+i*36,35,11,0,7); g.fill(); });
      g.fillStyle = "#9fb0c2"; g.font = '500 30px "JetBrains Mono",Consolas,monospace'; g.textBaseline = "middle"; g.fillText(short(s.title||"Terminal",44),160,36);
      let left = nc; g.font = '400 32px "JetBrains Mono",Consolas,monospace';
      lines.forEach((l,i) => { if (left <= 0) return; const show = l.slice(0,left); left -= l.length; const y = head + i*lh + lh/2;
        if (i === s.highlight){ g.fillStyle = "rgba(46,170,180,.28)"; g.fillRect(18,y-lh/2+6,W-36,lh-12); }
        g.fillStyle = i === s.highlight ? "#5fe0ea" : /^(PS |\$ |# |> |C:\\|┌|└)/.test(l) ? "#ffd479" : "#d6e2ee"; g.fillText(show,34,y); });
      tex.needsUpdate = true; }
    const w = 7.6, h = w*H/W;
    const bez = box(w+.4,h+.4,.3,"#222b36"); bez.position.set(0,h/2+.7,-.17); scene.add(bez);
    const scr = new THREE.Mesh(new THREE.PlaneGeometry(w,h), new THREE.MeshBasicMaterial({map:tex})); scr.position.set(0,h/2+.7,0); scene.add(scr);
    const stn = box(.6,.5,.4,"#222b36"); stn.position.set(0,.25,-.17); scene.add(stn);
    let last = -1; draw(reduce ? total : 0);
    anims.push(t => { if (reduce) return; const k = Math.min(total, Math.floor((t*40) % (total + 80))); if (k !== last){ last = k; draw(k); } });
    frame([1.2,h/2+1.1,9.6],[0,h/2+.7,0]);
  };

  B.sieve = (s,P) => {
    scene.add(floor(P));
    const items = (s.items||[]).slice(0,5), n = items.length || 1, keep = new Set(s.keep||[]), gy = 2.4;
    const grid = new THREE.Mesh(new THREE.BoxGeometry(7,.12,2.6), mat(P.accent,{opacity:.35})); grid.position.y = gy; scene.add(grid);
    for (let i=-3;i<=3;i++){ const b = box(.05,.14,2.6,P.accent); b.position.set(i,gy,0); scene.add(b); }
    tag(short(s.rule||"filtro",30), V3(-5.3,gy,0), {mono:true,border:P.accent});
    const bin = box(3,.4,2,P.noise,{opacity:.6}); bin.position.set(-1.9,.2,0); scene.add(bin); tag(short(s.dropLabel||"descartado",20), V3(-1.9,-.1,1.5), {bg:false,color:P.muted,size:24});
    const out = box(3,.4,2,P.alert,{opacity:.85}); out.position.set(1.9,.2,0); scene.add(out); tag(short(s.keepLabel||"vira alerta",20), V3(1.9,-.1,1.5), {bg:false,color:P.muted,size:24});
    const step = 1.1, T = n*step + 1.6;
    items.forEach((it,i) => { const k = keep.has(i), c = k ? P.alert : P.noise, x = -2.8 + i*(5.6/Math.max(1,n-1));
      tag(short(it,22), V3(x, 4.6 + (i%2)*.5, 0), {size:24,mono:true,border:c});
      const m = box(.45,.45,.45,c,{emissive:k?c:"#000000",ei:k?.5:0}); scene.add(m);
      const xe = (k ? 1.9 : -1.9) + ((i%3)-1)*.7;
      anims.push(t => { const f = reduce ? 1 : Math.min(1, Math.max(0, ((t % T) - i*step*.6)/1.6));
        const y = 4.4 - f*3.75, below = y < gy ? Math.min(1,(gy - y)/1.2) : 0; m.position.set(x + (xe - x)*below, y, 0); m.rotation.y = t; }); });
    frame([0,3.8,11],[0,2.5,0]);
  };

  B.layers = (s,P) => {
    scene.add(floor(P));
    const it = (s.items||[]).slice(0,6), n = it.length, R = RAINBOW(P);
    it.forEach((x,i) => { const on = i === s.highlight, w = 5 - i*.55, c = on ? P.accent : R[i%6];
      const m = box(w,.55,w*.6,c,{opacity:on?1:.72}); m.position.y = .3 + i*.64; if (on) glow(m,c); scene.add(m);
      tag(short(x,30), V3(w/2+2.2, .3+i*.64, 0), {size:28,border:c});
      if (on) anims.push(t => { m.position.x = reduce ? .4 : .4 + .15*Math.sin(t*2); }); });
    if (s.title) tag(short(s.title,34), V3(0,1+n*.64,0), {size:30,border:P.accent});
    frame([2.2,2.2+n*.3,9.5],[1.2,n*.32,0]);
  };

  B.steps = (s,P) => {
    scene.add(floor(P));
    const it = (s.items||[]).slice(0,6), n = it.length || 1, gap = 2.1, x0 = -(n-1)*gap/2, dots = [];
    it.forEach((x,i) => { const h = .4 + i*.4, on = i === s.highlight;
      const m = box(1.8,h,1.4,on?P.accent:P.panel); m.position.set(x0+i*gap,h/2,0); if (on) glow(m,P.accent); scene.add(m);
      tag(`${i+1}. ${short(x,22)}`, V3(x0+i*gap, h+.75+(i%2)*.6, 0), {size:26,border:on?P.accent:P.line});
      const d = new THREE.Mesh(new THREE.SphereGeometry(.2,16,16), mat(P.ok,{emissive:P.ok,ei:.7})); d.position.set(x0+i*gap,h+.22,.45); scene.add(d); dots.push(d); });
    const T = n*.8 + 1.6;
    anims.push(t => { const tt = reduce ? T : t % T; dots.forEach((d,i) => d.scale.setScalar(tt > i*.8 ? 1 : .01)); });
    if (s.title) tag(short(s.title,36), V3(0,-.1,1.6), {bg:false,color:P.muted,size:26});
    frame([0,3.3,Math.max(9,n*2.1)],[0,1.5,0]);
  };

  B.cycle = (s,P) => {
    scene.add(floor(P));
    const it = (s.items||[]).slice(0,7), n = it.length || 1, R = 3.2;
    const ring = new THREE.Mesh(new THREE.TorusGeometry(R,.05,8,96), mat(P.muted)); ring.rotation.x = Math.PI/2; ring.position.y = .5; scene.add(ring);
    it.forEach((x,i) => { const a = i/n*Math.PI*2 + Math.PI/2, on = i === s.highlight, c = on ? P.accent : P.info, p = V3(Math.cos(a)*R,.5,Math.sin(a)*R);
      const m = new THREE.Mesh(new THREE.CylinderGeometry(.5,.5,.5,32), mat(c)); m.position.copy(p); if (on) glow(m,c); scene.add(m);
      tag(`${i+1}. ${short(x,20)}`, p.clone().add(V3(0,1,0)), {size:26,border:on?P.accent:P.line}); });
    const dot = new THREE.Mesh(new THREE.SphereGeometry(.2,16,16), mat(P.accent,{emissive:P.accent,ei:.9})); scene.add(dot);
    anims.push(t => { const a = (reduce ? 0 : t*.6) + Math.PI/2; dot.position.set(Math.cos(a)*R,.85,Math.sin(a)*R); });
    if (s.title) tag(short(s.title,30), V3(0,1.3,0), {size:30,border:P.accent});
    frame([0,7,8.5],[0,.6,0]);
  };

  B.scale = (s,P) => {
    scene.add(floor(P));
    const post = box(.25,2.7,.25,P.muted); post.position.y = 1.35; scene.add(post);
    const beam = new THREE.Group(); beam.position.y = 2.75; scene.add(beam);
    beam.add(box(6.4,.15,.25,P.muted));
    const dir = s.heavier === "left" ? 1 : s.heavier === "right" ? -1 : 0, pans = [];
    [[-3.1,s.left,dir>0],[3.1,s.right,dir<0]].forEach(([x,txt,heavy]) => { const pan = new THREE.Group(), c = heavy ? P.alert : P.ok;
      const plate = new THREE.Mesh(new THREE.CylinderGeometry(1,1,.12,32), mat(c)); plate.position.y = -1.4; pan.add(plate);
      const sz = heavy ? .95 : .5, wt = box(sz,sz,sz,c); wt.position.y = -1.34 + sz/2; pan.add(wt);
      const l = label(short(txt||"",28),{size:28,border:c}); l.position.set(0,-2.3,.9); pan.add(l);
      pan.position.x = x; beam.add(pan); pans.push(pan); });
    if (s.title) tag(short(s.title,40), V3(0,4.3,0), {size:30,border:P.accent});
    anims.push(t => { const a = dir*.17*(reduce ? 1 : Math.min(1,t/1.2)*(.9+.1*Math.sin(t*1.6))); beam.rotation.z = a; pans.forEach(p => p.rotation.z = -a); });
    frame([0,2.8,9.5],[0,1.8,0]);
  };

  B.defang = (s,P) => {
    scene.add(floor(P));
    const top = card("Original · clicável", [short(s.before||"",40)], P.alert, 6.4); top.position.set(0, 3.6, 0); scene.add(top);
    const bot = card("Defang · seguro para colar", [short(s.after||"",40)], P.ok, 6.4); bot.position.set(0, 1.2, 0); scene.add(bot);
    const cone = new THREE.Mesh(new THREE.ConeGeometry(.28,.6,20), mat(P.accent,{emissive:P.accent,ei:.6})); cone.rotation.z = Math.PI; scene.add(cone);
    (s.changes||[]).slice(0,3).forEach((ch,i) => tag(short(ch,20), V3(4.8, 3.4 - i*.8, 0), {mono:true,size:26,border:P.accent}));
    anims.push(t => { cone.position.set(0, 2.45 + (reduce ? 0 : .12*Math.sin(t*3)), .2); bot.rotation.x = reduce ? 0 : Math.max(0, 1.4 - (t % 5)*1.6); });
    frame([1.2,2.6,9.5],[1,2.3,0]);
  };

  function resize(){
    const r = stage.getBoundingClientRect(); const w = Math.max(1, r.width|0), h = Math.max(1, r.height|0);
    renderer.setSize(w,h,false); camera.aspect = w/h; camera.updateProjectionMatrix();
  }
  new ResizeObserver(resize).observe(stage);
  new IntersectionObserver(es => { visible = es[0].isIntersecting; }).observe(stage);
  const clock = new THREE.Clock();
  (function loop(){ requestAnimationFrame(loop); if (!visible) return; const t = clock.getElapsedTime(); anims.forEach(f => f(t)); controls.update(); renderer.render(scene,camera); })();

  const TITLES = { network:"A rede do laboratório", timeline:"Linha do tempo", processTree:"Árvore de processos", ruleTree:"Árvore de regras do Wazuh",
    emailPath:"Caminho do e-mail", decode:"Decodificação", url:"Anatomia da URL", funnel:"Funil da triagem", fields:"Campos do log", shields:"Autenticação do e-mail",
    hash:"Hash e integridade", envelope:"Camadas do e-mail", bruteforce:"Tentativas de senha", threshold:"Limite de frequência", gauge:"Nível de severidade", mitre:"MITRE ATT&CK",
    pipeline:"Caminho do evento", compare:"Comparação", terminal:"Terminal", sieve:"Filtro de eventos", layers:"Camadas", steps:"Passo a passo", cycle:"Ciclo", scale:"Pesando evidências", defang:"Defang de IOC" };
  function build(sc){
    const P = fresh(); controls.autoRotate = false;
    const fn = B[sc && sc.type] || B.network;
    try { fn(sc || {}, P); } catch(e){ fresh(); B.network({}, pal()); }
    $("#vizTitle").textContent = "Ilustração 3D · " + (TITLES[sc && sc.type] || "Laboratório");
    clock.start();
  }
  return {
    show(q){ current = q; veil.hidden = true; build(q.scene); const cap = $("#vizCap"); if (cap){ cap.hidden = false;
      cap.innerHTML = `A ilustração mostra a resposta certa (<b>${"ABCD"[q.answer]}</b>): ${rich(q.options[q.answer])}.${q.scene && typeof q.scene.highlight === "number" ? " O item destacado é o ponto-chave." : ""}`; } },
    idle(msg){ current = null; veil.hidden = false; if ($("#vizCap")) $("#vizCap").hidden = true; veil.textContent = msg; build({type:"network"}); $("#vizTitle").textContent = "Ilustração 3D"; },
    retheme(){ if (current) build(current.scene); else build({type:"network"}); }
  };
})();
const mq = matchMedia("(prefers-color-scheme: dark)");
(mq.addEventListener ? mq.addEventListener("change", () => Viz.retheme()) : null);
new MutationObserver(() => Viz.retheme()).observe(document.documentElement, { attributes:true, attributeFilter:["data-theme"] });

buildList(); renderAll();
})();
