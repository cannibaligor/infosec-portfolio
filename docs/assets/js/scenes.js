import { THREE, createStage, makeNode, link, packet, ring, shake } from './engine3d.js';
import { L, esc, hms, utc, themeColors, reducedMotion, KIND_COLOR } from './common.js';

const LAB_POS = { kali: [-4.2, 0, 1.6], win: [3.4, 0, 1.6], wazuh: [0, 0, -3.2] };

function labNodes(stage, onPick) {
  const c = stage.colors;
  const kali = makeNode(stage, { pos: LAB_POS.kali, color: c.danger, shape: 'ico', label: 'SOC-Kali', sub: '10.0.10.30', onPick: () => onPick?.('kali') });
  const win = makeNode(stage, { pos: LAB_POS.win, color: c.accent, shape: 'tower', label: 'SOC-Win11', sub: '10.0.10.20 · Sysmon', onPick: () => onPick?.('win') });
  const wazuh = makeNode(stage, { pos: LAB_POS.wazuh, color: c.ok, shape: 'cyl', label: 'SOC-Wazuh', sub: '10.0.10.10 · SIEM', onPick: () => onPick?.('wazuh') });
  const atk = link(stage, kali, win, { color: c.muted, opacity: 0.5 });
  const logs = link(stage, win, wazuh, { color: c.accent, opacity: 0.55 });
  link(stage, kali, wazuh, { color: c.line, opacity: 0.5 });
  return { kali, win, wazuh, atk, logs };
}

/* ------------------------------------------------------------------ HERO */
export function heroScene(canvas) {
  const c = themeColors();
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
  camera.position.set(0, 0, 14);
  const group = new THREE.Group();
  scene.add(group);

  const N = 90, R = 5.2, pts = [];
  for (let i = 0; i < N; i++) {
    const y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), th = Math.PI * (3 - Math.sqrt(5)) * i;
    pts.push(new THREE.Vector3(Math.cos(th) * r * R, y * R, Math.sin(th) * r * R));
  }
  const dotGeo = new THREE.SphereGeometry(0.06, 8, 8);
  const muted = new THREE.MeshBasicMaterial({ color: new THREE.Color(c.muted) });
  const accent = new THREE.MeshBasicMaterial({ color: new THREE.Color(c.accent) });
  const danger = new THREE.MeshBasicMaterial({ color: new THREE.Color(c.danger) });
  pts.forEach((p, i) => {
    const m = new THREE.Mesh(dotGeo, i % 17 === 0 ? danger : i % 7 === 0 ? accent : muted);
    m.position.copy(p);
    if (m.material !== muted) m.scale.setScalar(1.8);
    group.add(m);
  });
  const seg = [];
  for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) if (pts[i].distanceTo(pts[j]) < 2.25) seg.push(pts[i], pts[j]);
  group.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(seg),
    new THREE.LineBasicMaterial({ color: new THREE.Color(c.muted), transparent: true, opacity: 0.22 })));

  // travelling "packets" on random edges
  const pk = [];
  for (let k = 0; k < 6; k++) {
    const m = new THREE.Mesh(new THREE.SphereGeometry(0.09, 10, 10), k === 0 ? danger : accent);
    group.add(m);
    pk.push({ m, i: 0, t: Math.random() });
  }
  const pickEdge = o => { o.i = Math.floor(Math.random() * (seg.length / 2)) * 2; o.t = 0; };
  pk.forEach(pickEdge);

  let mx = 0, my = 0, visible = true;
  window.addEventListener('pointermove', e => { mx = e.clientX / innerWidth - 0.5; my = e.clientY / innerHeight - 0.5; });
  new IntersectionObserver(([en]) => (visible = en.isIntersecting)).observe(canvas);

  function resize() {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    group.position.x = w > 900 ? 5.6 : 0;
    group.scale.setScalar(w > 900 ? 0.9 : 0.75);
    canvas.style.opacity = w > 900 ? '' : '0.35';
  }
  new ResizeObserver(resize).observe(canvas);
  resize();

  const clock = new THREE.Clock();
  renderer.setAnimationLoop(() => {
    if (!visible) return;
    const dt = Math.min(clock.getDelta(), 0.05);
    if (!reducedMotion) {
      group.rotation.y += dt * 0.08;
      group.rotation.x += ((my * 0.4) - group.rotation.x) * 0.03;
      group.rotation.z += ((mx * 0.2) - group.rotation.z) * 0.03;
      for (const o of pk) {
        o.t += dt * 0.9;
        if (o.t >= 1) pickEdge(o);
        o.m.position.lerpVectors(seg[o.i], seg[o.i + 1], o.t);
      }
    }
    renderer.render(scene, camera);
  });
}

/* ------------------------------------------------------------ ARCHITECTURE */
export function archScene(wrap, canvas, panel) {
  const stage = createStage(wrap, canvas, { camPos: [0, 7, 11.5] });
  const show = key => {
    panel.querySelectorAll('.node-info').forEach(n => (n.hidden = n.dataset.node !== key));
    for (const [k, n] of Object.entries(nodes)) if (n.el) n.el.style.outline = k === key ? `2px solid ${n.color}` : '';
  };
  const lab = labNodes(stage, show);
  const nodes = { kali: lab.kali, win: lab.win, wazuh: lab.wazuh };

  // idle: logs constantly flowing from the endpoint to the SIEM
  if (!reducedMotion) {
    let t = 0;
    stage.addTick(dt => {
      t += dt;
      if (t > 1.4) { t = 0; packet(stage, lab.logs.curve, { color: stage.colors.accent, size: 0.08, duration: 1.3 }); }
    });
  }
}

/* ----------------------------------------------------------------- REPLAY */
export function replayScene({ wrap, canvas, events, ui, openJson }) {
  const stage = createStage(wrap, canvas, { camPos: [0, 6.4, 10.5], target: [0, 0, -0.4], autoRotate: false });
  const c = stage.colors;
  const lab = labNodes(stage);
  const back = arcBack(lab);
  const N = events.length;
  let idx = 0, playing = false, timer = null, speed = 1;

  ui.scrub.max = N;
  buildTimeline();

  function arcBack(l) { return link(stage, l.win, l.kali, { color: c.line, opacity: 0 }); }

  function colorOf(kind) { return c[KIND_COLOR[kind]] || c.muted; }

  function setVisualState(k) {
    const upto = events.slice(0, k);
    const compromised = upto.some(e => e.kind === 'success');
    const alerting = upto.some(e => e.kind === 'alert');
    lab.win.setColor(compromised ? c.danger : c.accent);
    lab.win.el.classList.toggle('compromised', compromised);
    lab.wazuh.setColor(alerting ? c.warn : c.ok);
    lab.wazuh.el.classList.toggle('alerting', alerting);
    ui.status.className = 'hud-status' + (compromised ? ' danger' : '');
    ui.status.innerHTML = compromised ? L('joao.teste COMPROMETIDA', 'joao.teste COMPROMISED') : '';
    ui.clock.textContent = (k ? hms(events[k - 1].src.timestamp, true) : hms(events[0].src.timestamp)) + ' UTC';
  }

  async function animate(ev) {
    const col = colorOf(ev.kind);
    const shipLog = () => packet(stage, lab.logs.curve, { color: c.accent, size: 0.09, duration: 0.7 });
    const fromAttacker = ['recon', 'fail', 'alert', 'success'].includes(ev.kind);
    if (fromAttacker) {
      await packet(stage, lab.atk.curve, { color: col, size: ev.kind === 'success' ? 0.2 : 0.14, duration: 0.75 });
      if (ev.kind === 'fail' || ev.kind === 'alert') {
        shake(stage, lab.win);
        packet(stage, back.curve, { color: col, size: 0.07, duration: 0.6 });
      }
      ring(stage, lab.win.pos, { color: col, to: ev.kind === 'success' ? 3.4 : 2.2 });
    } else {
      ring(stage, lab.win.pos, { color: col, to: 1.8, duration: 0.8 });
    }
    await shipLog();
    if (ev.kind === 'alert') {
      ring(stage, lab.wazuh.pos, { color: c.warn, to: 3.6, duration: 1.3 });
      setTimeout(() => ring(stage, lab.wazuh.pos, { color: c.warn, to: 3.6, duration: 1.3 }), 350);
    }
  }

  function banner(ev) {
    clearTimeout(banner.t);
    if (ev.kind !== 'alert' && ev.kind !== 'success') { ui.banner.hidden = true; return; }
    ui.banner.className = 'banner' + (ev.kind === 'success' ? ' ok' : '');
    ui.banner.innerHTML = ev.kind === 'alert'
      ? L('🚨 Wazuh: "Multiple Windows Logon Failures", nível 10 (T1110)', '🚨 Wazuh: "Multiple Windows Logon Failures", level 10 (T1110)')
      : L('⚠️ Login aceito: a senha de joao.teste foi descoberta', '⚠️ Logon accepted: joao.teste password was guessed');
    ui.banner.hidden = false;
    banner.t = setTimeout(() => (ui.banner.hidden = true), 3800);
  }

  function detail(ev) {
    if (!ev) { ui.detail.innerHTML = `<p class="muted-t">${L('Nenhum evento selecionado ainda. Aperte ▶ para começar.', 'No event selected yet. Press ▶ to start.')}</p>`; return; }
    const s = ev.src, e = s.data?.win?.eventdata ?? {}, sys = s.data?.win?.system ?? {};
    const rows = [
      ['rule.id', s.rule?.id], ['rule.level', s.rule?.level], ['eventID', sys.eventID],
      ['targetUserName', e.targetUserName], ['ipAddress', e.ipAddress], ['logonType', e.logonType],
      ['subStatus', e.subStatus], ['mitre', (s.rule?.mitre?.id || []).join(', ')],
    ].filter(([, v]) => v !== undefined && v !== '');
    ui.detail.innerHTML = `
      <span class="ts">${esc(hms(s.timestamp, true))} UTC · ${ev.attack ? L('atacante', 'attacker') : L('ruído', 'noise')}</span>
      <h4><i class="dot ${ev.kind === 'logoff' ? 'noise' : ev.kind}"></i> ${ev.title}</h4>
      <p>${ev.text}</p>
      <dl class="kvs">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <button type="button" class="linkbtn" data-json>${L('Ver log original (JSON) →', 'View original log (JSON) →')}</button>`;
    ui.detail.querySelector('[data-json]').onclick = () => openJson(s);
  }

  function buildTimeline() {
    ui.timeline.innerHTML = events.map((ev, i) => `
      <li data-i="${i}" class="future"><i class="dot ${ev.kind === 'logoff' ? 'noise' : ev.kind}"></i>
        <span><span class="t">${esc(hms(ev.src.timestamp))} · ${esc(ev.src.rule?.id)}</span>${ev.title}</span></li>`).join('');
    ui.timeline.addEventListener('click', e => {
      const li = e.target.closest('li[data-i]');
      if (!li) return;
      pause();
      go(+li.dataset.i + 1, true);
    });
  }

  function markTimeline(k) {
    ui.timeline.querySelectorAll('li').forEach((li, i) => {
      li.classList.toggle('future', i >= k);
      li.classList.toggle('current', i === k - 1);
    });
  }

  /** Move to state k (k events applied). Animates the k-th event. */
  function go(k, animateIt = true) {
    idx = Math.max(0, Math.min(N, k));
    setVisualState(idx);
    ui.scrub.value = idx;
    ui.step.textContent = `${idx} / ${N}`;
    markTimeline(idx);
    const ev = events[idx - 1];
    detail(ev);
    if (ev && animateIt) { animate(ev); banner(ev); } else ui.banner.hidden = true;
  }

  function gapAfter(i) {
    if (i >= N - 1) return 0;
    const real = (utc(events[i + 1].src.timestamp) - utc(events[i].src.timestamp)) / 1000;
    return Math.max(0.55, Math.min(real, 2.4)) * 1000 + 450;
  }

  function tick() {
    if (!playing) return;
    if (idx >= N) { pause(); return; }
    go(idx + 1);
    timer = setTimeout(tick, gapAfter(idx - 1) / speed);
  }
  function play() {
    if (idx >= N) go(0, false);
    playing = true;
    ui.play.textContent = '❚❚';
    tick();
  }
  function pause() {
    playing = false;
    clearTimeout(timer);
    ui.play.textContent = '▶';
  }

  ui.play.onclick = () => (playing ? pause() : play());
  ui.prev.onclick = () => { pause(); go(idx - 1); };
  ui.next.onclick = () => { pause(); go(idx + 1); };
  ui.scrub.oninput = () => { pause(); go(+ui.scrub.value); };
  ui.speed.onchange = () => (speed = +ui.speed.value);

  // start playing once the replay scrolls into view (first time only)
  let started = false;
  new IntersectionObserver(([en]) => {
    if (en.isIntersecting && !started && !reducedMotion) { started = true; setTimeout(play, 600); }
  }, { threshold: 0.5 }).observe(wrap);

  go(0, false);
}

/* --------------------------------------------------------------- PHISHING */
const HOPS = [
  { key: 'vps', label: 'VPS Vultr', sub: '66[.]42[.]69[.]62', color: 'danger', shape: 'ico',
    h: 'Received: from [127.0.1.1] (66.42.69.62)',
    pt: 'Origem real do e-mail: um <b>VPS alugado na Vultr</b> (EUA). O servidor se apresenta como <code>[127.0.1.1]</code> (localhost), sinal de script de envio em massa num servidor mal configurado. O AbuseIPDB não tinha nenhuma denúncia: IP "descartável".',
    en: 'The real origin: a <b>rented Vultr VPS</b> (USA). The server introduces itself as <code>[127.0.1.1]</code> (localhost), a sign of a bulk-mailing script on a sloppy server. AbuseIPDB had no reports: a "throwaway" IP.' },
  { key: 'eop', label: 'Microsoft EOP', sub: 'mail.protection.outlook.com', color: 'warn', shape: 'box',
    h: 'Authentication-Results: spf=none; dkim=none; dmarc=none',
    pt: 'O gateway da Microsoft recebe o e-mail e verifica a autenticação. <b>SPF, DKIM e DMARC = none</b>: o remetente <code>infracao@detran659532</code> nem tem domínio de verdade (falta o <code>.gov.br</code>). Resultado: <b>SCL 9</b>, a nota máxima de spam.',
    en: 'Microsoft\'s gateway receives the email and checks authentication. <b>SPF, DKIM and DMARC = none</b>: the sender <code>infracao@detran659532</code> does not even have a real domain (no <code>.gov.br</code>). Result: <b>SCL 9</b>, the highest spam score.' },
  { key: 'o365', label: 'Exchange Online', sub: 'outlook.office365.com', color: 'muted', shape: 'box',
    h: 'Received: by PA7P264CA0523.outlook.office365.com',
    pt: 'Roteamento interno da Microsoft. Os cabeçalhos <code>Received</code> são lidos <b>de baixo para cima</b>: cada servidor adiciona o seu no topo.',
    en: 'Internal Microsoft routing. <code>Received</code> headers are read <b>bottom to top</b>: each server adds its own on top.' },
  { key: 'lam', label: 'Exchange (LATAM)', sub: 'lamprd80.prod.outlook.com', color: 'muted', shape: 'box',
    h: 'Received: by RO2PR80MB6676.lamprd80.prod.outlook.com',
    pt: 'Servidor da região América Latina, mais perto da caixa de destino. A entrega toda levou ~6 segundos.',
    en: 'Latin America region server, close to the destination mailbox. The whole delivery took ~6 seconds.' },
  { key: 'box', label: L('Caixa de entrada', 'Mailbox'), sub: L('→ Lixo Eletrônico', '→ Junk folder'), color: 'ok', shape: 'tower',
    h: 'X-Microsoft-Antispam-Mailbox-Delivery: RF:JunkEmail',
    pt: 'O e-mail chegou, mas direto no <b>Lixo Eletrônico</b>. Nenhum link foi clicado: exportei o <code>.eml</code> e fiz a análise toda offline.',
    en: 'The email arrived, but straight into the <b>Junk folder</b>. No link was clicked: I exported the <code>.eml</code> and did the whole analysis offline.' },
  { key: 'run', label: 'Google Cloud Run', sub: L('destino do link (não clicado)', 'link target (not clicked)'), color: 'danger', shape: 'cloud',
    h: 'hxxps://www[.]office[.]com-…@dete3-489991573399[.]southamerica-east1[.]run[.]app',
    pt: 'O botão do e-mail aponta para um app no <b>Google Cloud Run</b> (São Paulo). O atacante usa o domínio <code>run.app</code> do Google para <b>herdar a reputação</b> e ganhar HTTPS automático. O texto <code>office.com</code> antes do <code>@</code> é só disfarce.',
    en: 'The email button points to an app on <b>Google Cloud Run</b> (São Paulo). The attacker uses Google\'s <code>run.app</code> domain to <b>borrow its reputation</b> and get automatic HTTPS. The <code>office.com</code> text before the <code>@</code> is just a disguise.' },
];

export function mailScene(wrap, canvas, panel) {
  const stage = createStage(wrap, canvas, { camPos: [0, 6.2, 13], target: [0.2, 0, -1.2], maxDist: 26 });
  const c = stage.colors;
  const n = 5;
  const show = i => {
    const h = HOPS[i];
    panel.innerHTML = `<span class="pill ${h.color === 'muted' ? '' : h.color}">${L('Salto', 'Hop')} ${i < n ? i + 1 : '↗'}</span>
      <h4>${h.label}</h4><p><code>${esc(h.h)}</code></p><p>${L(h.pt, h.en)}</p>`;
    nodes.forEach((nd, k) => (nd.el.style.outline = k === i ? `2px solid ${nd.color}` : ''));
  };
  const nodes = HOPS.map((h, i) => {
    const pos = i < n ? [-6.4 + i * 3.2, 0, Math.sin((i / (n - 1)) * Math.PI) * -3.2 + 1.4] : [6.6, 0.4, -3.6];
    const labelY = i < n ? (i % 2 ? 2.2 : 1.3) : 2.6;
    const sub = i === 2 || i === 3 ? '' : h.sub; // middle hops: details live in the side panel
    return makeNode(stage, { pos, color: c[h.color], shape: h.shape, label: h.label, sub, labelY, onPick: () => show(i) });
  });
  const segs = [];
  for (let i = 0; i < n - 1; i++) segs.push(link(stage, nodes[i], nodes[i + 1], { color: c.muted, opacity: 0.6, lift: 0.4 }));
  const bad = link(stage, nodes[4], nodes[5], { color: c.danger, opacity: 0.7, lift: 1 });
  show(0);

  // envelope loop
  async function loop() {
    for (const s of segs) await packet(stage, s.curve, { color: c.warn, size: 0.16, duration: 0.8 });
    ring(stage, nodes[4].pos, { color: c.ok });
    await new Promise(r => setTimeout(r, 400));
    await packet(stage, bad.curve, { color: c.danger, size: 0.08, duration: 1.2 });
    ring(stage, nodes[5].pos, { color: c.danger, to: 1.8 });
    setTimeout(loop, 1800);
  }
  if (!reducedMotion) loop();
}
