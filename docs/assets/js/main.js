import { esc, L, hms, loadEvents } from './common.js';

const $ = s => document.querySelector(s);

/* ---------------- language ---------------- */
const root = document.documentElement;
function setLang(l) {
  root.dataset.lang = l;
  root.lang = l === 'pt' ? 'pt-BR' : 'en';
  try { localStorage.setItem('lang', l); } catch {}
}
let saved = null;
try { saved = localStorage.getItem('lang'); } catch {}
setLang(saved || (navigator.language?.toLowerCase().startsWith('pt') ? 'pt' : 'en'));
$('#langBtn').onclick = () => setLang(root.dataset.lang === 'pt' ? 'en' : 'pt');

/* ---------------- dialogs ---------------- */
for (const d of document.querySelectorAll('dialog')) {
  d.querySelector('.close').onclick = () => d.close();
  d.addEventListener('click', e => { if (e.target === d) d.close(); });
}
const lb = $('#lightbox');
document.querySelectorAll('.gallery figure').forEach(f => {
  f.tabIndex = 0;
  const open = () => {
    const img = f.querySelector('img');
    lb.querySelector('img').src = img.src;
    lb.querySelector('img').alt = img.alt;
    lb.querySelector('.cap').innerHTML = f.querySelector('figcaption').innerHTML;
    lb.showModal();
  };
  f.onclick = open;
  f.onkeydown = e => { if (e.key === 'Enter') open(); };
});

const jm = $('#jsonModal');
function highlight(json) {
  const re = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let out = '', last = 0;
  for (const m of json.matchAll(re)) {
    out += esc(json.slice(last, m.index));
    if (m[1]) out += m[2] ? `<span class="j-k">${esc(m[1])}</span>${m[2]}` : `<span class="j-s">${esc(m[1])}</span>`;
    else out += `<span class="j-n">${esc(m[0])}</span>`;
    last = m.index + m[0].length;
  }
  return out + esc(json.slice(last));
}
export function openJson(src) {
  $('#jmTitle').textContent = `rule ${src.rule?.id} · ${hms(src.timestamp, true)} UTC`;
  $('#jmBody').innerHTML = highlight(JSON.stringify(src, null, 2));
  jm.showModal();
  jm.scrollTop = 0;
}

/* ---------------- URL dissector ---------------- */
const URL_PARTS = {
  scheme: L('<b>Protocolo</b> (com "hxxp" no lugar de "http" para o link não ficar clicável: isso se chama <i>defang</i>).', '<b>Scheme</b> (with "hxxp" instead of "http" so the link is not clickable: this is called <i>defanging</i>).'),
  userinfo: L('<b>Isca.</b> Pela RFC 3986, tudo antes do <code>@</code> é "usuário:senha" e o navegador <b>ignora</b> para decidir o destino. Está aí só para a vítima ler "office.com" e confiar.', '<b>Bait.</b> Per RFC 3986, everything before the <code>@</code> is "user:password", and the browser <b>ignores</b> it when deciding where to go. It is only there so the victim reads "office.com" and trusts it.'),
  at: L('<b>O truque.</b> O <code>@</code> separa a isca do destino real. Regra de detecção sugerida: alertar URLs que batem com <code>https?://[^/]*@</code>.', '<b>The trick.</b> The <code>@</code> separates the bait from the real destination. Suggested detection rule: alert on URLs matching <code>https?://[^/]*@</code>.'),
  host: L('<b>Destino real</b>: um app no Google Cloud Run (<code>run.app</code>), região São Paulo. Domínio de boa reputação, HTTPS válido e descartável em minutos.', '<b>Real destination</b>: an app on Google Cloud Run (<code>run.app</code>), São Paulo region. Good-reputation domain, valid HTTPS, disposable in minutes.'),
};
const ux = $('#urlExplain');
if (ux) document.querySelectorAll('.u-part').forEach(p => {
  const on = () => {
    document.querySelectorAll('.u-part').forEach(x => x.classList.toggle('on', x === p));
    ux.innerHTML = `<p>${URL_PARTS[p.dataset.p]}</p>`;
  };
  p.addEventListener('mouseenter', on);
  p.addEventListener('click', on);
});

/* ---------------- logs table ---------------- */
function buildLogs(events) {
  const tbody = $('#logTable tbody');
  let filter = 'all', q = '';
  const render = () => {
    const rows = events.filter(ev =>
      (filter === 'all' || (filter === 'attack' ? ev.attack : !ev.attack)) &&
      (!q || JSON.stringify(ev.src).toLowerCase().includes(q)));
    tbody.innerHTML = rows.map(ev => {
      const s = ev.src, e = s.data?.win?.eventdata ?? {}, lv = +s.rule?.level;
      const cls = lv >= 10 ? 'hi' : lv >= 5 ? 'mid' : 'lo';
      return `<tr data-i="${events.indexOf(ev)}">
        <td>${esc(hms(s.timestamp, true))}</td><td>${esc(s.rule?.id)}</td>
        <td><span class="lvl ${cls}">${esc(lv)}</span></td><td>${esc(s.data?.win?.system?.eventID ?? '')}</td>
        <td>${esc(e.targetUserName ?? '')}</td><td>${esc(e.ipAddress ?? '')}</td><td>${esc(s.rule?.description)}</td></tr>`;
    }).join('') || `<tr><td colspan="7">${L('Nenhum resultado.', 'No results.')}</td></tr>`;
  };
  tbody.addEventListener('click', e => {
    const tr = e.target.closest('tr[data-i]');
    if (tr) openJson(events[+tr.dataset.i].src);
  });
  $('#logFilters').addEventListener('click', e => {
    const b = e.target.closest('button[data-f]');
    if (!b) return;
    filter = b.dataset.f;
    $('#logFilters').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
    render();
  });
  $('#logSearch').addEventListener('input', e => { q = e.target.value.trim().toLowerCase(); render(); });
  render();
}

/* ---------------- 3D ---------------- */
function fallback(wrap) {
  wrap.insertAdjacentHTML('beforeend', `<div class="fallback">${L('Seu navegador não conseguiu carregar o 3D (WebGL). O conteúdo ao lado e abaixo continua completo.', 'Your browser could not load 3D (WebGL). The content beside and below is still complete.')}</div>`);
}

async function boot() {
  let events = [];
  // Só carrega os logs nas páginas que usam (Home Lab).
  if ($('#logTable') || $('#replayWrap')) {
    try {
      events = await loadEvents();
      if ($('#logTable')) buildLogs(events);
    } catch (err) {
      if ($('#logTable')) $('#logTable tbody').innerHTML = `<tr><td colspan="7">${L('Não foi possível carregar os logs.', 'Could not load the logs.')}</td></tr>`;
      console.error(err);
    }
  }

  // Nenhuma cena 3D nesta página: nem carrega o motor 3D.
  if (!['#heroCanvas', '#archWrap', '#replayWrap', '#mailWrap'].some(s => $(s))) return;

  let S, ok = false;
  try {
    const eng = await import('./engine3d.js');
    ok = eng.webglOK();
    if (ok) S = await import('./scenes.js');
  } catch (err) { console.error(err); ok = false; }

  if (!ok) {
    ['#archWrap', '#replayWrap', '#mailWrap'].forEach(s => { if ($(s)) fallback($(s)); });
    $('#heroCanvas')?.remove();
    return;
  }
  const safe = (fn, wrapSel) => { try { fn(); } catch (e) { console.error(e); if (wrapSel) fallback($(wrapSel)); } };
  if ($('#heroCanvas')) safe(() => S.heroScene($('#heroCanvas')));
  if ($('#archWrap')) safe(() => S.archScene($('#archWrap'), $('#archCanvas'), $('#archInfo')), '#archWrap');
  if ($('#replayWrap') && events.length) safe(() => S.replayScene({
    wrap: $('#replayWrap'), canvas: $('#replayCanvas'), events, openJson,
    ui: {
      play: $('#btnPlay'), prev: $('#btnPrev'), next: $('#btnNext'), speed: $('#speed'), scrub: $('#scrub'),
      step: $('#stepLabel'), detail: $('#eventDetail'), timeline: $('#timeline'),
      clock: $('#hudClock'), status: $('#hudStatus'), banner: $('#banner'),
    },
  }), '#replayWrap');
  if ($('#mailWrap')) safe(() => S.mailScene($('#mailWrap'), $('#mailCanvas'), $('#mailInfo')), '#mailWrap');
}
boot();
