// Shared helpers: language, theme colors, escaping, event classification.

export const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Bilingual inline HTML (both languages rendered; CSS hides the inactive one). Only for trusted, author-written strings. */
export function L(pt, en) {
  return `<span data-l="pt">${pt}</span><span data-l="en">${en}</span>`;
}

export function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function themeColors() {
  return {
    ink: cssVar('--ink'), muted: cssVar('--muted'), line: cssVar('--line'), surface: cssVar('--surface'),
    surface2: cssVar('--surface-2'), accent: cssVar('--accent'), danger: cssVar('--danger'), ok: cssVar('--ok'),
    warn: cssVar('--warn'), recon: cssVar('--recon'), noise: cssVar('--noise'),
  };
}

export function utc(ts) {
  // "2026-11-14T05:56:39.976+0000" -> Date
  return new Date(String(ts).replace(/\+0000$/, 'Z'));
}
export function hms(ts, ms = false) {
  const d = utc(ts);
  const s = d.toISOString().slice(11, ms ? 23 : 19);
  return s;
}

let dataPromise;
export function loadEvents() {
  dataPromise ??= fetch('assets/data/cenario1.json')
    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(list => list
      .map(src => ({ src, ...classify(src) }))
      .sort((a, b) => utc(a.src.timestamp) - utc(b.src.timestamp)));
  return dataPromise;
}

const ANON = /AN[ÔO]NIMO|ANONYMOUS/i;

/** Classify a Wazuh alert into a replay "kind" and produce a human explanation. */
export function classify(s) {
  const id = String(s.rule?.id);
  const e = s.data?.win?.eventdata ?? {};
  const user = e.targetUserName ?? '';
  const ip = e.ipAddress ?? '';
  let kind = 'noise', attack = false, title, text;

  if (id === '92652' && ANON.test(user)) {
    kind = 'recon'; attack = true;
    title = L('Reconhecimento: login anônimo', 'Reconnaissance: anonymous logon');
    text = L(
      `O Kali (${esc(ip)}) abre uma <b>null session</b>: um login sem usuário nem senha, via NTLM V1. É a ferramenta <code>NetExec</code> sondando o SMB (nome da máquina, versão, se aceita conexões) <b>antes</b> de testar senhas. A regra chama de "pass-the-hash", mas é só enumeração.`,
      `Kali (${esc(ip)}) opens a <b>null session</b>: a logon with no user and no password, over NTLM V1. That is <code>NetExec</code> probing SMB (host name, version, whether it accepts connections) <b>before</b> trying passwords. The rule calls it "pass-the-hash", but it is only enumeration.`);
  } else if (id === '60122') {
    kind = 'fail'; attack = true;
    title = L('Falha de login (4625)', 'Failed logon (4625)');
    text = L(
      `Tentativa de senha <b>errada</b> para <code>${esc(user)}</code>, vinda de ${esc(ip)} pela rede (<code>logonType 3</code>). O <code>subStatus 0xC000006A</code> diz que o <b>usuário existe</b> e só a senha está errada. Sozinho, é nível 5: acontece todo dia quando alguém erra a senha.`,
      `A <b>wrong</b> password for <code>${esc(user)}</code> from ${esc(ip)} over the network (<code>logonType 3</code>). <code>subStatus 0xC000006A</code> means the <b>user exists</b> and only the password is wrong. On its own it is level 5: it happens every day when someone mistypes.`);
  } else if (id === '60204') {
    kind = 'alert'; attack = true;
    title = L('🚨 Alerta correlacionado: brute force (T1110)', '🚨 Correlated alert: brute force (T1110)');
    text = L(
      `O Wazuh percebeu <b>8 falhas</b> da mesma origem em pouco tempo (<code>rule.frequency: 8</code>) e subiu o nível de 5 para <b>10</b>. Isso é <b>correlação</b>: vários eventos fracos viram um alerta forte. Mesmo assim, nada bloqueou o atacante.`,
      `Wazuh saw <b>8 failures</b> from the same source in a short window (<code>rule.frequency: 8</code>) and raised the level from 5 to <b>10</b>. That is <b>correlation</b>: several weak events become one strong alert. Even so, nothing blocked the attacker.`);
  } else if (id === '92652') {
    kind = 'success'; attack = true;
    title = L('✅ Login com SUCESSO: conta comprometida', '✅ SUCCESSFUL logon: account compromised');
    text = L(
      `O mesmo IP (${esc(ip)}) entra na conta <code>${esc(user)}</code> com NTLM V2, 2 s depois da última falha. A senha foi descoberta. <b>Várias falhas → um sucesso</b> é o padrão que transforma "tentativa" em <b>incidente</b>. (A regra fala em pass-the-hash, mas aqui foi a senha.)`,
      `The same IP (${esc(ip)}) logs on as <code>${esc(user)}</code> with NTLM V2, 2 s after the last failure. The password was guessed. <b>Many failures → one success</b> is the pattern that turns an "attempt" into an <b>incident</b>. (The rule mentions pass-the-hash, but this was the password.)`);
  } else if (id === '60137') {
    kind = 'logoff'; attack = !!ip || ANON.test(user) || user === 'joao.teste';
    title = L('Logoff (4634)', 'Logoff (4634)');
    text = L(
      `A sessão de <code>${esc(user)}</code> foi encerrada logo após abrir. A ferramenta só <b>validou</b> a credencial e saiu. Um atacante real voltaria depois com a senha.`,
      `The <code>${esc(user)}</code> session closed right after opening. The tool only <b>validated</b> the credential and left. A real attacker would come back later with the password.`);
  } else if (id === '60106') {
    title = L('Ruído: logon do SISTEMA', 'Noise: SYSTEM logon');
    text = L(
      `Logon da conta <code>${esc(user)}</code> com <code>logonType 5</code> (serviço), iniciado pelo <code>services.exe</code>. É o Windows iniciando um serviço, <b>não o atacante</b>: falso positivo descartado.`,
      `A logon by <code>${esc(user)}</code> with <code>logonType 5</code> (service), started by <code>services.exe</code>. That is Windows starting a service, <b>not the attacker</b>: false positive ruled out.`);
  } else if (id === '61104') {
    title = L('Ruído: tipo de inicialização de serviço alterado', 'Noise: service start type changed');
    text = L(
      'Evento 7040: o Windows mudou o modo de inicialização de um serviço (atividade normal de atualização/manutenção). Sem relação com o ataque.',
      'Event 7040: Windows changed a service start mode (normal update/maintenance activity). Unrelated to the attack.');
  } else {
    title = esc(s.rule?.description ?? id);
    text = '';
  }
  return { kind, attack, title, text };
}

export const KIND_COLOR = { recon: 'recon', fail: 'danger', alert: 'warn', success: 'ok', logoff: 'noise', noise: 'noise' };
