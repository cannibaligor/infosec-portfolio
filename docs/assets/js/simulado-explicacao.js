/* ===================== Explicação dinâmica (teoria + por que cada alternativa) ===================== */
(function(){
"use strict";
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const rich = s => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
const L = "ABCD";

/* --- teoria fixa: conceitos casados por palavra-chave --- */
const T = [
 [/\.eml|cabeçalho|header/i, "Cabeçalhos de e-mail", "Todo e-mail carrega cabeçalhos técnicos (Received, From, Return-Path, Authentication-Results) que o leitor esconde. Salvar como .eml preserva a mensagem inteira em texto puro, para ler sem clicar em nada."],
 [/received|salto/i, "Cadeia Received", "Cada servidor que repassa a mensagem acrescenta um Received no topo. Lendo de baixo para cima você vai do remetente até a caixa da vítima; o último da lista é o primeiro salto."],
 [/spf|dkim|dmarc|autentica/i, "SPF, DKIM e DMARC", "SPF diz quais IPs podem enviar pelo domínio; DKIM é a assinatura digital do domínio; DMARC junta os dois e diz o que fazer quando falham. Os três provam só quem enviou, não se o domínio é honesto. Resultados: pass, fail, softfail, none."],
 [/\bscl\b|spam/i, "SCL da Microsoft", "Spam Confidence Level vai de -1 a 9. Quanto maior, mais certeza de spam; 5 ou mais costuma ir para o Lixo Eletrônico, 9 é spam de alta confiança."],
 [/@|userinfo|rfc 3986|url/i, "Anatomia da URL", "Formato: esquema://usuário:senha@host:porta/caminho. Tudo antes do @ é userinfo e não escolhe o destino. O host real fica entre o @ e a primeira barra."],
 [/defang|ioc|indicador/i, "IOCs", "Indicadores de comprometimento são dados técnicos que permitem detectar e bloquear a ameaça: IPs, domínios, URLs, remetentes, hashes. Em relatórios, ficam com defang (hxxp, [.]) para ninguém clicar sem querer."],
 [/hash|sha-?256|integridade/i, "Hash e cadeia de custódia", "Hash é a impressão digital de um arquivo: muda inteiro se um byte mudar. Serve para provar integridade da evidência. Não é criptografia: não esconde nada."],
 [/cloud run|run\.app|serverless|google cloud|vps|vultr/i, "Infraestrutura do atacante", "Golpistas alugam VPS descartáveis para enviar e usam nuvens confiáveis para hospedar páginas: herdam reputação e HTTPS automático. Em serverless o IP é compartilhado, então o bloqueio eficaz é por URL ou domínio."],
 [/gatilho|engenharia social|urgência|medo|autoridade/i, "Engenharia social", "Golpes exploram emoções para a vítima agir sem pensar: medo (perder algo), urgência (prazo curto), autoridade (órgão oficial). Reconhecer o gatilho é a primeira defesa."],
 [/mitre|att&ck|\bT1\d{3}/i, "MITRE ATT&CK", "Catálogo de táticas (o objetivo, como Initial Access) e técnicas (o como, como T1566.002). Mapear um incidente nele padroniza a comunicação entre equipes."],
 [/virustotal|abuseipdb|reputação|safe browsing/i, "Reputação e inteligência", "Serviços de reputação somam o que outros já viram. Detecções independentes são evidência forte; ausência de detecção não é aprovação, porque infraestrutura nova ainda não tem histórico."],
 [/cert\.br|denúncia|abuse/i, "Notificação de abuso", "Cada indicador vai para quem controla o recurso: o IP para o provedor dono do bloco, a URL para quem pode bloqueá-la nos navegadores, a campanha para o CERT.br."],
 [/playbook|purge|conten|escopo/i, "Resposta a incidente", "Ordem prática: medir o escopo, conter (bloquear, purge), investigar o impacto (logs de proxy e DNS), notificar e conscientizar. Logs são evidência: preserve, nunca apague."],
 [/4625|substatus|0xc0/i, "Evento 4625", "Falha de logon no Windows. O status 0xC000006D é a falha genérica; o subStatus traz o motivo: 0xC000006A senha errada, 0xC0000064 usuário inexistente, 0xC0000234 conta bloqueada."],
 [/4624|logontype|logon type|tipo de logon/i, "Evento 4624 e logonType", "Logon bem-sucedido. O logonType diz como: 2 interativo, 3 rede (SMB), 5 serviço, 10 RDP. O tipo e o IP de origem separam rotina de ataque."],
 [/60204|correla|frequency/i, "Correlação no SIEM", "Uma regra de frequência junta eventos parecidos numa janela de tempo. Uma falha é normal; oito em segundos, da mesma origem, vira um alerta mais grave (a 60204)."],
 [/92652|pass-the-hash|ntlm/i, "Rótulo da regra x contexto", "A descrição da regra é um palpite genérico. O analista confere os campos e a sequência dos eventos antes de aceitar o rótulo."],
 [/active response|bloque/i, "Active Response", "O Wazuh pode executar uma ação quando uma regra dispara, como bloquear o IP de origem. Sem resposta, o alerta só documenta o ataque."],
 [/brute force|netexec|nxc|smb|senha/i, "Brute force", "Testar muitas senhas até acertar (T1110). Sinais: rajada de 4625 da mesma origem, depois um 4624. Defesas: bloqueio de conta, MFA, senha forte e resposta automática."],
 [/4104|script ?block/i, "Script Block Logging (4104)", "Registra o código do PowerShell já decodificado, logo antes de executar. Por isso o Base64 não esconde o conteúdo dele."],
 [/encodedcommand|-enc|base64|utf-16/i, "-EncodedCommand", "O PowerShell aceita o comando em Base64 de texto UTF-16LE. Não é proteção: qualquer um decodifica. Atacantes usam para driblar filtros simples e olhos humanos (T1027)."],
 [/sysmon|eid|parentimage|processo pai/i, "Sysmon", "Ferramenta da Microsoft que registra detalhes que o Windows não guarda: EID 1 criação de processo (com pai e commandLine), 3 rede, 11 arquivo, 13 registro."],
 [/92057/i, "Regra 92057", "Detecta PowerShell criando outro PowerShell com comando em Base64 (nível 12). Olha o comportamento, não o conteúdo."],
 [/100210|100211|tuning|level ?0|nível 0|if_sid/i, "Regras próprias e tuning", "if_sid cria uma regra filha que só é avaliada quando a mãe casa. Nível 0 processa sem alertar: serve para silenciar ruído exato sem desligar a coleta."],
 [/ossec\.conf|localfile|agente|canal/i, "Coleta do agente Wazuh", "O agente só lê os canais listados em blocos localfile do ossec.conf. Log novo no Windows não chega ao SIEM até ser incluído e o serviço reiniciado."],
 [/\bpid\b|parentprocessid/i, "Correlação por PID", "PID e parentProcessId ligam eventos de fontes diferentes (Sysmon, 4104) na mesma história de processos."],
 [/falso positivo|falso negativo|\bfp\b/i, "Falso positivo e negativo", "Falso positivo: alerta sem ataque real. Falso negativo: ataque sem alerta, o mais perigoso. O analista confirma com contexto antes de decidir."],
 [/nível|level|severidade/i, "Nível do alerta", "No Wazuh vai de 0 a 15. Ajuda a priorizar a fila, mas não decide sozinho: um nível 15 pode ser falso positivo e um nível 6 pode ser a conta comprometida."],
 [/escala|n2|n1|ticket|relatório/i, "Papel do N1", "Triar, investigar o básico, documentar com evidências e escalar o que exige ação maior. Escrever 'provável' quando falta confirmação é honesto e ajuda quem continua o caso."],
 [/utc|timestamp|horário|fuso/i, "Horário dos eventos", "systemTime é quando aconteceu no Windows; @timestamp é quando foi indexado. Painéis convertem para o fuso local. Monte linhas do tempo sempre no mesmo fuso."],
 [/fodhelper|uac|ms-settings/i, "Bypass de UAC", "Alguns binários do Windows elevam sozinhos. O truque com o FodHelper depende de alterar a chave ms-settings; sem essa alteração, o evento tende a ser uso legítimo."],
 [/indexer|dashboard|manager|wazuh/i, "Componentes do Wazuh", "O agente coleta no endpoint, o manager aplica decoders e regras, o indexer guarda os alertas e o dashboard mostra tudo."]
];
const TOPIC_FALLBACK = { phishing:[4], smb:[13], powershell:[20], soc:[27] };
function theory(q){
  const hay = q.q + " " + q.options[q.answer] + " " + q.why;
  const hits = []; T.forEach((t, i) => { if (hits.length < 2 && t[0].test(hay)) hits.push(i); });
  if (!hits.length) (TOPIC_FALLBACK[q.topic] || [27]).forEach(i => hits.push(i));
  return hits.map(i => T[i]);
}

/* --- cache local das explicações do Claude --- */
const AKEY = "simulado-soc-n1-ai-v1";
let cache = {}; try { cache = JSON.parse(localStorage.getItem(AKEY) || "{}") || {}; } catch(e) { cache = {}; }
const saveCache = () => { try { localStorage.setItem(AKEY, JSON.stringify(cache)); } catch(e) {} };

let samplerP = null;
function sampler(){
  if (!samplerP) samplerP = (window.claude && typeof claude.use === "function") ? claude.use("sample").catch(() => null) : Promise.resolve(null);
  return samplerP;
}
let disabled = false; const inflight = {};
function prompt(q){
  const opts = q.options.map((o, i) => `${L[i]}) ${o}`).join("\n");
  return `Você é instrutor de analistas SOC nível 1. Explique a questão de simulado abaixo para um iniciante, em português do Brasil, com frases curtas e simples.
Use só o que está na questão, nas alternativas e na explicação oficial, mais conhecimento técnico geral e correto. Não invente fatos sobre o laboratório ou o caso. Dentro dos textos, nunca cite as letras das alternativas (A, B, C, D): fale do conteúdo delas, porque a ordem pode mudar na tela.

QUESTÃO: ${q.q}
ALTERNATIVAS:
${opts}
CORRETA: ${L[q.answer]}
EXPLICAÇÃO OFICIAL: ${q.why}

Responda só com um objeto JSON neste formato:
{"teoria":"2 a 4 frases com o conceito técnico por trás da questão","certa":"1 a 3 frases: por que ${L[q.answer]} está certa","erradas":{${q.options.map((o,i)=>i===q.answer?null:`"${L[i]}":"1 a 2 frases: o erro de raciocínio ou o fato errado nesta alternativa"`).filter(Boolean).join(",")}},"lembrete":"uma frase curta para memorizar"}`;
}
function fetchAI(q){
  if (cache[q.id]) return Promise.resolve(cache[q.id]);
  if (inflight[q.id]) return inflight[q.id];
  inflight[q.id] = sampler().then(s => {
    if (!s) throw { code:"not_granted" };
    return s.json(prompt(q), { modelTier:"quick", cache:{ gcTime:86400000 } });
  }).then(r => {
    if (!r || typeof r !== "object" || !r.erradas) throw { code:"invalid_json" };
    const clean = { teoria:String(r.teoria || ""), certa:String(r.certa || ""), lembrete:String(r.lembrete || ""), erradas:{} };
    Object.keys(r.erradas).forEach(k => { if (/^[ABCD]$/.test(k)) clean.erradas[k] = String(r.erradas[k] || ""); });
    cache[q.id] = clean; saveCache(); return clean;
  }).finally(() => { delete inflight[q.id]; });
  return inflight[q.id];
}

/* --- render --- */
function render(el, q, pick, opt = {}){
  const ord = opt.order || [0,1,2,3], D = x => L[ord.indexOf(x)];   // letra exibida da alternativa original x
  const ok = pick === q.answer, th = theory(q);
  const alts = ord.map((o, i) => {
    const cls = o === q.answer ? "right" : o === pick ? "mine" : "";
    const tag = o === q.answer ? "certa" : o === pick ? "sua resposta" : "";
    return `<li class="${cls}" data-o="${o}"><span class="k">${L[i]}</span><div><div class="atext">${rich(q.options[o])}${tag ? ` <em class="atag">${tag}</em>` : ""}</div>
      <div class="areason">${o === q.answer ? "Correta: veja acima." : ""}</div></div></li>`;
  }).join("");
  const wrong = !ok && pick != null;
  el.innerHTML = `<div class="xp">
    <div class="verdict"><span class="pill ${ok ? "ok" : "bad"}">${ok ? "Correta" : "Incorreta"}</span><span>${ok ? `Isso mesmo: ${D(q.answer)}.` : pick == null ? `Tempo esgotado. A certa é ${D(q.answer)}.` : `Você marcou ${D(pick)}. A certa é ${D(q.answer)}.`}</span></div>
    <section class="xs"><h4>Teoria</h4>${th.map(t => `<p><b>${esc(t[1])}.</b> ${esc(t[2])}</p>`).join("")}<p class="xai-teoria" hidden></p></section>
    <section class="xs xs-ok"><h4>Por que a ${D(q.answer)} está certa</h4><p>${rich(q.why)}</p><p class="xai-certa" hidden></p></section>
    ${wrong ? `<section class="xs xs-bad"><h4>Por que a ${D(pick)} está errada</h4><p class="xmine">${rich(q.options[pick])}</p><p class="xai-mine sub2">Gerando a explicação…</p></section>` : ""}
    <section class="xs xs-alts" hidden><h4>Por que cada alternativa</h4><ol class="alts">${alts}</ol></section>
    <p class="xai-lembrete" hidden></p>
    <div class="xai-bar"><span class="sub2 xai-status"></span><button class="btn ghost xai-btn" type="button" hidden>${wrong ? "Explicar meu erro com Claude" : "Explicar as alternativas com Claude"}</button></div>
  </div>`;
  const status = el.querySelector(".xai-status"), btn = el.querySelector(".xai-btn"), mine = el.querySelector(".xai-mine");
  function fill(r){
    if (!el.isConnected) return;
    const set = (sel, html) => { const p = el.querySelector(sel); if (p && html){ p.innerHTML = html; p.hidden = false; } };
    set(".xai-teoria", `<b>Em resumo:</b> ${esc(r.teoria)}`);
    set(".xai-certa", esc(r.certa));
    if (mine){ mine.textContent = r.erradas[L[pick]] || "Sem explicação para esta alternativa."; mine.classList.remove("sub2"); }
    el.querySelectorAll(".alts li").forEach(li => { const o = +li.dataset.o; if (o !== q.answer && r.erradas[L[o]]) li.querySelector(".areason").textContent = r.erradas[L[o]]; });
    // a lista só aparece quando traz explicação nova; sem ela, repetiria as alternativas já mostradas acima
    if (Object.keys(r.erradas).length) el.querySelector(".xs-alts").hidden = false;
    set(".xai-lembrete", `<b>Para lembrar:</b> ${esc(r.lembrete)}`);
    status.textContent = "Explicação das alternativas gerada pelo Claude."; btn.hidden = true;
  }
  function off(){
    status.textContent = ""; btn.hidden = true;
    if (mine){ mine.textContent = "Compare com a explicação da certa acima: o que a sua alternativa afirma não se sustenta diante desse fato."; mine.classList.remove("sub2"); }
    el.querySelectorAll(".alts li:not(.right) .areason").forEach(a => { a.textContent = ""; });
  }
  function fail(e){
    if (!el.isConnected) return;
    const code = e && e.code;
    if (["not_granted","sampling_disabled","not_declared","capability_disabled","capability_removed"].includes(code)){ disabled = true; return off(); }
    status.textContent = code === "rate_limited" ? "Muitos pedidos agora; tente de novo em instantes." : "Não foi possível gerar a explicação agora.";
    btn.textContent = "Tentar de novo"; btn.hidden = false;
    if (mine) mine.textContent = "Explicação indisponível no momento.";
  }
  function go(){ btn.hidden = true; status.textContent = "Gerando a explicação das alternativas…"; if (mine){ mine.textContent = "Gerando a explicação…"; mine.classList.add("sub2"); } fetchAI(q).then(fill, fail); }
  btn.onclick = go;
  if (cache[q.id]) fill(cache[q.id]);
  else if (disabled) off();
  else if (opt.auto && wrong) go();
  else {
    if (mine) mine.textContent = "Use o botão abaixo para ver por que ela está errada.";
    sampler().then(s => { if (!el.isConnected) return; if (s) btn.hidden = false; else { disabled = true; off(); } });
  }
}
window.SOCExplain = { render };
})();
