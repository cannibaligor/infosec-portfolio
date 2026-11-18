/* Passo a passo prático de cada questão do Simulado (escrito com apoio de IA).
   SOC_PASSOS.proc = procedimentos reutilizáveis; SOC_PASSOS.map = id da questão -> procedimentos.
   Texto entre crases vira <code>. Nomes de menus podem mudar conforme a versão do programa. */
window.SOC_PASSOS = {
proc: {

/* ===================== PHISHING ===================== */
eml: { t: "Salvar o e-mail como arquivo .eml (Outlook.com)", onde: "Navegador, outlook.live.com", s: [
  "Entre em `outlook.live.com` e abra a pasta onde o e-mail está (no caso, **Lixo Eletrônico**).",
  "Clique **uma vez** na mensagem para selecioná-la. Não clique em links, botões nem em \"Mostrar conteúdo bloqueado\".",
  "No canto superior direito da mensagem, clique nos **três pontos (…)**, que é o botão **Mais ações**.",
  "Clique em **Baixar** e depois em **Baixar como EML**. Em algumas versões o item se chama **Salvar como**.",
  "Atalho: na lista de mensagens, clique com o **botão direito** no e-mail → **Baixar** → **Baixar como EML**.",
  "O arquivo vai para a pasta **Downloads**. Renomeie para `amostra.eml` e mova para uma pasta do caso, por exemplo `C:\\casos\\phishing-detran\\`.",
  "Para ler: botão direito no arquivo → **Abrir com** → **Bloco de Notas**. Nunca dê duplo clique, porque isso abre no Outlook ou no Mail."
], dica: "Antes de mexer no arquivo, calcule o hash (próximo procedimento)." },

headers_view: { t: "Ver os cabeçalhos no próprio Outlook.com", onde: "Navegador, outlook.live.com", s: [
  "Selecione a mensagem com um clique.",
  "Clique nos **três pontos (…)** no canto superior direito da mensagem.",
  "Vá em **Exibir** → **Exibir detalhes da mensagem**.",
  "Abre uma janela com todos os cabeçalhos em texto. Clique dentro dela, aperte `Ctrl+A` e `Ctrl+C` para copiar.",
  "Cole num Bloco de Notas para analisar com calma."
] },

hash: { t: "Calcular o hash SHA-256 da evidência", onde: "PowerShell no Windows", s: [
  "Aperte a tecla **Windows**, digite `PowerShell` e aperte **Enter**.",
  "Vá até a pasta do arquivo: `cd C:\\casos\\phishing-detran`",
  "Rode: `Get-FileHash .\\amostra.eml -Algorithm SHA256`",
  "Copie o valor da coluna **Hash** (64 caracteres) e cole nas anotações do caso, junto com data, hora (UTC) e nome do arquivo.",
  "Para provar a integridade depois, rode o mesmo comando de novo: o hash precisa ser idêntico.",
  "Teste opcional: copie o arquivo, mude uma letra na cópia e calcule o hash dela. O hash muda inteiro."
] },

received: { t: "Ler os cabeçalhos Received de baixo para cima", onde: "Bloco de Notas com o .eml aberto", s: [
  "Abra o `amostra.eml` no **Bloco de Notas** (botão direito → Abrir com → Bloco de Notas).",
  "Aperte `Ctrl+F`, digite `Received:` e aperte **Enter** várias vezes até chegar na **última** ocorrência.",
  "Essa última linha Received é o **primeiro salto**: a máquina que enviou o e-mail.",
  "Leia o trecho `from … (IP)`: o que vem entre parênteses é o IP real visto pelo servidor que recebeu. No caso: `from [127.0.1.1] (66.42.69.62)`.",
  "Suba uma linha Received por vez e anote cada servidor (`from` → `by`) até chegar no topo, que é o servidor da sua caixa.",
  "Opcional: cole os cabeçalhos no **Message Header Analyzer** da Microsoft (pesquise o nome), que monta a lista de saltos em ordem.",
  "Antes de colar em qualquer site, apague seu próprio endereço de e-mail do texto."
] },

sender: { t: "Conferir remetente, Return-Path e Message-ID", onde: "Bloco de Notas com o .eml aberto", s: [
  "Com o .eml aberto, aperte `Ctrl+F` e procure `From:`. Veja o nome exibido e o endereço entre `< >`.",
  "Olhe o que vem depois do `@`: um domínio de verdade tem final, como `.gov.br` ou `.com`. No caso era só `detran659532`.",
  "Procure `Return-Path:` e compare com o From. Se forem diferentes, anote.",
  "Procure `Message-ID:` e veja o domínio depois do `@`. Ele costuma revelar o sistema que gerou o e-mail.",
  "Procure `To:` e veja se a mensagem chama você pelo nome ou só pelo e-mail.",
  "Anote tudo numa tabela: campo, valor e por que é suspeito."
] },

auth: { t: "Verificar SPF, DKIM e DMARC", onde: "Bloco de Notas + MXToolbox", s: [
  "No .eml aberto no Bloco de Notas, aperte `Ctrl+F` e procure `Authentication-Results`.",
  "Leia os três resultados: `spf=`, `dkim=` e `dmarc=`. Os valores possíveis são `pass`, `fail`, `none`, `softfail` etc.",
  "Lembre: `none` = não havia nada para verificar; `fail` = havia e não bateu; `pass` = o domínio citado realmente enviou.",
  "Para confirmar: copie os cabeçalhos (do começo do arquivo até a primeira linha em branco antes do corpo).",
  "Apague seu e-mail do texto copiado.",
  "Abra o **MXToolbox** → menu **Email Headers** (Email Header Analyzer), cole e clique em **Analyze Header**.",
  "Veja o quadro de autenticação. No caso, o e-mail reprovou nos 5 controles.",
  "Mesmo com tudo `pass`, confira o **domínio**: pass só prova que aquele domínio enviou, e ele pode ser do golpista."
] },

scl: { t: "Ler o veredito antispam da Microsoft (SCL)", onde: "Bloco de Notas com o .eml aberto", s: [
  "No .eml, aperte `Ctrl+F` e procure `SCL`.",
  "Ache `X-MS-Exchange-Organization-SCL:`. A escala vai de -1 a 9: 9 é spam de altíssima confiança.",
  "Procure também `JunkEmail` para ver o motivo da entrega no Lixo Eletrônico (`RF:JunkEmail`).",
  "Anote o valor no caso, mas continue a investigação: o filtro pode ter acertado com você e errado com outras pessoas."
] },

mime: { t: "Ver as partes MIME do corpo", onde: "Bloco de Notas + CyberChef", s: [
  "No .eml, aperte `Ctrl+F` e procure `Content-Type:`.",
  "Ache o `boundary=\"…\"` da parte `multipart/alternative`: é a \"linha divisória\" entre as partes.",
  "Ache cada parte: uma com `Content-Type: text/plain` e outra com `Content-Type: text/html`.",
  "Veja o `Content-Transfer-Encoding:` de cada parte. Se for `base64`, o texto está embaralhado.",
  "Copie só o bloco base64 da parte (sem o boundary) e cole no **CyberChef**, na caixa **Input**.",
  "Arraste a receita **From Base64** para a área **Recipe**. O texto decodificado aparece em **Output**. Ele é tratado como texto e nada é executado.",
  "Compare: a parte text/plain não tinha link, e a parte HTML tinha o botão do golpe."
] },

html_safe: { t: "Inspecionar o HTML sem renderizar", onde: "CyberChef ou script Python", s: [
  "Decodifique a parte `text/html` como no procedimento MIME, ou rode o `analisar_eml.py`.",
  "Copie o HTML decodificado para um Bloco de Notas. Nunca salve como .html nem abra no navegador.",
  "Com `Ctrl+F`, procure `<img`, `<script`, `<iframe`, `<form` e `href=`.",
  "Procure o texto do logo (por exemplo `gov`) e veja se ele é uma imagem (`<img`) ou letras em `<span style=\"color…\">`.",
  "Anote quantos links existem e para onde cada `href` aponta."
] },

python: { t: "Rodar o analisar_eml.py no .eml", onde: "PowerShell no Windows", s: [
  "Instale o Python pelo site oficial `python.org`. Na primeira tela do instalador, marque **Add python.exe to PATH**.",
  "Baixe o `analisar_eml.py` do repositório (pasta `01-phishing-analysis`) para a pasta do caso.",
  "Abra o PowerShell e vá até a pasta: `cd C:\\casos\\phishing-detran`",
  "Rode: `python analisar_eml.py \"amostra.eml\"`",
  "O script só lê texto: não abre navegador, não executa scripts, não baixa imagens e não acessa a internet.",
  "Confira cada saída com o arquivo original: hash, IP do primeiro Received, partes MIME, links e host real.",
  "Se algo não bater (como o número de versão `15.21.522.6` aparecendo como IP), corrija o script e rode de novo."
] },

url_at: { t: "Descobrir o host real de uma URL (truque do @)", onde: "Bloco de Notas ou aba Ferramentas", s: [
  "Copie a URL como **texto** (do script ou do código HTML). Não clique nela.",
  "Ache o `://`. A parte de autoridade vai do `://` até a **primeira** `/` depois dele.",
  "Dentro desse trecho, procure um `@`. Tudo o que vem **antes** do `@` é o userinfo (usuário e senha) e é ignorado.",
  "O host real é o que vem **depois** do último `@`, até a `/`, `:` ou `?`. No caso: `dete3-489991573399.southamerica-east1.run.app`.",
  "Confirme na aba **Ferramentas** deste site (analisador de URL), que separa cada parte com cores.",
  "Faça o defang do host antes de colar no relatório."
] },

defang: { t: "Fazer o defang de URLs e IPs", onde: "Bloco de Notas, aba Ferramentas ou CyberChef", s: [
  "Copie o IOC como texto.",
  "Troque `http` por `hxxp` (e `https` por `hxxps`).",
  "Troque cada `.` do domínio ou do IP por `[.]`. Exemplo: `66[.]42[.]69[.]62`.",
  "Atalho: no **CyberChef**, use a receita **Defang URL** (ou **Defang IP Addresses**).",
  "Use a versão com defang em tickets, relatórios, prints e chats. Use a versão original só dentro das ferramentas de análise."
] },

cloudrun: { t: "Identificar onde a página falsa está hospedada", onde: "Navegador (sem abrir o link)", s: [
  "Pegue o host real (procedimento do @) e leia o final dele: `run.app` é o domínio do **Google Cloud Run**.",
  "Leia a parte do meio: `southamerica-east1` é o nome de uma região do Google Cloud (São Paulo).",
  "No **urlscan.io**, cole a URL e rode o scan: o resultado mostra o IP, o ASN (dono da rede) e o país do servidor.",
  "Anote por que o golpista escolheu essa nuvem: reputação boa do domínio, HTTPS automático, perto da vítima, descartável."
] },

cert: { t: "Entender o cadeado (HTTPS) sem abrir o site", onde: "urlscan.io ou crt.sh", s: [
  "No resultado do **urlscan.io**, abra a aba de detalhes e veja o certificado TLS: emissor e validade.",
  "Ou pesquise o domínio no **crt.sh** para ver os certificados emitidos para ele.",
  "Lembre: o cadeado só prova que a conexão é criptografada e que o certificado vale para aquele domínio. Ele não diz se o dono é honesto."
] },

virustotal: { t: "Consultar a URL no VirusTotal", onde: "virustotal.com", s: [
  "Abra o **virustotal.com** e clique na aba **URL**.",
  "Cole a URL original (sem defang) e aperte **Enter**. O próprio VirusTotal acessa o site, não o seu computador.",
  "Leia o número no topo, por exemplo **11/93**: quantos fornecedores marcaram a URL como maliciosa.",
  "Na aba **Detection**, veja quem detectou e como (phishing, malware).",
  "Na aba **Details**, veja o código HTTP da última análise (ex.: `404`) e a data.",
  "Não envie o arquivo .eml para o VirusTotal: ele fica público e contém seu e-mail."
] },

urlscan: { t: "Rodar um scan no urlscan.io", onde: "urlscan.io", s: [
  "Abra o **urlscan.io** e cole a URL na caixa principal.",
  "Em **Options**, escolha a visibilidade **Unlisted** ou **Private**, para não expor o caso.",
  "Se a opção existir, escolha o país do scanner (para testar cloaking, um país do Brasil).",
  "Clique em **Public Scan** / **Scan** e espere o resultado.",
  "Veja o **screenshot**, o IP, o ASN, o país e as requisições. Sem captura e com 404, considere página removida ou cloaking."
] },

safebrowsing: { t: "Consultar e denunciar no Google Safe Browsing", onde: "Navegador", s: [
  "Pesquise **Google Transparency Report Safe Browsing** e abra a página de consulta de status de site.",
  "Cole a URL e veja o status. \"Sem dados\" significa que o Chrome **não** mostra aviso.",
  "Para denunciar, pesquise **Report phishing page Google Safe Browsing** e abra o formulário oficial.",
  "Cole a URL, escreva em uma linha o que a página imita (ex.: gov.br/DETRAN) e envie.",
  "Anote a data da denúncia no caso e consulte o status de novo dias depois."
] },

rdap: { t: "Descobrir o dono de um IP (RDAP/WHOIS)", onde: "search.arin.net ou rdap.org", s: [
  "Abra o `search.arin.net` (ou `rdap.org`).",
  "Digite o IP `66.42.69.62` e pesquise.",
  "Leia o campo **Organization**/**Name**: no caso, **Vultr Holdings** (aluguel de VPS, EUA).",
  "Procure o contato **Abuse** (e-mail de denúncia) e anote.",
  "Se o IP for de outro continente, o ARIN mostra para qual registro (RIPE, LACNIC, APNIC) ele pertence. Consulte lá."
] },

abuseipdb: { t: "Consultar e denunciar o IP no AbuseIPDB", onde: "abuseipdb.com", s: [
  "Abra o **abuseipdb.com**, cole o IP na caixa e clique em **Check**.",
  "Leia **Confidence of Abuse**, número de denúncias, **ISP** e **Usage Type** (ex.: Data Center).",
  "0 denúncias não é prova de segurança: VPS novo e descartável também aparece zerado.",
  "Para denunciar: faça login, clique em **Report IP**, marque as categorias **Phishing** e **Email Spam**.",
  "No comentário, cole só os cabeçalhos necessários, com seu e-mail e seus dados apagados. Clique em **Report**."
] },

report_ip: { t: "Denunciar o IP de envio ao provedor", onde: "E-mail ou formulário do provedor", s: [
  "Pegue o contato **Abuse** do IP na consulta RDAP (procedimento anterior).",
  "Prepare o texto: o que aconteceu, data/hora em UTC, IP e os cabeçalhos **completos**.",
  "Apague do texto seu endereço de e-mail e qualquer dado pessoal.",
  "Envie para o contato abuse (ou pelo formulário de abuse do provedor, no caso a Vultr).",
  "Denuncie também no **AbuseIPDB**, para que outros analistas vejam.",
  "Anote no caso: para quem, quando e o número do ticket, se houver."
] },

report_gcp: { t: "Denunciar uma página hospedada no Google Cloud", onde: "Formulário de abuse do Google Cloud", s: [
  "Pesquise **Report abuse Google Cloud Platform** e abra o formulário oficial do Google.",
  "Escolha o tipo **Phishing**.",
  "Coloque a **URL completa** do Cloud Run (`…run.app`). Não coloque só o IP: o IP é a borda compartilhada do Google.",
  "Não cite o IP de outro provedor (como o da Vultr) no texto: a triagem automática pode avaliar o IP errado.",
  "Envie e anote o número do caso. Se for encerrado automaticamente, denuncie a URL no **Safe Browsing**, que bloqueia por URL."
] },

report_cert: { t: "Notificar o CERT.br", onde: "E-mail", s: [
  "Crie um e-mail para `cert@cert.br`.",
  "No assunto, escreva algo como \"Notificação de phishing: falso DETRAN\".",
  "No corpo, coloque: data/hora (UTC), URL e IP com defang, e o resumo do golpe.",
  "Anexe os cabeçalhos completos, com seus dados pessoais apagados.",
  "Envie e guarde a resposta automática como comprovante."
] },

social: { t: "Mapear gatilhos e inconsistências do texto", onde: "Texto decodificado do e-mail", s: [
  "Pegue o texto do corpo já decodificado (script ou CyberChef). Não abra o e-mail no Outlook.",
  "Marque as frases de **autoridade** (ex.: \"NOTIFICAÇÃO OFICIAL\", logo gov.br).",
  "Marque as frases de **medo** (ex.: \"suspensão imediata da CNH\").",
  "Marque as frases de **urgência** (prazos curtos, \"regularize urgente\").",
  "Compare números e dados: protocolo do assunto x protocolo do corpo, órgão estadual x endereço federal.",
  "Veja a saudação (nome ou só e-mail?) e o horário de envio no cabeçalho `Date:`.",
  "Monte uma tabela: trecho, gatilho e por que é suspeito."
] },

iocs: { t: "Montar a lista de IOCs do caso", onde: "Planilha ou arquivo CSV", s: [
  "Abra uma planilha (ou o Bloco de Notas) com as colunas: tipo, valor (com defang), contexto, fonte.",
  "Liste o **IP** de envio, o **host/URL** do golpe, o **remetente** e o **hash** da amostra.",
  "Não liste o que não é indicador do atacante (ex.: servidores da Microsoft, seu próprio e-mail).",
  "Salve como `iocs.csv` e anexe ao caso."
] },

mitre: { t: "Mapear uma ação no MITRE ATT&CK", onde: "attack.mitre.org", s: [
  "Escreva a lista de ações do atacante, uma por linha (ex.: \"alugou VPS\", \"mandou link\", \"usou @ para enganar\").",
  "Abra o `attack.mitre.org` e use a caixa de busca (lupa) no topo.",
  "Pesquise pelo ID (ex.: `T1566.002`) ou por uma palavra (ex.: `brute force`).",
  "Na página da técnica, leia a descrição e, no quadro à direita, a **Tactic** (o objetivo).",
  "Confira se a descrição combina com a evidência. Se o rótulo automático do SIEM não combinar, não use.",
  "No relatório, escreva: ID, nome, tática e a evidência que justifica."
] },

phish_scope: { t: "Medir o escopo e fazer o purge (numa empresa)", onde: "Microsoft 365 / Exchange (exemplo)", s: [
  "No **Exchange admin center**, vá em **Mail flow** → **Message trace** e busque pelo remetente, pelo IP de envio e pelo assunto.",
  "Anote quantos destinatários receberam e em que pasta foi entregue (Caixa de Entrada ou Lixo).",
  "Faça o **purge**: remova a mensagem de todas as caixas (no Defender, **Explorer** → selecionar → **Take action** → **Soft/Hard delete**).",
  "Bloqueie o remetente e a URL/domínio na lista de bloqueio do gateway.",
  "Procure nos logs de **proxy/firewall** quem acessou o host do golpe.",
  "Avise os usuários e registre tudo no ticket. Os nomes de menus variam conforme a licença e a ferramenta da empresa."
] },

click_response: { t: "Resposta quando alguém clicou e digitou a senha", onde: "Empresa (playbook)", s: [
  "Confirme no log de proxy: usuário, horário e URL acessada.",
  "Escale para o N2 com as evidências.",
  "Resete a senha da conta e **encerre todas as sessões** (revogar tokens).",
  "Revise os logins da conta nos últimos dias: IPs, países e horários estranhos.",
  "Verifique se o MFA continua do usuário e se não foram criadas regras de encaminhamento na caixa.",
  "Bloqueie a URL no proxy e registre a linha do tempo no ticket."
] },

victim_govbr: { t: "Se a senha do gov.br foi digitada na página falsa", onde: "Outro dispositivo confiável", s: [
  "De um aparelho confiável, entre no `gov.br` e troque a senha na hora.",
  "Ative a **verificação em duas etapas** no app gov.br.",
  "Troque a senha de todo serviço que usava a mesma senha (principalmente o e-mail e o banco).",
  "Confira os dispositivos e acessos recentes da conta gov.br.",
  "Consulte o **Registrato** do Banco Central para ver contas e empréstimos no seu CPF."
] },

victim_pix: { t: "Se a falsa multa foi paga via Pix", onde: "Banco e polícia", s: [
  "Ligue para o seu banco **imediatamente** e peça a abertura do **MED** (Mecanismo Especial de Devolução do Pix).",
  "Guarde comprovante, chave Pix, horário e prints.",
  "Registre um **boletim de ocorrência** (a maioria dos estados aceita pela delegacia online).",
  "Informe o número do BO ao banco."
] },

regex_url: { t: "Testar a regra que pega URL com @", onde: "PowerShell", s: [
  "Abra o PowerShell.",
  "Teste uma URL com o truque: `'https://www.office.com@exemplo.test/x' -match 'https?://[^/]*@'` → deve dar `True`.",
  "Teste uma URL normal: `'https://exemplo.test/a@b' -match 'https?://[^/]*@'` → deve dar `False` (o @ está depois da barra).",
  "Se os dois testes derem certo, a regex pode virar regra no gateway de e-mail ou no SIEM."
] },

verdict: { t: "Escrever veredito e severidade", onde: "Ticket ou relatório", s: [
  "**Veredito** (o que é): verdadeiro positivo, falso positivo ou provável falso positivo.",
  "**Severidade** (o quanto importa): pense em alcance, se houve interação/sucesso e no impacto.",
  "Escreva 2 ou 3 evidências que sustentam o veredito.",
  "Escreva o que **não** foi possível confirmar (se houver). Isso separa \"confirmado\" de \"provável\".",
  "Feche com a ação tomada e a recomendação."
] },

interview: { t: "Montar a resposta de entrevista", onde: "Treino em voz alta", s: [
  "Comece com uma frase de **contexto**: qual caso e o que disparou.",
  "Cite **2 ou 3 evidências** concretas (IDs de evento, regra, IP, campo).",
  "Diga **como confirmou**: qual log ou qual consulta você olhou.",
  "Dê a **conclusão** (veredito) e a **recomendação**.",
  "Se usou IA, diga o que foi com IA e o que você executou e consegue explicar.",
  "Treine em voz alta até caber em uns 60 segundos."
] },

/* ===================== WINDOWS / BRUTE FORCE SMB ===================== */
evt_sec: { t: "Achar os eventos 4624, 4625 e 4634 no Visualizador de Eventos", onde: "Windows 11 do lab", s: [
  "Aperte `Windows+R`, digite `eventvwr.msc` e aperte **Enter**.",
  "Na esquerda, abra **Logs do Windows** → **Segurança**.",
  "Na direita, clique em **Filtrar Log Atual…**.",
  "No campo **<Todas as Identificações de Evento>**, digite `4624,4625,4634` e clique em **OK**.",
  "Dê duplo clique num evento. A aba **Geral** mostra o texto; a aba **Detalhes** → **Modo de Exibição XML** mostra os campos exatos.",
  "Anote: horário, conta (`TargetUserName`), IP de origem (`IpAddress`), tipo de logon e, nas falhas, o subStatus.",
  "No Wazuh, o mesmo filtro é `data.win.system.eventID:4625` (troque o número)."
] },

logontype: { t: "Ler o tipo de logon (logonType)", onde: "Evento 4624/4625", s: [
  "Abra um evento 4624 ou 4625 (procedimento anterior).",
  "Na aba **Geral**, ache **Tipo de Logon** (no XML: `LogonType`; no Wazuh: `data.win.eventdata.logonType`).",
  "Compare com a tabela: `2` = teclado da máquina, `3` = rede (SMB, compartilhamentos), `5` = serviço, `10` = Área de Trabalho Remota.",
  "Junte com a conta e o processo: logonType 5 da conta SISTEMA iniciado pelo `services.exe` é serviço normal do Windows."
] },

substatus: { t: "Ler o motivo da falha (Status e SubStatus)", onde: "Evento 4625", s: [
  "Abra um evento **4625**.",
  "Na aba **Geral**, desça até **Informações sobre falha**: Motivo, **Status** e **Substatus**.",
  "No Wazuh: `data.win.eventdata.status`, `data.win.eventdata.subStatus` e `data.win.eventdata.failureReason`.",
  "Compare: `0xC000006D` = falha genérica; `0xC000006A` = usuário existe e senha errada; `0xC0000064` = usuário não existe.",
  "`%%2313` no failureReason é o código do texto \"Nome de usuário desconhecido ou senha incorreta\".",
  "Se todas as falhas são 0xC000006A na mesma conta, o atacante já sabe um usuário válido."
] },

auth_pkg: { t: "Comparar o pacote de autenticação (NTLM)", onde: "Evento 4624", s: [
  "Abra o 4624 do login com sucesso.",
  "Desça até **Informações detalhadas de autenticação**.",
  "Leia **Pacote de Autenticação**, **Pacote (somente NTLM)** e **Comprimento da Chave**.",
  "No Wazuh: `data.win.eventdata.lmPackageName` e `data.win.eventdata.keyLength`.",
  "Compare com o 4624 anônimo da sondagem: NTLM V1 com chave 0 = sessão sem senha; NTLM V2 com chave 128 = autenticação real."
] },

anon: { t: "Achar logins anônimos (null session)", onde: "Wazuh, aba Events", s: [
  "No Wazuh, abra **Threat Hunting** → aba **Events**.",
  "Na busca, digite: `data.win.eventdata.targetUserName:\"ANONYMOUS LOGON\"` e aperte **Enter**.",
  "Ajuste o período (ícone de calendário) para a janela do ataque.",
  "Abra cada evento e veja o IP de origem e o horário.",
  "Coloque esses eventos na linha do tempo antes das falhas: é a fase de reconhecimento."
] },

nxc_recon: { t: "Reconhecimento SMB com o NetExec (só no lab)", onde: "Kali, terminal", s: [
  "Só faça isso contra as VMs do seu próprio laboratório.",
  "No Kali, abra o **Terminal**.",
  "Anote a hora: `date -u`",
  "Rode: `nxc smb 10.0.10.20`",
  "Leia a linha de resposta: nome da máquina, build do Windows, `domain:`, `signing:` e `SMBv1:`.",
  "`domain` igual ao nome da máquina = sem Active Directory (contas locais). `signing:True` barra relay. `SMBv1:None` = SMBv1 desligado."
] },

nxc_brute: { t: "Simular o brute force SMB (só no lab)", onde: "Kali, terminal", s: [
  "Confirme que o alvo é a VM do lab (`10.0.10.20`) e que existe um snapshot limpo para voltar.",
  "Crie a lista de senhas: `printf 'senha1\\nsenha2\\nVerao2026\\n' > senhas.txt`",
  "Anote a hora de início: `date -u`",
  "Rode: `nxc smb 10.0.10.20 -u joao.teste -p senhas.txt --local-auth`",
  "`--local-auth` = conta local da máquina, não de domínio. `[-]` = senha errada, `[+]` = senha certa.",
  "Anote a hora do fim (`date -u`) e vá conferir os eventos 4625/4624 no Windows e no Wazuh. O log é a prova, não a saída da ferramenta."
] },

port445: { t: "Conferir a porta 445 (SMB)", onde: "PowerShell", s: [
  "Do seu PC ou de outra VM, rode: `Test-NetConnection 10.0.10.20 -Port 445`",
  "`TcpTestSucceeded : True` = a porta está aberta.",
  "No próprio Windows 11, veja quem escuta: `Get-NetTCPConnection -LocalPort 445 -State Listen`"
] },

smb_limiter: { t: "Ver o limitador de autenticação SMB (Windows 11 24H2)", onde: "PowerShell como administrador", s: [
  "Confira a versão: aperte `Windows+R`, digite `winver` e veja o build (24H2 = 26100).",
  "Abra o PowerShell **como administrador**.",
  "Rode: `Get-SmbServerConfiguration | Select-Object InvalidAuthenticationDelayTimeInMs`",
  "O valor padrão é `2000` (2 s de atraso a cada senha errada). É por isso que o NetExec mostrou \"timed out\".",
  "Conte os 4625 no Visualizador de Eventos para confirmar que as tentativas chegaram."
] },

wazuh_login: { t: "Abrir o painel do Wazuh", onde: "Navegador do PC (host)", s: [
  "Ligue a VM do Wazuh e espere uns 3 minutos (antes disso aparece erro 503).",
  "No navegador do PC, abra `https://127.0.0.1:8443`.",
  "No aviso de certificado, clique em **Avançado** → **Continuar** (o certificado do lab é autoassinado).",
  "Entre com o usuário `admin` e a senha do lab."
] },

hunting: { t: "Abrir o Threat Hunting e escolher o período", onde: "Painel do Wazuh", s: [
  "No painel, clique no menu **☰** (canto superior esquerdo).",
  "Vá em **Threat intelligence** → **Threat Hunting**.",
  "No canto superior direito, clique no **ícone de calendário** e escolha o período (ex.: **Last 24 hours**) ou datas exatas em **Absolute**.",
  "Aba **Dashboard** = cards e gráficos resumidos. Aba **Events** = lista de cada alerta com os campos."
] },

dql: { t: "Filtrar eventos com uma consulta DQL", onde: "Wazuh, Threat Hunting → Events", s: [
  "Abra **Threat Hunting** → aba **Events**.",
  "Clique na barra de busca e digite a consulta, por exemplo: `agent.name:SOC-Win11 and data.win.eventdata.ipAddress:10.0.10.30`",
  "Aperte **Enter** (ou clique em **Refresh**).",
  "`and` = as duas condições juntas; `or` = qualquer uma (ex.: `rule.id:100210 or rule.id:92057`).",
  "Confira o número de **hits** no topo antes e depois de cada filtro.",
  "Ordene pela coluna de horário para ler os eventos em sequência."
] },

dql_level: { t: "Triagem pelos alertas mais graves", onde: "Wazuh, Threat Hunting → Events", s: [
  "Em **Events**, escolha o período (ex.: últimas 24 h).",
  "Digite na busca: `rule.level >= 12` e aperte **Enter**.",
  "Trabalhe essa lista primeiro: abra cada alerta e decida (ataque, falso positivo ou provável FP).",
  "Depois baixe para `rule.level >= 8` e assim por diante. Não pare no 12: no Cenário 1 o ataque tinha nível 10."
] },

dash_cards: { t: "Ler os cards do Dashboard", onde: "Wazuh, Threat Hunting → Dashboard", s: [
  "Abra **Threat Hunting** → aba **Dashboard** e ajuste o período.",
  "Leia os cards: total de alertas, **Level 12 or above alerts**, **Authentication failure** e **Authentication success**.",
  "Um card com número não diz de onde veio: vá para **Events** e filtre pelo IP de origem para saber quantos são do atacante.",
  "Nunca conclua só pelo card de nível 12+: ele pode estar em 0 com um ataque real acontecendo."
] },

doc_details: { t: "Abrir os detalhes de um alerta (Document Details)", onde: "Wazuh, Threat Hunting → Events", s: [
  "Na lista de **Events**, clique no ícone de expandir (à esquerda da linha) do alerta.",
  "Abre o **Document Details**. A aba **Table** lista os campos; a aba **JSON** mostra o documento completo do índice.",
  "Campos úteis: `rule.id`, `rule.level`, `rule.description`, `rule.groups`, `rule.mitre.id`, `rule.frequency`, `rule.pci_dss`.",
  "Em alertas correlacionados (ex.: 60204), o campo `previous_output` mostra os eventos que somaram para o disparo.",
  "Campos do Windows ficam em `data.win.eventdata.*` (ex.: `ipAddress`, `targetUserName`, `subStatus`) e `data.win.system.*` (ex.: `systemTime`).",
  "`agent.ip` é a máquina que gerou o log; `data.win.eventdata.ipAddress` é a origem do login."
] },

add_column: { t: "Adicionar uma coluna na tabela de eventos", onde: "Wazuh, Threat Hunting → Events", s: [
  "Clique no botão de campos (**available fields**) acima da tabela.",
  "Na caixa de busca da lista de campos, digite o nome (ex.: `scriptBlockText`).",
  "Clique no **+** (add) ao lado do campo. Ele vira coluna.",
  "Não digite o nome do campo na barra de busca principal: isso vira busca de texto livre e muda os resultados."
] },

rule_view: { t: "Ver a definição de uma regra do Wazuh", onde: "Painel do Wazuh", s: [
  "Clique no menu **☰** → **Server management** → **Rules**.",
  "Na busca, digite o ID (ex.: `60204`) e aperte **Enter**.",
  "Veja nível, descrição, grupos e o arquivo onde a regra está. Clique no nome do arquivo para ler o XML.",
  "No XML, procure `level`, `frequency` e `timeframe` (correlação: quantos eventos em quanto tempo), `if_sid`/`if_matched_sid` (regra mãe) e `<mitre>`.",
  "Escala de nível: 0 (sem alerta) até 15 (mais grave)."
] },

timeline: { t: "Montar a linha do tempo em UTC", onde: "Wazuh + Bloco de Notas", s: [
  "Filtre os eventos do caso (ex.: pelo IP de origem) em **Events**.",
  "Abra cada evento e copie `data.win.system.systemTime` (quando aconteceu no Windows, em UTC).",
  "Monte uma tabela: horário UTC, evento/regra, conta, IP, o que significa.",
  "Ordene por horário e calcule os intervalos (ex.: 9 falhas a cada ~2 s = automação).",
  "Use sempre UTC no relatório e escreva o fuso explicitamente."
] },

timezone: { t: "Conferir o fuso do painel", onde: "Painel do Wazuh", s: [
  "Abra um alerta e compare o horário da tabela com `data.win.system.systemTime` no JSON (que está em UTC).",
  "A diferença é o fuso do painel (no lab: UTC−4).",
  "Para ver ou trocar: **☰** → **Dashboard management** → **Advanced settings** → procure `Timezone for date formatting` (`dateFormat:tz`).",
  "No ticket, escreva sempre com o fuso: ex. `05:57:04 UTC`."
] },

ntp: { t: "Conferir se os relógios estão sincronizados", onde: "Windows e Kali", s: [
  "No Windows, PowerShell: `(Get-Date).ToUniversalTime()` e `w32tm /query /status`.",
  "No Kali, terminal: `date -u` e `timedatectl`.",
  "Rode os dois no mesmo instante e compare a diferença (no lab: ~53 s).",
  "Para sincronizar o Windows (como administrador): `w32tm /resync`.",
  "No relatório, anote a diferença e corrija os horários antes de cruzar logs de máquinas diferentes."
] },

session_trace: { t: "Rastrear o que uma sessão fez (Logon ID)", onde: "Wazuh, Events", s: [
  "Abra o 4624 do login suspeito e copie o `targetLogonId` (ex.: `0x1bf006`).",
  "Na busca, digite: `data.win.eventdata.targetLogonId:0x1bf006 or data.win.eventdata.subjectLogonId:0x1bf006`",
  "Veja o que veio depois: processos, acessos a arquivos, logoff (4634) com o mesmo ID.",
  "Busque o IP do atacante em **todos** os agentes: `data.win.eventdata.ipAddress:10.0.10.30` (sem filtro de agent.name).",
  "Cada login gera um Logon ID novo: numa reexecução, procure o ID novo."
] },

contain_account: { t: "Conter uma conta comprometida (lab)", onde: "Windows 11, PowerShell como administrador", s: [
  "Abra o PowerShell **como administrador** (botão direito → Executar como administrador).",
  "Troque a senha: `net user joao.teste *` (o Windows pede a nova senha duas vezes).",
  "Feche as sessões SMB abertas: `Get-SmbSession | Where-Object ClientUserName -like '*joao.teste*' | Close-SmbSession -Force`",
  "Se precisar, desative a conta: `Disable-LocalUser -Name joao.teste`",
  "Bloqueie o IP de origem: `New-NetFirewallRule -DisplayName 'Bloqueio 10.0.10.30' -Direction Inbound -RemoteAddress 10.0.10.30 -Action Block`",
  "Registre no ticket cada ação com horário. Essas ações são da fase de **contenção**."
] },

lockout: { t: "Configurar o bloqueio de conta (lockout)", onde: "Windows 11, como administrador", s: [
  "Aperte `Windows+R`, digite `secpol.msc` e aperte **Enter**.",
  "Vá em **Políticas de Conta** → **Política de Bloqueio de Conta**.",
  "Dê duplo clique em **Limite de bloqueio de conta** e coloque, por exemplo, `5`.",
  "Aceite as sugestões de **Duração** e **Zerar contador** (ex.: 15 minutos).",
  "Alternativa no terminal (admin): `net accounts /lockoutthreshold:5`",
  "Teste no lab: o brute force deve travar a conta e gerar o evento **4740**."
] },

active_response: { t: "Configurar um Active Response no Wazuh", onde: "Servidor Wazuh, ossec.conf do manager", s: [
  "Entenda primeiro: Active Response = o Wazuh executa uma ação automática quando uma regra dispara.",
  "No painel: **☰** → **Server management** → **Settings** → **Edit configuration** (ou edite `/var/ossec/etc/ossec.conf` via SSH).",
  "Adicione um bloco `<active-response>` com `<command>netsh</command>` (bloqueio no Windows), `<location>local</location>`, `<rules_id>60204</rules_id>` e `<timeout>600</timeout>`.",
  "Salve e reinicie o manager (botão **Restart** no painel).",
  "Teste no lab repetindo o brute force: o IP de origem deve ser bloqueado depois do alerta.",
  "Comece com timeout curto: um bloqueio automático errado também derruba usuário legítimo."
] },

spray: { t: "Diferenciar brute force de password spraying", onde: "Wazuh, Events", s: [
  "Filtre as falhas: `data.win.system.eventID:4625`",
  "Clique no campo `data.win.eventdata.ipAddress` na lista de campos e veja os valores mais comuns (**Visualize/Top values**).",
  "Para o IP suspeito, veja `data.win.eventdata.targetUserName`: **muitas senhas em 1 conta** = brute force; **1 senha em muitas contas** = spraying.",
  "Spraying costuma escapar de regras por conta: correlacione por IP de origem."
] },

label_check: { t: "Conferir se o rótulo do SIEM combina com a evidência", onde: "Wazuh, Document Details", s: [
  "Leia `rule.description` e `rule.mitre.id` do alerta.",
  "Liste o que você **viu** nos logs (ex.: 9 senhas erradas e depois um acerto).",
  "Abra a técnica no `attack.mitre.org` e compare com a evidência.",
  "Se não combinar, mantenha o alerta, mas escreva no ticket o contexto real e a técnica correta (ex.: T1110 + T1078 em vez de pass-the-hash)."
] },

/* ===================== POWERSHELL ===================== */
encode_test: { t: "Gerar um -EncodedCommand inofensivo (lab)", onde: "Windows 11 do lab, PowerShell (usuário comum)", s: [
  "Abra o PowerShell normal (sem administrador).",
  "Escreva o comando inofensivo: `$cmd = 'Write-Host \"LAB-SOC teste\" -ForegroundColor Green'`",
  "Converta para Base64 de UTF-16LE: `$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))`",
  "Veja o texto: `$enc` (repare nos muitos `A`).",
  "Execute: `powershell.exe -EncodedCommand $enc`",
  "A frase verde na tela prova que o comando escondido executou. Anote a hora e vá procurar o alerta no Wazuh (~3 min)."
] },

decode: { t: "Decodificar o Base64 de um -EncodedCommand", onde: "PowerShell ou CyberChef", s: [
  "No Wazuh, abra o alerta (ex.: 92057) e copie só o texto depois de `-EncodedCommand` no campo `data.win.eventdata.commandLine`.",
  "No PowerShell, guarde o texto: `$b64 = 'COLE_AQUI'`",
  "Decodifique: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))`",
  "Use **Unicode** (UTF-16LE), não UTF8: o PowerShell codifica nesse formato, por isso aparecem tantos `A`.",
  "Alternativa: no **CyberChef**, receitas **From Base64** + **Decode text** com **UTF-16LE (1200)**.",
  "Só leia o resultado. Não execute o comando decodificado."
] },

sysmon_eid1: { t: "Ler o evento 1 do Sysmon (criação de processo)", onde: "Visualizador de Eventos ou Wazuh", s: [
  "No Windows: `Windows+R` → `eventvwr.msc`.",
  "Abra **Logs de Aplicativos e Serviços** → **Microsoft** → **Windows** → **Sysmon** → **Operational**.",
  "Clique em **Filtrar Log Atual…** e filtre o ID `1`.",
  "Abra o evento e leia: `Image` (programa), `CommandLine`, `ParentImage` (quem criou), `User`, `IntegrityLevel`, `ProcessId`, `ProcessGuid`.",
  "No Wazuh os mesmos campos ficam em `data.win.eventdata.*` (ex.: `parentImage`, `commandLine`).",
  "Pai suspeito (ex.: `WINWORD.EXE` criando `powershell.exe`) aumenta muito a gravidade."
] },

integrity: { t: "Ver o nível de integridade (privilégio)", onde: "Alerta do Sysmon / PowerShell", s: [
  "No alerta, leia `data.win.eventdata.integrityLevel`: `Medium` = usuário comum; `High` = elevado (administrador); `System` = SISTEMA.",
  "Para conferir o seu próprio terminal: `whoami /groups` e procure a linha **Mandatory Label**.",
  "Abra um PowerShell normal e outro **como administrador** e compare: Medium x High."
] },

sbl_view: { t: "Ler o evento 4104 (Script Block Logging)", onde: "Visualizador de Eventos ou Wazuh", s: [
  "No Windows: `eventvwr.msc` → **Logs de Aplicativos e Serviços** → **Microsoft** → **Windows** → **PowerShell** → **Operational**.",
  "Filtre o ID `4104`.",
  "Abra o evento: o texto mostra o **código já decodificado** que o PowerShell executou.",
  "No Wazuh: busque `rule.id:100210` e leia o campo `data.win.eventdata.scriptBlockText`.",
  "O 4104 mostra **qual** código rodou; o Sysmon (evento 1) mostra **quem** criou o processo."
] },

sbl_enable: { t: "Ativar o Script Block Logging (evento 4104)", onde: "Windows 11, PowerShell como administrador", s: [
  "Abra o PowerShell **como administrador**.",
  "Crie a chave: `New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force`",
  "Ative: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord`",
  "Feche e abra **um PowerShell novo**: as sessões que já estavam abertas não passam a gerar 4104.",
  "Confira no Visualizador de Eventos (PowerShell → Operational) se surgem eventos 4104.",
  "Numa empresa, faça por GPO: **Configuração do Computador** → **Modelos Administrativos** → **Componentes do Windows** → **Windows PowerShell** → **Ativar Log de Bloqueio de Script do PowerShell**.",
  "O script usado no lab está em `02-soc-home-lab/configuracoes/cenario2-ativar-scriptblock.ps1`."
] },

agent_localfile: { t: "Fazer o agente Wazuh ler um canal novo", onde: "Windows 11, como administrador", s: [
  "Abra o PowerShell **como administrador**.",
  "Faça backup: `Copy-Item 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf.bak-cenario2'`",
  "Abra para editar: `notepad 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf'`",
  "Antes do último `</ossec_config>`, cole: `<localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>`",
  "Salve (`Ctrl+S`) e reinicie o agente: `Restart-Service WazuhSvc`",
  "Confira: `Get-Service WazuhSvc` (Status = Running) e `Get-Content 'C:\\Program Files (x86)\\ossec-agent\\ossec.log' -Tail 20` (sem erros).",
  "Gere um evento de teste e procure no Wazuh depois de alguns minutos. Se der errado, volte o `.bak`."
] },

custom_rule: { t: "Criar uma regra personalizada no Wazuh", onde: "Painel do Wazuh", s: [
  "Clique em **☰** → **Server management** → **Rules**.",
  "Clique em **Manage rules files**, ative o filtro **Custom rules** e abra o `local_rules.xml` (ícone de lápis).",
  "Cole a regra dentro de um `<group>`. Exemplo: `<rule id=\"100210\" level=\"4\"><if_sid>91802</if_sid><description>…</description></rule>`",
  "Use ID **acima de 100000** (faixa local, não colide com as regras oficiais). `if_sid` = só avalia quando a regra mãe já casou.",
  "Clique em **Save**. Vai aparecer \"Changes will not take effect until a reload\": clique em **Reload**.",
  "O arquivo fica no servidor em `/var/ossec/etc/rules/local_rules.xml`. A versão do lab está em `02-soc-home-lab/configuracoes/cenario2-local_rules.xml`."
] },

rule_verify: { t: "Confirmar que a regra carregou", onde: "Painel do Wazuh", s: [
  "Abra **☰** → **Server management** → **Dev Tools**.",
  "Digite `GET /rules?rule_ids=100210` e clique no botão de executar (▶).",
  "A resposta deve trazer a regra com `\"status\": \"enabled\"`.",
  "Abra **☰** → **Server management** → **Logs** e procure erros de regra (XML inválido).",
  "Teste opcional: **☰** → **Server management** → **Ruleset Test**, cole um log e veja qual regra casa."
] },

logtest: { t: "Ver o caminho decoder → regra → alerta", onde: "Painel do Wazuh, Ruleset Test", s: [
  "Abra **☰** → **Server management** → **Ruleset Test**.",
  "Cole uma linha de log (ou o JSON de um evento) e clique em **Test**.",
  "Leia as fases: **Phase 1** (pré-decodificação), **Phase 2** (decoder extrai os campos), **Phase 3** (a regra que casou, com ID e nível).",
  "Se o nível for 0, o evento foi reconhecido mas **não** vira alerta."
] },

refresh_fields: { t: "Atualizar a lista de campos (index pattern)", onde: "Painel do Wazuh", s: [
  "Abra **☰** → **Dashboard management** → **Dashboards Management** → **Index patterns**.",
  "Clique em `wazuh-alerts-*`.",
  "No canto superior direito, clique no ícone **Refresh field list** (setas em círculo) e confirme.",
  "Volte ao Threat Hunting: o campo novo (ex.: `scriptBlockText`) agora aparece na lista."
] },

time_zero: { t: "Consertar o período \"No results\"", onde: "Wazuh, Threat Hunting", s: [
  "Olhe o período no topo: se o início e o fim são iguais (ex.: `17:05:08.50 → 17:05:08.50`), um clique no gráfico criou um intervalo de zero segundos.",
  "Clique no **ícone de calendário** e escolha **Last 24 hours** (ou datas em **Absolute**).",
  "Para dar zoom no gráfico, **arraste** sobre um trecho em vez de clicar numa barra."
] },

ingest: { t: "Quando o alerta ainda não apareceu", onde: "Wazuh", s: [
  "Anote a hora exata do teste.",
  "Espere uns 3 minutos (no lab, a ingestão atrasa isso) e clique em **Refresh**.",
  "Confira o período: ele precisa incluir a hora do teste.",
  "Compare `@timestamp` (quando o Wazuh processou) com `data.win.system.systemTime` (quando aconteceu). No relatório vai o systemTime."
] },

pid_correlation: { t: "Correlacionar Sysmon e 4104 pelo PID", onde: "Wazuh, Events", s: [
  "No alerta 92057 (Sysmon), anote `data.win.eventdata.processId` (o filho) e `data.win.eventdata.parentProcessId` (o pai).",
  "Busque os 4104 do pai: `rule.id:100210 and data.win.system.processID:5572` (troque pelo PID anotado).",
  "Busque os 4104 do filho com o PID dele: lá aparece o código já decodificado.",
  "Confira os horários: precisam estar em sequência.",
  "Em investigações longas, use o `processGuid` do Sysmon: o PID pode ser reutilizado pelo Windows, o GUID não."
] },

uac_check: { t: "Checar se um FodHelper foi bypass de UAC", onde: "Wazuh, Events", s: [
  "Abra o alerta do `FodHelper.exe` e veja o pai (`parentImage`) e a linha de comando.",
  "Busque alterações no registro: `data.win.eventdata.targetObject:*ms-settings*` (eventos 12/13 do Sysmon).",
  "Busque também `*DelegateExecute*` no mesmo campo.",
  "Sem essas alterações e com pai `svchost -k DcomLaunch`, falta o rastro do bypass → **provável falso positivo**.",
  "Escreva no veredito o que não foi possível confirmar (ex.: se o usuário abriu as Configurações)."
] },

fp_triage: { t: "Triar um possível falso positivo", onde: "Wazuh, Events", s: [
  "Abra o alerta e leia: regra, processo, usuário, processo pai e linha de comando.",
  "Busque a mesma regra nos últimos 7 dias (`rule.id:92058`, por exemplo): repete sempre igual?",
  "Compare com o comportamento conhecido do Windows (serviço, conta SYSTEM, arquivo de teste do PowerShell etc.).",
  "\"Rodou sozinho\" **não** é argumento: persistência maliciosa também roda sozinha. Use o **conteúdo** e o **padrão**.",
  "Decida: verdadeiro positivo, falso positivo confirmado ou provável falso positivo.",
  "Documente as evidências e, se o ruído for frequente, proponha um tuning estreito."
] },

noise: { t: "Achar a origem do ruído de uma regra", onde: "Wazuh, Events", s: [
  "Filtre a regra: `rule.id:100210`",
  "Adicione a coluna `data.win.eventdata.scriptBlockText` (botão de campos → **+**).",
  "Clique no nome do campo na lista lateral para ver os **valores mais comuns**.",
  "Os textos que se repetem muito e são inofensivos (ex.: `prompt`, `$global:?`) são candidatos a tuning."
] },

tuning: { t: "Criar uma exceção estreita (tuning)", onde: "Painel do Wazuh, local_rules.xml", s: [
  "Abra o `local_rules.xml` (**☰** → **Server management** → **Rules** → **Manage rules files** → **Custom rules**).",
  "Crie uma regra filha com `level=\"0\"` e `<if_sid>100210</if_sid>`: o evento continua chegando, mas não vira alerta.",
  "Use um campo exato com regex ancorada: `<field name=\"win.eventdata.scriptBlockText\" type=\"pcre2\">^\\s*(?:prompt|\\$global:\\?|\\$Host)\\s*$</field>`",
  "`^` e `$` exigem que o texto **inteiro** seja um dos três; `\\$` e `\\?` são os caracteres literais.",
  "Nunca crie exceção ampla (ex.: \"ignorar tudo do SYSTEM\"): isso abre um ponto cego.",
  "Salve, clique em **Reload** e faça o teste de validação."
] },

regex_test: { t: "Testar a regex do tuning antes de usar", onde: "PowerShell", s: [
  "Guarde a regex: `$re = '^\\s*(?:prompt|\\$global:\\?|\\$Host)\\s*$'`",
  "Deve casar: `'prompt' -match $re` → `True`",
  "Não deve casar: `'Invoke-Malware; prompt' -match $re` → `False`",
  "Não deve casar: `'whoami' -match $re` → `False`",
  "Só depois de passar nos três testes, coloque a regex na regra do Wazuh."
] },

tuning_test: { t: "Provar que o tuning funcionou", onde: "Windows 11 + Wazuh", s: [
  "Abra um **PowerShell novo** no Windows 11.",
  "Rode dois comandos reais: `whoami` e `Get-Date`. Anote a hora.",
  "Espere uns 3 minutos e busque no Wazuh: `rule.id:100210` nos últimos 15 minutos.",
  "Precisa aparecer: os alertas de `whoami` e `Get-Date` (a detecção continua).",
  "Não pode aparecer: alertas de `prompt` entre eles (o ruído sumiu).",
  "Guarde um print das duas coisas como prova."
] },

fn_check: { t: "Procurar falsos negativos", onde: "Lab (teste controlado)", s: [
  "Escolha uma técnica que deveria ser detectada (ex.: PowerShell codificado).",
  "Execute uma versão inofensiva no lab e anote a hora.",
  "Procure o alerta no Wazuh pela hora e pela máquina.",
  "Se não houver alerta, é um **falso negativo**: veja se o log chegou (regra nível 0?) ou se nem foi coletado (canal faltando no agente)."
] },

ps_hardening: { t: "Restringir o PowerShell para usuários comuns", onde: "Windows, como administrador", s: [
  "Veja o modo atual: `$ExecutionContext.SessionState.LanguageMode` (`FullLanguage` = sem restrição).",
  "Numa empresa, o caminho é **AppLocker** ou **WDAC**: `secpol.msc` → **Políticas de Controle de Aplicativo** → **AppLocker**.",
  "Com a política ativa, o PowerShell de usuários comuns entra em **ConstrainedLanguage**.",
  "Teste num lab antes, porque políticas erradas bloqueiam programas legítimos."
] },

escalate: { t: "Escalar o caso para o N2", onde: "Ticket", s: [
  "Escreva um resumo de 2 linhas: o que aconteceu e por que é sério.",
  "Liste as evidências: IDs de alerta, horários em UTC, host, conta, IOCs (com defang).",
  "Diga o que já foi feito (ex.: conta resetada, host isolado).",
  "Diga o que precisa do N2 (ex.: análise do arquivo baixado, conexões do host).",
  "Atribua ao N2 e avise pelo canal combinado (chat ou telefone, se for urgente)."
] },

report: { t: "Escrever o relatório de incidente", onde: "Documento do caso", s: [
  "**Resumo executivo** (para gestor): 3 ou 4 frases sem jargão.",
  "**Linha do tempo** em UTC.",
  "**Evidências**: eventos, alertas, prints e hashes.",
  "**Veredito e severidade**, com justificativa.",
  "**MITRE ATT&CK**: técnicas com a evidência de cada uma.",
  "**Contenção** feita e **recomendações**.",
  "Os relatórios do portfólio estão em `docs/assets/relatorios/` como modelo."
] },

/* ===================== LAB / WAZUH ===================== */
wazuh_arch: { t: "Conferir os componentes do Wazuh", onde: "Painel do Wazuh", s: [
  "Abra **☰** → **Server management** → **Status**: mostra o **manager** e os agentes conectados.",
  "Abra **☰** → **Indexer management** → **Index management**: mostra os índices `wazuh-alerts-*` do **indexer**.",
  "O próprio site que você está usando é o **dashboard**.",
  "Caminho de um evento: agente lê o log → envia ao manager → decoder → regras → alerta → indexer → dashboard."
] },

agent_install: { t: "Instalar o agente Wazuh no Windows", onde: "Painel do Wazuh + Windows 11", s: [
  "No painel: **☰** → **Agents management** → **Summary** → **Deploy new agent**.",
  "Escolha **Windows** (MSI), coloque o endereço do servidor `10.0.10.10` e o nome do agente `SOC-Win11`.",
  "Copie o comando PowerShell que o painel gera.",
  "No Windows 11, abra o PowerShell **como administrador**, cole e rode o comando.",
  "Inicie o serviço: `NET START WazuhSvc`",
  "Volte ao painel: o agente deve aparecer como **active**."
] },

sysmon_install: { t: "Instalar o Sysmon", onde: "Windows 11, como administrador", s: [
  "Baixe o **Sysmon** do site oficial da Microsoft (Sysinternals) e extraia o .zip.",
  "Baixe um arquivo de configuração conhecido (ex.: o `sysmonconfig` da comunidade) para a mesma pasta.",
  "Abra o PowerShell **como administrador** nessa pasta.",
  "Instale: `.\\Sysmon64.exe -accepteula -i sysmonconfig.xml`",
  "Confira no Visualizador de Eventos: **Microsoft** → **Windows** → **Sysmon** → **Operational**.",
  "Adicione o canal `Microsoft-Windows-Sysmon/Operational` no `ossec.conf` do agente (como no procedimento do agente) e reinicie o `WazuhSvc`."
] },

lab_net: { t: "Montar a rede isolada do lab (VirtualBox)", onde: "VirtualBox no PC", s: [
  "No VirtualBox: **Arquivo** → **Ferramentas** → **Network Manager** → aba **NAT Networks** → **Criar**.",
  "Nome `SOC-LAB`, prefixo IPv4 `10.0.10.0/24`, **DHCP** ativado. Clique em **Aplicar**.",
  "Em cada VM: **Configurações** → **Rede** → **Adaptador 1** → **Conectado a: Rede NAT** → nome `SOC-LAB`.",
  "Para abrir o painel pelo PC: na rede SOC-LAB, aba **Port Forwarding** → **+** → Host IP `127.0.0.1`, porta `8443` → Guest IP `10.0.10.10`, porta `443`.",
  "IPs do lab: `10.0.10.10` Wazuh, `10.0.10.20` Windows 11, `10.0.10.30` Kali.",
  "Confira em cada VM: `ipconfig` (Windows) ou `ip a` (Kali)."
] },

snapshot: { t: "Tirar e restaurar snapshots", onde: "VirtualBox", s: [
  "**Desligue** a VM antes (neste PC, snapshot com a VM ligada trava).",
  "Selecione a VM, clique no ícone de menu ao lado do nome → **Snapshots**.",
  "Clique em **Tirar** (Take), dê um nome por etapa (ex.: `00-base-limpa`, `01-sysmon-agente`) e uma descrição.",
  "Para voltar: selecione o snapshot → **Restaurar**. Desmarque a opção de salvar o estado atual se não precisar dele."
] },

ram: { t: "Ligar as VMs sem estourar a memória", onde: "PC (host)", s: [
  "Abra o Gerenciador de Tarefas (`Ctrl+Shift+Esc`) → **Desempenho** → **Memória** e veja quanto está livre.",
  "Feche programas pesados (navegador com muitas abas etc.).",
  "Ligue a ordem: **Wazuh** primeiro (espere ~3 min), depois o **Kali**, por último o **Windows 11**.",
  "Se ainda faltar memória, reduza a RAM de uma VM: **Configurações** → **Sistema** → **Memória Base** (com a VM desligada)."
] },

export_json: { t: "Exportar alertas do indexer em JSON", onde: "VM do Wazuh via SSH", s: [
  "No PC, abra o PowerShell e conecte: `ssh -p 2210 wazuh-user@127.0.0.1` (porta encaminhada do lab).",
  "Rode a consulta e salve em arquivo: `curl -k -u admin \"https://127.0.0.1:9200/wazuh-alerts-*/_search?q=rule.id:60204&size=100&pretty\" > alertas.json` (o curl pede a senha).",
  "Copie o arquivo para o PC: `scp -P 2210 wazuh-user@127.0.0.1:alertas.json .`",
  "Abra e confira se não há senha nem dado pessoal.",
  "Para um alerta só: no Document Details, aba **JSON**, copie o conteúdo.",
  "Guarde em `evidencias/` no repositório, junto com o hash do arquivo."
] },

screenshot: { t: "Tirar e limpar prints antes de publicar", onde: "Windows", s: [
  "Aperte `Windows+Shift+S` e selecione só a área necessária.",
  "Clique na notificação para abrir na **Ferramenta de Captura**.",
  "Use a ferramenta de **cortar** para tirar barra de favoritos, abas e barra de endereço.",
  "Confira: seu e-mail, seu IP real, nomes de pastas pessoais e favoritos não podem aparecer.",
  "Salve como PNG com nome numerado (ex.: `03-alerta-60204-detalhe.png`)."
] },

ethics: { t: "Garantir que o teste é autorizado", onde: "Antes de qualquer ataque", s: [
  "Confira o IP do alvo: tem que ser uma VM sua (`10.0.10.x`).",
  "Confira que a rede é a NAT Network isolada `SOC-LAB`.",
  "Tire um snapshot antes.",
  "Numa empresa, só teste com **autorização por escrito** e escopo definido (regras de engajamento)."
] }
},

map: {
"ph-001":["eml","headers_view"],"ph-002":["hash"],"ph-003":["received"],"ph-004":["received","rdap"],"ph-005":["rdap"],
"ph-006":["sender"],"ph-007":["auth"],"ph-008":["auth"],"ph-009":["auth","sender"],"ph-010":["scl"],
"ph-011":["scl","phish_scope"],"ph-012":["mime"],"ph-013":["mime"],"ph-014":["url_at"],"ph-015":["url_at"],
"ph-016":["url_at","defang"],"ph-017":["cloudrun"],"ph-018":["cloudrun"],"ph-019":["cert"],"ph-020":["virustotal","urlscan"],
"ph-021":["html_safe"],"ph-022":["python","html_safe"],"ph-023":["social"],"ph-024":["social"],"ph-025":["social"],
"ph-026":["social","sender"],"ph-027":["defang"],"ph-028":["iocs","defang"],"ph-029":["virustotal"],"ph-030":["abuseipdb"],
"ph-031":["safebrowsing","virustotal"],"ph-032":["mitre"],"ph-033":["mitre"],"ph-034":["mitre"],"ph-035":["mitre"],
"ph-036":["report_gcp"],"ph-037":["report_gcp"],"ph-038":["report_ip","abuseipdb"],"ph-039":["report_cert"],"ph-040":["phish_scope"],
"ph-041":["click_response","escalate"],"ph-042":["phish_scope"],"ph-043":["regex_url"],"ph-044":["python"],"ph-045":["python","html_safe"],
"ph-046":["python","received"],"ph-047":["victim_govbr"],"ph-048":["victim_pix"],"ph-049":["victim_govbr","click_response"],"ph-050":["interview","auth"],
"ph-051":["interview","virustotal"],"ph-052":["interview","report_gcp"],"ph-053":["interview","verdict"],"ph-054":["interview","url_at"],"ph-055":["interview","python"],

"smb-001":["evt_sec"],"smb-002":["evt_sec"],"smb-003":["evt_sec"],"smb-004":["logontype"],"smb-005":["logontype"],
"smb-006":["logontype"],"smb-007":["logontype","fp_triage"],"smb-008":["substatus"],"smb-009":["substatus"],"smb-010":["substatus"],
"smb-011":["substatus","doc_details"],"smb-012":["substatus"],"smb-013":["auth_pkg"],"smb-014":["anon"],"smb-015":["anon","timeline"],
"smb-016":["nxc_brute"],"smb-017":["nxc_brute"],"smb-018":["nxc_recon"],"smb-019":["nxc_recon"],"smb-020":["nxc_recon"],
"smb-021":["nxc_recon"],"smb-022":["port445"],"smb-023":["rule_view"],"smb-024":["rule_view"],"smb-025":["doc_details","rule_view"],
"smb-026":["rule_view","doc_details"],"smb-027":["doc_details"],"smb-028":["doc_details"],"smb-029":["dash_cards"],"smb-030":["dash_cards","dql"],
"smb-031":["dql"],"smb-032":["dql","timeline"],"smb-033":["timeline","dql"],"smb-034":["timeline"],"smb-035":["label_check"],
"smb-036":["mitre"],"smb-037":["label_check"],"smb-038":["mitre"],"smb-039":["doc_details"],"smb-040":["active_response"],
"smb-041":["active_response"],"smb-042":["lockout"],"smb-043":["contain_account"],"smb-044":["session_trace"],"smb-045":["session_trace"],
"smb-046":["evt_sec","nxc_brute"],"smb-047":["smb_limiter"],"smb-048":["interview","evt_sec"],"smb-049":["anon"],"smb-050":["ntp"],
"smb-051":["interview","ntp"],"smb-052":["session_trace"],"smb-053":["timeline"],"smb-054":["ntp"],"smb-055":["interview","timeline"],
"smb-056":["interview","label_check"],"smb-057":["interview","lockout"],"smb-058":["interview","nxc_brute"],"smb-059":["session_trace"],"smb-060":["evt_sec"],
"smb-061":["lab_net"],"smb-062":["timezone"],"smb-063":["dql"],"smb-064":["nxc_brute"],"smb-065":["spray"],

"ps-001":["encode_test"],"ps-002":["decode"],"ps-003":["decode"],"ps-004":["decode"],"ps-005":["decode"],
"ps-006":["mitre"],"ps-007":["mitre","decode"],"ps-008":["sysmon_eid1"],"ps-009":["sysmon_eid1"],"ps-010":["integrity"],
"ps-011":["integrity"],"ps-012":["rule_view"],"ps-013":["decode"],"ps-014":["sbl_view"],"ps-015":["sbl_view"],
"ps-016":["sbl_enable"],"ps-017":["sbl_enable"],"ps-018":["agent_localfile"],"ps-019":["agent_localfile"],"ps-020":["agent_localfile"],
"ps-021":["agent_localfile"],"ps-022":["rule_view"],"ps-023":["custom_rule"],"ps-024":["custom_rule"],"ps-025":["custom_rule"],
"ps-026":["custom_rule"],"ps-027":["rule_verify"],"ps-028":["pid_correlation"],"ps-029":["pid_correlation"],"ps-030":["sysmon_eid1","escalate"],
"ps-031":["pid_correlation"],"ps-032":["pid_correlation"],"ps-033":["ingest","timeline"],"ps-034":["timezone"],"ps-035":["refresh_fields"],
"ps-036":["time_zero"],"ps-037":["dql"],"ps-038":["fp_triage"],"ps-039":["fp_triage"],"ps-040":["uac_check"],
"ps-041":["verdict"],"ps-042":["fp_triage"],"ps-043":["verdict","fp_triage"],"ps-044":["noise"],"ps-045":["tuning"],
"ps-046":["regex_test"],"ps-047":["regex_test"],"ps-048":["regex_test"],"ps-049":["tuning"],"ps-050":["tuning_test"],
"ps-051":["tuning_test"],"ps-052":["noise","tuning"],"ps-053":["sysmon_eid1","sbl_view"],"ps-054":["escalate"],"ps-055":["ps_hardening"],
"ps-056":["encode_test"],"ps-057":["encode_test"],"ps-058":["dql_level"],"ps-059":["fp_triage"],"ps-060":["dql"],
"ps-061":["sbl_enable"],"ps-062":["tuning"],"ps-063":["interview","report"],"ps-064":["verdict"],"ps-065":["sysmon_eid1","sbl_view"],

"soc-001":["wazuh_arch"],"soc-002":["agent_install"],"soc-003":["agent_localfile"],"soc-004":["agent_localfile"],"soc-005":["logtest"],
"soc-006":["logtest","rule_view"],"soc-007":["rule_view"],"soc-008":["custom_rule"],"soc-009":["custom_rule"],"soc-010":["rule_view"],
"soc-011":["doc_details"],"soc-012":["dql"],"soc-013":["dql"],"soc-014":["dql_level"],"soc-015":["dash_cards","dql_level"],
"soc-016":["hunting","dash_cards"],"soc-017":["add_column"],"soc-018":["add_column"],"soc-019":["time_zero"],"soc-020":["refresh_fields"],
"soc-021":["timezone"],"soc-022":["ingest","doc_details"],"soc-023":["ingest"],"soc-024":["ntp"],"soc-025":["ntp"],
"soc-026":["export_json","hash"],"soc-027":["lab_net"],"soc-028":["lab_net","wazuh_login"],"soc-029":["lab_net"],"soc-030":["sysmon_install","sysmon_eid1"],
"soc-031":["snapshot"],"soc-032":["snapshot"],"soc-033":["ram"],"soc-034":["fp_triage"],"soc-035":["fn_check"],
"soc-036":["verdict","uac_check"],"soc-037":["fp_triage"],"soc-038":["escalate"],"soc-039":["verdict"],"soc-040":["report"],
"soc-041":["timeline"],"soc-042":["hash"],"soc-043":["screenshot"],"soc-044":["mitre"],"soc-045":["label_check"],
"soc-046":["active_response"],"soc-047":["active_response"],"soc-048":["tuning"],"soc-049":["tuning_test"],"soc-050":["custom_rule","rule_verify"],
"soc-051":["doc_details"],"soc-052":["interview","dql_level"],"soc-053":["interview","report"],"soc-054":["tuning","tuning_test"],"soc-055":["interview","active_response"],
"soc-056":["interview"],"soc-057":["interview","nxc_brute"],"soc-058":["lab_net","snapshot"],"soc-059":["interview","evt_sec"],"soc-060":["fp_triage","tuning"],
"soc-061":["wazuh_arch","export_json"],"soc-062":["doc_details"],"soc-063":["contain_account"],"soc-064":["ethics"],"soc-065":["fp_triage"]
}
};
