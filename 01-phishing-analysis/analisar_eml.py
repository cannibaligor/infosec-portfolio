"""
analisar_eml.py - Análise estática (offline) de um e-mail suspeito salvo em .eml

Uso:
    python analisar_eml.py "caminho/do/arquivo.eml"

O que o script faz:
    1. Calcula o hash SHA-256 do arquivo (prova de integridade da evidência)
    2. Mostra os cabeçalhos importantes (remetente, assunto, IDs, veredito antispam)
    3. Mostra o caminho do e-mail (cabeçalhos Received), do primeiro ao último salto
    4. Mostra o resultado de SPF, DKIM e DMARC
    5. Separa as partes MIME do corpo e decodifica cada uma (base64, quoted-printable)
    6. Lê o HTML como TEXTO e lista os links e os elementos perigosos
    7. Divide cada URL em partes e mostra o destino real (o que vem depois do "@")
    8. Imprime as URLs "desarmadas" (defang), para colar em relatórios sem risco

Por que é seguro:
    - Usa só bibliotecas que já vêm com o Python (nada é instalado).
    - Não abre navegador, não renderiza HTML, não executa scripts,
      não baixa imagens e não faz nenhuma conexão com a internet.
    - O arquivo .eml é tratado apenas como texto.
"""

import email                      # lê o formato de e-mail (cabeçalhos + partes MIME)
import hashlib                    # calcula o hash SHA-256
import re                         # expressões regulares (busca de padrões em texto)
import sys                        # lê o argumento da linha de comando
from email import policy          # política moderna: decodifica cabeçalhos com acento
from html.parser import HTMLParser  # lê HTML como texto, sem renderizar nada
from urllib.parse import urlsplit   # divide uma URL nas suas partes (RFC 3986)

# Faz o terminal do Windows exibir acentos corretamente.
sys.stdout.reconfigure(encoding="utf-8")


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------

def titulo(texto):
    """Imprime um título de seção, para a saída ficar organizada."""
    print()
    print("=" * 70)
    print(texto)
    print("=" * 70)


def defang(texto):
    """Desarma uma URL/IP: https -> hxxps e . -> [.]
    Assim o link deixa de ser clicável em relatórios e tickets."""
    texto = re.sub(r"^http", "hxxp", texto, flags=re.IGNORECASE)
    return texto.replace(".", "[.]")


class LeitorDeHTML(HTMLParser):
    """Percorre o HTML tag por tag, SEM exibir nada.
    Guarda os links (<a href>) e conta as tags que costumam ser perigosas."""

    TAGS_DE_RISCO = ("img", "script", "iframe", "form", "object", "embed")

    def __init__(self):
        super().__init__()
        self.links = []
        self.contagem = {tag: 0 for tag in self.TAGS_DE_RISCO}

    def handle_starttag(self, tag, atributos):
        # Chamado para cada tag de abertura encontrada, ex.: <a href="...">
        if tag in self.contagem:
            self.contagem[tag] += 1
        if tag == "a":
            for nome, valor in atributos:
                if nome == "href" and valor:
                    self.links.append(valor)


def analisar_url(url):
    """Mostra as partes de uma URL e alerta sobre o truque do '@'.

    Pela RFC 3986, uma URL tem o formato:
        esquema://usuario:senha@host:porta/caminho
    Tudo o que vem ANTES do '@' é 'userinfo' (usuário e senha) e é IGNORADO
    na hora de decidir para qual site ir. O destino real é o 'host'."""
    partes = urlsplit(url)
    print(f"  URL (desarmada): {defang(url)}")
    print(f"  Esquema........: {partes.scheme}")
    if partes.username:
        print(f"  Userinfo.......: {defang(partes.username)}   <-- IGNORADO pelo navegador")
        print("  [ALERTA] A URL tem '@': o texto antes dele serve só para enganar.")
    print(f"  Host REAL......: {defang(partes.hostname or '')}")
    print(f"  Caminho........: {partes.path or '/'}")


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print('Uso: python analisar_eml.py "caminho/do/arquivo.eml"')
        sys.exit(1)

    caminho = sys.argv[1]

    # O arquivo é lido em modo binário ("rb"): bytes puros, exatamente como estão no disco.
    with open(caminho, "rb") as arquivo:
        dados = arquivo.read()

    # 1. HASH ---------------------------------------------------------------
    titulo("1. INTEGRIDADE DA EVIDÊNCIA")
    print(f"Arquivo: {caminho}")
    print(f"Tamanho: {len(dados)} bytes")
    print(f"SHA-256: {hashlib.sha256(dados).hexdigest()}")

    # Converte os bytes em um objeto de e-mail (separa cabeçalhos e corpo).
    msg = email.message_from_bytes(dados, policy=policy.default)

    # 2. CABEÇALHOS ---------------------------------------------------------
    titulo("2. CABEÇALHOS PRINCIPAIS")
    for nome in ("From", "Return-Path", "Reply-To", "Subject", "Date",
                 "Message-ID", "X-Sender-IP",
                 "X-MS-Exchange-Organization-SCL",
                 "X-Microsoft-Antispam-Mailbox-Delivery"):
        valor = msg.get(nome)
        if valor:
            print(f"{nome}: {valor}")
    # O destinatário NÃO é impresso, para não expor o seu e-mail em prints.
    print("To: [REDACTED]")

    # Verifica se o remetente tem um domínio de verdade (algo.algo, ex.: detran.sp.gov.br)
    remetente = str(msg.get("From", ""))
    dominio = remetente.rsplit("@", 1)[-1].strip(" >")
    if "." not in dominio:
        print(f"[ALERTA] O remetente '{dominio}' não tem domínio válido (falta .com, .gov.br...).")

    # 3. CAMINHO (RECEIVED) -------------------------------------------------
    titulo("3. CAMINHO DO E-MAIL (do primeiro ao último servidor)")
    # Cada servidor ADICIONA uma linha Received no TOPO. Por isso invertemos
    # a lista: assim o primeiro item é o servidor que enviou a mensagem.
    saltos = msg.get_all("Received") or []
    for numero, salto in enumerate(reversed(saltos), start=1):
        resumo = " ".join(str(salto).split())  # junta as quebras de linha
        print(f"Salto {numero}: {resumo[:160]}")
    if saltos:
        # Só olhamos o trecho "from ... by": é ali que fica quem ENVIOU.
        # (O resto da linha descreve o servidor que RECEBEU.)
        primeiro = " ".join(str(saltos[-1]).split())
        trecho_from = primeiro.split(" by ", 1)[0]
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", trecho_from)
        print(f"Origem declarada no primeiro salto: {trecho_from}")
        print(f"IPs da origem: {', '.join(ips)}")
        if "127.0.1.1" in ips or "127.0.0.1" in ips:
            print("[ALERTA] O servidor se apresentou como 'localhost' (127.x): "
                  "típico de script de disparo em massa num servidor alugado.")

    # 4. AUTENTICAÇÃO -------------------------------------------------------
    titulo("4. AUTENTICAÇÃO (SPF / DKIM / DMARC)")
    autenticacao = str(msg.get("Authentication-Results", ""))
    for controle in ("spf", "dkim", "dmarc"):
        achado = re.search(rf"\b{controle}=(\w+)", autenticacao, re.IGNORECASE)
        resultado = achado.group(1) if achado else "(não encontrado)"
        print(f"{controle.upper():6}: {resultado}")
    print("Obs.: 'none' = não havia nada para verificar; 'pass' = aprovado; 'fail' = reprovado.")

    # 5. PARTES MIME --------------------------------------------------------
    titulo("5. PARTES DO CORPO (MIME)")
    htmls = []
    for parte in msg.walk():                     # percorre todas as partes do e-mail
        if parte.is_multipart():                 # "caixas" que só agrupam outras partes
            continue
        tipo = parte.get_content_type()
        codificacao = parte.get("Content-Transfer-Encoding", "nenhuma")
        anexo = parte.get_filename()
        print(f"- {tipo} | codificação: {codificacao}" + (f" | ANEXO: {anexo}" if anexo else ""))
        if anexo:
            # Anexos NÃO são abertos nem salvos: só registramos que existem.
            continue
        conteudo = parte.get_content()           # decodifica base64/quoted-printable
        if tipo == "text/plain":
            print(f"  Texto: {conteudo.strip()[:300]}")
        elif tipo == "text/html":
            htmls.append(conteudo)
            print(f"  HTML com {len(conteudo)} caracteres (lido como texto, não exibido)")

    # 6. HTML: LINKS E ELEMENTOS DE RISCO -----------------------------------
    titulo("6. O QUE HÁ DENTRO DO HTML")
    links = []
    for html in htmls:
        leitor = LeitorDeHTML()
        leitor.feed(html)
        links.extend(leitor.links)
        for tag, quantidade in leitor.contagem.items():
            print(f"<{tag}>: {quantidade}")
    print(f"Total de links encontrados: {len(links)}")

    # 7 e 8. ANÁLISE E DEFANG DAS URLs --------------------------------------
    titulo("7. ANÁLISE DAS URLs")
    for numero, link in enumerate(links, start=1):
        print(f"Link {numero}:")
        analisar_url(link)
        print()


if __name__ == "__main__":
    main()
