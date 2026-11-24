#!/usr/bin/env python3
"""Kit de Bolso do Técnico — servidor local de diagnóstico de rede.

Roda no próprio aparelho (Termux) e serve a interface web em index.html.
Sem dependências externas de Python (apenas a biblioteca padrão).

Segurança:
  - Autenticação por token obrigatório em todas as rotas /api/*.
  - Validação do cabeçalho Host (anti DNS rebinding).
  - Ações que mudam estado exigem POST.
  - Alvos de varredura validados; varreduras ativas só em faixas privadas.
  - Porta de captura (UDP) ouve apenas em 127.0.0.1.

Uso:
  python server.py                       # só neste aparelho (127.0.0.1)
  python server.py --lan                 # acessível na rede local
  python server.py --porta 8090          # porta HTTP alternativa
  python server.py --agendar 30          # inventário automático a cada 30 min
  python server.py --relatorio rel.json  # exporta o relatório e sai
  python server.py --novo-token          # gera um token novo (invalida o antigo)
"""
import argparse
import base64
import collections
import datetime
import errno
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import zlib

VERSAO = "3.3"
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "kit.db")
TOKEN_FILE = os.path.join(HERE, ".token")
UDP_PORT = 5123
LIMITE_IMPORT = 25 * 1024 * 1024  # 25 MB por arquivo .pcap importado

# Retenção do banco e da memória
MAX_ALERTAS = 5000          # linhas na tabela alertas
DIAS_VARREDURAS = 90        # varreduras mais antigas são apagadas
MAX_CHAVES = 5000           # chaves nos contadores de hosts e domínios
COOKIE_DIAS = 30            # validade do cookie de acesso

# Preenchidos em main()
HTTP_PORT = 8080
LAN = False
TOKEN = ""
HOSTS_OK = set()

RUN_SEM = threading.Semaphore(2)

# ---------------------------------------------------------------- Banco
DBLOCK = threading.Lock()


def db():
    c = sqlite3.connect(DB, timeout=10, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=10000")
    return c


REDE_LEGADO = "legado"


def _colunas(c, tabela):
    return {r[1] for r in c.execute(f"PRAGMA table_info({tabela})")}


def _existe(c, tabela):
    return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                     (tabela,)).fetchone() is not None


ESQUEMA = """
CREATE TABLE IF NOT EXISTS redes(
    rede_id TEXT PRIMARY KEY, nome TEXT, gateway TEXT, gw_mac TEXT,
    wifi TEXT, ssid TEXT, bssid TEXT, primeiro REAL, ultimo REAL);
CREATE TABLE IF NOT EXISTS dispositivos(
    rede_id TEXT NOT NULL DEFAULT 'legado',
    ip TEXT, mac TEXT, fabricante TEXT, nome TEXT, portas TEXT,
    primeiro REAL, ultimo REAL, autorizado INTEGER DEFAULT 0,
    PRIMARY KEY(rede_id, ip, mac));
CREATE TABLE IF NOT EXISTS alertas(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, nivel TEXT,
    tipo TEXT, msg TEXT, rede_id TEXT);
CREATE TABLE IF NOT EXISTS varreduras(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, alvo TEXT,
    hosts INTEGER, resumo TEXT, rede_id TEXT NOT NULL DEFAULT 'legado');
CREATE TABLE IF NOT EXISTS arp(
    rede_id TEXT NOT NULL DEFAULT 'legado', ip TEXT, mac TEXT, visto REAL,
    PRIMARY KEY(rede_id, ip));
CREATE TABLE IF NOT EXISTS config(
    chave TEXT PRIMARY KEY, valor TEXT);
CREATE TABLE IF NOT EXISTS bssids(
    rede_id TEXT, bssid TEXT, seguranca TEXT, canal INTEGER, primeiro REAL,
    PRIMARY KEY(rede_id, bssid));
CREATE TABLE IF NOT EXISTS medidas(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, tipo TEXT, rotulo TEXT,
    valor REAL, extra TEXT, rede_id TEXT);
CREATE INDEX IF NOT EXISTS ix_medidas ON medidas(tipo, ts);
CREATE INDEX IF NOT EXISTS ix_var_rede ON varreduras(rede_id, ts);
CREATE INDEX IF NOT EXISTS ix_disp_rede ON dispositivos(rede_id, ip);
CREATE INDEX IF NOT EXISTS ix_alerta_rede ON alertas(rede_id);
"""


def db_init():
    """Cria o esquema e migra bancos antigos (sem a noção de rede).

    dispositivos e arp têm a rede na chave primária, o que o SQLite não
    consegue alterar com ALTER TABLE: essas duas tabelas são recriadas e os
    dados copiados. varreduras e alertas ganham a coluna com ALTER TABLE.
    Registros antigos ficam com rede_id='legado'.
    """
    with DBLOCK:
        c = db()
        recriar = []
        for t in ("dispositivos", "arp"):
            if _existe(c, t) and "rede_id" not in _colunas(c, t):
                c.execute(f"ALTER TABLE {t} RENAME TO {t}_antigo")
                recriar.append(t)
        for t in ("varreduras", "alertas"):
            if _existe(c, t) and "rede_id" not in _colunas(c, t):
                padrao = " NOT NULL DEFAULT 'legado'" if t == "varreduras" else ""
                c.execute(f"ALTER TABLE {t} ADD COLUMN rede_id TEXT{padrao}")
        c.executescript(ESQUEMA)
        if "dispositivos" in recriar:
            c.execute("INSERT OR IGNORE INTO dispositivos(rede_id,ip,mac,fabricante,"
                      "nome,portas,primeiro,ultimo,autorizado) SELECT 'legado',ip,"
                      "mac,fabricante,nome,portas,primeiro,ultimo,autorizado "
                      "FROM dispositivos_antigo")
            c.execute("DROP TABLE dispositivos_antigo")
        if "arp" in recriar:
            c.execute("INSERT OR IGNORE INTO arp(rede_id,ip,mac,visto) "
                      "SELECT 'legado',ip,mac,visto FROM arp_antigo")
            c.execute("DROP TABLE arp_antigo")
        tem_legado = any(c.execute(
            f"SELECT 1 FROM {t} WHERE rede_id='legado' LIMIT 1").fetchone()
            for t in ("dispositivos", "varreduras", "arp"))
        if tem_legado:
            c.execute("INSERT OR IGNORE INTO redes(rede_id,nome,primeiro,ultimo) "
                      "VALUES('legado','Dados antigos (antes da separação por rede)',"
                      "0,0)")
        aplicar_retencao(c)
        c.commit()
        c.close()


def aplicar_retencao(c, agora=None):
    """Mantém só os últimos MAX_ALERTAS alertas e DIAS_VARREDURAS de varreduras.

    Recebe uma conexão aberta (quem chama segura o DBLOCK e faz o commit).
    """
    agora = agora or time.time()
    c.execute("DELETE FROM alertas WHERE id NOT IN "
              "(SELECT id FROM alertas ORDER BY id DESC LIMIT ?)", (MAX_ALERTAS,))
    c.execute("DELETE FROM varreduras WHERE ts < ?",
              (agora - DIAS_VARREDURAS * 86400,))


def config_get(chave, padrao=None):
    with DBLOCK:
        c = db()
        row = c.execute("SELECT valor FROM config WHERE chave=?",
                        (chave,)).fetchone()
        c.close()
    if not row:
        return padrao
    try:
        return json.loads(row["valor"])
    except ValueError:
        return padrao


def config_set(chave, valor):
    with DBLOCK:
        c = db()
        c.execute("INSERT OR REPLACE INTO config(chave, valor) VALUES(?,?)",
                  (chave, json.dumps(valor)))
        c.commit()
        c.close()


_ultimo_alerta = {}
_ALERTA_LOCK = threading.Lock()


def alerta(nivel, tipo, msg, dedup_s=0, chave=None, rede_id=None):
    """Registra um alerta persistente (SQLite).

    dedup_s evita repetir o mesmo alerta por N segundos. Por padrão a
    deduplicação usa (tipo, msg); 'chave' permite agrupar mensagens que
    variam (ex.: o mesmo protocolo inseguro para destinos diferentes).
    'rede_id' associa o alerta a uma rede (None = vale para todas, como os
    da captura). Retorna True se o alerta foi gravado.
    """
    if dedup_s:
        k = (tipo, rede_id, chave if chave is not None else msg)
        agora = time.time()
        with _ALERTA_LOCK:
            if agora - _ultimo_alerta.get(k, 0) < dedup_s:
                return False
            _ultimo_alerta[k] = agora
    with DBLOCK:
        c = db()
        c.execute("INSERT INTO alertas(ts, nivel, tipo, msg, rede_id) "
                  "VALUES(?,?,?,?,?)", (time.time(), nivel, tipo, msg, rede_id))
        c.commit()
        c.close()
    print(f"[{nivel}] {tipo}: {msg}")
    if nivel == "alto" or tipo == "novo_host":
        notificar(f"Kit de Bolso: {TITULOS_ALERTA.get(tipo, tipo)}", msg)
    return True


TITULOS_ALERTA = {
    "novo_host": "aparelho novo na rede", "mac_trocado": "aparelho trocado",
    "arp_spoof": "possível ARP spoofing", "dhcp_falso": "DHCP falso",
    "deauth": "ataque de desautenticação", "credencial": "senha sem criptografia",
    "evil_twin": "possível Wi-Fi falso", "dns_sequestro": "DNS suspeito",
    "varredura": "varredura de portas", "ra_falso": "roteador IPv6 falso",
    "temperatura": "aparelho quente", "celular_2g": "celular caiu para 2G",
}
# Quem envia a notificação (trocado nos testes). Recebe (titulo, texto).
NOTIFICADOR = [None]


def notificar(titulo, texto):
    """Notificação do Android (Termux:API). Silencioso se não houver."""
    if config_get("notificacoes", True) is False:
        return False
    if NOTIFICADOR[0]:
        NOTIFICADOR[0](titulo, texto)
        return True
    from shutil import which
    if not which("termux-notification"):
        return False
    try:
        subprocess.Popen(["termux-notification", "--title", titulo[:80],
                          "--content", texto[:300], "--priority", "high",
                          "--group", "kit-de-bolso"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- OUI
OUI = {
    "FCFBFB": "Apple", "001A11": "Google", "DCA632": "Raspberry Pi",
    "B827EB": "Raspberry Pi", "E45F01": "Raspberry Pi", "2CF05D": "Micro-Star",
    "001132": "Synology", "F0F6C1": "TP-Link", "50C7BF": "TP-Link",
    "AC84C6": "TP-Link", "C46E1F": "TP-Link", "001D0F": "TP-Link",
    "E894F6": "TP-Link", "B0BE76": "TP-Link", "7C2EBD": "Google",
    "44070B": "Google", "3C5AB4": "Google", "F4F5E8": "Google",
    "001567": "Samsung", "E8508B": "Samsung", "D4619D": "Samsung",
    "5CF370": "ASUS", "04D4C4": "ASUS", "D850E6": "ASUS",
    "00156D": "Ubiquiti", "FC3F9A": "Mikrotik", "4C5E0C": "Mikrotik",
    "000C42": "Mikrotik", "6466B3": "Mikrotik", "D4CA6D": "Mikrotik",
    "087395": "Xiaomi", "286C07": "Xiaomi", "64CC2E": "Xiaomi",
    "FCA47A": "Xiaomi", "98FAE3": "Xiaomi", "8CBEBE": "Xiaomi",
    "00EABD": "Intelbras", "E0191D": "Intelbras", "0C8063": "Intelbras",
    "000E8F": "Sercomm",
}


def fabricante(mac):
    if not mac:
        return "?"
    limpo = mac.upper().replace(":", "").replace("-", "")
    if len(limpo) < 12:
        return "?"
    # Bit "localmente administrado" (2º nibble em 2, 6, A ou E) = MAC aleatório.
    try:
        segundo = int(limpo[1], 16)
        if segundo & 0x2:
            return "MAC aleatório (privacidade)"
    except ValueError:
        return "?"
    return OUI.get(limpo[:6], "?")


# ---------------------------------------------------------------- Captura
PK = collections.deque(maxlen=20000)
LOCK = threading.Lock()
SEQ = [0]
LINK = [101]  # tipo de enlace padrão (101 = IP puro, usado pelo PCAPdroid)
ST = {
    "pkts": 0, "bytes": 0, "proto": collections.Counter(),
    "hosts": collections.Counter(), "dominios": collections.Counter(),
    "portas": collections.Counter(), "inicio": None,
    "inseguro": collections.Counter(),
    "inseguro_host": collections.Counter(),  # "ip -> protocolo"
}
PORTNAMES = {
    53: "DNS", 80: "HTTP", 443: "HTTPS", 123: "NTP", 22: "SSH", 21: "FTP",
    23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 993: "IMAPS",
    5228: "Google", 1900: "SSDP", 5353: "mDNS", 67: "DHCP", 68: "DHCP",
    853: "DoT", 3478: "STUN", 8080: "HTTP-alt", 1883: "MQTT", 554: "RTSP",
    3389: "RDP", 445: "SMB", 139: "NetBIOS",
}
INSEGURO = {
    23: "Telnet (texto puro)", 21: "FTP (texto puro)",
    80: "HTTP (sem criptografia)", 110: "POP3 (texto puro)",
    143: "IMAP (texto puro)", 161: "SNMP", 445: "SMB exposto",
}
CRED_RE = re.compile(rb"(?i)(password=|senha=|passwd=|token=|authorization:\s*basic)")

# Tipos de enlace (linktype) suportados na decodificação
LINK_ETHERNET = 1
LINK_RAW = (101, 228, 229)  # IP puro (PCAPdroid usa 101)
LINK_80211 = 105
LINK_SLL = 113
LINK_RADIOTAP = 127
LINKS_OK = {LINK_ETHERNET, LINK_80211, LINK_SLL, LINK_RADIOTAP, *LINK_RAW}


def dns_name(d, i):
    out = []
    try:
        for _ in range(60):
            length = d[i]
            if length == 0 or length & 0xC0:
                break
            out.append(d[i + 1:i + 1 + length].decode("ascii", "replace"))
            i += length + 1
    except IndexError:
        pass
    return ".".join(out)


def sni(d):
    try:
        if len(d) < 44 or d[0] != 0x16 or d[5] != 1:
            return None
        i = 43
        i += 1 + d[i]
        i += 2 + struct.unpack(">H", d[i:i + 2])[0]
        i += 1 + d[i]
        end = i + 2 + struct.unpack(">H", d[i:i + 2])[0]
        i += 2
        while i + 4 <= end:
            t, length = struct.unpack(">HH", d[i:i + 4])
            i += 4
            if t == 0:
                n = struct.unpack(">H", d[i + 3:i + 5])[0]
                return d[i + 5:i + 5 + n].decode("ascii", "replace")
            i += length
    except (IndexError, struct.error):
        return None
    return None


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def dhcp_info(data):
    """Decodifica uma resposta DHCP (servidor -> cliente).

    Retorna dict com tipo, servidor (opção 54), roteador (3), dns (6) e o
    IP oferecido, ou None se não for uma resposta DHCP válida.
    """
    if len(data) < 240 or data[0] != 2 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    r = {"ip_oferecido": socket.inet_ntoa(data[16:20]), "tipo": None,
         "servidor": None, "roteador": None, "dns": []}
    i = 240
    while i < len(data):
        op = data[i]
        if op == 255:
            break
        if op == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        n = data[i + 1]
        v = data[i + 2:i + 2 + n]
        if op == 53 and n >= 1:
            r["tipo"] = {2: "OFFER", 5: "ACK", 6: "NAK"}.get(v[0], str(v[0]))
        elif op == 54 and n == 4:
            r["servidor"] = socket.inet_ntoa(v)
        elif op == 3 and n >= 4:
            r["roteador"] = socket.inet_ntoa(v[:4])
        elif op == 6 and n >= 4:
            r["dns"] = [socket.inet_ntoa(v[k:k + 4]) for k in range(0, n - 3, 4)]
        i += 2 + n
    return r


def parse_arp(d, r):
    """Pacote ARP (Ethernet/IPv4). Preenche r e retorna r, ou None."""
    if len(d) < 28 or d[0:2] != b"\x00\x01" or d[2:4] != b"\x08\x00":
        return None
    op = struct.unpack(">H", d[6:8])[0]
    sha, spa = mac_str(d[8:14]), socket.inet_ntoa(d[14:18])
    tpa = socket.inet_ntoa(d[24:28])
    r.update(proto="ARP", app="ARP", src=spa, dst=tpa,
             arp={"op": op, "ip": spa, "mac": sha})
    if op == 1:
        r["info"] = f"Quem tem {tpa}? Diga a {spa}"
    else:
        r["info"] = f"{spa} está em {sha}"
    return r


def parse_80211(f, r):
    """Quadro 802.11 (gerência/controle/dados). Marca deauth e disassoc."""
    if len(f) < 24:
        return None
    fc = f[0]
    tipo, sub = (fc >> 2) & 3, (fc >> 4) & 0xF
    r.update(proto="802.11", dst=mac_str(f[4:10]), src=mac_str(f[10:16]))
    r["bssid"] = mac_str(f[16:22])
    if tipo == 0 and sub in (10, 12):
        motivo = struct.unpack("<H", f[24:26])[0] if len(f) >= 26 else 0
        nome = "Deauth" if sub == 12 else "Disassoc"
        r.update(app=nome, wifi="deauth",
                 info=f"{nome} motivo {motivo} (BSSID {r['bssid']})")
    elif tipo == 0 and sub == 8:
        ssid = ""
        if len(f) >= 38 and f[36] == 0:
            ssid = f[38:38 + f[37]].decode("utf-8", "replace")
        r.update(app="Beacon", info="Beacon " + (ssid or "(oculta)"))
    else:
        r.update(app={0: "Gerência", 1: "Controle", 2: "Dados"}.get(tipo, "802.11"),
                 info=f"tipo {tipo} subtipo {sub}")
    return r


def parse(pkt, link=None):
    """Decodifica um pacote conforme o tipo de enlace.

    Suporta 101/228/229 (IP puro, PCAPdroid), 1 (Ethernet, com VLAN e ARP),
    113 (Linux cooked), 105 (802.11) e 127 (radiotap + 802.11).
    """
    link = LINK[0] if link is None else link
    r = {"len": len(pkt)}
    if link == LINK_RADIOTAP:
        if len(pkt) < 4:
            return None
        rt_len = struct.unpack("<H", pkt[2:4])[0]
        return parse_80211(pkt[rt_len:], r)
    if link == LINK_80211:
        return parse_80211(pkt, r)
    if link in (LINK_ETHERNET, LINK_SLL):
        if link == LINK_ETHERNET:
            if len(pkt) < 14:
                return None
            etype, off = struct.unpack(">H", pkt[12:14])[0], 14
            if etype == 0x8100 and len(pkt) >= 18:  # VLAN 802.1Q
                etype, off = struct.unpack(">H", pkt[16:18])[0], 18
        else:
            if len(pkt) < 16:
                return None
            etype, off = struct.unpack(">H", pkt[14:16])[0], 16
        if etype == 0x0806:
            return parse_arp(pkt[off:], r)
        if etype not in (0x0800, 0x86DD):
            return None
        pkt = pkt[off:]
    if not pkt:
        return None
    v = pkt[0] >> 4
    if v == 4:
        if len(pkt) < 20:
            return None
        ihl = (pkt[0] & 15) * 4
        if ihl < 20 or len(pkt) < ihl:
            return None
        p = pkt[9]
        r["src"] = socket.inet_ntoa(pkt[12:16])
        r["dst"] = socket.inet_ntoa(pkt[16:20])
        pl = pkt[ihl:]
    elif v == 6:
        if len(pkt) < 40:
            return None
        p = pkt[6]
        r["src"] = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
        r["dst"] = socket.inet_ntop(socket.AF_INET6, pkt[24:40])
        pl = pkt[40:]
    else:
        return None
    r["proto"] = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(p, str(p))
    info = ""
    if p == 58 and pl[:1] == b"\x86":  # ICMPv6 tipo 134: anúncio de roteador
        r.update(ra=1, app="IPv6-RA", info=f"Anúncio de roteador IPv6 de {r['src']}")
        return r
    if p in (6, 17) and len(pl) >= 8:
        sp, dp = struct.unpack(">HH", pl[:4])
        r["sp"], r["dp"] = sp, dp
        if p == 6:
            if len(pl) < 20:
                r["info"] = ""
                return r
            off = (pl[12] >> 4) * 4
            data = pl[off:] if len(pl) >= off else b""
            if pl[13] & 0x12 == 0x02:  # SYN sem ACK: início de conexão
                r["syn"] = 1
        else:
            data = pl[8:]
        svc = PORTNAMES.get(dp) or PORTNAMES.get(sp)
        if svc:
            r["app"] = svc
        ins = INSEGURO.get(dp) or INSEGURO.get(sp)
        if ins:
            r["inseguro"] = ins
        if p == 17 and 53 in (sp, dp) and len(data) > 12:
            q = dns_name(data, 12)
            if q:
                resp = data[2] & 0x80
                info = ("resposta " if resp else "consulta ") + q
                r["dom"] = q if not resp else None
        elif p == 17 and sp == 67 and dp == 68:
            d = dhcp_info(data)
            if d:
                r["dhcp"] = d
                info = (f"DHCP {d['tipo']} de {d['servidor'] or r['src']}: "
                        f"{d['ip_oferecido']} gw {d['roteador']}")
        elif p == 6 and data:
            s = sni(data)
            if s:
                info = "TLS -> " + s
                r["dom"] = s
                r["app"] = "HTTPS"
            elif data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                m = re.search(rb"\r\nHost: ([^\r]+)", data[:2000])
                h = m.group(1).decode("ascii", "replace") if m else ""
                info = data.split(b"\r\n", 1)[0].decode("ascii", "replace")[:70] + " @" + h
                r["dom"] = h
                r["app"] = "HTTP"
                if CRED_RE.search(data[:1500]):
                    r["alerta_cred"] = 1
    r["info"] = info
    return r


AO_VIVO = "ao vivo"


class Detector:
    """Detecções defensivas sobre os pacotes decodificados.

    Usa o horário do próprio pacote, então funciona igual na captura ao vivo
    e na análise de um .pcap importado.
      - deauth/disassoc em rajada (802.11 / radiotap)
      - ARP spoofing (IP que muda de MAC em pacotes ARP)
      - DHCP falso (mais de um servidor DHCP respondendo)
      - tráfego inseguro (primeira ocorrência de cada protocolo)
      - varredura de portas (um IP tentando muitas portas de outro)
      - anúncio de roteador IPv6 vindo de mais de uma origem (RA falso)
      - possível túnel por DNS (nomes consultados longos demais)

    O estado (mapa ARP, servidores DHCP, janela de deauth) é separado por
    contexto: um para a captura ao vivo e um novo para cada arquivo
    importado. Assim, dois .pcap de redes diferentes não se misturam. Na
    captura ao vivo, entradas sem novidade há mais de EXPIRA_S somem.
    """
    JANELA_DEAUTH = 10.0   # segundos
    LIMIAR_DEAUTH = 15     # quadros na janela
    EXPIRA_S = 3600.0      # validade das entradas ao vivo (ARP/DHCP)
    MAX_ARQUIVOS = 5       # contextos de arquivos importados guardados
    JANELA_SCAN = 10.0     # segundos
    LIMIAR_SCAN = 30       # portas diferentes do mesmo par origem/destino
    DNS_LONGO = 60         # caracteres no nome consultado
    DNS_ROTULO = 40        # caracteres num pedaço do nome

    def __init__(self):
        self.lock = threading.Lock()
        self._zerar()

    @staticmethod
    def _ctx_novo():
        return {"deauth": collections.deque(), "arp": {}, "dhcp": {},
                "scan": {}, "ra": {}, "dns_longo": set()}

    def _zerar(self):
        self.ctx = {}
        self.deauth_total = 0
        self.eventos = collections.deque(maxlen=200)

    def reset(self):
        with self.lock:
            self._zerar()

    def novo_contexto(self, nome):
        """Começa um contexto limpo (usado a cada arquivo importado)."""
        with self.lock:
            self.ctx.pop(nome, None)
            self.ctx[nome] = self._ctx_novo()
            arquivos = [k for k in self.ctx if k != AO_VIVO]
            for k in arquivos[:-self.MAX_ARQUIVOS]:
                del self.ctx[k]

    def esquecer(self, nome):
        with self.lock:
            self.ctx.pop(nome, None)

    def _expirar(self, ctx, ts):
        for tab in (ctx["arp"], ctx["dhcp"]):
            for k in [k for k, v in tab.items() if ts - v["visto"] > self.EXPIRA_S]:
                del tab[k]

    def _evento(self, ts, nivel, tipo, msg, origem):
        self.eventos.append({"ts": ts, "nivel": nivel, "tipo": tipo, "msg": msg,
                             "origem": origem})
        return (nivel, tipo, msg)

    def processar(self, r, contexto=AO_VIVO):
        """Retorna lista de (nivel, tipo, msg) a virar alerta."""
        ts = r.get("t") or time.time()
        achados = []
        with self.lock:
            ctx = self.ctx.get(contexto)
            if ctx is None:
                ctx = self.ctx[contexto] = self._ctx_novo()
            if contexto == AO_VIVO:
                self._expirar(ctx, ts)
            if r.get("wifi") == "deauth":
                self.deauth_total += 1
                dq = ctx["deauth"]
                dq.append((ts, r.get("bssid")))
                while dq and ts - dq[0][0] > self.JANELA_DEAUTH:
                    dq.popleft()
                if len(dq) == self.LIMIAR_DEAUTH:
                    alvos = collections.Counter(b for _, b in dq)
                    bssid = alvos.most_common(1)[0][0]
                    achados.append(self._evento(
                        ts, "alto", "deauth",
                        f"Rajada de {len(dq)} quadros deauth/disassoc "
                        f"em {self.JANELA_DEAUTH:.0f}s (BSSID {bssid}): "
                        f"possível ataque de desautenticação.", contexto))
            arp = r.get("arp")
            if arp and arp["ip"] != "0.0.0.0":
                antigo = ctx["arp"].get(arp["ip"])
                if antigo and antigo["mac"] != arp["mac"]:
                    achados.append(self._evento(
                        ts, "alto", "arp_spoof",
                        f"{arp['ip']} mudou de MAC {antigo['mac']} -> {arp['mac']} "
                        f"(possível ARP spoofing)", contexto))
                ctx["arp"][arp["ip"]] = {"mac": arp["mac"], "visto": ts}
            dh = r.get("dhcp")
            if dh:
                srv = dh.get("servidor") or r.get("src")
                novo = srv not in ctx["dhcp"]
                ctx["dhcp"][srv] = dict(dh, visto=ts)
                if novo and len(ctx["dhcp"]) > 1:
                    achados.append(self._evento(
                        ts, "alto", "dhcp_falso",
                        f"Mais de um servidor DHCP respondendo: "
                        f"{', '.join(sorted(ctx['dhcp']))}. Um deles pode ser "
                        f"falso (gw oferecido por {srv}: {dh.get('roteador')}).",
                        contexto))
            if r.get("syn") and r.get("dp"):
                chave = (r.get("src"), r.get("dst"))
                janela = ctx["scan"].setdefault(chave, {})
                janela[r["dp"]] = ts
                for porta in [k for k, t in janela.items()
                              if ts - t > self.JANELA_SCAN]:
                    del janela[porta]
                if len(janela) == self.LIMIAR_SCAN:
                    achados.append(self._evento(
                        ts, "alto", "varredura",
                        f"{chave[0]} tentou {len(janela)} portas diferentes de "
                        f"{chave[1]} em {self.JANELA_SCAN:.0f}s: varredura de "
                        f"portas na rede.", contexto))
                if len(ctx["scan"]) > 2000:
                    ctx["scan"].clear()
            if r.get("ra"):
                novo = r["src"] not in ctx["ra"]
                ctx["ra"][r["src"]] = ts
                if novo and len(ctx["ra"]) > 1:
                    achados.append(self._evento(
                        ts, "alto", "ra_falso",
                        f"Mais de um roteador IPv6 se anunciando: "
                        f"{', '.join(sorted(ctx['ra']))}. Um deles pode ser "
                        f"falso (ataque por IPv6).", contexto))
            dom = r.get("dom")
            if dom and r.get("app") != "HTTPS" and r.get("app") != "HTTP" and (
                    len(dom) > self.DNS_LONGO or
                    max(map(len, dom.split("."))) > self.DNS_ROTULO):
                base = ".".join(dom.rstrip(".").split(".")[-2:])
                if base not in ctx["dns_longo"] and len(ctx["dns_longo"]) < 500:
                    ctx["dns_longo"].add(base)
                    achados.append(self._evento(
                        ts, "medio", "dns_tunel",
                        f"Consulta DNS com nome muito longo para {base} "
                        f"({len(dom)} caracteres): pode ser túnel/vazamento "
                        f"de dados por DNS.", contexto))
            if r.get("inseguro"):
                achados.append(("baixo", "inseguro",
                                f"{r['inseguro']} visto ({r.get('dst')}:"
                                f"{r.get('dp')})"))
        return achados

    def resumo(self):
        with self.lock:
            contextos = {
                k: {"arp": {ip: v["mac"] for ip, v in c["arp"].items()},
                    "servidores_dhcp": sorted(c["dhcp"])}
                for k, c in self.ctx.items()}
            dhcp, arp = {}, {}
            for k, c in self.ctx.items():
                for srv, v in c["dhcp"].items():
                    dhcp[srv] = dict(v, origem=k)
                arp.update({ip: v["mac"] for ip, v in c["arp"].items()})
            return {"deauth_total": self.deauth_total,
                    "servidores_dhcp": dhcp, "arp": arp,
                    "contextos": contextos,
                    "eventos": list(self.eventos)[::-1]}


DET = Detector()


def _podar(contador, limite=MAX_CHAVES):
    """Mantém o Counter abaixo do limite descartando as menores contagens.

    Poda para 80% do limite de uma vez, para não repetir o trabalho a cada
    pacote novo.
    """
    if len(contador) > limite:
        manter = contador.most_common(int(limite * 0.8))
        contador.clear()
        contador.update(dict(manter))


def add(ts, raw, link=None, origem="", contexto=AO_VIVO):
    """Decodifica, guarda e analisa um pacote. Retorna o registro ou None."""
    link = LINK[0] if link is None else link
    r = parse(raw, link)
    if not r:
        return None
    cred = None
    with LOCK:
        SEQ[0] += 1
        r["n"] = SEQ[0]
        r["t"] = ts
        r["raw"] = raw
        r["link"] = link
        PK.append(r)
        ST["pkts"] += 1
        ST["bytes"] += r["len"]
        ST["inicio"] = ST["inicio"] or r["t"]
        ST["proto"][r.get("app") or r["proto"]] += 1
        for h in (r["src"], r["dst"]):
            ST["hosts"][h] += r["len"]
        if r.get("dom"):
            ST["dominios"][r["dom"]] += 1
        _podar(ST["hosts"])
        _podar(ST["dominios"])
        if r.get("dp"):
            ST["portas"][r["dp"]] += 1
        if r.get("inseguro"):
            ST["inseguro"][r["inseguro"]] += 1
            ST["inseguro_host"][f"{r['src']} -> {r['inseguro']}"] += 1
            _podar(ST["inseguro_host"])
        if r.get("alerta_cred"):
            cred = r.get("dom", "?")
    # alertas fora do LOCK de captura
    pre = f"[{origem}] " if origem else ""
    if cred:
        alerta("alto", "credencial",
               f"{pre}Possível senha/token em HTTP para {cred}", dedup_s=300)
    for nivel, tipo, msg in DET.processar(r, contexto):
        chave = r.get("inseguro") if tipo == "inseguro" else None
        alerta(nivel, tipo, pre + msg, dedup_s=600 if chave else 60, chave=chave)
    return r


def limpar_captura():
    with LOCK:
        PK.clear()
        ST.update(pkts=0, bytes=0, inicio=None)
        for k in ("proto", "hosts", "dominios", "portas", "inseguro",
                  "inseguro_host"):
            ST[k].clear()
    DET.reset()


# Magics PCAP: (bytes) -> (ordem struct, divisor de fração de tempo)
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 1e6), b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\x3c\x4d": (">", 1e9), b"\x4d\x3c\xb2\xa1": ("<", 1e9),
}


def ler_pcap(dados):
    """Lê um arquivo .pcap (clássico) ou .pcapng.

    Retorna lista de (timestamp, bytes, linktype). Lança ValueError se o
    formato não for reconhecido.
    """
    if dados[:4] in PCAP_MAGICS:
        order, div = PCAP_MAGICS[dados[:4]]
        if len(dados) < 24:
            raise ValueError("arquivo .pcap truncado")
        link = struct.unpack(order + "I", dados[20:24])[0]
        out, i = [], 24
        while i + 16 <= len(dados):
            ts, frac, incl, _ = struct.unpack(order + "IIII", dados[i:i + 16])
            if incl > 262144 or i + 16 + incl > len(dados):
                break
            out.append((ts + frac / div, dados[i + 16:i + 16 + incl], link))
            i += 16 + incl
        return out
    if dados[:4] == b"\x0a\x0d\x0d\x0a":
        return _ler_pcapng(dados)
    raise ValueError("formato não reconhecido (use .pcap ou .pcapng)")


def _ler_pcapng(dados):
    if len(dados) < 12:
        raise ValueError("arquivo .pcapng truncado")
    bom = dados[8:12]
    order = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
    ifaces = []  # (linktype, divisor)
    out, i = [], 0
    ultimo_ts = None  # o Simple Packet não tem horário: herda o do anterior
    while i + 12 <= len(dados):
        btype, blen = struct.unpack(order + "II", dados[i:i + 8])
        if blen < 12 or i + blen > len(dados):
            break
        corpo = dados[i + 8:i + blen - 4]
        if btype == 0x0A0D0D0A:          # Section Header: nova seção
            ifaces = []
        elif btype == 1 and len(corpo) >= 8:  # Interface Description
            link = struct.unpack(order + "H", corpo[0:2])[0]
            div = 1e6
            j = 8
            while j + 4 <= len(corpo):
                oc, ol = struct.unpack(order + "HH", corpo[j:j + 4])
                if oc == 0:
                    break
                if oc == 9 and ol >= 1:   # if_tsresol
                    res = corpo[j + 4]
                    div = 2.0 ** (res & 0x7F) if res & 0x80 else 10.0 ** res
                j += 4 + ((ol + 3) & ~3)
            ifaces.append((link, div))
        elif btype == 6 and len(corpo) >= 20:  # Enhanced Packet
            iface, hi, lo, cap, _ = struct.unpack(order + "IIIII", corpo[:20])
            if iface < len(ifaces):
                link, div = ifaces[iface]
                ultimo_ts = ((hi << 32) | lo) / div
                out.append((ultimo_ts, corpo[20:20 + cap], link))
        elif btype == 3 and ifaces and len(corpo) >= 4:  # Simple Packet
            link, _ = ifaces[0]
            if ultimo_ts is None:  # sem pacote anterior: única opção é o agora
                ultimo_ts = time.time()
            out.append((ultimo_ts, corpo[4:], link))
        i += blen
    return out


_N_IMPORT = [0]


def importar_pcap(dados, origem="arquivo"):
    """Passa os pacotes de um arquivo pelo mesmo pipeline da captura.

    Cada importação usa um contexto novo no detector: o ARP e o DHCP de um
    arquivo não são comparados com os de outro (podem ser de redes
    diferentes).
    """
    pacotes = ler_pcap(dados)
    with LOCK:
        _N_IMPORT[0] += 1
        contexto = f"{origem} #{_N_IMPORT[0]}"
    DET.novo_contexto(contexto)
    with DET.lock:
        antes = len(DET.eventos)
        primeiro = DET.eventos[0] if DET.eventos else None
    ok = ignorados = 0
    links = collections.Counter()
    for ts, raw, link in pacotes:
        links[link] += 1
        if link not in LINKS_OK:
            ignorados += 1
            continue
        try:
            if add(ts, raw, link, origem=origem, contexto=contexto):
                ok += 1
            else:
                ignorados += 1
        except Exception as e:
            print("pacote importado ignorado:", e)
            ignorados += 1
    return {"lidos": len(pacotes), "decodificados": ok, "contexto": contexto,
            "ignorados": ignorados, "tipos_enlace": dict(links),
            "deteccoes": _eventos_desde(antes, primeiro)}


def _eventos_desde(antes, primeiro):
    """Eventos do detector gerados depois do instante marcado."""
    with DET.lock:
        ev = list(DET.eventos)
    if ev and ev[0] is not primeiro:  # o deque girou ou foi limpo
        antes = 0 if primeiro is None or primeiro not in ev else ev.index(primeiro)
    return ev[antes:][-50:]


def pcap_bytes():
    """Gera um .pcap com os pacotes em memória.

    O formato clássico só aceita um tipo de enlace por arquivo; se houver
    mistura (ex.: captura ao vivo + arquivo 802.11 importado), exporta os
    pacotes do tipo de enlace mais recente.
    """
    with LOCK:
        L = list(PK)
    link = L[-1].get("link", LINK[0]) if L else LINK[0]
    partes = [struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, link)]
    for r in L:
        if r.get("link", link) != link:
            continue
        raw = r["raw"]
        partes.append(struct.pack("<IIII", int(r["t"]),
                                  int(r["t"] % 1 * 1e6), len(raw), len(raw)))
        partes.append(raw)
    return b"".join(partes)


def processar_datagrama(d, estado):
    """Trata um datagrama do Exportador UDP do PCAPdroid.

    'estado' guarda ordem de bytes, divisor e linktype entre datagramas.
    """
    if d[:4] in PCAP_MAGICS:
        estado["order"], estado["div"] = PCAP_MAGICS[d[:4]]
        estado["link"] = struct.unpack(estado["order"] + "I", d[20:24])[0]
        LINK[0] = estado["link"]
        d = d[24:]
    order, div = estado["order"], estado["div"]
    n = 0
    while len(d) >= 16:
        ts, frac, incl, _orig = struct.unpack(order + "IIII", d[:16])
        if incl > 70000 or 16 + incl > len(d):
            break
        try:
            if add(ts + frac / div, d[16:16 + incl], estado["link"]):
                n += 1
        except Exception as e:
            print("pacote ignorado:", e)
        d = d[16 + incl:]
    return n


def udp_loop(porta=None, pronto=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    porta = UDP_PORT if porta is None else porta
    try:
        s.bind(("127.0.0.1", porta))
    except OSError:
        print(f"Aviso: porta de captura {porta} em uso; a captura ao vivo "
              f"ficará indisponível nesta instância.")
        return
    if pronto is not None:
        pronto.append(s.getsockname()[1])
    estado = {"order": "<", "div": 1e6, "link": LINK[0]}
    while True:
        try:
            d, _ = s.recvfrom(70000)
        except OSError:
            continue
        try:
            processar_datagrama(d, estado)
        except Exception as e:
            print("datagrama ignorado:", e)


# ---------------------------------------------------------------- Rede
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def termux(cmd, *args):
    from shutil import which
    if not which(cmd):
        return None
    try:
        out = subprocess.run([cmd, *args], capture_output=True, text=True,
                             timeout=20)
        return json.loads(out.stdout)
    except Exception:
        return None


def gateway():
    try:
        out = subprocess.run(["ip", "route"], capture_output=True,
                             text=True, timeout=5).stdout
        m = re.search(r"default via (\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    ip = local_ip()
    return ip.rsplit(".", 1)[0] + ".1" if ip else None


# ---------------------------------------------------------------- Redes
# Uma "rede" é identificada por gateway + MAC do gateway (quando o Android
# deixa ler) + SSID do Wi-Fi (ou BSSID, se o SSID vier oculto). O BSSID não
# entra quando há SSID porque redes mesh trocam de BSSID dentro da mesma casa.
SSID_INVALIDOS = {"", "<unknown ssid>", "0x", "null", "none"}
BSSID_INVALIDOS = {"", "02:00:00:00:00:00", "00:00:00:00:00:00"}
REDE_TTL = 30.0
_REDE = {"ts": 0.0, "rede": None, "id_anterior": None}
_REDE_LOCK = threading.Lock()
REDE_ID_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def coletar_rede():
    """Lê do aparelho os dados que identificam a rede atual."""
    gw = gateway() or ""
    gw_mac = dict(arp_table()).get(gw, "") if gw else ""
    w = termux("termux-wifi-connectioninfo") or {}
    if not isinstance(w, dict):
        w = {}
    return {"gateway": gw, "gw_mac": gw_mac, "ssid": w.get("ssid") or "",
            "bssid": w.get("bssid") or ""}


def _normaliza_rede(info):
    gw = str(info.get("gateway") or "").strip()
    gw_mac = str(info.get("gw_mac") or "").strip().lower()
    ssid = str(info.get("ssid") or "").strip().strip('"')
    if ssid.lower() in SSID_INVALIDOS:
        ssid = ""
    bssid = str(info.get("bssid") or "").strip().lower()
    if bssid in BSSID_INVALIDOS:
        bssid = ""
    return gw, gw_mac, ssid, bssid


def identificar_rede(info, agora=None):
    """Acha (ou cria) a rede correspondente a 'info'. Retorna dict ou None.

    O rede_id é um hash curto dos componentes vistos na criação; fica salvo
    na tabela redes, então continua estável mesmo que o MAC do gateway passe
    a aparecer depois.
    """
    gw, gw_mac, ssid, bssid = _normaliza_rede(info)
    if not gw:
        return None
    wifi = ssid or bssid
    agora = agora or time.time()
    with DBLOCK:
        c = db()
        cand = [dict(r) for r in c.execute(
            "SELECT * FROM redes WHERE gateway=? AND wifi=? ORDER BY ultimo DESC",
            (gw, wifi))]
        escolhida = None
        if gw_mac:
            escolhida = next((r for r in cand if r["gw_mac"] == gw_mac), None)
            if not escolhida:
                escolhida = next((r for r in cand if not r["gw_mac"]), None)
                if escolhida:
                    c.execute("UPDATE redes SET gw_mac=? WHERE rede_id=?",
                              (gw_mac, escolhida["rede_id"]))
                    escolhida["gw_mac"] = gw_mac
        elif cand:
            escolhida = cand[0]
        if not escolhida:
            rid = hashlib.sha1(f"{gw}|{gw_mac}|{wifi}".encode()).hexdigest()[:10]
            nome = ssid or f"Rede {gw}"
            c.execute("INSERT OR IGNORE INTO redes(rede_id,nome,gateway,gw_mac,wifi,"
                      "ssid,bssid,primeiro,ultimo) VALUES(?,?,?,?,?,?,?,?,?)",
                      (rid, nome, gw, gw_mac, wifi, ssid, bssid, agora, agora))
            escolhida = dict(c.execute("SELECT * FROM redes WHERE rede_id=?",
                                       (rid,)).fetchone())
        c.execute("UPDATE redes SET ultimo=?, bssid=COALESCE(NULLIF(?,''),bssid) "
                  "WHERE rede_id=?", (agora, bssid, escolhida["rede_id"]))
        c.commit()
        c.close()
    escolhida["id"] = escolhida["rede_id"]
    return escolhida


def rede_atual(forcar=False):
    """Rede em que o aparelho está agora (com cache de REDE_TTL segundos).

    Quando a rede muda, o contexto ao vivo do detector é zerado para não
    comparar o ARP/DHCP da rede nova com o da anterior.
    """
    with _REDE_LOCK:
        if not forcar and time.time() - _REDE["ts"] < REDE_TTL:
            return _REDE["rede"]
    rede = identificar_rede(coletar_rede())
    with _REDE_LOCK:
        novo_id = rede["id"] if rede else None
        mudou = _REDE["id_anterior"] is not None and novo_id != _REDE["id_anterior"]
        _REDE.update(ts=time.time(), rede=rede, id_anterior=novo_id)
    if mudou:
        DET.esquecer(AO_VIVO)
    return rede


def rede_id_atual():
    r = rede_atual()
    return r["id"] if r else None


def listar_redes():
    atual = rede_id_atual()
    with DBLOCK:
        c = db()
        rows = [dict(r) for r in c.execute("SELECT * FROM redes ORDER BY ultimo DESC")]
        cont = dict(c.execute("SELECT rede_id, COUNT(*) FROM dispositivos "
                              "GROUP BY rede_id").fetchall())
        c.close()
    for r in rows:
        r["dispositivos"] = cont.get(r["rede_id"], 0)
        r["atual"] = r["rede_id"] == atual
    return {"atual": atual, "redes": rows}


def valida_rede_id(rid):
    rid = str(rid or "").strip()
    if not REDE_ID_RE.match(rid):
        raise ValueError("identificador de rede inválido")
    return rid


def nome_rede(rid):
    if not rid:
        return None
    with DBLOCK:
        c = db()
        row = c.execute("SELECT nome FROM redes WHERE rede_id=?", (rid,)).fetchone()
        c.close()
    return row["nome"] if row else rid


def renomear_rede(rid, nome):
    rid = valida_rede_id(rid)
    nome = re.sub(r"\s+", " ", str(nome or "")).strip()[:60]
    if not nome:
        raise ValueError("informe um nome")
    with DBLOCK:
        c = db()
        n = c.execute("UPDATE redes SET nome=? WHERE rede_id=?", (nome, rid)).rowcount
        c.commit()
        c.close()
    if not n:
        raise ValueError("rede não encontrada")
    with _REDE_LOCK:
        if _REDE["rede"] and _REDE["rede"]["id"] == rid:
            _REDE["rede"]["nome"] = nome
    return {"rede_id": rid, "nome": nome}


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
PUBLICO_OK = {"ping", "traceroute", "mtr", "dig", "whois", "headers", "cert"}
PRIVADO_OK = {"nmap_hosts", "nmap_rapido", "nmap_servicos", "nmap_todas",
              "nmap_scripts", "nmap_vuln"}


def valida_alvo(tool, alvo):
    """Valida o alvo conforme a ferramenta. Lança ValueError se inseguro."""
    alvo = (alvo or "").strip()
    if not alvo or alvo.startswith("-"):
        raise ValueError("alvo inválido")
    if tool == "headers":
        u = urllib.parse.urlparse(alvo)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("URL deve começar com http:// ou https://")
        if not HOSTNAME_RE.match(u.hostname) and not _eh_ip(u.hostname):
            raise ValueError("host inválido na URL")
        return alvo
    # IP, CIDR ou hostname
    rede = None
    try:
        rede = ipaddress.ip_network(alvo, strict=False)
    except ValueError:
        if not HOSTNAME_RE.match(alvo):
            raise ValueError("alvo deve ser IP, CIDR ou hostname válido")
    exige_privado = tool in PRIVADO_OK or tool in ("inventario", "portas", "roteador")
    if exige_privado:
        if rede is None:
            raise ValueError("varredura só aceita IP ou faixa privada")
        if not (rede.is_private or rede.is_loopback):
            raise ValueError("varredura ativa só é permitida em faixas privadas "
                             "(sua rede). Alvo público recusado.")
        if rede.version == 4 and rede.prefixlen < 24:
            raise ValueError("limite a faixa a /24 (máx. 256 endereços)")
    return alvo


def _eh_ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def ssdp():
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    s.sendto(msg.encode(), ("239.255.255.250", 1900))
    f = {}
    try:
        while True:
            d, a = s.recvfrom(4096)
            t = d.decode("utf-8", "replace")

            def g(k, t=t):
                m = re.search(rf"(?im)^{k}:\s*(.+)$", t)
                return m.group(1).strip() if m else ""
            e = f.setdefault(a[0], {"ip": a[0], "servidor": g("SERVER"),
                                    "local": g("LOCATION"), "tipos": set()})
            e["tipos"].add(g("ST"))
    except socket.timeout:
        pass
    finally:
        s.close()
    return [dict(v, tipos=sorted(x for x in v["tipos"] if x)[:6]) for v in f.values()]


def mdns():
    nome = "_services._dns-sd._udp.local"
    q = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         + b"".join(bytes([len(p)]) + p.encode() for p in nome.split("."))
         + b"\x00\x00\x0c\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, ("224.0.0.251", 5353))
    res = set()
    try:
        while True:
            _, a = s.recvfrom(9000)
            res.add(a[0])
    except socket.timeout:
        pass
    finally:
        s.close()
    return sorted(res)


def cert(host):
    porta = 443
    if ":" in host and not host.count(":") > 1:
        host, p = host.rsplit(":", 1)
        if not p.isdigit() or not 0 < int(p) < 65536:
            raise ValueError("porta inválida")
        porta = int(p)
    valida_alvo("cert", host)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, porta), 8) as raw, \
                ctx.wrap_socket(raw, server_hostname=host) as s:
            ver, ciph = s.version(), s.cipher()[0]
    except (socket.timeout, OSError) as e:
        return {"erro": f"não foi possível conectar: {e}"}
    info, valido = {}, True
    try:
        c2 = ssl.create_default_context()
        with socket.create_connection((host, porta), 8) as raw, \
                c2.wrap_socket(raw, server_hostname=host) as s:
            info = s.getpeercert()
    except (ssl.SSLError, ssl.SSLCertVerificationError) as e:
        valido = str(e)
    except (socket.timeout, OSError) as e:
        return {"erro": f"não foi possível conectar: {e}"}
    r = {"tls": ver, "cifra": ciph, "cadeia_valida": valido}
    if info:
        def f(x):
            return ", ".join("=".join(i) for t in x for i in t)
        exp = ssl.cert_time_to_seconds(info["notAfter"])
        dias = int((exp - time.time()) / 86400)
        r.update(assunto=f(info["subject"]), emissor=f(info["issuer"]),
                 expira=info["notAfter"], dias_restantes=dias,
                 nomes=[v for k, v in info.get("subjectAltName", [])][:15])
    return r


COMMON = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 631,
          993, 995, 1883, 1900, 3306, 3389, 5000, 5353, 7547, 8000, 8008,
          8080, 8081, 8443, 8888, 9100, 49152, 62078]


def pscan(host, ports):
    from concurrent.futures import ThreadPoolExecutor
    res = []

    def chk(p):
        with socket.socket() as s:
            s.settimeout(1.2)
            if s.connect_ex((host, p)) == 0:
                res.append(p)

    with ThreadPoolExecutor(max_workers=64) as ex:
        ex.map(chk, ports)
    return [{"porta": p, "servico": PORTNAMES.get(p, "?")} for p in sorted(res)]


def wol(mac):
    m = bytes.fromhex(re.sub("[^0-9a-fA-F]", "", mac))
    if len(m) != 6:
        raise ValueError("MAC inválido")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(b"\xff" * 6 + m * 16, ("255.255.255.255", 9))
    s.close()
    return "Pacote mágico enviado para " + mac


def router_page(gw):
    import urllib.request
    out = {}
    for sch in ("http", "https"):
        try:
            ctx = ssl._create_unverified_context() if sch == "https" else None
            r = urllib.request.urlopen(f"{sch}://{gw}/", timeout=5, context=ctx)
            b = r.read(20000).decode("utf-8", "replace")
            t = re.search(r"(?is)<title>(.*?)</title>", b)
            out[sch] = {"status": r.status, "servidor": r.headers.get("Server"),
                        "titulo": t.group(1).strip() if t else None}
        except Exception as e:
            out[sch] = str(e)[:120]
    return out


def arp_table():
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True,
                             text=True, timeout=5).stdout
        res = []
        for ln in out.splitlines():
            m = re.match(r"(\S+).*lladdr (\S+)", ln)
            if m:
                res.append((m.group(1), m.group(2)))
        return res
    except Exception:
        return []


def hosts_da_faixa(faixa):
    """Lista os endereços IPv4 utilizáveis da faixa (respeita o prefixo)."""
    rede = ipaddress.ip_network(faixa, strict=False)
    if rede.version != 4:
        raise ValueError("o inventário só suporta IPv4")
    if rede.num_addresses > 256:
        raise ValueError("limite a faixa a /24 (máx. 256 endereços)")
    hosts = list(rede.hosts()) or [rede.network_address]
    return [str(h) for h in hosts]


def _ping(ip):
    """Um ping com 1 s de espera. No Android funciona sem root."""
    from shutil import which
    if not which("ping"):
        return False
    try:
        return subprocess.run(["ping", "-c", "1", "-W", "1", "--", ip],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, timeout=3).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


PORTAS_SONDA = (80, 443, 22, 8080, 53, 139, 445, 7547, 62078, 9100)


def host_vivo(ip, pinger=None, conectar=None):
    """True se o host responde a ping ou em alguma porta comum.

    Celulares costumam não ter porta aberta, por isso o ping vem primeiro.
    Porta recusada (ECONNREFUSED) também prova que o host está vivo.
    """
    if (pinger or _ping)(ip):
        return True

    def _conectar(ip_, porta):
        with socket.socket() as s:
            s.settimeout(0.6)
            return s.connect_ex((ip_, porta))
    conectar = conectar or _conectar
    for p in PORTAS_SONDA:
        rc = conectar(ip, p)
        if rc == 0 or rc == errno.ECONNREFUSED:
            return True
    return False


def inventario(faixa, sonda=None, tabela_arp=None, rede_id=None):
    """Varre a faixa, atualiza o inventário da rede atual e gera alertas.

    Tudo é separado por rede: o mesmo 192.168.0.10 na casa A e no cliente B
    são dispositivos diferentes, e nenhum gera alerta sobre o outro.
    'sonda' e 'tabela_arp' permitem injetar resultados simulados nos testes.
    """
    from concurrent.futures import ThreadPoolExecutor
    sonda = sonda or host_vivo
    rede_id = rede_id or rede_id_atual() or "sem-rede"
    ips = hosts_da_faixa(faixa)
    with ThreadPoolExecutor(max_workers=64) as ex:
        vivos = {ip for ip, ok in zip(ips, ex.map(sonda, ips)) if ok}

    arp = {ip: (m or "").lower()
           for ip, m in (arp_table() if tabela_arp is None else tabela_arp)}
    agora = time.time()
    novos, trocas = [], []
    with DBLOCK:
        c = db()
        for ip in sorted(vivos, key=lambda x: ipaddress.ip_address(x)):
            mac = arp.get(ip, "")
            fab = fabricante(mac)
            row = c.execute("SELECT * FROM dispositivos WHERE rede_id=? AND ip=? "
                            "ORDER BY ultimo DESC", (rede_id, ip)).fetchone()
            if not row:
                c.execute("INSERT OR REPLACE INTO dispositivos(rede_id,ip,mac,"
                          "fabricante,primeiro,ultimo) VALUES(?,?,?,?,?,?)",
                          (rede_id, ip, mac, fab, agora, agora))
                novos.append({"ip": ip, "mac": mac, "fabricante": fab})
                continue
            antigo = (row["mac"] or "").lower()
            if not mac or mac == antigo:
                # mesmo aparelho (ou MAC desconhecido nesta varredura)
                c.execute("UPDATE dispositivos SET ultimo=? WHERE rede_id=? AND ip=? "
                          "AND mac=?", (agora, rede_id, ip, row["mac"]))
                continue
            existe = c.execute("SELECT * FROM dispositivos WHERE rede_id=? AND ip=? "
                               "AND mac=?", (rede_id, ip, mac)).fetchone()
            if not antigo:
                # o MAC passou a ser conhecido: completa (ou mescla) o registro
                if existe:
                    c.execute("UPDATE dispositivos SET ultimo=?, fabricante=?, "
                              "autorizado=MAX(autorizado,?), "
                              "nome=COALESCE(NULLIF(nome,''),?), "
                              "primeiro=MIN(primeiro,?) WHERE rede_id=? AND ip=? "
                              "AND mac=?",
                              (agora, fab, row["autorizado"], row["nome"],
                               row["primeiro"], rede_id, ip, mac))
                    c.execute("DELETE FROM dispositivos WHERE rede_id=? AND ip=? "
                              "AND mac=''", (rede_id, ip))
                else:
                    c.execute("UPDATE dispositivos SET mac=?, fabricante=?, ultimo=? "
                              "WHERE rede_id=? AND ip=? AND mac=''",
                              (mac, fab, agora, rede_id, ip))
                continue
            # MAC diferente do último visto neste IP: outro aparelho (ou
            # spoofing). Não herda nome nem autorização do anterior; o
            # registro antigo fica como histórico.
            trocas.append({"ip": ip, "antes": row["mac"], "agora": mac})
            if existe:
                c.execute("UPDATE dispositivos SET ultimo=?, fabricante=? "
                          "WHERE rede_id=? AND ip=? AND mac=?",
                          (agora, fab, rede_id, ip, mac))
            else:
                c.execute("INSERT INTO dispositivos(rede_id,ip,mac,fabricante,"
                          "primeiro,ultimo) VALUES(?,?,?,?,?,?)",
                          (rede_id, ip, mac, fab, agora, agora))
        c.execute("INSERT INTO varreduras(ts,alvo,hosts,resumo,rede_id) "
                  "VALUES(?,?,?,?,?)",
                  (agora, faixa, len(vivos), json.dumps(sorted(vivos)), rede_id))
        aplicar_retencao(c, agora)
        c.commit()
        c.close()
    todos = listar_dispositivos(rede_id)
    for n in novos:
        alerta("medio", "novo_host",
               f"Novo dispositivo na rede: {n['ip']} ({n['fabricante'] or '?'})",
               rede_id=rede_id)
    for t in trocas:
        alerta("alto", "mac_trocado",
               f"{t['ip']} agora responde com MAC {t['agora']} "
               f"(antes {t['antes']}): aparelho trocado ou spoofing.",
               dedup_s=3600, rede_id=rede_id)
    return {"faixa": faixa, "rede_id": rede_id, "rede_nome": nome_rede(rede_id),
            "ativos": sorted(vivos, key=ipaddress.ip_address), "novos": novos,
            "macs_trocados": trocas, "inventario": todos}


def listar_dispositivos(rede_id):
    with DBLOCK:
        c = db()
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM dispositivos WHERE rede_id=? ORDER BY ultimo DESC",
            (rede_id,)).fetchall()]
        c.close()
    return rows


def check_arp():
    arp = arp_table()
    if not arp:
        return {"erro": "No Android 10+ a tabela ARP (ip neigh) vem vazia sem "
                        "root. Use o Inventário (varredura ativa), importe um "
                        ".pcap da rede ou use um roteador OpenWrt."}
    gw = gateway()
    gw_mac = dict(arp).get(gw)
    rede_id = rede_id_atual() or "sem-rede"
    achados, spoofs = [], []
    with DBLOCK:
        c = db()
        for ip, mac in arp:
            row = c.execute("SELECT mac FROM arp WHERE rede_id=? AND ip=?",
                            (rede_id, ip)).fetchone()
            if row and row["mac"] and row["mac"] != mac:
                msg = f"{ip} mudou de MAC {row['mac']} -> {mac} (possível ARP spoofing)"
                achados.append(msg)
                spoofs.append(msg)
            c.execute("INSERT OR REPLACE INTO arp(rede_id,ip,mac,visto) "
                      "VALUES(?,?,?,?)", (rede_id, ip, mac, time.time()))
        c.commit()
        c.close()
    macs = collections.Counter(m for _, m in arp)
    for m, n in macs.items():
        if n > 2 and m != gw_mac:  # o MAC do gateway responder por vários IPs é normal
            achados.append(f"MAC {m} responde por {n} IPs (possível spoofing)")
    for s in spoofs:
        alerta("alto", "arp_spoof", s, dedup_s=300, rede_id=rede_id)
    return {"tabela": arp, "alertas": achados, "rede_id": rede_id}


# ---------------------------------------------------------------- Histórico
def _varredura(row):
    if not row:
        return None
    d = dict(row)
    try:
        d["ips"] = json.loads(d.pop("resumo") or "[]")
    except ValueError:
        d["ips"] = []
    return d


def comparar_varreduras(horas=24, rede_id=None):
    """Compara a última varredura da rede com a de ~N horas atrás (mesma faixa).

    Se não houver uma tão antiga, usa a mais antiga disponível da faixa.
    Nunca compara redes diferentes, mesmo que usem a mesma faixa de IP.
    """
    rede_id = rede_id or rede_id_atual() or "sem-rede"
    with DBLOCK:
        c = db()
        atual = _varredura(c.execute(
            "SELECT * FROM varreduras WHERE rede_id=? ORDER BY id DESC LIMIT 1",
            (rede_id,)).fetchone())
        ref = None
        if atual:
            ref = _varredura(c.execute(
                "SELECT * FROM varreduras WHERE rede_id=? AND alvo=? AND id<? "
                "AND ts<=? ORDER BY ts DESC LIMIT 1",
                (rede_id, atual["alvo"], atual["id"],
                 atual["ts"] - horas * 3600)).fetchone())
            if not ref:
                ref = _varredura(c.execute(
                    "SELECT * FROM varreduras WHERE rede_id=? AND alvo=? AND id<? "
                    "ORDER BY ts ASC LIMIT 1",
                    (rede_id, atual["alvo"], atual["id"])).fetchone())
        c.close()
    if not atual or not ref:
        return {"erro": "são necessárias ao menos duas varreduras da mesma "
                        "faixa nesta rede para comparar", "rede_id": rede_id}
    a, b = set(atual["ips"]), set(ref["ips"])
    return {"rede_id": rede_id,
            "atual": {k: atual[k] for k in ("id", "ts", "alvo", "hosts")},
            "referencia": {k: ref[k] for k in ("id", "ts", "alvo", "hosts")},
            "horas_entre": round((atual["ts"] - ref["ts"]) / 3600, 1),
            "novos": sorted(a - b, key=ipaddress.ip_address),
            "sumiram": sorted(b - a, key=ipaddress.ip_address),
            "mantidos": len(a & b)}


def listar_varreduras(lim=20, rede_id=None):
    rede_id = rede_id or rede_id_atual() or "sem-rede"
    with DBLOCK:
        c = db()
        rows = [_varredura(x) for x in c.execute(
            "SELECT * FROM varreduras WHERE rede_id=? ORDER BY id DESC LIMIT ?",
            (rede_id, lim))]
        c.close()
    return rows


def listar_alertas(rede_id=None, lim=100):
    """Alertas da rede indicada mais os que valem para todas (captura)."""
    with DBLOCK:
        c = db()
        if rede_id == "todas":
            q = c.execute("SELECT * FROM alertas ORDER BY id DESC LIMIT ?", (lim,))
        else:
            q = c.execute("SELECT * FROM alertas WHERE rede_id IS NULL OR rede_id=? "
                          "ORDER BY id DESC LIMIT ?", (rede_id or "", lim))
        rows = [dict(x) for x in q.fetchall()]
        c.close()
    return rows


# ---------------------------------------------------------------- Agenda
AGENDA_ESTADO = {"ultima": None, "ultimo_erro": None, "execucoes": 0,
                 "pausada": None}
AGENDA_LOCK = threading.Lock()
AGENDA_PADRAO = {"minutos": 0, "faixa": "", "rede_id": "", "rede_nome": ""}


def agenda_get():
    cfg = dict(AGENDA_PADRAO, **config_get("agenda", {}))
    with AGENDA_LOCK:
        est = dict(AGENDA_ESTADO)
    prox = None
    if cfg.get("minutos") and est["ultima"] and not est["pausada"]:
        prox = est["ultima"] + cfg["minutos"] * 60
    return dict(cfg, **est, proxima=prox)


def agenda_set(minutos, faixa="", rede=None):
    """Salva a agenda presa à rede atual (ou à 'rede' dada)."""
    try:
        minutos = int(minutos)
    except (TypeError, ValueError):
        raise ValueError("minutos inválido")
    if minutos != 0 and not 5 <= minutos <= 1440:
        raise ValueError("intervalo deve ser 0 (desligado) ou de 5 a 1440 minutos")
    faixa = (faixa or "").strip()
    if faixa:
        valida_alvo("inventario", faixa)
        hosts_da_faixa(faixa)
    cfg = dict(AGENDA_PADRAO, minutos=minutos, faixa=faixa)
    if minutos:
        rede = rede if rede is not None else rede_atual(forcar=True)
        if not rede or not rede.get("id"):
            raise ValueError("nenhuma rede identificada: conecte-se à rede que "
                             "deseja monitorar antes de agendar")
        cfg.update(rede_id=rede["id"], rede_nome=rede.get("nome") or rede["id"])
    config_set("agenda", cfg)
    with AGENDA_LOCK:
        AGENDA_ESTADO["pausada"] = None
    return cfg


def faixa_padrao():
    ip = local_ip()
    return ip.rsplit(".", 1)[0] + ".0/24" if ip else ""


def agenda_tick(agora=None, executar=None, rede=None):
    """Executa a varredura agendada se estiver na hora. Retorna True se rodou.

    A agenda só roda na rede em que foi configurada. Em qualquer outra rede
    (café, cliente, 4G) ela fica pausada e nada é varrido.
    """
    agora = agora or time.time()
    cfg = dict(AGENDA_PADRAO, **config_get("agenda", {}))
    if not cfg.get("minutos"):
        return False
    rede = rede if rede is not None else rede_atual()
    atual = rede.get("id") if rede else None
    if not cfg.get("rede_id") or atual != cfg["rede_id"]:
        if not cfg.get("rede_id"):
            motivo = "agenda sem rede definida; salve-a de novo na rede a monitorar"
        else:
            motivo = (f"agenda pausada: rede diferente (configurada em "
                      f"'{cfg['rede_nome']}', atual: "
                      f"'{(rede or {}).get('nome') or 'nenhuma'}')")
        with AGENDA_LOCK:
            ja = AGENDA_ESTADO["pausada"] == motivo
            AGENDA_ESTADO["pausada"] = motivo
        if not ja:
            alerta("medio", "agenda", motivo, dedup_s=3600, chave="pausada")
        return False
    with AGENDA_LOCK:
        AGENDA_ESTADO["pausada"] = None
        ult = AGENDA_ESTADO["ultima"]
        if ult and agora - ult < cfg["minutos"] * 60:
            return False
        AGENDA_ESTADO["ultima"] = agora
    faixa = cfg.get("faixa") or faixa_padrao()
    padrao = executar is None
    erro = None
    try:
        if not faixa:
            raise ValueError("sem rede para varrer")
        valida_alvo("inventario", faixa)
        if padrao:
            inventario(faixa, rede_id=atual)
            check_arp()
        else:
            executar(faixa)
    except Exception as e:
        erro = str(e)
        alerta("medio", "agenda", f"Varredura agendada falhou: {erro}",
               dedup_s=3600, rede_id=atual)
    with AGENDA_LOCK:
        AGENDA_ESTADO["ultimo_erro"] = erro
        AGENDA_ESTADO["execucoes"] += 1
    return True


def agenda_loop():
    while True:
        try:
            agenda_tick()
        except Exception as e:
            print("agenda:", e)
        time.sleep(20)


# ---------------------------------------------------------------- Relatório
def relatorio(completo_rede=True, rede_id=None):
    """Relatório consolidado (JSON) de uma rede: inventário, alertas,
    histórico, captura e detecções. Sem 'rede_id', usa a rede atual."""
    from shutil import which
    rede_id = rede_id or rede_id_atual() or "sem-rede"
    disp = listar_dispositivos(rede_id)
    alr = listar_alertas(rede_id, 200)
    with LOCK:
        dur = (PK[-1]["t"] - ST["inicio"]) if PK else 0
        cap = {"pacotes": ST["pkts"], "bytes": ST["bytes"],
               "duracao_s": round(dur, 1),
               "protocolos": ST["proto"].most_common(15),
               "hosts": ST["hosts"].most_common(20),
               "dominios": ST["dominios"].most_common(30),
               "portas": ST["portas"].most_common(15),
               "inseguro": ST["inseguro"].most_common(10),
               "inseguro_por_aparelho": ST["inseguro_host"].most_common(30)}
    ferr = ["nmap", "ping", "traceroute", "dig", "whois", "curl", "mtr",
            "iperf3", "termux-wifi-connectioninfo"]
    rede = {"ip": local_ip() or "sem rede", "gateway": gateway() or "sem rede"}
    if completo_rede:
        rede["wifi"] = termux("termux-wifi-connectioninfo")
    niveis = collections.Counter(a["nivel"] for a in alr)
    return {
        "kit": {"versao": VERSAO, "host": socket.gethostname(),
                "python": sys.version.split()[0]},
        "gerado": datetime.datetime.now().astimezone().isoformat(),
        "escopo": "Diagnóstico defensivo da rede e dos aparelhos do próprio "
                  "operador.",
        "rede_inventario": {"id": rede_id, "nome": nome_rede(rede_id),
                            "atual": rede_id == rede_id_atual()},
        "rede": rede,
        "ferramentas": {t: bool(which(t)) for t in ferr},
        "resumo": {"dispositivos": len(disp),
                   "nao_autorizados": sum(1 for d in disp if not d["autorizado"]),
                   "alertas": len(alr), "alertas_por_nivel": dict(niveis),
                   "pacotes": cap["pacotes"]},
        "dispositivos": disp,
        "alertas": alr,
        "varreduras": listar_varreduras(20, rede_id),
        "comparacao_24h": comparar_varreduras(24, rede_id),
        "agenda": agenda_get(),
        "captura": cap,
        "deteccoes": DET.resumo(),
        "mapa_sinal": mapa_sinal(rede_id),
        "linha_do_tempo": linha_do_tempo(rede_id, 50),
    }


# Comandos externos. '--' separa opções do alvo onde a ferramenta aceita.
# traceroute usa o modo UDP padrão, que funciona sem root no Android.
TOOLS = {
    "ping": lambda a: ["ping", "-c", "20", "-i", "0.5", "--", a],
    "traceroute": lambda a: ["traceroute", "-w", "2", "-q", "1", a],
    "mtr": lambda a: ["mtr", "-r", "-c", "10", "-w", "--", a],
    "nmap_hosts": lambda a: ["nmap", "-sn", "-T4", "--", a],
    "nmap_rapido": lambda a: ["nmap", "-F", "-T4", "--open", "--", a],
    "nmap_servicos": lambda a: ["nmap", "-sV", "--version-light", "-T4", "--open", "--", a],
    "nmap_todas": lambda a: ["nmap", "-p-", "-T4", "--open", "--", a],
    "nmap_scripts": lambda a: ["nmap", "-sV", "-sC", "-T4", "--open", "--", a],
    "nmap_vuln": lambda a: ["nmap", "-sV", "--script", "vuln", "-T4", "--", a],
    "whois": lambda a: ["whois", "--", a],
    "headers": lambda a: ["curl", "-sSIL", "--max-time", "10", "--", a],
}
TIMEOUTS = {"ping": 30, "nmap_todas": 600, "nmap_vuln": 600}


def dig_cmd(alvo):
    tipos = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    return ["dig", "+noall", "+answer", "+stats"] + \
        sum(([alvo, t] for t in tipos), [])


# ------------------------------------------- Ferramentas embutidas (stdlib)
# Usadas quando o pacote do Termux não está instalado, para o Kit funcionar
# logo depois de instalar, sem downloads extras.
DNS_TIPOS = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def servidor_dns():
    """Primeiro nameserver do sistema; no Android cai no DNS público."""
    for arq in (os.path.join(os.environ.get("PREFIX", "/usr"), "etc", "resolv.conf"),
                "/etc/resolv.conf"):
        try:
            with open(arq) as f:
                for linha in f:
                    partes = linha.split()
                    if len(partes) >= 2 and partes[0] == "nameserver":
                        ipaddress.ip_address(partes[1])
                        return partes[1]
        except (OSError, ValueError):
            continue
    return "8.8.8.8"


def dns_montar(nome, tipo, ident):
    cab = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(r)]) + r.encode("idna")
                 for r in nome.strip(".").split(".") if r) + b"\0"
    return cab + q + struct.pack("!HH", tipo, 1)


def dns_nome(msg, i, saltos=0):
    rotulos = []
    while True:
        if i >= len(msg) or saltos > 20:
            raise ValueError("resposta DNS inválida")
        n = msg[i]
        if n == 0:
            return ".".join(rotulos) + ".", i + 1
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[i:i + 2])[0] & 0x3FFF
            resto, _ = dns_nome(msg, ptr, saltos + 1)
            return ".".join(rotulos + [resto.rstrip(".")]) + ".", i + 2
        rotulos.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n


def dns_respostas(msg):
    """Lê a seção de respostas: lista de (nome, ttl, tipo, valor)."""
    _, flags, qd, an = struct.unpack("!HHHH", msg[:8])
    i = 12
    for _ in range(qd):
        _, i = dns_nome(msg, i)
        i += 4
    nomes = {v: k for k, v in DNS_TIPOS.items()}
    saida = []
    for _ in range(an):
        nome, i = dns_nome(msg, i)
        tipo, _, ttl, tam = struct.unpack("!HHIH", msg[i:i + 10])
        i += 10
        dado = msg[i:i + tam]
        if tipo == 1:
            valor = socket.inet_ntop(socket.AF_INET, dado)
        elif tipo == 28:
            valor = socket.inet_ntop(socket.AF_INET6, dado)
        elif tipo in (2, 5):
            valor = dns_nome(msg, i)[0]
        elif tipo == 15:
            valor = f"{struct.unpack('!H', dado[:2])[0]} {dns_nome(msg, i + 2)[0]}"
        elif tipo == 16:
            pedacos, j = [], 0
            while j < len(dado):
                pedacos.append(dado[j + 1:j + 1 + dado[j]].decode("utf-8", "replace"))
                j += 1 + dado[j]
            valor = " ".join(f'"{p}"' for p in pedacos)
        else:
            valor = dado.hex()
        saida.append((nome, ttl, nomes.get(tipo, str(tipo)), valor))
        i += tam
    return flags & 0xF, saida


def dig_embutido(alvo, servidor=None, porta=53, timeout=3):
    servidor = servidor or servidor_dns()
    yield f";; servidor: {servidor}"
    for tipo in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        ident = int.from_bytes(os.urandom(2), "big")
        with socket.socket(socket.AF_INET6 if ":" in servidor else socket.AF_INET,
                           socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t = time.monotonic()
            try:
                s.sendto(dns_montar(alvo, DNS_TIPOS[tipo], ident), (servidor, porta))
                msg, _ = s.recvfrom(4096)
            except OSError as e:
                yield f";; {tipo}: sem resposta ({e})"
                continue
        if len(msg) < 12 or struct.unpack("!H", msg[:2])[0] != ident:
            yield f";; {tipo}: resposta descartada (id não confere)"
            continue
        rcode, resp = dns_respostas(msg)
        for nome, ttl, t2, valor in resp:
            yield f"{nome}\t{ttl}\tIN\t{t2}\t{valor}"
        if rcode:
            yield f";; {tipo}: erro do servidor (rcode {rcode})"
    yield ";; fim da consulta"


def whois_consulta(servidor, alvo, porta=43, timeout=10):
    with socket.create_connection((servidor, porta), timeout=timeout) as s:
        s.sendall(alvo.encode("idna") + b"\r\n")
        partes = []
        while sum(map(len, partes)) < 200000:
            b = s.recv(4096)
            if not b:
                break
            partes.append(b)
    return b"".join(partes).decode("utf-8", "replace")


def whois_embutido(alvo, raiz="whois.iana.org", porta=43):
    """Pergunta à IANA quem cuida do domínio/IP e segue a indicação."""
    texto = whois_consulta(raiz, alvo, porta)
    indicado = None
    for linha in texto.splitlines():
        if linha.lower().startswith(("refer:", "whois:")):
            indicado = linha.split(":", 1)[1].strip()
            break
    if indicado and indicado != raiz:
        yield f"% servidor: {indicado}"
        texto = whois_consulta(indicado, alvo, porta)
    else:
        yield f"% servidor: {raiz}"
    yield from texto.splitlines()


def headers_embutido(alvo, timeout=10):
    import urllib.error
    import urllib.request
    url = alvo
    for _ in range(6):
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "kit-de-bolso"})

        class SemSeguir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        abridor = urllib.request.build_opener(SemSeguir)
        try:
            r = abridor.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            r = e
        yield f"HTTP {r.status} {r.reason}"
        for k, v in r.headers.items():
            yield f"{k}: {v}"
        yield ""
        destino = r.headers.get("Location")
        if r.status in (301, 302, 303, 307, 308) and destino:
            url = urllib.parse.urljoin(url, destino)
            continue
        return


EMBUTIDOS = {"dig": dig_embutido, "whois": whois_embutido,
             "headers": headers_embutido}


def run_stream(tool, alvo, wfile, flush):
    from shutil import which
    if tool == "dig":
        cmd = dig_cmd(alvo)
    else:
        cmd = TOOLS[tool](alvo)
    if not which(cmd[0]):
        if tool in EMBUTIDOS:
            # Versão em Python puro: funciona sem baixar pacote nenhum.
            wfile.write(f"(versão embutida do Kit; {cmd[0]} não está "
                        f"instalado)\n".encode())
            flush()
            try:
                for linha in EMBUTIDOS[tool](alvo):
                    wfile.write((linha + "\n").encode())
                    flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            except (OSError, ValueError) as e:
                wfile.write(f"erro: {e}\n".encode())
            return
        pacote = {"dig": "dnsutils", "ping": "inetutils"}.get(cmd[0], cmd[0])
        wfile.write(f"{cmd[0]} não instalado. Rode: pkg install {pacote}\n".encode())
        return
    limite = TIMEOUTS.get(tool, 120)
    if not RUN_SEM.acquire(timeout=5):
        wfile.write("muitas tarefas em execução; tente de novo em instantes\n".encode())
        return
    pr = None
    try:
        wfile.write(("$ " + " ".join(cmd) + "\n").encode())
        flush()
        pr = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                              bufsize=1, text=True, errors="replace")
        morto = threading.Timer(limite, pr.kill)
        morto.start()
        try:
            for line in pr.stdout:
                wfile.write(line.encode())
                flush()
        except (BrokenPipeError, ConnectionResetError):
            pr.kill()
        finally:
            morto.cancel()
        if tool == "mtr" and pr.poll() not in (0, None):
            wfile.write(b"\n(o mtr pode exigir root no Android; "
                        b"se veio vazio, use o traceroute ou o ping)\n")
    finally:
        if pr:
            if pr.poll() is None:
                pr.kill()
            # Fecha o pipe e recolhe o processo: o servidor agora fica dias
            # ligado em segundo plano e não pode acumular descritores/zumbis.
            pr.stdout.close()
            pr.wait()
        RUN_SEM.release()


# ---------------------------------------------------------------- App (PWA)
TEMA = "#0b0f0c"
VERDE = (0x5d, 0xff, 0x8f)
FUNDO = (0x0b, 0x0f, 0x0c)

ICONE_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
<rect width="100" height="100" fill="#0b0f0c"/>
<circle cx="50" cy="50" r="33" fill="none" stroke="#5dff8f" stroke-width="6"/>
<polyline points="24,52 38,52 44,38 52,66 58,46 62,52 76,52" fill="none"
 stroke="#5dff8f" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

_PULSO = [(24, 52), (38, 52), (44, 38), (52, 66), (58, 46), (62, 52), (76, 52)]


def _dist_seg(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return ((px - ax - t * dx) ** 2 + (py - ay - t * dy) ** 2) ** 0.5


_ICONES = {}


def icone_png(tam):
    """Gera o ícone do app em PNG (só stdlib: zlib + struct), com cache.

    Mesmo desenho do SVG: anel e linha de pulso verdes sobre fundo escuro.
    Ocupa o quadrado inteiro, então serve também como ícone 'maskable'.
    """
    if tam in _ICONES:
        return _ICONES[tam]
    esc = 100.0 / tam
    linhas = []
    for y in range(tam):
        linha = bytearray(b"\x00")
        py = (y + 0.5) * esc
        for x in range(tam):
            px = (x + 0.5) * esc
            d = abs(((px - 50) ** 2 + (py - 50) ** 2) ** 0.5 - 33)
            if d > 3 + esc:
                d2 = min(_dist_seg(px, py, *_PULSO[i], *_PULSO[i + 1])
                         for i in range(len(_PULSO) - 1)) if 20 < px < 80 and 34 < py < 70 else 99
                d = min(d, d2)
            # cobertura suave na borda do traço (anti-serrilhado)
            a = max(0.0, min(1.0, (3 - d) / esc + 0.5))
            linha += bytes(int(FUNDO[k] + (VERDE[k] - FUNDO[k]) * a) for k in range(3))
        linhas.append(bytes(linha))

    def bloco(tipo, dados):
        return (struct.pack(">I", len(dados)) + tipo + dados
                + struct.pack(">I", zlib.crc32(tipo + dados) & 0xFFFFFFFF))
    png = (b"\x89PNG\r\n\x1a\n"
           + bloco(b"IHDR", struct.pack(">IIBBBBB", tam, tam, 8, 2, 0, 0, 0))
           + bloco(b"IDAT", zlib.compress(b"".join(linhas), 9))
           + bloco(b"IEND", b""))
    _ICONES[tam] = png
    return png


def manifesto():
    return {
        "name": "Kit de Bolso do Técnico",
        "short_name": "Kit de Bolso",
        "description": "Diagnóstico e defesa da sua rede e dos seus aparelhos.",
        "lang": "pt-BR",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": TEMA,
        "theme_color": TEMA,
        "icons": [
            {"src": "/icone-192.png", "sizes": "192x192", "type": "image/png",
             "purpose": "any"},
            {"src": "/icone-512.png", "sizes": "512x512", "type": "image/png",
             "purpose": "any"},
            {"src": "/icone-512.png", "sizes": "512x512", "type": "image/png",
             "purpose": "maskable"},
            {"src": "/icone.svg", "sizes": "any", "type": "image/svg+xml"},
        ],
    }


# Link que abre o app Termux pelo navegador (intent do Android). Com o modo
# automático (kit --automatico liga), abrir o Termux já liga o servidor.
INTENT_TERMUX = ("intent:#Intent;action=android.intent.action.MAIN;"
                 "category=android.intent.category.LAUNCHER;package=com.termux;"
                 "component=com.termux/.app.TermuxActivity;end")

# O service worker não guarda a página principal em cache (ela leva o
# token). Ele só mostra um aviso quando o servidor do Termux está desligado.
SERVICE_WORKER = """// Kit de Bolso: service worker (v__VERSAO__)
const PAGINA_OFFLINE = `<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content=3><title>Kit de Bolso</title>
<body style="font-family:monospace;background:#0b0f0c;color:#b6f5c8;padding:20px">
<h2 style="color:#5dff8f">Kit de Bolso</h2>
<p>O servidor do Kit está desligado.</p>
<p><a href="__INTENT__" style="display:inline-block;padding:12px 16px;
background:#163d24;color:#c9ffd9;border:1px solid #2e7a47;border-radius:8px;
text-decoration:none">▶ Abrir o Termux</a></p>
<p>Com o modo automático ligado, só abrir o Termux já liga o Kit. Depois volte
para cá: esta tela tenta de novo sozinha a cada 3 segundos.</p>
<p style="font-size:12px;color:#7a9c85">Sem o automático, digite <code>kit</code>
no Termux. Para ligar o automático uma vez: <code>kit --automatico liga</code>.</p>
<p><a style="color:#5dff8f" href="/">Tentar agora</a></p>`;
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode !== 'navigate') return;
  e.respondWith(fetch(e.request).catch(() => new Response(PAGINA_OFFLINE,
    {headers: {'Content-Type': 'text/html; charset=utf-8'}})));
});
""".replace("__INTENT__", INTENT_TERMUX).replace("__VERSAO__", VERSAO)

# /abrir: ponte para quem chega de fora (index.html aberto como arquivo, outro
# site). A navegação feita pela própria página do Kit leva o cookie
# SameSite=Strict, que um link vindo de outro site não levaria. Não contém
# segredo nenhum.
PAGINA_ABRIR = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content="0;url=/"><title>Kit de Bolso</title>
<body style="font-family:monospace;background:#0b0f0c;color:#b6f5c8;padding:20px">
<p>Abrindo o Kit… <a style="color:#5dff8f" href="/">toque aqui</a> se não abrir.</p>"""

PUBLICAS = {
    "/manifest.webmanifest": "manifest",
    "/sw.js": "sw",
    "/abrir": "abrir",
    "/icone.svg": "svg",
    "/favicon.ico": "svg",
    "/icone-192.png": 192,
    "/icone-512.png": 512,
}


# ---------------------------------------------------------------- HTTP
# ===================================================================
# Kit 3.3: defesa da rede de casa, bancada, treino e emissão própria.
# Tudo em stdlib. Funções "puras" (avaliar_*, analisar_*) recebem os dados
# prontos, para poderem ser testadas sem Android.
# ===================================================================

# ------------------------------------------------------- Wi-Fi: segurança
NIVEL_SEG = {"aberta": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}


def seguranca_wifi(cap):
    """Classifica o campo 'capabilities' do scan do Android."""
    c = (cap or "").upper()
    if "SAE" in c or "WPA3" in c:
        return "WPA3"
    if "WPA2" in c or "RSN" in c:
        return "WPA2"
    if "WPA" in c:
        return "WPA"
    if "WEP" in c:
        return "WEP"
    return "aberta"


def canal_wifi(freq):
    try:
        f = int(freq)
    except (TypeError, ValueError):
        return None
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5000 <= f <= 5900:
        return (f - 5000) // 5
    if 5925 <= f <= 7125:
        return (f - 5950) // 5
    return None


SSID_REVELA = re.compile(
    r"(?i)(tp-?link|d-?link|intelbras|multilaser|huawei|zte|vivo|claro|oi_|"
    r"tim_|net_|nos-|mercusys|tenda|asus|linksys|netgear|apto|ap\s?\d|casa\s?\d|"
    r"rua|av\.?|\d{3,})")


def avaliar_wifi_proprio(ssid, scan):
    """Nota de 0 a 100 da SUA rede Wi-Fi, a partir do scan.

    Não pede a senha: a força da senha é calculada só na tela, no aparelho.
    """
    ssid = (ssid or "").strip().strip('"')
    meus = [x for x in (scan or []) if isinstance(x, dict) and x.get("ssid") == ssid]
    itens, nota = [], 100
    if not ssid:
        return {"erro": "Conecte-se ao seu Wi-Fi para avaliar."}
    if not meus:
        return {"ssid": ssid, "nota": None,
                "itens": [("medio", "Sua rede não apareceu no scan. Dê permissão "
                           "de Localização ao Termux:API e tente de novo.")]}
    segs = {seguranca_wifi(x.get("capabilities")) for x in meus}
    pior = min(segs, key=NIVEL_SEG.get)
    if pior == "aberta":
        nota -= 60
        itens.append(("alto", "Rede ABERTA: qualquer um entra e vê o tráfego sem "
                      "criptografia. Ative WPA2 ou WPA3 no roteador."))
    elif pior == "WEP":
        nota -= 50
        itens.append(("alto", "WEP é quebrado em minutos. Troque para WPA2/WPA3."))
    elif pior == "WPA":
        nota -= 30
        itens.append(("alto", "WPA (versão 1/TKIP) é antigo. Use WPA2-AES ou WPA3."))
    elif pior == "WPA2":
        itens.append(("baixo", "WPA2: bom. Se o roteador oferecer WPA3 "
                      "(ou WPA2/WPA3 misto), prefira."))
    else:
        itens.append(("baixo", "WPA3: o melhor disponível hoje."))
    if len(segs) > 1:
        nota -= 10
        itens.append(("medio", f"A mesma rede aparece com segurança diferente "
                      f"({', '.join(sorted(segs))}). Confira se não há um ponto "
                      f"de acesso falso (aba Defesa, 'Wi-Fi falso')."))
    if any("WPS" in (x.get("capabilities") or "").upper() for x in meus):
        nota -= 20
        itens.append(("alto", "WPS ligado: o PIN do WPS pode ser descoberto por força "
                      "bruta. Desligue o WPS no painel do roteador."))
    if SSID_REVELA.search(ssid):
        nota -= 5
        itens.append(("baixo", "O nome da rede revela marca, operadora ou endereço. "
                      "Um nome neutro dá menos pistas a quem quer atacar."))
    ocupacao = analisar_canais(scan)
    for x in meus:
        ch = canal_wifi(x.get("frequency_mhz"))
        faixa = "5" if (x.get("frequency_mhz") or 0) > 4000 else "2.4"
        uso = ocupacao.get(faixa, {}).get("ocupacao", {}).get(str(ch), 0)
        if faixa == "2.4" and uso >= 5:
            nota -= 5
            itens.append(("medio", f"Canal {ch} (2,4 GHz) disputado por {uso} redes. "
                          f"Sugestão: canal {ocupacao['2.4']['melhor']}."))
            break
    return {"ssid": ssid, "seguranca": sorted(segs), "nota": max(0, nota),
            "pontos_de_acesso": len(meus), "itens": itens}


def analisar_canais(scan):
    """Ocupação por canal (com sobreposição em 2,4 GHz) e melhor canal."""
    res = {}
    for faixa, candidatos in (("2.4", [1, 6, 11]), ("5", None)):
        ocup = collections.Counter()
        peso = collections.Counter()
        for x in scan or []:
            if not isinstance(x, dict):
                continue
            f = x.get("frequency_mhz") or 0
            if (faixa == "5") != (f > 4000):
                continue
            ch = canal_wifi(f)
            if ch is None:
                continue
            ocup[ch] += 1
            forca = max(1, 100 + int(x.get("rssi") or -100))  # -40 dBm pesa mais
            if faixa == "2.4":
                for c in range(ch - 4, ch + 5):  # canais de 20 MHz se sobrepõem
                    peso[c] += forca
            else:
                peso[ch] += forca
        if faixa == "5":
            candidatos = [36, 40, 44, 48, 149, 153, 157, 161]
        melhor = min(candidatos, key=lambda c: (peso[c], c))
        res[faixa] = {"ocupacao": {str(k): v for k, v in sorted(ocup.items())},
                      "interferencia": {str(c): peso[c] for c in candidatos},
                      "melhor": melhor}
    return res


# ----------------------------------------------- Wi-Fi falso (evil twin)
def aprender_bssids(rede_id, ssid, scan, bssid_conectado="", todos=False):
    """Guarda os pontos de acesso confiáveis da rede.

    Sempre aprende o BSSID em que o aparelho está conectado. Com todos=True
    (botão "são todos meus"), aprende também os outros com o mesmo nome.
    """
    agora = time.time()
    novos = 0
    with DBLOCK:
        c = db()
        for x in scan or []:
            if not isinstance(x, dict) or x.get("ssid") != ssid:
                continue
            b = (x.get("bssid") or "").lower()
            if not b or (not todos and b != (bssid_conectado or "").lower()):
                continue
            novos += c.execute(
                "INSERT OR IGNORE INTO bssids(rede_id,bssid,seguranca,canal,"
                "primeiro) VALUES(?,?,?,?,?)",
                (rede_id, b, seguranca_wifi(x.get("capabilities")),
                 canal_wifi(x.get("frequency_mhz")), agora)).rowcount
        c.commit()
        c.close()
    return novos


def avaliar_evil_twin(rede_id, ssid, scan):
    """Procura sinais de ponto de acesso falso com o nome da sua rede."""
    with DBLOCK:
        c = db()
        conhecidos = {r["bssid"]: dict(r) for r in c.execute(
            "SELECT * FROM bssids WHERE rede_id=?", (rede_id,))}
        c.close()
    achados = []
    if not conhecidos:
        return {"conhecidos": 0, "achados": [], "aviso":
                "Ainda não conheço os roteadores da sua rede. Toque em "
                "'Aprender' estando conectado nela."}
    seg_boa = max((NIVEL_SEG[v["seguranca"]] for v in conhecidos.values()), default=0)
    canais = {v["canal"] for v in conhecidos.values()}
    for x in scan or []:
        if not isinstance(x, dict) or x.get("ssid") != ssid:
            continue
        b = (x.get("bssid") or "").lower()
        if b in conhecidos:
            continue
        seg = seguranca_wifi(x.get("capabilities"))
        ch = canal_wifi(x.get("frequency_mhz"))
        if NIVEL_SEG[seg] < seg_boa:
            achados.append({"nivel": "alto", "bssid": b, "seguranca": seg,
                            "canal": ch, "rssi": x.get("rssi"),
                            "msg": f"'{ssid}' apareceu com segurança mais fraca "
                                   f"({seg}) no BSSID {b}: forte sinal de Wi-Fi "
                                   f"falso. Não conecte nele."})
        else:
            achados.append({"nivel": "medio", "bssid": b, "seguranca": seg,
                            "canal": ch, "rssi": x.get("rssi"),
                            "msg": f"'{ssid}' apareceu num roteador desconhecido "
                                   f"({b}, canal {ch}). Se for um repetidor seu, "
                                   f"toque em 'São todos meus'."
                                   + ("" if ch in canais else
                                      " Canal diferente dos seus.")})
    return {"conhecidos": len(conhecidos), "achados": achados}


def portal_cativo(abrir=None):
    """Confere se a internet responde como esperado (HTTP 204).

    Se vier uma página no lugar, há portal de login ou alguém no meio.
    """
    import urllib.request
    url = "http://connectivitycheck.gstatic.com/generate_204"
    try:
        if abrir:
            status, corpo = abrir(url)
        else:
            r = urllib.request.urlopen(url, timeout=6)
            status, corpo = r.status, r.read(300)
    except Exception as e:
        return {"ok": None, "msg": f"sem resposta ({str(e)[:80]})"}
    if status == 204:
        return {"ok": True, "msg": "Resposta normal (204): sem portal no caminho."}
    return {"ok": False, "status": status,
            "msg": "A internet devolveu uma página no lugar da resposta vazia: há "
                   "portal de login (hotel, café) ou interceptação. Em casa isso "
                   "não deveria acontecer."}


# -------------------------------------------------- DNS sequestrado
DOMINIOS_TESTE = ["google.com", "wikipedia.org", "gov.br", "bb.com.br"]


def dns_a(nome, servidor=None, porta=53, timeout=3):
    """Consulta tipo A. Retorna (rcode, [ips]) ou lança OSError."""
    servidor = servidor or servidor_dns()
    ident = int.from_bytes(os.urandom(2), "big")
    with socket.socket(socket.AF_INET6 if ":" in servidor else socket.AF_INET,
                       socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(dns_montar(nome, 1, ident), (servidor, porta))
        msg, _ = s.recvfrom(4096)
    if len(msg) < 12 or struct.unpack("!H", msg[:2])[0] != ident:
        raise OSError("resposta DNS com id errado")
    rcode, resp = dns_respostas(msg)
    return rcode, sorted(v for _, _, t, v in resp if t == "A")


def doh_a(nome, timeout=6):
    """Mesma pergunta por DNS seguro (HTTPS), que o roteador não altera."""
    import urllib.request
    url = ("https://cloudflare-dns.com/dns-query?type=A&name="
           + urllib.parse.quote(nome))
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    d = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    return sorted(a["data"] for a in d.get("Answer", []) if a.get("type") == 1)


def checar_dns(dominios=None, consulta=None, seguro=None, aleatorio=None):
    """Compara o DNS da rede com o DNS seguro e procura sequestro.

    - nome inventado que "existe": o provedor/roteador está trocando o
      erro por uma página dele (sequestro de NXDOMAIN);
    - site público respondendo com IP privado: redirecionamento local;
    - respostas sem nenhum IP em comum com o DNS seguro: possível troca
      (CDNs variam, então isso é aviso médio, não prova).
    """
    consulta = consulta or dns_a
    seguro = seguro or doh_a
    aleatorio = aleatorio or ("kit-" + secrets.token_hex(6) + ".com")
    itens, detalhes = [], []
    try:
        rc, ips = consulta(aleatorio)
        if rc == 0 and ips:
            itens.append(("alto", f"O nome inventado {aleatorio} 'existe' "
                          f"({', '.join(ips)}): o DNS da rede troca erros por "
                          f"outra página (sequestro de NXDOMAIN)."))
        else:
            itens.append(("baixo", "Nome inventado deu erro, como deve ser."))
    except OSError as e:
        itens.append(("medio", f"O DNS da rede não respondeu ({e})."))
    for d in dominios or DOMINIOS_TESTE:
        linha = {"dominio": d}
        try:
            _, linha["rede"] = consulta(d)
        except OSError as e:
            linha["rede"] = []
            linha["erro"] = str(e)
        try:
            linha["seguro"] = seguro(d)
        except Exception as e:
            linha["seguro"] = None
            linha["erro_seguro"] = str(e)[:80]
        privados = [ip for ip in linha["rede"]
                    if ipaddress.ip_address(ip).is_private]
        if privados:
            linha["veredito"] = "alto"
            itens.append(("alto", f"{d} respondeu com IP da rede local "
                          f"({', '.join(privados)}): redirecionamento suspeito."))
        elif linha["seguro"] and linha["rede"] and \
                not set(linha["rede"]) & set(linha["seguro"]):
            # mesma rede /16 conta como mesma origem (CDN)
            r16 = {ip.rsplit(".", 2)[0] for ip in linha["rede"]}
            s16 = {ip.rsplit(".", 2)[0] for ip in linha["seguro"]}
            if r16 & s16:
                linha["veredito"] = "ok"
            else:
                linha["veredito"] = "medio"
                itens.append(("medio", f"{d}: IPs diferentes do DNS seguro. Pode "
                              f"ser só CDN; repita o teste e veja se insiste."))
        else:
            linha["veredito"] = "ok"
        detalhes.append(linha)
    graves = [m for n, m in itens if n == "alto"]
    rid = rede_id_atual()
    for m in graves:
        alerta("alto", "dns_sequestro", m, dedup_s=3600, rede_id=rid)
    return {"servidor": servidor_dns(), "itens": itens, "dominios": detalhes,
            "resumo": "suspeito" if graves else "ok"}


# --------------------------------------------- Auditoria do roteador
def upnp_controle(xml_texto, base):
    """Acha a URL de controle WANIPConnection/WANPPPConnection no XML."""
    import xml.etree.ElementTree as ET
    raiz = ET.fromstring(xml_texto)
    for serv in raiz.iter():
        if not serv.tag.endswith("service"):
            continue
        campos = {c.tag.split("}")[-1]: (c.text or "").strip() for c in serv}
        tipo = campos.get("serviceType", "")
        if "WANIPConnection" in tipo or "WANPPPConnection" in tipo:
            return tipo, urllib.parse.urljoin(base, campos.get("controlURL", ""))
    return None, None


def upnp_resposta_mapeamento(xml_texto):
    import xml.etree.ElementTree as ET
    campos = {}
    for el in ET.fromstring(xml_texto).iter():
        nome = el.tag.split("}")[-1]
        if nome.startswith("New"):
            campos[nome[3:]] = (el.text or "").strip()
    if not campos:
        return None
    return {"externa": campos.get("ExternalPort"), "protocolo": campos.get("Protocol"),
            "interno": campos.get("InternalClient"),
            "porta_interna": campos.get("InternalPort"),
            "descricao": campos.get("PortMappingDescription")}


def upnp_mapeamentos(local, abrir=None, maximo=64):
    """Lista as portas que o UPnP do roteador abriu para a internet."""
    import urllib.request
    import urllib.error

    def _abrir(url, dados=None, cab=None):
        req = urllib.request.Request(url, data=dados, headers=cab or {})
        try:
            r = urllib.request.urlopen(req, timeout=4)
            return r.status, r.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(20000).decode("utf-8", "replace")
    abrir = abrir or _abrir
    u = urllib.parse.urlparse(local)
    if not u.hostname or not ipaddress.ip_address(u.hostname).is_private:
        raise ValueError("descrição UPnP fora da rede local")
    _, xml_desc = abrir(local)
    tipo, ctrl = upnp_controle(xml_desc, local)
    if not ctrl:
        return {"igd": False, "mapeamentos": []}
    lista = []
    for i in range(maximo):
        corpo = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap'
                 '.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/'
                 f'soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u='
                 f'"{tipo}"><NewPortMappingIndex>{i}</NewPortMappingIndex></u:'
                 'GetGenericPortMappingEntry></s:Body></s:Envelope>')
        st, resp = abrir(ctrl, corpo.encode(), {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{tipo}#GetGenericPortMappingEntry"'})
        if st != 200:
            break
        m = upnp_resposta_mapeamento(resp)
        if not m:
            break
        lista.append(m)
    return {"igd": True, "controle": ctrl, "mapeamentos": lista}


def avaliar_roteador(dados):
    """Nota de 0 a 100 do roteador a partir do que foi coletado.

    'dados' tem: portas (lista de números), pagina ({http, https}), upnp
    ({igd, mapeamentos}), wifi (resultado de avaliar_wifi_proprio).
    """
    portas = set(dados.get("portas") or [])
    pag = dados.get("pagina") or {}
    itens, nota = [], 100

    def ruim(peso, nivel, txt):
        nonlocal nota
        nota -= peso
        itens.append((nivel, txt))
    if 23 in portas:
        ruim(25, "alto", "Telnet (23) aberto no roteador: senha trafega sem "
             "criptografia. Desligue no painel.")
    if 21 in portas:
        ruim(10, "medio", "FTP (21) aberto no roteador (compartilhamento de USB?). "
             "Desligue se não usa.")
    if 7547 in portas:
        ruim(5, "medio", "TR-069 (7547) aberto: gerência remota da operadora. "
             "Comum, mas é porta de ataque conhecida; mantenha o firmware em dia.")
    if 22 in portas:
        itens.append(("baixo", "SSH (22) aberto no roteador: ok se foi você que "
                      "ligou e a senha é forte."))
    http_ok = isinstance(pag.get("http"), dict)
    https_ok = isinstance(pag.get("https"), dict)
    if http_ok and not https_ok:
        ruim(10, "medio", "Painel só em HTTP: a senha de admin passa sem "
             "criptografia pela rede. Prefira entrar pelo cabo ou ative HTTPS.")
    servidor = " ".join(str((pag.get(k) or {}).get("servidor") or "")
                        for k in ("http", "https") if isinstance(pag.get(k), dict))
    if servidor.strip():
        itens.append(("baixo", f"O painel se identifica como '{servidor.strip()}'. "
                      f"Confira no site do fabricante se há firmware novo."))
    up = dados.get("upnp") or {}
    if up.get("igd"):
        maps = up.get("mapeamentos") or []
        if maps:
            ruim(min(30, 10 + 5 * len(maps)), "alto",
                 f"UPnP abriu {len(maps)} porta(s) da internet para dentro da sua "
                 f"rede: " + ", ".join(
                     f"{m.get('externa')}/{m.get('protocolo')} → "
                     f"{m.get('interno')}:{m.get('porta_interna')} "
                     f"({m.get('descricao') or 'sem descrição'})" for m in maps[:6])
                 + ". Confira se reconhece cada uma; se não, desligue o UPnP.")
        else:
            ruim(5, "baixo", "UPnP ligado (nenhuma porta aberta agora). Qualquer "
                 "programa da rede pode abrir portas sozinho; desligue se não "
                 "precisa (jogos online e câmeras às vezes usam).")
    elif 1900 in portas:
        ruim(5, "baixo", "Porta do UPnP (1900) responde.")
    w = dados.get("wifi") or {}
    if w.get("nota") is not None:
        for nivel, txt in w.get("itens", []):
            if nivel != "baixo":
                itens.append((nivel, "Wi-Fi: " + txt))
        nota -= (100 - w["nota"]) // 3
    itens.append(("baixo", "Confira à mão (o Kit não testa senhas): a senha de "
                  "admin do roteador NÃO é a de fábrica? A gerência remota (WAN) "
                  "está desligada? Os aparelhos IoT estão na rede de convidados?"))
    nota = max(0, nota)
    conceito = "boa" if nota >= 80 else "regular" if nota >= 55 else "ruim"
    return {"nota": nota, "conceito": conceito, "itens": itens}


def auditoria_roteador(gw):
    """Coleta tudo do roteador (só o seu: faixa privada) e dá a nota."""
    valida_alvo("roteador", gw)
    portas = [p["porta"] for p in pscan(gw, COMMON)]
    pagina = router_page(gw)
    upnp = {"igd": False, "mapeamentos": []}
    try:
        for disp in ssdp_igd():
            if urllib.parse.urlparse(disp).hostname == gw:
                upnp = upnp_mapeamentos(disp)
                break
    except Exception as e:
        upnp["erro"] = str(e)[:120]
    w = termux("termux-wifi-connectioninfo") or {}
    scan = termux("termux-wifi-scaninfo")
    wifi = avaliar_wifi_proprio(w.get("ssid") if isinstance(w, dict) else "",
                                scan if isinstance(scan, list) else [])
    dados = {"gateway": gw, "portas": portas, "pagina": pagina, "upnp": upnp,
             "wifi": wifi}
    return dict(dados, **avaliar_roteador(dados))


def ssdp_igd(timeout=3):
    """Pergunta pelo roteador UPnP (InternetGatewayDevice). Lista de LOCATION."""
    st = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           f"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    locais = []
    try:
        s.sendto(msg.encode(), ("239.255.255.250", 1900))
        while True:
            d, _ = s.recvfrom(4096)
            m = re.search(rb"(?im)^location:\s*(\S+)", d)
            if m:
                locais.append(m.group(1).decode("ascii", "replace"))
    except (socket.timeout, OSError):
        pass
    finally:
        s.close()
    return locais


# ------------------------------------------------- Linha do tempo
def linha_do_tempo(rede_id=None, lim=200):
    """Alertas, varreduras e medições num lugar só, do mais novo ao mais velho."""
    ev = []
    with DBLOCK:
        c = db()
        q = "SELECT ts,nivel,tipo,msg FROM alertas"
        args = ()
        if rede_id:
            q += " WHERE rede_id=? OR rede_id IS NULL"
            args = (rede_id,)
        for r in c.execute(q + " ORDER BY ts DESC LIMIT ?", args + (lim,)):
            ev.append({"ts": r["ts"], "tipo": "alerta", "nivel": r["nivel"],
                       "titulo": TITULOS_ALERTA.get(r["tipo"], r["tipo"]),
                       "msg": r["msg"]})
        q = "SELECT ts,alvo,hosts FROM varreduras"
        if rede_id:
            q += " WHERE rede_id=?"
        for r in c.execute(q + " ORDER BY ts DESC LIMIT ?", args + (lim,)):
            ev.append({"ts": r["ts"], "tipo": "varredura", "nivel": "info",
                       "titulo": "varredura da rede",
                       "msg": f"{r['alvo']}: {r['hosts']} aparelho(s) ativo(s)"})
        q = "SELECT ts,tipo,rotulo,valor FROM medidas WHERE tipo IN ('sinal','evento')"
        if rede_id:
            q += " AND (rede_id=? OR rede_id IS NULL)"
        for r in c.execute(q + " ORDER BY ts DESC LIMIT ?", args + (lim,)):
            ev.append({"ts": r["ts"], "tipo": r["tipo"], "nivel": "info",
                       "titulo": "sinal medido" if r["tipo"] == "sinal" else "evento",
                       "msg": f"{r['rotulo']}: {r['valor']:.0f} dBm"
                       if r["tipo"] == "sinal" else r["rotulo"]})
        c.close()
    ev.sort(key=lambda e: e["ts"] or 0, reverse=True)
    return ev[:lim]


# --------------------------------------------------- Medições (SQLite)
MAX_MEDIDAS = 50000
TEMP_ALERTA = 45.0  # °C da bateria


def medida_add(tipo, valor, rotulo="", extra=None, rede_id=None, ts=None):
    with DBLOCK:
        c = db()
        c.execute("INSERT INTO medidas(ts,tipo,rotulo,valor,extra,rede_id) "
                  "VALUES(?,?,?,?,?,?)",
                  (ts or time.time(), tipo, rotulo, float(valor),
                   json.dumps(extra) if extra is not None else None, rede_id))
        c.execute("DELETE FROM medidas WHERE id <= (SELECT MAX(id) FROM medidas)"
                  " - ?", (MAX_MEDIDAS,))
        c.commit()
        c.close()


def medidas(tipo, horas=24, rotulo=None):
    desde = time.time() - horas * 3600
    q = "SELECT ts,rotulo,valor,extra FROM medidas WHERE tipo=? AND ts>=?"
    args = [tipo, desde]
    if rotulo:
        q += " AND rotulo=?"
        args.append(rotulo)
    with DBLOCK:
        c = db()
        rows = [dict(r) for r in c.execute(q + " ORDER BY ts", args)]
        c.close()
    for r in rows:
        r["extra"] = json.loads(r["extra"]) if r["extra"] else None
    return rows


def registrar_bateria(leitura):
    """Grava carga/temperatura/corrente. Alerta se esquentar."""
    if not isinstance(leitura, dict) or "percentage" not in leitura:
        return None
    temp = leitura.get("temperature")
    extra = {"temperatura": temp, "corrente_ma": None, "status": leitura.get("status"),
             "saude": leitura.get("health"), "plug": leitura.get("plugged")}
    cur = leitura.get("current")
    if isinstance(cur, (int, float)):
        # o Android informa em µA na maioria dos aparelhos
        extra["corrente_ma"] = round(cur / 1000, 1) if abs(cur) > 10000 else cur
    medida_add("bateria", leitura["percentage"], extra=extra)
    if isinstance(temp, (int, float)) and temp >= TEMP_ALERTA:
        alerta("alto", "temperatura",
               f"Bateria a {temp:.1f} °C (limite {TEMP_ALERTA:.0f} °C). Tire da "
               f"capa, pare jogos/carregamento rápido e deixe esfriar.",
               dedup_s=1800)
    return extra


GERACOES = {"gsm": 2, "cdma": 2, "wcdma": 3, "tdscdma": 3, "lte": 4, "nr": 5}


def analisar_celular(celulas, anterior=None):
    """Acha a célula registrada e avisa se o aparelho caiu para 2G.

    Retorna (registro, alerta_ou_None). Queda de 4G/5G para 2G de repente
    pode ser só cobertura ruim, mas também é o que uma estação falsa
    (IMSI catcher) provoca. É um indício, não prova.
    """
    reg = next((c for c in celulas or [] if isinstance(c, dict)
                and c.get("registered")), None)
    if not reg:
        return None, None
    atual = {"tipo": reg.get("type"), "geracao": GERACOES.get(reg.get("type"), 0),
             "id": reg.get("ci") or reg.get("cid") or reg.get("nci"),
             "dbm": reg.get("dbm")}
    msg = None
    if anterior and anterior.get("geracao", 0) >= 4 and atual["geracao"] == 2:
        msg = (f"O celular caiu de {anterior['geracao']}G para 2G (célula "
               f"{atual['id']}, {atual['dbm']} dBm). Pode ser só cobertura; se "
               f"acontecer onde sempre teve 4G, desconfie de estação falsa e "
               f"desative o 2G nas configurações de rede, se o aparelho deixar.")
    return atual, msg


_CELULAR_ANTERIOR = [None]


def registro_tick():
    """Uma rodada do registro automático (bateria e celular)."""
    if config_get("registro", True) is False:
        return
    registrar_bateria(termux("termux-battery-status"))
    cel = termux("termux-telephony-cellinfo")
    if isinstance(cel, list):
        atual, msg = analisar_celular(cel, _CELULAR_ANTERIOR[0])
        if atual:
            medida_add("celular", atual["dbm"] or 0, rotulo=str(atual["tipo"]),
                       extra=atual)
            _CELULAR_ANTERIOR[0] = atual
        if msg:
            alerta("alto", "celular_2g", msg, dedup_s=3600)


def registro_loop(intervalo=300):
    while True:
        try:
            registro_tick()
        except Exception as e:
            print("registro:", e)
        time.sleep(intervalo)


# --------------------------------------------------- Mapa de sinal
LOCAL_RE = re.compile(r"^[\w À-ÿ.,()/-]{1,40}$")


def marcar_sinal(local, leituras=3, ler=None, pausa=1.0):
    """Mede o RSSI do Wi-Fi algumas vezes e guarda com o nome do cômodo."""
    local = re.sub(r"\s+", " ", str(local or "")).strip()
    if not LOCAL_RE.match(local):
        raise ValueError("nome do local inválido (até 40 letras/números)")
    ler = ler or (lambda: termux("termux-wifi-connectioninfo"))
    valores = []
    for i in range(max(1, min(int(leituras), 10))):
        w = ler()
        if isinstance(w, dict) and isinstance(w.get("rssi"), (int, float)) \
                and w["rssi"] < 0:
            valores.append(w["rssi"])
        if i < leituras - 1:
            time.sleep(pausa)
    if not valores:
        raise ValueError("não consegui ler o sinal do Wi-Fi (Termux:API e Wi-Fi "
                         "ligados?)")
    media = sum(valores) / len(valores)
    medida_add("sinal", media, rotulo=local, extra={"leituras": valores},
               rede_id=rede_id_atual())
    return {"local": local, "media": round(media, 1), "leituras": valores}


def qualidade_sinal(dbm):
    if dbm >= -55:
        return "ótimo"
    if dbm >= -67:
        return "bom"
    if dbm >= -75:
        return "fraco"
    return "ruim"


def mapa_sinal(rede_id=None, dias=30):
    rede_id = rede_id or rede_id_atual()
    desde = time.time() - dias * 86400
    with DBLOCK:
        c = db()
        rows = c.execute(
            "SELECT rotulo, AVG(valor) m, MIN(valor) mi, MAX(valor) ma, COUNT(*) n,"
            " MAX(ts) ult FROM medidas WHERE tipo='sinal' AND ts>=? AND "
            "(rede_id=? OR ? IS NULL) GROUP BY rotulo ORDER BY m DESC",
            (desde, rede_id, rede_id)).fetchall()
        c.close()
    locais = [{"local": r["rotulo"], "media": round(r["m"], 1), "pior": r["mi"],
               "melhor": r["ma"], "medicoes": r["n"], "ultima": r["ult"],
               "qualidade": qualidade_sinal(r["m"])} for r in rows]
    dica = ""
    ruins = [x["local"] for x in locais if x["qualidade"] in ("fraco", "ruim")]
    if ruins:
        dica = (f"Sinal fraco em: {', '.join(ruins)}. Aproxime o roteador desses "
                f"cômodos, tire-o de dentro de armário, ou ponha um repetidor/mesh "
                f"no meio do caminho (num ponto em que o sinal ainda seja 'bom').")
    elif locais:
        dica = "Todos os pontos medidos estão bons."
    return {"rede_id": rede_id, "locais": locais, "dica": dica}


# ----------------------------------------- Treino: .pcap de laboratório
# Os pacotes são GERADOS aqui e só passam pelo detector do próprio Kit.
# Nada sai do aparelho.
def _ipv4(src, dst, proto, corpo):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(corpo), 0, 0, 64, proto,
                       0, socket.inet_aton(src), socket.inet_aton(dst)) + corpo


def _eth(dst, src, etype, corpo):
    return (bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", ""))
            + struct.pack(">H", etype) + corpo)


def _arp_resp(ip, hw, alvo_ip, alvo_hw):
    corpo = (struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2)
             + bytes.fromhex(hw.replace(":", "")) + socket.inet_aton(ip)
             + bytes.fromhex(alvo_hw.replace(":", "")) + socket.inet_aton(alvo_ip))
    return _eth(alvo_hw, hw, 0x0806, corpo)


def _dhcp_offer(servidor, mac_srv, gw, oferecido):
    corpo = bytearray(240)
    corpo[0] = 2
    corpo[16:20] = socket.inet_aton(oferecido)
    corpo[236:240] = b"\x63\x82\x53\x63"
    opc = (bytes([53, 1, 2, 54, 4]) + socket.inet_aton(servidor)
           + bytes([3, 4]) + socket.inet_aton(gw)
           + bytes([6, 4]) + socket.inet_aton(gw) + b"\xff")
    udp = struct.pack(">HHHH", 67, 68, 8 + 240 + len(opc), 0) + bytes(corpo) + opc
    return _eth("ff:ff:ff:ff:ff:ff", mac_srv, 0x0800,
                _ipv4(servidor, "255.255.255.255", 17, udp))


def _tcp(src, dst, sp, dp, flags=0x18, dados=b""):
    tcp = struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 0x50, flags, 0, 0, 0) + dados
    return _ipv4(src, dst, 6, tcp)


def _deauth(bssid, cliente):
    return (b"\xc0\x00\x00\x00" + bytes.fromhex(cliente.replace(":", ""))
            + bytes.fromhex(bssid.replace(":", "")) * 2 + b"\x00\x00"
            + struct.pack("<H", 7))


def _pcap(link, pacotes, t0=1700000000.0):
    b = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, link)
    for i, p in enumerate(pacotes):
        t = t0 + i * 0.2
        b += struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(p), len(p)) + p
    return b


GW_MAC = "f0:f6:c1:00:00:01"
VITIMA_MAC = "aa:aa:aa:aa:aa:10"
ATACANTE_MAC = "de:ad:be:ef:00:66"

TREINOS = {
    "arp": {
        "titulo": "ARP spoofing (homem no meio)",
        "explica": "O atacante manda respostas ARP dizendo 'eu sou o roteador'. "
                   "Os aparelhos passam a mandar o tráfego para ele. O Kit percebe "
                   "porque o IP do roteador (192.168.0.1) muda de MAC no meio da "
                   "captura. Defesa: Wi-Fi com senha forte, isolamento de "
                   "clientes no roteador e HTTPS sempre.",
    },
    "dhcp": {
        "titulo": "Servidor DHCP falso",
        "explica": "Um segundo aparelho responde aos pedidos de IP e entrega a ele "
                   "mesmo como roteador/DNS. Quem pegar o IP dele é desviado. O Kit "
                   "alerta quando mais de um servidor DHCP responde. Defesa: "
                   "'DHCP snooping' em switches gerenciáveis; em casa, saber quem "
                   "está na rede (inventário).",
    },
    "deauth": {
        "titulo": "Desautenticação Wi-Fi (deauth)",
        "explica": "Quadros 'deauth' forjados derrubam os aparelhos do Wi-Fi, "
                   "seja para atrapalhar, seja para obrigá-los a reconectar num "
                   "Wi-Fi falso. O Kit alerta com 15 quadros em 10 s. Defesa: "
                   "WPA3 ou WPA2 com PMF (proteção de quadros de gerência) ligado.",
    },
    "inseguro": {
        "titulo": "Senha trafegando sem criptografia",
        "explica": "Um login feito por HTTP (sem o cadeado) leva a senha em texto "
                   "puro: qualquer um no caminho lê. O Kit marca o protocolo "
                   "inseguro e a senha. Defesa: só digite senha em HTTPS; troque "
                   "câmeras/roteadores que só têm HTTP ou Telnet.",
    },
    "varredura": {
        "titulo": "Varredura de portas",
        "explica": "Um aparelho tenta dezenas de portas de outro em segundos: é "
                   "alguém (ou um vírus) procurando serviço aberto. O Kit alerta "
                   "com 30 portas em 10 s. Defesa: feche serviços que não usa e "
                   "descubra de quem é o IP pelo inventário.",
    },
}


def gerar_pcap_treino(cenario):
    """Monta um .pcap sintético com o cenário de ataque pedido."""
    if cenario == "arp":
        pk = [_arp_resp("192.168.0.1", GW_MAC, "192.168.0.10", VITIMA_MAC),
              _arp_resp("192.168.0.20", "aa:aa:aa:aa:aa:20", "192.168.0.10",
                        VITIMA_MAC),
              _arp_resp("192.168.0.1", ATACANTE_MAC, "192.168.0.10", VITIMA_MAC)]
        return _pcap(LINK_ETHERNET, pk)
    if cenario == "dhcp":
        pk = [_dhcp_offer("192.168.0.1", GW_MAC, "192.168.0.1", "192.168.0.50"),
              _dhcp_offer("192.168.0.66", ATACANTE_MAC, "192.168.0.66",
                          "192.168.0.51")]
        return _pcap(LINK_ETHERNET, pk)
    if cenario == "deauth":
        pk = [_deauth("f0:f6:c1:00:00:01", VITIMA_MAC) for _ in range(20)]
        return _pcap(LINK_80211, pk)
    if cenario == "inseguro":
        pk = [_tcp("192.168.0.10", "192.168.0.30", 40000, 80, dados=(
            b"POST /login HTTP/1.1\r\nHost: camera.local\r\n\r\n"
            b"usuario=admin&senha=123456")),
              _tcp("192.168.0.10", "192.168.0.31", 40001, 23, dados=b"admin\r\n")]
        return _pcap(101, pk)
    if cenario == "varredura":
        pk = [_tcp("192.168.0.66", "192.168.0.10", 50000 + i, 1 + i, flags=0x02)
              for i in range(35)]
        return _pcap(101, pk)
    raise ValueError("cenário de treino desconhecido")


def rodar_treino(cenario):
    dados = gerar_pcap_treino(cenario)
    r = importar_pcap(dados, origem=f"TREINO {cenario}")
    return dict(r, cenario=cenario, **TREINOS[cenario])


# --------------------------------------------- Infravermelho (IR) próprio
# Protocolos públicos. Cada função devolve (frequência_Hz, [µs liga, µs
# desliga, ...]), o formato do termux-infrared-transmit.
def ir_nec(endereco, comando):
    end = endereco & 0xFFFF
    if end <= 0xFF:  # NEC padrão: endereço e o inverso
        end = end | ((~end & 0xFF) << 8)
    bits = end | ((comando & 0xFF) << 16) | ((~comando & 0xFF) << 24)
    p = [9000, 4500]
    for i in range(32):
        p += [562, 1687 if bits >> i & 1 else 562]
    return 38000, p + [562]


def ir_samsung(endereco, comando):
    end = endereco & 0xFF
    bits = end | (end << 8) | ((comando & 0xFF) << 16) | ((~comando & 0xFF) << 24)
    p = [4500, 4500]
    for i in range(32):
        p += [560, 1690 if bits >> i & 1 else 560]
    return 38000, p + [560]


def ir_sony(endereco, comando, bits_end=5):
    p = [2400, 600]
    valor = (comando & 0x7F) | ((endereco & ((1 << bits_end) - 1)) << 7)
    for i in range(7 + bits_end):
        p += [1200 if valor >> i & 1 else 600, 600]
    p[-1] = 25000  # pausa até a repetição
    return 40000, p * 3  # Sony exige 3 repetições


def ir_rc5(endereco, comando, alterna=0):
    """Philips RC5 (Manchester, 889 µs por meio bit)."""
    bits = [1, 1 if comando < 64 else 0, alterna & 1]
    bits += [(endereco >> i) & 1 for i in range(4, -1, -1)]
    bits += [(comando >> i) & 1 for i in range(5, -1, -1)]
    meio = []
    for b in bits:  # 1 = desliga→liga, 0 = liga→desliga
        meio += [0, 1] if b else [1, 0]
    # transforma em durações começando por "liga"
    while meio and meio[0] == 0:
        meio.pop(0)
    p, atual, n = [], 1, 0
    for m in meio:
        if m == atual:
            n += 1
        else:
            p.append(n * 889)
            atual, n = m, 1
    p.append(n * 889)
    if len(p) % 2 == 0:
        p = p[:-1]
    return 36000, p


IR_PROTOCOLOS = {"nec": ir_nec, "samsung": ir_samsung, "sony": ir_sony,
                 "rc5": ir_rc5}

# Base pequena de códigos de LIGAR/DESLIGAR por marca (protocolos públicos).
# Várias marcas têm mais de um código: o "Descobrir" testa um por um.
IR_CODIGOS = {
    "Samsung": [("samsung", 0x07, 0x02), ("samsung", 0x07, 0x98)],
    "LG": [("nec", 0x04, 0x08), ("nec", 0x04, 0xC4)],
    "Sony": [("sony", 0x01, 0x15)],
    "Philips": [("rc5", 0x00, 0x0C)],
    "Toshiba / Semp": [("nec", 0x40, 0x12)],
    "Panasonic (via NEC)": [("nec", 0x80, 0x3D)],
    "Philco / Britânia": [("nec", 0x00, 0x08), ("nec", 0x01, 0x12)],
    "AOC": [("nec", 0x00, 0x0C)],
    "TCL": [("nec", 0x00, 0x0A), ("nec", 0x01, 0x0A)],
    "Hisense": [("nec", 0x00, 0x1C), ("nec", 0x00, 0x40)],
    "Multilaser / genéricas": [("nec", 0x00, 0x45), ("nec", 0x00, 0x46),
                               ("nec", 0x00, 0x0D)],
}
IR_TECLAS = {  # outras teclas (NEC LG e Samsung) para o controle completo
    "LG": {"vol+": 0x02, "vol-": 0x03, "canal+": 0x00, "canal-": 0x01,
           "mudo": 0x09, "entrada": 0x0B, "ok": 0x44, "voltar": 0x28},
    "Samsung": {"vol+": 0x07, "vol-": 0x0B, "canal+": 0x12, "canal-": 0x10,
                "mudo": 0x0F, "entrada": 0x01, "ok": 0x68, "voltar": 0x58},
}


def ir_pronto(texto):
    """Converte código Pronto Hex (0000 ...) em (frequência, padrão)."""
    w = [int(x, 16) for x in texto.split()]
    if len(w) < 6 or w[0] != 0:
        raise ValueError("código Pronto inválido (precisa começar com 0000)")
    freq = int(1000000 / (w[1] * 0.241246))
    n1, n2 = w[2], w[3]
    pares = w[4:4 + 2 * (n1 + n2)]
    if len(pares) != 2 * (n1 + n2) or not pares:
        raise ValueError("código Pronto com tamanho errado")
    periodo = 1e6 / freq
    return freq, [max(1, int(round(x * periodo))) for x in pares]


def ir_montar(corpo):
    """Monta (freq, padrão) a partir do pedido da tela."""
    if corpo.get("pronto"):
        return ir_pronto(str(corpo["pronto"])[:4000])
    prot = str(corpo.get("protocolo") or "").lower()
    if prot not in IR_PROTOCOLOS:
        raise ValueError("protocolo IR desconhecido")
    try:
        end = int(str(corpo.get("endereco")), 0)
        cmd = int(str(corpo.get("comando")), 0)
    except ValueError:
        raise ValueError("endereço/comando devem ser números (ex.: 0x07)")
    if not (0 <= end <= 0xFFFF and 0 <= cmd <= 0xFF):
        raise ValueError("endereço/comando fora da faixa")
    return IR_PROTOCOLOS[prot](end, cmd)


def ir_frequencias(rodar=None):
    """Faixas que o emissor IR do celular aceita ([] = não tem emissor)."""
    from shutil import which
    if rodar is None:
        if not which("termux-infrared-frequencies"):
            return {"tem_ir": False, "faixas": [], "motivo":
                    "Termux:API não instalado (pkg install termux-api)."}
        try:
            saida = subprocess.run(["termux-infrared-frequencies"],
                                   capture_output=True, text=True,
                                   timeout=10).stdout
        except Exception as e:
            return {"tem_ir": False, "faixas": [], "motivo": str(e)}
    else:
        saida = rodar()
    try:
        faixas = json.loads(saida or "[]")
    except ValueError:
        faixas = []
    if not isinstance(faixas, list):
        faixas = []
    return {"tem_ir": bool(faixas), "faixas": faixas,
            "motivo": "" if faixas else "Este celular não tem emissor IR. Use o "
            "adaptador IR de fone (modo 'Fone') ou controle a TV pela rede."}


_IR_ENVIOS = collections.deque(maxlen=120)
IR_MAX_MIN = 60  # envios por minuto (o "Descobrir" usa ~30)
IR_ENVIADOR = [None]


def ir_enviar(corpo):
    """Envia um código IR pelo emissor do celular, só com confirmação."""
    if corpo.get("proprio") is not True:
        raise ValueError("confirme que o aparelho é seu (ou que tem autorização)")
    freq, padrao = ir_montar(corpo)
    agora = time.time()
    while _IR_ENVIOS and agora - _IR_ENVIOS[0] > 60:
        _IR_ENVIOS.popleft()
    if len(_IR_ENVIOS) >= IR_MAX_MIN:
        raise ValueError("limite de envios IR por minuto atingido; espere um pouco")
    _IR_ENVIOS.append(agora)
    if IR_ENVIADOR[0]:
        IR_ENVIADOR[0](freq, padrao)
    else:
        from shutil import which
        if not which("termux-infrared-transmit"):
            raise ValueError("sem emissor IR acessível (Termux:API)")
        subprocess.run(["termux-infrared-transmit", "-f", str(freq),
                        ",".join(map(str, padrao))], timeout=10,
                       capture_output=True)
    return {"ok": True, "frequencia": freq, "pulsos": len(padrao)}


# --------------------------------------------- TV pela rede (só a sua)
ROKU_TECLAS = {"PowerOff", "PowerOn", "Power", "Home", "Back", "Select", "Up",
               "Down", "Left", "Right", "Play", "VolumeUp", "VolumeDown",
               "VolumeMute", "InputHDMI1", "InputHDMI2", "InputTuner"}


def tv_roku(ip, tecla, abrir=None):
    """Roku/TCL Roku: comando pela porta 8060 (ECP)."""
    import urllib.request
    valida_alvo("portas", ip)
    if tecla not in ROKU_TECLAS:
        raise ValueError("tecla não permitida")
    url = f"http://{ip}:8060/keypress/{tecla}"
    if abrir:
        return abrir(url)
    req = urllib.request.Request(url, data=b"", method="POST")
    urllib.request.urlopen(req, timeout=4).read()
    return {"ok": True, "tecla": tecla}


TV_PORTAS = {
    8060: ("Roku (ECP)", "alto", "aceita comandos de QUALQUER aparelho da rede, "
           "sem senha (ligar, desligar, abrir apps). Desative 'Controle por apps "
           "móveis' ou deixe a TV na rede de convidados."),
    5555: ("ADB (depuração Android)", "alto", "depuração do Android TV aberta na "
           "rede: dá controle total da TV. Desligue em Opções do desenvolvedor."),
    8001: ("Samsung (controle remoto)", "baixo", "pede autorização na tela na "
           "primeira vez. Recuse pedidos que você não fez."),
    8002: ("Samsung (controle remoto, TLS)", "baixo", "idem."),
    3000: ("LG webOS", "baixo", "pede autorização na tela. Recuse pedidos que "
           "você não fez."),
    3001: ("LG webOS (TLS)", "baixo", "idem."),
    8008: ("Chromecast / Google Cast", "medio", "qualquer aparelho da rede pode "
           "transmitir para ela. Normal em casa; em empresa, separe a rede."),
    8009: ("Google Cast (TLS)", "medio", "idem."),
    6466: ("Android TV (controle remoto)", "baixo", "pareamento com código na tela."),
    1925: ("Philips JointSpace", "medio", "alguns modelos aceitam comando sem senha."),
    7676: ("Samsung (UPnP)", "baixo", "descoberta e mídia."),
}


def tv_auditar(ip, varrer=None):
    """O que a TV (sua) deixa a rede fazer com ela."""
    valida_alvo("portas", ip)
    varrer = varrer or (lambda h, ps: [p["porta"] for p in pscan(h, ps)])
    abertas = varrer(ip, list(TV_PORTAS))
    itens = [dict(porta=p, servico=TV_PORTAS[p][0], nivel=TV_PORTAS[p][1],
                  msg=TV_PORTAS[p][2]) for p in sorted(abertas)]
    if not itens:
        itens.append(dict(porta=None, servico="-", nivel="baixo",
                          msg="Nenhuma porta de controle remoto de TV aberta."))
    return {"ip": ip, "roku": 8060 in abertas, "itens": itens}


# ---------------------------------------------------- CSV e backup
def csv_texto(tipo, rede_id=None):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    if tipo == "dispositivos":
        linhas = listar_dispositivos(rede_id or rede_id_atual() or "sem-rede")
        cols = ["ip", "mac", "fabricante", "nome", "autorizado", "primeiro", "ultimo"]
    elif tipo == "alertas":
        linhas = listar_alertas(rede_id or rede_id_atual(), 5000)
        cols = ["ts", "nivel", "tipo", "msg"]
    elif tipo in ("bateria", "sinal", "celular"):
        linhas = medidas(tipo, horas=24 * 90)
        cols = ["ts", "rotulo", "valor", "extra"]
    else:
        raise ValueError("tipo de CSV desconhecido")
    w.writerow(cols)
    for r in linhas:
        lin = []
        for c in cols:
            v = r.get(c)
            if c in ("ts", "primeiro", "ultimo") and isinstance(v, (int, float)):
                v = datetime.datetime.fromtimestamp(v).isoformat(timespec="seconds")
            elif isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False)
            lin.append(v)
        w.writerow(lin)
    return buf.getvalue()


def backup_bytes():
    """Cópia consistente do banco (API de backup do SQLite)."""
    tmp = DB + ".backup"
    with DBLOCK:
        origem = db()
        destino = sqlite3.connect(tmp)
        origem.backup(destino)
        destino.close()
        origem.close()
    with open(tmp, "rb") as f:
        dados = f.read()
    os.remove(tmp)
    return dados


def selar(rel):
    """Acrescenta o SHA-256 do relatório (para provar que não foi alterado)."""
    texto = json.dumps(rel, ensure_ascii=False, sort_keys=True, default=str)
    rel["integridade"] = {"algoritmo": "sha256",
                          "hash": hashlib.sha256(texto.encode()).hexdigest(),
                          "como_conferir": "Apague o campo 'integridade', grave o "
                          "JSON com chaves ordenadas e calcule o SHA-256."}
    return rel


def cookie_token(headers):
    raw = headers.get("Cookie", "")
    for parte in raw.split(";"):
        if "=" in parte:
            k, v = parte.strip().split("=", 1)
            if k == "kit_token":
                return v
    return None


def token_ok(valor):
    """Compara o token em tempo constante; token vazio nunca autoriza."""
    if not TOKEN or not valor:
        return False
    return secrets.compare_digest(str(valor).encode(), TOKEN.encode())


PAGINA_401 = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Kit de Bolso</title>
<body style="font-family:monospace;background:#0b0f0c;color:#b6f5c8;padding:20px">
<h2 style="color:#5dff8f">Kit de Bolso</h2>
<p>Acesso protegido por token. Abra pelo comando <code>kit</code> no Termux
ou pelo atalho "Kit de Bolso" do Termux:Widget (os dois já incluem o token),
ou cole o token abaixo.</p>
<form method=get action="/"><input name=token autocomplete=off placeholder="token"
 style="width:100%;padding:8px;background:#050806;color:#c9ffd9;border:1px solid #2e7a47">
<button style="margin-top:8px;padding:8px 14px">Entrar</button></form>
<p style="font-size:12px;color:#7a9c85">O token fica em <code>~/kit/.token</code>.
Se você gerou um novo com <code>kit --novo-token</code>, o antigo deixou de valer.</p>
</body>"""


class H(http.server.BaseHTTPRequestHandler):
    server_version = "KitDeBolso"
    sys_version = ""

    def log_message(self, *a):
        pass

    # -- helpers
    def j(self, o, code=200, baixar=None):
        b = json.dumps(o, ensure_ascii=False, default=str,
                       indent=1 if baixar else None).encode()
        self.send_response(code)
        self._headers_comuns()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if baixar:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{baixar}"')
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _bruto(self, b, tipo, code=200, cache=None, nonce=None):
        self.send_response(code)
        self._headers_comuns(nonce, cache)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _headers_comuns(self, nonce=None, cache=None):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", cache or "no-store")
        # Sem 'unsafe-inline' em script-src: o único <script> leva um nonce
        # novo a cada carregamento e a interface não usa onclick="...".
        script = f"'nonce-{nonce}'" if nonce else "'none'"
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; "
                         "connect-src 'self' https://speed.cloudflare.com "
                         "https://api.wheretheiss.at; img-src 'self' data:; "
                         "style-src 'self' 'unsafe-inline'; "
                         f"script-src {script}; worker-src 'self'; "
                         "manifest-src 'self'; object-src 'none'; "
                         "base-uri 'none'; frame-ancestors 'none'")

    def _host_ok(self):
        h = self.headers.get("Host", "")
        return h in HOSTS_OK

    def _autorizado(self):
        return (token_ok(self.headers.get("X-Kit-Token"))
                or token_ok(cookie_token(self.headers)))

    # -- roteamento
    def do_GET(self):
        self._rotear("GET")

    def do_POST(self):
        self._rotear("POST")

    def _rotear(self, metodo):
        try:
            if not self._host_ok():
                return self.j({"erro": "host não permitido"}, 403)
            u = urllib.parse.urlparse(self.path)
            p = u.path
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}

            # Página inicial e autenticação por token
            if p in ("/", "/index.html"):
                return self._servir_index(q)
            if p in PUBLICAS and metodo == "GET":
                return self._servir_publico(PUBLICAS[p])

            if not p.startswith("/api/"):
                return self.j({"erro": "não encontrado"}, 404)

            # Todas as rotas /api exigem token
            if not self._autorizado():
                return self.j({"erro": "não autorizado (token ausente ou inválido)"}, 401)

            if p == "/api/cap/importar":  # corpo binário, não JSON
                if metodo != "POST":
                    return self.j({"erro": "use POST"}, 405)
                return self._importar(q)

            corpo = self._ler_json() if metodo == "POST" else {}
            a = (corpo.get("a") if metodo == "POST" else q.get("a", "")) or ""
            if not isinstance(a, str):
                raise ValueError("parâmetro 'a' deve ser texto")

            self._api(metodo, p, q, corpo, a.strip())
        except ValueError as e:
            self.j({"erro": str(e)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except OSError as e:
            self.j({"erro": f"falha de rede: {e.strerror or e}"}, 503)
        except Exception as e:
            print("ERRO 500:", repr(e))
            self.j({"erro": "erro interno ao processar a requisição"}, 500)

    def _ler_json(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0 or n > 65536:
            return {}
        try:
            d = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception:
            return {}
        return d if isinstance(d, dict) else {}

    def _importar(self, q):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0:
            return self.j({"erro": "arquivo vazio"}, 400)
        if n > LIMITE_IMPORT:
            return self.j({"erro": "arquivo maior que 25 MB"}, 413)
        dados = self.rfile.read(n)
        if q.get("limpar") == "1":
            limpar_captura()
        return self.j(importar_pcap(dados))

    def _servir_publico(self, qual):
        """Arquivos do app instalável. Não têm segredo, então não pedem token."""
        if qual == "manifest":
            return self._bruto(json.dumps(manifesto(), ensure_ascii=False).encode(),
                               "application/manifest+json; charset=utf-8",
                               cache="no-cache")
        if qual == "abrir":
            return self._bruto(PAGINA_ABRIR.encode(), "text/html; charset=utf-8")
        if qual == "sw":
            return self._bruto(SERVICE_WORKER.encode(),
                               "text/javascript; charset=utf-8", cache="no-cache")
        if qual == "svg":
            return self._bruto(ICONE_SVG.encode(), "image/svg+xml",
                               cache="max-age=86400")
        return self._bruto(icone_png(qual), "image/png", cache="max-age=86400")

    def _servir_index(self, q):
        # /?token=... define cookie e redireciona para limpar a URL
        if token_ok(q.get("token")):
            self.send_response(302)
            self.send_header("Set-Cookie",
                             f"kit_token={TOKEN}; HttpOnly; SameSite=Strict; "
                             f"Path=/; Max-Age={COOKIE_DIAS * 86400}")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Location", "/")
            self.end_headers()
            return
        if not self._autorizado():
            return self._bruto(PAGINA_401.encode(), "text/html; charset=utf-8", 401)
        with open(os.path.join(HERE, "index.html"), "r", encoding="utf-8") as f:
            html = f.read()
        nonce = secrets.token_urlsafe(16)
        html = html.replace("/*KIT_TOKEN*/\"\"", json.dumps(TOKEN))
        html = html.replace("<script>", f'<script nonce="{nonce}">')
        self._bruto(html.encode(), "text/html; charset=utf-8", nonce=nonce)

    # Rotas que mudam estado ou fazem varredura ativa -> exigem POST
    ESCRITA = {"/api/run", "/api/inventario", "/api/wol", "/api/alertas/limpar",
               "/api/cap/limpar", "/api/dispositivo/autorizar", "/api/arpwatch",
               "/api/cap/importar", "/api/agenda/salvar", "/api/portas",
               "/api/roteador", "/api/ssdp", "/api/mdns", "/api/rede/renomear",
               "/api/auditoria", "/api/eviltwin", "/api/eviltwin/aprender",
               "/api/dnscheck", "/api/sinal/marcar", "/api/treino",
               "/api/ir/enviar", "/api/tv/roku", "/api/tv/auditar",
               "/api/config", "/api/wifi/autoteste"}

    def _rede_param(self, q, corpo):
        rid = (corpo.get("rede") if corpo else None) or q.get("rede")
        return valida_rede_id(rid) if rid else (rede_id_atual() or "sem-rede")

    def _api(self, metodo, p, q, corpo, a):
        if p in self.ESCRITA and metodo != "POST":
            return self.j({"erro": "use POST"}, 405)

        if p == "/api/info":
            from shutil import which
            ip = local_ip()
            ferr = ["nmap", "ping", "traceroute", "dig", "whois", "curl", "mtr",
                    "iperf3", "termux-wifi-connectioninfo"]
            return self.j({
                "versao": VERSAO,
                "ip_local": ip or "sem rede", "gateway": gateway() or "sem rede",
                "host": socket.gethostname(), "python": sys.version.split()[0],
                "ferramentas": {t: bool(which(t)) for t in ferr},
                "embutidos": [t for t, e in (("dig", "dig"), ("whois", "whois"),
                                             ("curl", "headers"))
                              if not which(t) and e in EMBUTIDOS],
                "rede": rede_atual(), "lan": LAN,
                "wifi": termux("termux-wifi-connectioninfo"), "pacotes": ST["pkts"]})
        if p == "/api/redes":
            return self.j(listar_redes())
        if p == "/api/rede/renomear":
            return self.j(dict(renomear_rede(corpo.get("rede"), corpo.get("nome")),
                               ok=True))
        if p == "/api/dispositivos":
            rid = self._rede_param(q, corpo)
            return self.j({"rede_id": rid, "rede_nome": nome_rede(rid),
                           "inventario": listar_dispositivos(rid)})
        if p == "/api/wifiscan":
            return self.j(termux("termux-wifi-scaninfo") or
                          {"erro": "Instale Termux:API (mesma loja do Termux) e "
                                   "rode pkg install termux-api; dê permissão de "
                                   "Localização."})
        if p == "/api/celular":
            return self.j(termux("termux-telephony-cellinfo") or
                          {"erro": "Requer Termux:API"})
        if p == "/api/bateria":
            return self.j(termux("termux-battery-status") or
                          {"erro": "Requer Termux:API (pkg install termux-api)"})
        if p == "/api/ssdp":
            return self.j(ssdp())
        if p == "/api/mdns":
            return self.j(mdns())
        if p == "/api/cert":
            if not a:
                return self.j({"erro": "informe o domínio"}, 400)
            return self.j(cert(a))
        if p == "/api/oui":
            return self.j({"mac": a, "fabricante": fabricante(a)})
        if p == "/api/portas":
            if not a:
                return self.j({"erro": "informe o host"}, 400)
            if _eh_ip(a):  # recusa IP público antes de qualquer consulta DNS
                valida_alvo("portas", a)
            try:
                host = socket.gethostbyname(a)
            except (socket.gaierror, UnicodeError):
                return self.j({"erro": "nome não resolvido"}, 400)
            valida_alvo("portas", host)
            return self.j(pscan(host, COMMON))
        if p == "/api/wol":
            return self.j({"resultado": wol(a)})
        if p == "/api/roteador":
            gw = a or gateway()
            if not gw:
                return self.j({"erro": "sem rede"}, 400)
            valida_alvo("roteador", gw)
            return self.j({"gateway": gw, "pagina": router_page(gw),
                           "portas_abertas": pscan(gw, COMMON)})
        if p == "/api/inventario":
            faixa = a or (local_ip() or "")
            if not faixa:
                return self.j({"erro": "sem rede"}, 400)
            if "/" not in faixa:
                faixa = faixa.rsplit(".", 1)[0] + ".0/24"
            valida_alvo("inventario", faixa)
            return self.j(inventario(faixa))
        if p == "/api/arpwatch":
            return self.j(check_arp())
        if p == "/api/alertas":
            rid = q.get("rede")
            if rid != "todas":
                rid = valida_rede_id(rid) if rid else rede_id_atual()
            return self.j(listar_alertas(rid))
        if p == "/api/alertas/limpar":
            with DBLOCK:
                c = db()
                c.execute("DELETE FROM alertas")
                c.commit()
                c.close()
            with _ALERTA_LOCK:
                _ultimo_alerta.clear()
            return self.j({"ok": True})
        if p == "/api/dispositivo/autorizar":
            nome = re.sub(r"\s+", " ", str(corpo.get("nome", "") or "")).strip()[:60]
            ip = a
            if not _eh_ip(ip):
                return self.j({"erro": "IP inválido"}, 400)
            rid = self._rede_param(q, corpo)
            mac = str(corpo.get("mac", "") or "").lower()
            with DBLOCK:
                c = db()
                if mac:
                    n = c.execute("UPDATE dispositivos SET autorizado=1, nome=? "
                                  "WHERE rede_id=? AND ip=? AND lower(mac)=?",
                                  (nome, rid, ip, mac)).rowcount
                else:
                    n = c.execute("UPDATE dispositivos SET autorizado=1, nome=? "
                                  "WHERE rede_id=? AND ip=?", (nome, rid, ip)).rowcount
                c.commit()
                c.close()
            if not n:
                return self.j({"erro": "dispositivo não encontrado nesta rede"}, 404)
            return self.j({"ok": True})
        if p == "/api/historico":
            try:
                horas = max(1, min(int(q.get("horas", 24)), 24 * 30))
            except ValueError:
                return self.j({"erro": "parâmetros inválidos"}, 400)
            rid = self._rede_param(q, corpo)
            return self.j({"rede_id": rid, "rede_nome": nome_rede(rid),
                           "comparacao": comparar_varreduras(horas, rid),
                           "varreduras": listar_varreduras(20, rid)})
        if p == "/api/agenda":
            return self.j(dict(agenda_get(), rede_atual=rede_id_atual()))
        if p == "/api/agenda/salvar":
            cfg = agenda_set(corpo.get("minutos", 0), corpo.get("faixa", ""))
            return self.j(dict(cfg, ok=True))
        if p == "/api/deteccoes":
            return self.j(DET.resumo())
        if p == "/api/run":
            tool = corpo.get("t")
            if tool not in TOOLS and tool != "dig":
                return self.j({"erro": "ferramenta desconhecida"}, 400)
            alvo = valida_alvo(tool, a)
            self.send_response(200)
            self._headers_comuns()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            return run_stream(tool, alvo, self.wfile, self.wfile.flush)
        if p == "/api/cap/pacotes":
            try:
                desde = int(q.get("desde", 0))
                lim = max(1, min(int(q.get("lim", 300)), 1000))
            except ValueError:
                return self.j({"erro": "parâmetros inválidos"}, 400)
            with LOCK:
                L = [{k: v for k, v in r.items() if k != "raw"}
                     for r in PK if r["n"] > desde][-lim:]
            return self.j(L)
        if p == "/api/cap/stats":
            with LOCK:
                dur = (PK[-1]["t"] - ST["inicio"]) if PK else 0
                return self.j({
                    "pacotes": ST["pkts"], "bytes": ST["bytes"],
                    "duracao_s": round(dur, 1),
                    "protocolos": ST["proto"].most_common(12),
                    "hosts": ST["hosts"].most_common(15),
                    "dominios": ST["dominios"].most_common(30),
                    "portas": ST["portas"].most_common(12),
                    "inseguro": ST["inseguro"].most_common(10),
                    "inseguro_por_aparelho": ST["inseguro_host"].most_common(20)})
        if p == "/api/cap/limpar":
            limpar_captura()
            return self.j({"ok": True})
        if p == "/api/cap/pcap":
            b = pcap_bytes()
            self.send_response(200)
            self._headers_comuns()
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Disposition",
                             f'attachment; filename="captura-'
                             f'{time.strftime("%Y%m%d-%H%M%S")}.pcap"')
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            return self.wfile.write(b)
        if p == "/api/relatorio":
            nome = None
            if q.get("baixar") == "1":
                nome = f"relatorio-kit-{time.strftime('%Y%m%d-%H%M%S')}.json"
            return self.j(selar(relatorio(rede_id=self._rede_param(q, corpo))),
                          baixar=nome)
        if self._api_33(p, q, corpo, a):
            return
        self.j({"erro": "não encontrado"}, 404)

    def _scan_lista(self):
        scan = termux("termux-wifi-scaninfo")
        if not isinstance(scan, list):
            raise ValueError("scan Wi-Fi indisponível: instale o Termux:API e dê "
                             "permissão de Localização")
        return scan

    def _api_33(self, p, q, corpo, a):
        """Rotas da versão 3.3. Retorna True se tratou a rota."""
        if p == "/api/wifi/autoteste":
            w = termux("termux-wifi-connectioninfo") or {}
            ssid = w.get("ssid") if isinstance(w, dict) else ""
            self.j(avaliar_wifi_proprio(ssid, self._scan_lista()))
        elif p == "/api/canais":
            self.j(analisar_canais(self._scan_lista()))
        elif p in ("/api/eviltwin", "/api/eviltwin/aprender"):
            rede = rede_atual()
            if not rede:
                raise ValueError("sem rede identificada (conecte-se ao seu Wi-Fi)")
            w = termux("termux-wifi-connectioninfo") or {}
            ssid = rede.get("ssid") or (w.get("ssid") if isinstance(w, dict) else "")
            scan = self._scan_lista()
            if p.endswith("aprender"):
                n = aprender_bssids(rede["id"], ssid, scan,
                                    w.get("bssid") if isinstance(w, dict) else "",
                                    todos=corpo.get("todos") is True)
                self.j({"ok": True, "aprendidos": n})
                return True
            r = avaliar_evil_twin(rede["id"], ssid, scan)
            r["portal"] = portal_cativo()
            for x in r["achados"]:
                if x["nivel"] == "alto":
                    alerta("alto", "evil_twin", x["msg"], dedup_s=3600,
                           rede_id=rede["id"])
            self.j(dict(r, ssid=ssid))
        elif p == "/api/dnscheck":
            self.j(checar_dns())
        elif p == "/api/auditoria":
            gw = a or gateway()
            if not gw:
                raise ValueError("sem rede")
            self.j(auditoria_roteador(gw))
        elif p == "/api/linha-tempo":
            rid = q.get("rede")
            rid = None if rid == "todas" else (valida_rede_id(rid) if rid
                                               else rede_id_atual())
            self.j(linha_do_tempo(rid))
        elif p == "/api/medidas":
            tipo = q.get("tipo", "bateria")
            if tipo not in ("bateria", "sinal", "celular"):
                raise ValueError("tipo inválido")
            try:
                horas = max(1, min(int(q.get("horas", 24)), 24 * 90))
            except ValueError:
                raise ValueError("horas inválido")
            self.j(medidas(tipo, horas))
        elif p == "/api/sinal/marcar":
            self.j(marcar_sinal(corpo.get("local")))
        elif p == "/api/sinal/mapa":
            self.j(mapa_sinal(self._rede_param(q, corpo)))
        elif p == "/api/treino":
            c = corpo.get("cenario")
            if c not in TREINOS:
                raise ValueError("cenário de treino desconhecido")
            self.j(rodar_treino(c))
        elif p == "/api/treinos":
            self.j({k: v["titulo"] for k, v in TREINOS.items()})
        elif p == "/api/ir/info":
            self.j(dict(ir_frequencias(), marcas={k: len(v) for k, v in
                                                  IR_CODIGOS.items()},
                        teclas={k: sorted(v) for k, v in IR_TECLAS.items()}))
        elif p == "/api/ir/codigo":
            marca = q.get("marca", "")
            if marca not in IR_CODIGOS:
                raise ValueError("marca desconhecida")
            try:
                i = int(q.get("i", 0))
                prot, end, cmd = IR_CODIGOS[marca][i]
            except (ValueError, IndexError):
                raise ValueError("índice fora da lista")
            tecla = q.get("tecla")
            if tecla:
                if tecla not in IR_TECLAS.get(marca, {}):
                    raise ValueError("tecla desconhecida para essa marca")
                cmd = IR_TECLAS[marca][tecla]
            freq, padrao = IR_PROTOCOLOS[prot](end, cmd)
            self.j({"marca": marca, "i": i, "total": len(IR_CODIGOS[marca]),
                    "protocolo": prot, "endereco": hex(end), "comando": hex(cmd),
                    "frequencia": freq, "padrao": padrao})
        elif p == "/api/ir/padrao":
            freq, padrao = ir_montar(q)
            self.j({"frequencia": freq, "padrao": padrao})
        elif p == "/api/ir/enviar":
            self.j(ir_enviar(corpo))
        elif p == "/api/tv/auditar":
            self.j(tv_auditar(a))
        elif p == "/api/tv/roku":
            self.j(tv_roku(a, corpo.get("tecla")))
        elif p == "/api/config":
            mudou = {}
            for k in ("notificacoes", "registro"):
                if isinstance(corpo.get(k), bool):
                    config_set(k, corpo[k])
                    mudou[k] = corpo[k]
            self.j({"ok": True, "mudou": mudou,
                    "notificacoes": config_get("notificacoes", True),
                    "registro": config_get("registro", True)})
        elif p == "/api/config/ver":
            self.j({"notificacoes": config_get("notificacoes", True),
                    "registro": config_get("registro", True)})
        elif p == "/api/csv":
            tipo = q.get("tipo", "")
            txt = csv_texto(tipo, self._rede_param(q, corpo)).encode("utf-8-sig")
            self._baixar(txt, "text/csv; charset=utf-8",
                         f"kit-{tipo}-{time.strftime('%Y%m%d-%H%M%S')}.csv")
        elif p == "/api/backup":
            self._baixar(backup_bytes(), "application/vnd.sqlite3",
                         f"kit-backup-{time.strftime('%Y%m%d-%H%M%S')}.db")
        else:
            return False
        return True

    def _baixar(self, b, tipo, nome):
        self.send_response(200)
        self._headers_comuns()
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Disposition", f'attachment; filename="{nome}"')
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def carregar_token(novo=False):
    """Lê o token persistente ou cria um (permissão 600).

    novo=True gera um token novo e invalida o antigo (cookies e links
    antigos param de funcionar).
    """
    token = ""
    if not novo and os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            token = f.read().strip()
    if not token:
        token = secrets.token_urlsafe(24)
        tmp = TOKEN_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token)
        os.replace(tmp, TOKEN_FILE)  # troca atômica: o atalho nunca lê pela metade
    os.chmod(TOKEN_FILE, 0o600)
    return token


def montar_hosts_ok(porta, lan, ip):
    """Valores aceitos no cabeçalho Host (anti DNS rebinding)."""
    hosts = {f"127.0.0.1:{porta}", f"localhost:{porta}"}
    if porta == 80:  # o navegador omite ":80" no cabeçalho Host
        hosts |= {"127.0.0.1", "localhost"}
    if lan and ip:
        hosts.add(f"{ip}:{porta}")
        if porta == 80:
            hosts.add(ip)
    return hosts


def atualizar_hosts_ok(ip=None):
    """Recalcula HOSTS_OK com o IP atual. Retorna True se mudou.

    No modo --lan o IP do aparelho pode mudar (novo DHCP); sem isso o
    servidor passaria a responder 403 no endereço novo.
    """
    global HOSTS_OK
    novo = montar_hosts_ok(HTTP_PORT, LAN, local_ip() if ip is None else ip)
    mudou = novo != HOSTS_OK
    HOSTS_OK = novo
    return mudou


def hosts_loop(intervalo=30):
    while True:
        time.sleep(intervalo)
        try:
            if atualizar_hosts_ok() and LAN:
                ip = local_ip()
                if ip:
                    print(f"IP do aparelho mudou. Novo endereço: "
                          f"http://{ip}:{HTTP_PORT}/")
        except Exception as e:
            print("hosts:", e)


AVISO_LAN = """
==================================================
 MODO REDE (--lan): {url}
 ATENÇÃO: o tráfego é HTTP SEM criptografia. Quem estiver na
 mesma rede pode capturar o token. Use --lan só na SUA rede e,
 ao terminar, troque o token:  kit --novo-token
==================================================
"""


def criar_parser():
    ap = argparse.ArgumentParser(description="Kit de Bolso do Técnico")
    ap.add_argument("--lan", action="store_true",
                    help="acessível por outros aparelhos da rede (HTTP sem "
                         "criptografia: use só na sua rede)")
    ap.add_argument("--porta", type=int, default=8080, help="porta HTTP")
    ap.add_argument("--agendar", type=int, metavar="MIN",
                    help="inventário automático a cada MIN minutos (0 desliga); "
                         "fica preso à rede atual")
    ap.add_argument("--faixa", default=None,
                    help="faixa do inventário agendado (ex.: 192.168.0.0/24)")
    ap.add_argument("--relatorio", metavar="ARQ",
                    help="grava o relatório JSON em ARQ e sai")
    ap.add_argument("--novo-token", action="store_true",
                    help="gera um token novo e invalida o antigo (use depois "
                         "do --lan ou se o token vazou)")
    return ap


def main(argv=None):
    global HTTP_PORT, LAN, TOKEN
    args = criar_parser().parse_args(argv)
    if not 1 <= args.porta <= 65535:
        print("Porta inválida (1 a 65535).")
        sys.exit(2)
    HTTP_PORT, LAN = args.porta, args.lan

    db_init()

    if args.relatorio:
        with open(args.relatorio, "w", encoding="utf-8") as f:
            json.dump(relatorio(), f, ensure_ascii=False, indent=1, default=str)
        print(f"Relatório gravado em {args.relatorio}")
        return

    if args.agendar is not None:
        try:
            cfg = agenda_set(args.agendar, args.faixa or "")
        except ValueError as e:
            print(f"Agendamento inválido: {e}")
            sys.exit(2)
        print("Agendamento:", "desligado" if not cfg["minutos"] else
              f"a cada {cfg['minutos']} min em {cfg['faixa'] or 'faixa automática'}"
              f", só na rede '{cfg['rede_nome']}'")

    ip = local_ip()
    atualizar_hosts_ok(ip)
    bind = "0.0.0.0" if LAN else "127.0.0.1"
    try:
        srv = S((bind, HTTP_PORT), H)
    except OSError:
        print(f"A porta {HTTP_PORT} está em uso (outro kit aberto?). "
              f"Feche-o ou use: kit --porta 8090")
        sys.exit(1)
    # O token só é lido/gerado depois de a porta estar garantida: assim um
    # --novo-token com outro kit aberto não deixa o arquivo fora de sincronia.
    TOKEN = carregar_token(args.novo_token)
    if args.novo_token:
        print("Token novo gerado. Links e cookies antigos deixaram de valer.")

    threading.Thread(target=udp_loop, daemon=True).start()
    threading.Thread(target=agenda_loop, daemon=True).start()
    threading.Thread(target=registro_loop, daemon=True).start()
    if LAN:
        threading.Thread(target=hosts_loop, daemon=True).start()

    url = f"http://127.0.0.1:{HTTP_PORT}/?token={TOKEN}"
    print(f"Kit de Bolso {VERSAO} em {url}")
    print(f"Captura (PCAPdroid -> Exportador UDP): 127.0.0.1:{UDP_PORT}")
    if LAN:
        if ip:
            print(AVISO_LAN.format(url=f"http://{ip}:{HTTP_PORT}/?token={TOKEN}"))
        else:
            print("Modo rede pedido, mas o aparelho está sem IP de rede agora.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nKit encerrado.")


if __name__ == "__main__":
    main()
