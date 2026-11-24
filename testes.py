#!/usr/bin/env python3
"""Testes do Kit (stdlib unittest). Rode: python testes.py

Não há Android no ambiente de teste, então tudo é SIMULADO:
  - pacotes PCAP sintéticos (IP puro, Ethernet/ARP, DHCP, 802.11/radiotap);
  - injeção desses pacotes na porta UDP, igual ao Exportador do PCAPdroid;
  - faixas de rede fictícias com sonda e tabela ARP mockadas;
  - servidor HTTP real numa porta livre, com banco SQLite temporário;
  - redes (casa, cliente) simuladas trocando o coletor de rede;
  - o atalho "kit" executado de verdade com um servidor falso lento:
    segundo plano, "já ligado", parar, duas partidas juntas, modo automático
    (Termux:Boot e ~/.bashrc) e o instalar.sh com pkg falso.
"""
import http.client
import json
import errno
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import struct
import tempfile
import threading
import time
import unittest

import server

# Banco temporário: os testes nunca tocam o kit.db real.
_TMP = tempfile.mkdtemp(prefix="kit-testes-")
server.DB = os.path.join(_TMP, "kit.db")
server.TOKEN_FILE = os.path.join(_TMP, ".token")
server.db_init()
AQUI = os.path.dirname(os.path.abspath(__file__))

# Redes fictícias: mesma faixa 192.168.0.0/24, lugares diferentes.
REDE_CASA = {"gateway": "192.168.0.1", "gw_mac": "", "ssid": "CasaHesblan",
             "bssid": "aa:bb:cc:00:00:01"}
REDE_CLIENTE = {"gateway": "192.168.0.1", "gw_mac": "", "ssid": "VIVO-CLIENTE",
                "bssid": "aa:bb:cc:00:00:99"}


def na_rede(info):
    """Simula o aparelho conectado à rede 'info' (sem Termux nem ip route)."""
    server.coletar_rede = lambda: dict(info)
    return server.rede_atual(forcar=True)


na_rede(REDE_CASA)


# ------------------------------------------------------------ geradores
def ip_tcp(src="10.0.0.5", dst="93.184.1.1", sp=40000, dp=80, payload=b""):
    tcp = struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 0x50, 0x18, 0, 0, 0) + payload
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + tcp


def ip_udp(src, dst, sp, dp, payload=b""):
    udp = struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + udp


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack(">H", etype) + payload


def arp_reply(ip, hw, alvo_ip="192.168.0.10", alvo_hw="aa:aa:aa:aa:aa:aa"):
    corpo = (struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2) + mac(hw)
             + socket.inet_aton(ip) + mac(alvo_hw) + socket.inet_aton(alvo_ip))
    return eth(alvo_hw, hw, 0x0806, corpo)


def dhcp_offer(servidor, roteador, oferecido="192.168.0.50"):
    bootp = bytearray(240)
    bootp[0] = 2  # BOOTREPLY
    bootp[1], bootp[2] = 1, 6
    bootp[16:20] = socket.inet_aton(oferecido)
    bootp[236:240] = b"\x63\x82\x53\x63"
    opts = (b"\x35\x01\x02"                                  # OFFER
            + b"\x36\x04" + socket.inet_aton(servidor)       # server id
            + b"\x03\x04" + socket.inet_aton(roteador)       # router
            + b"\x06\x08" + socket.inet_aton(roteador) + socket.inet_aton("8.8.8.8")
            + b"\xff")
    pkt = ip_udp(servidor, "255.255.255.255", 67, 68, bytes(bootp) + opts)
    return eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x0800, pkt)


def radiotap_deauth(bssid="11:22:33:44:55:66", alvo="ff:ff:ff:ff:ff:ff", motivo=7):
    rt = struct.pack("<BBHI", 0, 0, 8, 0)  # cabeçalho radiotap mínimo (8 bytes)
    quadro = (struct.pack("<BBH", 0xC0, 0, 0) + mac(alvo) + mac(bssid)
              + mac(bssid) + b"\x00\x00" + struct.pack("<H", motivo))
    return rt + quadro


def pcap(pacotes, link, t0=1700000000.0, passo=0.1):
    out = [struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, link)]
    for i, p in enumerate(pacotes):
        t = t0 + i * passo
        out.append(struct.pack("<IIII", int(t), int(t % 1 * 1e6), len(p), len(p)))
        out.append(p)
    return b"".join(out)


def pcapng(pacotes, link, t0=1700000000.0):
    def bloco(tipo, corpo):
        corpo += b"\x00" * ((4 - len(corpo) % 4) % 4)
        n = 12 + len(corpo)
        return struct.pack("<II", tipo, n) + corpo + struct.pack("<I", n)
    out = [bloco(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)),
           bloco(1, struct.pack("<HHI", link, 0, 262144))]
    for i, p in enumerate(pacotes):
        us = int((t0 + i) * 1e6)
        out.append(bloco(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF,
                                        len(p), len(p)) + p))
    return b"".join(out)


def limpar_tudo():
    server.limpar_captura()
    server._ultimo_alerta.clear()
    with server.DBLOCK:
        c = server.db()
        for t in ("alertas", "dispositivos", "varreduras", "config", "arp", "redes",
                  "bssids", "medidas"):
            c.execute(f"DELETE FROM {t}")
        c.commit()
        c.close()
    server._REDE.update(ts=0.0, rede=None, id_anterior=None)
    return na_rede(REDE_CASA)


def alertas(tipo=None):
    with server.DBLOCK:
        c = server.db()
        rows = [dict(r) for r in c.execute("SELECT * FROM alertas")]
        c.close()
    return [r for r in rows if tipo is None or r["tipo"] == tipo]


# ------------------------------------------------------------ decodificação
class TestParse(unittest.TestCase):
    def setUp(self):
        server.LINK[0] = 101

    def test_tcp_http_valido(self):
        r = server.parse(ip_tcp(payload=b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"))
        self.assertEqual(r["proto"], "TCP")
        self.assertEqual(r["app"], "HTTP")

    def test_ipv4_truncado(self):
        self.assertIsNone(server.parse(b"\x45\x00\x00"))  # < 20 bytes

    def test_ipv6_truncado(self):
        self.assertIsNone(server.parse(b"\x60" + b"\x00" * 10))  # < 40 bytes

    def test_tcp_sem_header_completo(self):
        ihl = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 25, 0, 0, 64, 6, 0,
                          socket.inet_aton("1.1.1.1"),
                          socket.inet_aton("2.2.2.2")) + b"\x00" * 5
        self.assertIsNotNone(server.parse(ihl))  # não deve lançar

    def test_lixo(self):
        self.assertIsNone(server.parse(b"\x00\x01\x02"))

    def test_ethernet_ipv4(self):
        p = eth("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", 0x0800, ip_tcp(dp=443))
        r = server.parse(p, server.LINK_ETHERNET)
        self.assertEqual(r["dst"], "93.184.1.1")
        self.assertEqual(r["app"], "HTTPS")

    def test_ethernet_vlan(self):
        p = (mac("aa:aa:aa:aa:aa:aa") + mac("bb:bb:bb:bb:bb:bb")
             + b"\x81\x00\x00\x0a\x08\x00" + ip_tcp(dp=22))
        self.assertEqual(server.parse(p, server.LINK_ETHERNET)["app"], "SSH")

    def test_arp(self):
        r = server.parse(arp_reply("192.168.0.1", "00:11:22:33:44:55"),
                         server.LINK_ETHERNET)
        self.assertEqual(r["proto"], "ARP")
        self.assertEqual(r["arp"]["mac"], "00:11:22:33:44:55")

    def test_dhcp_offer(self):
        r = server.parse(dhcp_offer("192.168.0.1", "192.168.0.1"),
                         server.LINK_ETHERNET)
        self.assertEqual(r["dhcp"]["tipo"], "OFFER")
        self.assertEqual(r["dhcp"]["servidor"], "192.168.0.1")
        self.assertEqual(r["dhcp"]["dns"], ["192.168.0.1", "8.8.8.8"])

    def test_radiotap_deauth(self):
        r = server.parse(radiotap_deauth(motivo=3), server.LINK_RADIOTAP)
        self.assertEqual(r["wifi"], "deauth")
        self.assertIn("motivo 3", r["info"])

    def test_80211_truncado(self):
        self.assertIsNone(server.parse(b"\xc0\x00", server.LINK_80211))


# ------------------------------------------------------------ alvos
class TestValidaAlvo(unittest.TestCase):
    def test_rejeita_opcao_nmap(self):
        with self.assertRaises(ValueError):
            server.valida_alvo("nmap_rapido", "-oN/sdcard/x")

    def test_rejeita_publico_na_varredura(self):
        with self.assertRaises(ValueError):
            server.valida_alvo("inventario", "8.8.8.8/24")

    def test_rejeita_injecao(self):
        with self.assertRaises(ValueError):
            server.valida_alvo("ping", "a;b")

    def test_aceita_privado(self):
        self.assertEqual(server.valida_alvo("inventario", "192.168.0.0/24"),
                         "192.168.0.0/24")

    def test_aceita_host_publico_no_ping(self):
        self.assertEqual(server.valida_alvo("ping", "8.8.8.8"), "8.8.8.8")

    def test_headers_exige_url(self):
        with self.assertRaises(ValueError):
            server.valida_alvo("headers", "google.com")
        self.assertTrue(server.valida_alvo("headers", "https://google.com"))

    def test_limite_prefixo(self):
        with self.assertRaises(ValueError):
            server.valida_alvo("nmap_rapido", "10.0.0.0/8")

    def test_cert_rejeita_lixo(self):
        with self.assertRaises(ValueError):
            server.cert("-x;rm")
        with self.assertRaises(ValueError):
            server.cert("exemplo.com:99999")


class TestFabricante(unittest.TestCase):
    def test_conhecido(self):
        self.assertEqual(server.fabricante("B8:27:EB:11:22:33"), "Raspberry Pi")

    def test_aleatorio(self):
        self.assertIn("aleatório", server.fabricante("DA:11:22:33:44:55"))

    def test_vazio(self):
        self.assertEqual(server.fabricante(""), "?")


# ------------------------------------------------------------ detecções
class TestDetectores(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_rajada_de_deauth_gera_alerta(self):
        dados = pcap([radiotap_deauth()] * 40, server.LINK_RADIOTAP, passo=0.05)
        r = server.importar_pcap(dados)
        self.assertEqual(r["decodificados"], 40)
        self.assertEqual(len(alertas("deauth")), 1)  # deduplicado
        self.assertEqual(server.DET.resumo()["deauth_total"], 40)

    def test_deauth_esparso_nao_alerta(self):
        # 10 quadros espaçados de 5 s: nunca 15 na janela de 10 s
        server.importar_pcap(pcap([radiotap_deauth()] * 10,
                                  server.LINK_RADIOTAP, passo=5))
        self.assertEqual(alertas("deauth"), [])

    def test_arp_spoof_na_captura(self):
        pk = [arp_reply("192.168.0.1", "00:11:22:33:44:55"),
              arp_reply("192.168.0.1", "00:11:22:33:44:55"),
              arp_reply("192.168.0.1", "de:ad:be:ef:00:01")]
        server.importar_pcap(pcap(pk, server.LINK_ETHERNET))
        a = alertas("arp_spoof")
        self.assertEqual(len(a), 1)
        self.assertIn("de:ad:be:ef:00:01", a[0]["msg"])

    def test_dhcp_falso(self):
        pk = [dhcp_offer("192.168.0.1", "192.168.0.1"),
              dhcp_offer("192.168.0.1", "192.168.0.1"),
              dhcp_offer("192.168.0.66", "192.168.0.66")]
        server.importar_pcap(pcap(pk, server.LINK_ETHERNET))
        a = alertas("dhcp_falso")
        self.assertEqual(len(a), 1)
        self.assertIn("192.168.0.66", a[0]["msg"])

    def test_importacao_lista_so_as_proprias_deteccoes(self):
        server.importar_pcap(pcap([radiotap_deauth()] * 20, server.LINK_RADIOTAP,
                                  passo=0.01))
        r = server.importar_pcap(pcap([ip_tcp(dp=443)], 101))
        self.assertEqual(r["deteccoes"], [])

    def test_um_dhcp_so_nao_alerta(self):
        server.importar_pcap(pcap([dhcp_offer("192.168.0.1", "192.168.0.1")] * 3,
                                  server.LINK_ETHERNET))
        self.assertEqual(alertas("dhcp_falso"), [])

    def test_trafego_inseguro_deduplicado(self):
        pk = [ip_tcp(dst=f"10.0.0.{i}", dp=23) for i in range(1, 6)]
        server.importar_pcap(pcap(pk, 101))
        self.assertEqual(len(alertas("inseguro")), 1)

    def test_credencial_em_http(self):
        p = ip_tcp(payload=b"POST /login HTTP/1.1\r\nHost: roteador.lan\r\n\r\n"
                           b"usuario=admin&senha=1234")
        server.importar_pcap(pcap([p], 101))
        self.assertEqual(len(alertas("credencial")), 1)


# ------------------------------------------------------------ arquivos pcap
class TestArquivosPcap(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_pcapng(self):
        r = server.importar_pcap(pcapng([ip_tcp(dp=443), ip_tcp(dp=80)], 101))
        self.assertEqual(r["decodificados"], 2)
        self.assertEqual(r["tipos_enlace"], {101: 2})

    def test_pcap_big_endian(self):
        p = ip_tcp()
        dados = (struct.pack(">IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
                 + struct.pack(">IIII", 1700000000, 0, len(p), len(p)) + p)
        self.assertEqual(server.importar_pcap(dados)["decodificados"], 1)

    def test_formato_invalido(self):
        with self.assertRaises(ValueError):
            server.ler_pcap(b"isto nao e pcap")

    def test_pcap_truncado_nao_quebra(self):
        dados = pcap([ip_tcp()] * 3, 101)[:-10]
        self.assertEqual(len(server.ler_pcap(dados)), 2)

    def test_exporta_e_reimporta(self):
        server.importar_pcap(pcap([ip_tcp(dp=443)] * 5, 101))
        exportado = server.pcap_bytes()
        server.limpar_captura()
        self.assertEqual(server.importar_pcap(exportado)["decodificados"], 5)


# ------------------------------------------------------------ captura UDP
class TestCapturaUDP(unittest.TestCase):
    """Simula o Exportador UDP do PCAPdroid enviando para 127.0.0.1."""

    @classmethod
    def setUpClass(cls):
        pronto = []
        threading.Thread(target=server.udp_loop, args=(0, pronto),
                         daemon=True).start()
        for _ in range(50):
            if pronto:
                break
            time.sleep(0.02)
        cls.porta = pronto[0]

    def setUp(self):
        limpar_tudo()

    def _enviar(self, datagramas):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for d in datagramas:
            s.sendto(d, ("127.0.0.1", self.porta))
        s.close()
        for _ in range(100):
            time.sleep(0.02)
            if server.ST["pkts"] >= self.esperado:
                break

    def test_cabecalho_e_pacotes_separados(self):
        dados = pcap([ip_tcp(dp=443), ip_udp("10.0.0.5", "8.8.8.8", 5000, 53,
                                             b"\x00" * 12 + b"\x03www\x00")], 101)
        self.esperado = 2
        self._enviar([dados[:24], dados[24:]])
        self.assertEqual(server.ST["pkts"], 2)
        self.assertIn("HTTPS", server.ST["proto"])

    def test_datagrama_lixo_nao_derruba(self):
        self.esperado = 1
        self._enviar([b"\xff" * 7, pcap([ip_tcp(dp=22)], 101)])
        self.assertEqual(server.ST["pkts"], 1)


# ------------------------------------------------------------ inventário
class TestInventario(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_respeita_o_prefixo(self):
        # antes o /28 varria o /24 inteiro (fora da faixa pedida)
        ips = server.hosts_da_faixa("192.168.0.16/28")
        self.assertEqual(ips[0], "192.168.0.17")
        self.assertEqual(ips[-1], "192.168.0.30")
        self.assertEqual(len(ips), 14)

    def test_recusa_ipv6_e_faixa_grande(self):
        with self.assertRaises(ValueError):
            server.hosts_da_faixa("fd00::/120")
        with self.assertRaises(ValueError):
            server.hosts_da_faixa("10.0.0.0/23")

    def test_novo_host_e_mac_trocado(self):
        vivos = {"192.168.50.1", "192.168.50.20"}
        arp = [("192.168.50.1", "b8:27:eb:00:00:01"),
               ("192.168.50.20", "dc:a6:32:00:00:02")]
        r = server.inventario("192.168.50.0/24", sonda=vivos.__contains__,
                              tabela_arp=arp)
        self.assertEqual(r["ativos"], ["192.168.50.1", "192.168.50.20"])
        self.assertEqual(len(r["novos"]), 2)
        self.assertEqual(len(alertas("novo_host")), 2)
        # mesma faixa, gateway agora com outro MAC
        arp[0] = ("192.168.50.1", "de:ad:be:ef:00:99")
        r = server.inventario("192.168.50.0/24", sonda=vivos.__contains__,
                              tabela_arp=arp)
        self.assertEqual(r["novos"], [])
        self.assertEqual(len(r["macs_trocados"]), 1)
        self.assertEqual(len(alertas("mac_trocado")), 1)


# ------------------------------------------------------------ histórico
class TestHistorico(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def _varredura(self, ts, ips, alvo="192.168.0.0/24", rede=None):
        rede = rede or server.rede_id_atual()
        with server.DBLOCK:
            c = server.db()
            c.execute("INSERT INTO varreduras(ts,alvo,hosts,resumo,rede_id) "
                      "VALUES(?,?,?,?,?)",
                      (ts, alvo, len(ips), json.dumps(ips), rede))
            c.commit()
            c.close()

    def test_hoje_contra_ontem(self):
        agora = time.time()
        self._varredura(agora - 30 * 3600, ["192.168.0.1", "192.168.0.9"])
        self._varredura(agora - 25 * 3600, ["192.168.0.1", "192.168.0.7"])
        self._varredura(agora - 3600, ["192.168.0.1"])
        self._varredura(agora, ["192.168.0.1", "192.168.0.42"])
        r = server.comparar_varreduras(24)
        self.assertEqual(r["novos"], ["192.168.0.42"])
        self.assertEqual(r["sumiram"], ["192.168.0.7"])  # a de 25h atrás
        self.assertEqual(r["mantidos"], 1)

    def test_sem_historico(self):
        self.assertIn("erro", server.comparar_varreduras())

    def test_nao_compara_redes_diferentes(self):
        agora = time.time()
        cliente = na_rede(REDE_CLIENTE)["id"]
        self._varredura(agora - 25 * 3600, ["192.168.0.1", "192.168.0.50"],
                        rede=cliente)
        casa = na_rede(REDE_CASA)["id"]
        self._varredura(agora, ["192.168.0.1", "192.168.0.7"], rede=casa)
        # só existe UMA varredura da casa: não há o que comparar
        self.assertIn("erro", server.comparar_varreduras(24))
        self.assertEqual(len(server.listar_varreduras(20, casa)), 1)


# ------------------------------------------------------------ agenda
class TestAgenda(unittest.TestCase):
    def setUp(self):
        limpar_tudo()
        server.AGENDA_ESTADO.update(ultima=None, ultimo_erro=None, execucoes=0,
                                    pausada=None)

    def test_validacao(self):
        with self.assertRaises(ValueError):
            server.agenda_set(2)
        with self.assertRaises(ValueError):
            server.agenda_set(30, "8.8.8.0/24")
        self.assertEqual(server.agenda_set(0)["minutos"], 0)

    def test_executa_no_intervalo(self):
        server.agenda_set(10, "192.168.7.0/24")
        chamadas = []
        t0 = 1_000_000.0
        self.assertTrue(server.agenda_tick(t0, chamadas.append))
        self.assertFalse(server.agenda_tick(t0 + 300, chamadas.append))
        self.assertTrue(server.agenda_tick(t0 + 601, chamadas.append))
        self.assertEqual(chamadas, ["192.168.7.0/24"] * 2)

    def test_desligada_nao_executa(self):
        server.agenda_set(0)
        self.assertFalse(server.agenda_tick(executar=lambda f: None))

    def test_falha_vira_alerta(self):
        server.agenda_set(5, "192.168.7.0/24")

        def quebra(faixa):
            raise OSError("sem rede")
        server.agenda_tick(executar=quebra)
        self.assertEqual(server.agenda_get()["ultimo_erro"], "sem rede")
        self.assertEqual(len(alertas("agenda")), 1)

    def test_agenda_presa_a_rede(self):
        # configurada em casa; o técnico vai ao cliente: nada é varrido
        na_rede(REDE_CASA)
        server.agenda_set(10, "192.168.0.0/24")
        chamadas = []
        na_rede(REDE_CLIENTE)
        self.assertFalse(server.agenda_tick(1_000_000.0, chamadas.append))
        self.assertEqual(chamadas, [])
        est = server.agenda_get()
        self.assertTrue(est["pausada"].startswith("agenda pausada: rede diferente"))
        self.assertIsNone(est["proxima"])
        self.assertEqual(len(alertas("agenda")), 1)
        # repetir o tick não enche a central de alertas
        server.agenda_tick(1_000_100.0, chamadas.append)
        self.assertEqual(len(alertas("agenda")), 1)
        # de volta em casa, a agenda volta a rodar
        na_rede(REDE_CASA)
        self.assertTrue(server.agenda_tick(1_000_200.0, chamadas.append))
        self.assertEqual(chamadas, ["192.168.0.0/24"])
        self.assertIsNone(server.agenda_get()["pausada"])

    def test_agenda_sem_rede_nao_roda(self):
        server.agenda_set(10, "192.168.0.0/24")
        na_rede({"gateway": ""})  # 4G / sem Wi-Fi
        self.assertFalse(server.agenda_tick(executar=lambda f: None))

    def test_agenda_antiga_sem_rede_nao_roda(self):
        # config gravada pela versão anterior (sem rede_id)
        server.config_set("agenda", {"minutos": 10, "faixa": "192.168.0.0/24"})
        chamadas = []
        self.assertFalse(server.agenda_tick(executar=chamadas.append))
        self.assertEqual(chamadas, [])

    def test_nao_agenda_sem_rede(self):
        na_rede({"gateway": ""})
        with self.assertRaises(ValueError):
            server.agenda_set(10)


# ------------------------------------------------------------ relatório
class TestRelatorio(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_relatorio_completo(self):
        server.importar_pcap(pcap([radiotap_deauth()] * 20, server.LINK_RADIOTAP,
                                  passo=0.01))
        r = server.relatorio(completo_rede=False)
        for chave in ("kit", "gerado", "rede", "resumo", "dispositivos", "alertas",
                      "varreduras", "comparacao_24h", "agenda", "captura",
                      "deteccoes"):
            self.assertIn(chave, r)
        self.assertEqual(r["captura"]["pacotes"], 20)
        self.assertEqual(r["resumo"]["alertas_por_nivel"].get("alto"), 1)
        json.dumps(r, default=str)  # serializável

    def test_relatorio_so_da_rede_escolhida(self):
        vivos = {"192.168.0.1", "192.168.0.10"}.__contains__
        server.inventario("192.168.0.0/24", sonda=vivos,
                          tabela_arp=[("192.168.0.10", "b8:27:eb:00:00:01")])
        casa = server.rede_id_atual()
        na_rede(REDE_CLIENTE)
        server.inventario("192.168.0.0/24", sonda={"192.168.0.1"}.__contains__,
                          tabela_arp=[])
        r = server.relatorio(completo_rede=False, rede_id=casa)
        self.assertEqual(r["rede_inventario"]["nome"], "CasaHesblan")
        self.assertFalse(r["rede_inventario"]["atual"])
        self.assertEqual(len(r["dispositivos"]), 2)
        self.assertTrue(all(a["rede_id"] in (None, casa) for a in r["alertas"]))

    def test_cli_relatorio(self):
        destino = os.path.join(_TMP, "rel.json")
        server.main(["--relatorio", destino])
        with open(destino, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["kit"]["versao"], server.VERSAO)


# ------------------------------------------------------------ HTTP real
class TestHTTP(unittest.TestCase):
    """Sobe o servidor de verdade numa porta livre e fala HTTP com ele."""

    @classmethod
    def setUpClass(cls):
        server.TOKEN = "token-de-teste"
        cls.srv = server.S(("127.0.0.1", 0), server.H)
        cls.porta = cls.srv.server_address[1]
        server.HOSTS_OK = {f"127.0.0.1:{cls.porta}"}
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        limpar_tudo()

    def req(self, metodo, caminho, corpo=None, token=True, cab=None):
        c = http.client.HTTPConnection("127.0.0.1", self.porta, timeout=10)
        h = dict(cab or {})
        if token:
            h["X-Kit-Token"] = server.TOKEN
        if isinstance(corpo, dict):
            corpo = json.dumps(corpo).encode()
            h["Content-Type"] = "application/json"
        c.request(metodo, caminho, body=corpo, headers=h)
        r = c.getresponse()
        dados = r.read()
        c.close()
        return r.status, dados, r

    def test_sem_token_401(self):
        self.assertEqual(self.req("GET", "/api/alertas", token=False)[0], 401)

    def test_token_errado_401(self):
        st = self.req("GET", "/api/alertas", token=False,
                      cab={"X-Kit-Token": "chute"})[0]
        self.assertEqual(st, 401)

    def test_host_estranho_403(self):
        st = self.req("GET", "/api/alertas", cab={"Host": "evil.com"})[0]
        self.assertEqual(st, 403)

    def test_escrita_exige_post(self):
        self.assertEqual(self.req("GET", "/api/cap/limpar")[0], 405)
        self.assertEqual(self.req("GET", "/api/cap/importar")[0], 405)
        self.assertEqual(self.req("GET", "/api/agenda/salvar")[0], 405)

    def test_corpo_json_nao_objeto(self):
        st, d, _ = self.req("POST", "/api/wol", b"[1,2]",
                            cab={"Content-Type": "application/json"})
        self.assertEqual(st, 400)  # sem MAC -> erro claro, não 500

    def test_importar_e_consultar(self):
        pk = [arp_reply("192.168.0.1", "00:11:22:33:44:55"),
              arp_reply("192.168.0.1", "de:ad:be:ef:00:01")]
        st, d, _ = self.req("POST", "/api/cap/importar?limpar=1",
                            pcap(pk, server.LINK_ETHERNET),
                            cab={"Content-Type": "application/octet-stream"})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(d)["decodificados"], 2)
        det = json.loads(self.req("GET", "/api/deteccoes")[1])
        self.assertEqual(det["eventos"][0]["tipo"], "arp_spoof")
        stats = json.loads(self.req("GET", "/api/cap/stats")[1])
        self.assertEqual(stats["pacotes"], 2)

    def test_importar_lixo_400(self):
        st, d, _ = self.req("POST", "/api/cap/importar", b"nada a ver",
                            cab={"Content-Type": "application/octet-stream"})
        self.assertEqual(st, 400)
        self.assertIn("formato", json.loads(d)["erro"])

    def test_agenda_via_api(self):
        st, d, _ = self.req("POST", "/api/agenda/salvar",
                            {"minutos": 30, "faixa": "192.168.0.0/24"})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(self.req("GET", "/api/agenda")[1])["minutos"], 30)
        st, d, _ = self.req("POST", "/api/agenda/salvar", {"minutos": 1})
        self.assertEqual(st, 400)

    def test_relatorio_para_baixar(self):
        st, d, r = self.req("GET", "/api/relatorio?baixar=1")
        self.assertEqual(st, 200)
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        self.assertIn("deteccoes", json.loads(d))

    def test_index_injeta_token_e_esc(self):
        st, d, _ = self.req("GET", "/")
        self.assertEqual(st, 200)
        html = d.decode()
        self.assertIn('const TOKEN="token-de-teste"', html)
        self.assertIn("const esc=", html)

    def test_inventario_publico_recusado(self):
        st, d, _ = self.req("POST", "/api/inventario", {"a": "8.8.8.0/24"})
        self.assertEqual(st, 400)


# ============================================================ 2ª rodada
# ------------------------------------------------------------ 1. repositório
class TestRepositorio(unittest.TestCase):
    def test_sem_zip_duplicado_e_gitignore(self):
        self.assertFalse(os.path.exists(os.path.join(AQUI, "kit-de-bolso.zip")))
        with open(os.path.join(AQUI, ".gitignore"), encoding="utf-8") as f:
            regras = f.read().split()
        for r in ("*.zip", "*.pcap", "*.pcapng"):
            self.assertIn(r, regras)


# ------------------------------------------------------------ 2. redes
class TestRedes(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_id_estavel_e_redes_distintas(self):
        a1 = server.identificar_rede(REDE_CASA)
        a2 = server.identificar_rede(dict(REDE_CASA, bssid="aa:bb:cc:00:00:02"))
        self.assertEqual(a1["id"], a2["id"])  # mesh: outro BSSID, mesma casa
        b = server.identificar_rede(REDE_CLIENTE)
        self.assertNotEqual(a1["id"], b["id"])  # mesmo gateway, outro SSID
        self.assertRegex(a1["id"], r"^[0-9a-f]{10}$")
        self.assertEqual(a1["nome"], "CasaHesblan")

    def test_mac_do_gateway_aparece_depois(self):
        sem = server.identificar_rede(REDE_CASA)
        com = server.identificar_rede(dict(REDE_CASA, gw_mac="00:11:22:33:44:55"))
        self.assertEqual(sem["id"], com["id"])
        # mesmo gateway e SSID, roteador diferente: outra rede
        outro = server.identificar_rede(dict(REDE_CASA, gw_mac="66:77:88:99:aa:bb"))
        self.assertNotEqual(com["id"], outro["id"])

    def test_ssid_oculto_usa_bssid(self):
        r = server.identificar_rede(dict(REDE_CASA, ssid="<unknown ssid>"))
        self.assertEqual(r["wifi"], "aa:bb:cc:00:00:01")

    def test_sem_gateway_sem_rede(self):
        self.assertIsNone(server.identificar_rede({"gateway": ""}))

    def test_casa_e_cliente_nao_se_misturam(self):
        # o bug principal: casa A e cliente B, ambos em 192.168.0.0/24
        casa = server.rede_id_atual()
        vivos = {"192.168.0.1", "192.168.0.10"}.__contains__
        server.inventario("192.168.0.0/24", sonda=vivos,
                          tabela_arp=[("192.168.0.1", "00:11:22:33:44:55"),
                                      ("192.168.0.10", "b8:27:eb:00:00:01")])
        self.assertEqual(len(alertas("novo_host")), 2)
        cliente = na_rede(REDE_CLIENTE)["id"]
        r = server.inventario("192.168.0.0/24", sonda=vivos,
                              tabela_arp=[("192.168.0.1", "de:ad:be:ef:00:01"),
                                          ("192.168.0.10", "de:ad:be:ef:00:02")])
        # no cliente tudo é novo, e NADA de "MAC trocado"
        self.assertEqual(len(r["novos"]), 2)
        self.assertEqual(r["macs_trocados"], [])
        self.assertEqual(alertas("mac_trocado"), [])
        self.assertEqual({a["rede_id"] for a in alertas("novo_host")}, {casa, cliente})
        # o inventário da casa continua intacto
        casa_disp = server.listar_dispositivos(casa)
        self.assertEqual({d["mac"] for d in casa_disp},
                         {"00:11:22:33:44:55", "b8:27:eb:00:00:01"})

    def test_mudar_de_rede_zera_o_contexto_ao_vivo(self):
        server.DET.processar({"t": 100.0, "arp": {
            "ip": "192.168.0.1", "mac": "00:11:22:33:44:55"}})
        na_rede(REDE_CLIENTE)
        achados = server.DET.processar({"t": 101.0, "arp": {
            "ip": "192.168.0.1", "mac": "de:ad:be:ef:00:01"}})
        self.assertEqual(achados, [])

    def test_migracao_de_banco_antigo(self):
        antigo = os.path.join(_TMP, "antigo.db")
        c = sqlite3.connect(antigo)
        c.executescript("""
        CREATE TABLE dispositivos(ip TEXT, mac TEXT, fabricante TEXT, nome TEXT,
            portas TEXT, primeiro REAL, ultimo REAL, autorizado INTEGER DEFAULT 0,
            PRIMARY KEY(ip, mac));
        CREATE TABLE alertas(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL,
            nivel TEXT, tipo TEXT, msg TEXT);
        CREATE TABLE varreduras(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL,
            alvo TEXT, hosts INTEGER, resumo TEXT);
        CREATE TABLE arp(ip TEXT PRIMARY KEY, mac TEXT, visto REAL);
        CREATE TABLE config(chave TEXT PRIMARY KEY, valor TEXT);
        INSERT INTO dispositivos VALUES('192.168.0.5','aa:aa:aa:aa:aa:aa','?',
            'TV',NULL,1,2,1);
        INSERT INTO varreduras(ts,alvo,hosts,resumo) VALUES(?,
            '192.168.0.0/24',1,'["192.168.0.5"]');
        INSERT INTO arp VALUES('192.168.0.1','00:11:22:33:44:55',1);
        INSERT INTO alertas(ts,nivel,tipo,msg) VALUES(1,'medio','x','antigo');
        """.replace("VALUES(?,", f"VALUES({time.time()},"))
        c.commit()
        c.close()
        original = server.DB
        server.DB = antigo
        try:
            server.db_init()
            server.db_init()  # rodar duas vezes não pode quebrar
            c = server.db()
            d = dict(c.execute("SELECT * FROM dispositivos").fetchone())
            self.assertEqual((d["rede_id"], d["nome"], d["autorizado"]),
                             ("legado", "TV", 1))
            self.assertEqual(c.execute("SELECT rede_id FROM varreduras").fetchone()[0],
                             "legado")
            self.assertEqual(c.execute("SELECT rede_id FROM arp").fetchone()[0],
                             "legado")
            self.assertIsNone(c.execute("SELECT rede_id FROM alertas").fetchone()[0])
            nome = c.execute("SELECT nome FROM redes WHERE rede_id='legado'").fetchone()
            self.assertIn("antigos", nome[0])
            c.close()
        finally:
            server.DB = original

    def test_renomear(self):
        rid = server.rede_id_atual()
        server.renomear_rede(rid, "  Casa   da praia ")
        self.assertEqual(server.nome_rede(rid), "Casa da praia")
        with self.assertRaises(ValueError):
            server.renomear_rede("../x", "a")
        with self.assertRaises(ValueError):
            server.renomear_rede(rid, "   ")


# ------------------------------------------------------------ 2.3 detector
class TestDetectorPorArquivo(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_arquivos_de_redes_diferentes_nao_geram_spoof(self):
        a = pcap([arp_reply("192.168.0.1", "00:11:22:33:44:55")], server.LINK_ETHERNET)
        b = pcap([arp_reply("192.168.0.1", "de:ad:be:ef:00:01")], server.LINK_ETHERNET)
        server.importar_pcap(a)
        r = server.importar_pcap(b)
        self.assertEqual(alertas("arp_spoof"), [])
        self.assertEqual(r["deteccoes"], [])

    def test_dhcp_de_arquivos_diferentes(self):
        server.importar_pcap(pcap([dhcp_offer("192.168.0.1", "192.168.0.1")],
                                  server.LINK_ETHERNET))
        server.importar_pcap(pcap([dhcp_offer("192.168.0.254", "192.168.0.254")],
                                  server.LINK_ETHERNET))
        self.assertEqual(alertas("dhcp_falso"), [])
        ctx = server.DET.resumo()["contextos"]
        self.assertEqual(len(ctx), 2)

    def test_guarda_poucos_contextos(self):
        for _ in range(server.Detector.MAX_ARQUIVOS + 3):
            server.importar_pcap(pcap([ip_tcp()], 101))
        self.assertEqual(len(server.DET.resumo()["contextos"]),
                         server.Detector.MAX_ARQUIVOS)

    def test_ao_vivo_expira_em_1h(self):
        d = server.Detector()
        d.processar({"t": 1000.0, "arp": {"ip": "10.0.0.1", "mac": "aa"}})
        self.assertEqual(d.processar({"t": 1000.0 + 3601,
                                      "arp": {"ip": "10.0.0.1", "mac": "bb"}}), [])
        # dentro da hora, a troca é detectada
        achados = d.processar({"t": 1000.0 + 3700,
                               "arp": {"ip": "10.0.0.1", "mac": "cc"}})
        self.assertEqual(achados[0][1], "arp_spoof")

    def test_ao_vivo_renova_quem_continua_aparecendo(self):
        d = server.Detector()
        for t in range(0, 3 * 3600, 600):  # gateway visto a cada 10 min
            d.processar({"t": float(t), "arp": {"ip": "10.0.0.1", "mac": "aa"}})
        achados = d.processar({"t": 3 * 3600.0, "arp": {"ip": "10.0.0.1", "mac": "ee"}})
        self.assertEqual(len(achados), 1)


# ------------------------------------------------------------ 4. traceroute
class TestTraceroute(unittest.TestCase):
    def test_modo_udp_sem_root(self):
        self.assertEqual(server.TOOLS["traceroute"]("8.8.8.8"),
                         ["traceroute", "-w", "2", "-q", "1", "8.8.8.8"])
        self.assertNotIn("-T", server.TOOLS["traceroute"]("x"))

    def test_aviso_de_root_so_no_mtr(self):
        if not shutil.which("traceroute"):
            # sem o binário, simula um traceroute que falha
            alvo = os.path.join(_TMP, "bin")
            os.makedirs(alvo, exist_ok=True)
            falso = os.path.join(alvo, "traceroute")
            with open(falso, "w") as f:
                f.write("#!/bin/sh\necho falhou\nexit 1\n")
            os.chmod(falso, 0o755)
            os.environ["PATH"] = alvo + os.pathsep + os.environ["PATH"]

        class W(list):
            def write(self, b):
                self.append(b)
        w = W()
        server.run_stream("traceroute", "127.0.0.1", w, lambda: None)
        self.assertNotIn(b"exigir root", b"".join(w))


# ------------------------------------------------------------ 5. atalho e token
def _atalho_do_instalador():
    with open(os.path.join(AQUI, "kit.sh"), encoding="utf-8") as f:
        return f.read()


# Servidor falso: responde o manifesto como o Kit, conta quantas vezes subiu e
# vive ``VIDA`` segundos. Com --lento só cria o token depois de 1,6 s.
SERVIDOR_FALSO = r"""
import http.server, os, sys, time
porta = int(sys.argv[sys.argv.index("--porta") + 1]) if "--porta" in sys.argv else 8080
with open("partidas", "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
if os.environ.get("FALSO_LENTO"):
    time.sleep(1.6)  # aparelho lento: o token só aparece depois de 1,6 s
with open(".token", "w") as f:
    f.write("token-lento")
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b'{"name": "Kit de Bolso do T\xc3\xa9cnico"}'
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a):
        pass
try:
    srv = http.server.HTTPServer(("127.0.0.1", porta), H)
except OSError:
    print("A porta est\xe1 em uso"); sys.exit(1)
srv.timeout = 0.2
fim = time.time() + float(os.environ.get("FALSO_VIDA", "4"))
while time.time() < fim:
    srv.handle_request()
"""


def _porta_livre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(shutil.which("bash") and shutil.which("curl"),
                     "precisa de bash e curl")
class TestAtalho(unittest.TestCase):
    def setUp(self):
        self.casa = tempfile.mkdtemp(prefix="kit-home-")
        self.kit = os.path.join(self.casa, "kit")
        self.bin = os.path.join(self.casa, "bin")
        os.makedirs(self.kit)
        os.makedirs(self.bin)
        with open(os.path.join(self.kit, "server.py"), "w") as f:
            f.write(SERVIDOR_FALSO)
        self.aberto = os.path.join(self.casa, "url_aberta")
        self._bin("termux-open-url", f'#!/bin/sh\necho "$1" >> "{self.aberto}"\n')
        self._bin("python", f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        self.atalho = os.path.join(self.casa, "kit.sh")
        with open(self.atalho, "w") as f:
            f.write(_atalho_do_instalador())
        self.porta = _porta_livre()
        self.amb = dict(os.environ, HOME=self.casa, PREFIX=self.casa,
                        PATH=self.bin + os.pathsep + os.environ["PATH"])

    def tearDown(self):
        self.kit_("--parar")
        shutil.rmtree(self.casa, ignore_errors=True)

    def _bin(self, nome, txt):
        caminho = os.path.join(self.bin, nome)
        with open(caminho, "w") as f:
            f.write(txt)
        os.chmod(caminho, 0o755)

    def kit_(self, *args, **amb):
        r = subprocess.run(["bash", self.atalho, *args], timeout=40,
                           capture_output=True, text=True,
                           env=dict(self.amb, **amb))
        return r.returncode, r.stdout + r.stderr

    def urls(self):
        if not os.path.exists(self.aberto):
            return []
        with open(self.aberto) as f:
            return f.read().split()

    def partidas(self):
        caminho = os.path.join(self.kit, "partidas")
        if not os.path.exists(caminho):
            return 0
        with open(caminho) as f:
            return len(f.read().splitlines())

    def test_espera_token_e_servidor(self):
        self.kit_("--porta", str(self.porta), FALSO_LENTO="1")
        self.assertEqual(self.urls(),
                         [f"http://127.0.0.1:{self.porta}/?token=token-lento"])

    def test_segundo_plano_status_e_parar(self):
        t0 = time.time()
        rc, saida = self.kit_("--porta", str(self.porta), FALSO_VIDA="30")
        self.assertEqual(rc, 0, saida)
        self.assertLess(time.time() - t0, 20)          # voltou ao prompt
        self.assertIn("segundo plano", saida)
        with open(os.path.join(self.kit, ".servidor")) as f:
            pid, porta = f.read().split()
        self.assertEqual(int(porta), self.porta)
        os.kill(int(pid), 0)                            # continua vivo
        log = os.path.join(self.kit, "kit.log")         # tem o token: só o dono lê
        self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)
        self.assertIn(f"ligado na porta {self.porta}", self.kit_("--status")[1])
        rc, saida = self.kit_("--parar")
        self.assertIn("desligado", saida)
        time.sleep(0.3)
        with self.assertRaises(OSError):
            os.kill(int(pid), 0)
        self.assertFalse(os.path.exists(os.path.join(self.kit, ".servidor")))

    def test_ja_ligado_so_abre_o_navegador(self):
        self.kit_("--porta", str(self.porta), FALSO_VIDA="30")
        rc, saida = self.kit_()      # sem --porta: usa a porta salva
        self.assertEqual(rc, 0)
        self.assertIn("já está ligado", saida)
        self.assertEqual(self.partidas(), 1)
        self.assertEqual(len(self.urls()), 2)

    def test_fundo_nao_abre_o_navegador(self):
        rc, _ = self.kit_("--fundo", "--quieto", "--porta", str(self.porta),
                          FALSO_VIDA="30")
        self.assertEqual(rc, 0)
        self.assertEqual(self.urls(), [])
        self.assertEqual(self.partidas(), 1)

    def test_duas_partidas_juntas_sobe_um_servidor(self):
        cmd = ["bash", self.atalho, "--fundo", "--porta", str(self.porta)]
        amb = dict(self.amb, FALSO_VIDA="30", FALSO_LENTO="1")
        ps = [subprocess.Popen(cmd, env=amb, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) for _ in range(2)]
        self.assertEqual([p.wait(timeout=40) for p in ps], [0, 0])
        self.assertEqual(self.partidas(), 1)

    def test_lan_reinicia_o_servidor(self):
        self.kit_("--porta", str(self.porta), FALSO_VIDA="30")
        rc, saida = self.kit_("--porta", str(self.porta), "--novo-token",
                              FALSO_VIDA="30")
        self.assertEqual(rc, 0, saida)
        self.assertIn("Reiniciando", saida)
        self.assertEqual(self.partidas(), 2)

    def test_porta_de_outro_programa_nao_engana(self):
        # Um servidor qualquer (não o Kit) na porta: o atalho não abre nada.
        outro = subprocess.Popen([sys.executable, "-m", "http.server", "--bind",
                                  "127.0.0.1", str(self.porta)], cwd=self.casa,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                try:
                    socket.create_connection(("127.0.0.1", self.porta), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            rc, saida = self.kit_("--porta", str(self.porta))
            self.assertEqual(rc, 1)
            self.assertIn("não conseguiu ligar", saida)
            self.assertEqual(self.urls(), [])
        finally:
            outro.terminate()
            outro.wait()

    def test_automatico_liga_e_desliga(self):
        rc_path = os.path.join(self.casa, ".bashrc")
        with open(rc_path, "w") as f:
            f.write("alias ll='ls -l'\n")
        self.kit_("--automatico", "liga")
        self.kit_("--automatico", "liga")              # não duplica
        boot = os.path.join(self.casa, ".termux", "boot", "kit-de-bolso")
        with open(boot) as f:
            self.assertIn("kit\" --fundo", f.read())
        with open(rc_path) as f:
            rc = f.read()
        self.assertEqual(rc.count("--fundo --quieto"), 1)
        self.kit_("--automatico", "desliga")
        self.assertFalse(os.path.exists(boot))
        with open(rc_path) as f:
            self.assertEqual(f.read(), "alias ll='ls -l'\n")

    def test_atalho_documenta_novo_token(self):
        self.assertIn("--novo-token", _atalho_do_instalador())


@unittest.skipUnless(shutil.which("bash"), "precisa de bash")
class TestInstalador(unittest.TestCase):
    """Roda o instalar.sh com pkg falso, num HOME e PREFIX temporários."""

    def test_instala_comando_atalhos_e_automatico(self):
        casa = tempfile.mkdtemp(prefix="kit-inst-")
        prefixo = os.path.join(casa, "usr")
        binarios = os.path.join(prefixo, "bin")
        os.makedirs(binarios)
        falsos = {
            "pkg": "#!/bin/sh\nexit 0\n",
            # python testes.py dentro do instalador: não roda os testes de novo.
            "python": (f'#!/bin/sh\n[ "$1" = testes.py ] && exit 0\n'
                       f'exec "{sys.executable}" "$@"\n'),
        }
        for nome, txt in falsos.items():
            with open(os.path.join(binarios, nome), "w") as f:
                f.write(txt)
            os.chmod(os.path.join(binarios, nome), 0o755)
        amb = dict(os.environ, HOME=casa, PREFIX=prefixo, KIT_NAO_ABRIR="1",
                   PATH=binarios + os.pathsep + os.environ["PATH"])
        try:
            r = subprocess.run(["bash", os.path.join(AQUI, "instalar.sh")], env=amb,
                               timeout=60, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            for arq in ("server.py", "index.html", "testes.py", "kit.sh"):
                self.assertTrue(os.path.exists(os.path.join(casa, "kit", arq)), arq)
            with open(os.path.join(binarios, "kit")) as f, \
                    open(os.path.join(AQUI, "kit.sh")) as g:
                self.assertEqual(f.read(), g.read())
            for atalho in ("Kit de Bolso", "Desligar Kit"):
                caminho = os.path.join(casa, ".shortcuts", atalho)
                self.assertTrue(os.access(caminho, os.X_OK), atalho)
            self.assertTrue(os.path.exists(
                os.path.join(casa, ".termux", "boot", "kit-de-bolso")))
            with open(os.path.join(casa, ".bashrc")) as f:
                self.assertIn("--fundo --quieto", f.read())
            self.assertIn("Pronto!", r.stdout)
        finally:
            shutil.rmtree(casa, ignore_errors=True)


class TestToken(unittest.TestCase):
    def setUp(self):
        if os.path.exists(server.TOKEN_FILE):
            os.remove(server.TOKEN_FILE)

    def test_persistente_e_novo_token(self):
        t1 = server.carregar_token()
        self.assertEqual(server.carregar_token(), t1)
        t2 = server.carregar_token(novo=True)
        self.assertNotEqual(t1, t2)
        with open(server.TOKEN_FILE) as f:
            self.assertEqual(f.read(), t2)
        self.assertEqual(os.stat(server.TOKEN_FILE).st_mode & 0o777, 0o600)

    def test_parser_aceita_novo_token(self):
        self.assertTrue(server.criar_parser().parse_args(["--novo-token"]).novo_token)

    def test_aviso_lan(self):
        self.assertIn("SEM criptografia", server.AVISO_LAN)
        self.assertIn("--novo-token", server.AVISO_LAN)

    def test_hosts_ok_acompanha_o_ip(self):
        porta, lan = server.HTTP_PORT, server.LAN
        antigo = set(server.HOSTS_OK)
        try:
            server.HTTP_PORT, server.LAN = 8080, True
            server.atualizar_hosts_ok("192.168.0.20")
            self.assertIn("192.168.0.20:8080", server.HOSTS_OK)
            self.assertTrue(server.atualizar_hosts_ok("192.168.0.77"))  # novo DHCP
            self.assertIn("192.168.0.77:8080", server.HOSTS_OK)
            self.assertNotIn("192.168.0.20:8080", server.HOSTS_OK)
            self.assertIn("127.0.0.1:8080", server.HOSTS_OK)
            server.LAN = False
            server.atualizar_hosts_ok("192.168.0.77")
            self.assertNotIn("192.168.0.77:8080", server.HOSTS_OK)
        finally:
            server.HTTP_PORT, server.LAN = porta, lan
            server.HOSTS_OK = antigo


# ------------------------------------------------------------ 6. ajustes
class TestHostVivo(unittest.TestCase):
    def test_ping_primeiro(self):
        portas = []
        self.assertTrue(server.host_vivo("10.0.0.2", pinger=lambda ip: True,
                                         conectar=lambda ip, p: portas.append(p)))
        self.assertEqual(portas, [])  # celular sem porta aberta, achado pelo ping

    def test_porta_recusada_e_host_vivo(self):
        self.assertTrue(server.host_vivo(
            "10.0.0.2", pinger=lambda ip: False,
            conectar=lambda ip, p: errno.ECONNREFUSED))

    def test_sem_resposta(self):
        self.assertFalse(server.host_vivo(
            "10.0.0.2", pinger=lambda ip: False,
            conectar=lambda ip, p: errno.ETIMEDOUT))

    def test_sem_numero_magico(self):
        with open(os.path.join(AQUI, "server.py"), encoding="utf-8") as f:
            self.assertNotIn("rc == 111", f.read())


class TestRetencao(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_alertas_e_varreduras(self):
        agora = time.time()
        with server.DBLOCK:
            c = server.db()
            c.executemany("INSERT INTO alertas(ts,nivel,tipo,msg) VALUES(?,?,?,?)",
                          [(agora, "baixo", "t", str(i))
                           for i in range(server.MAX_ALERTAS + 20)])
            c.execute("INSERT INTO varreduras(ts,alvo,hosts,resumo,rede_id) "
                      "VALUES(?,?,?,?,?)", (agora - 91 * 86400, "x", 0, "[]", "a"))
            c.execute("INSERT INTO varreduras(ts,alvo,hosts,resumo,rede_id) "
                      "VALUES(?,?,?,?,?)", (agora - 10 * 86400, "x", 0, "[]", "a"))
            server.aplicar_retencao(c, agora)
            c.commit()
            n_al = c.execute("SELECT COUNT(*), MIN(msg+0) FROM alertas").fetchone()
            n_var = c.execute("SELECT COUNT(*) FROM varreduras").fetchone()[0]
            c.close()
        self.assertEqual(n_al[0], server.MAX_ALERTAS)
        self.assertEqual(n_al[1], 20)  # os 20 mais antigos saíram
        self.assertEqual(n_var, 1)

    def test_contadores_limitados(self):
        for i in range(server.MAX_CHAVES + 50):
            ip = f"10.{i // 65536}.{i // 256 % 256}.{i % 256}"
            server.add(1.0, ip_tcp(src=ip, dst="10.255.255.1", dp=443), 101)
        self.assertLessEqual(len(server.ST["hosts"]), server.MAX_CHAVES)
        self.assertIn("10.255.255.1", server.ST["hosts"])  # o maior fica


class TestInventarioConflito(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_mac_conhecido_depois_mescla(self):
        vivos = {"192.168.0.9"}.__contains__
        server.inventario("192.168.0.0/24", sonda=vivos, tabela_arp=[])
        rid = server.rede_id_atual()
        # alguém já tinha registrado esse IP+MAC (ex.: varredura antiga)
        with server.DBLOCK:
            c = server.db()
            c.execute("INSERT INTO dispositivos(rede_id,ip,mac,primeiro,ultimo,"
                      "autorizado,nome) VALUES(?,?,?,?,?,1,'Impressora')",
                      (rid, "192.168.0.9", "aa:00:00:00:00:09", 1.0, 1.0))
            c.commit()
            c.close()
        r = server.inventario("192.168.0.0/24", sonda=vivos,
                              tabela_arp=[("192.168.0.9", "AA:00:00:00:00:09")])
        linhas = [d for d in r["inventario"] if d["ip"] == "192.168.0.9"]
        self.assertEqual(len(linhas), 1)  # mesclado, sem registro órfão
        self.assertEqual(linhas[0]["nome"], "Impressora")
        self.assertGreater(linhas[0]["ultimo"], 1.0)  # atualizado, não ignorado

    def test_mac_trocado_nao_herda_autorizacao(self):
        vivos = {"192.168.0.1"}.__contains__
        server.inventario("192.168.0.0/24", sonda=vivos,
                          tabela_arp=[("192.168.0.1", "00:11:22:33:44:55")])
        rid = server.rede_id_atual()
        with server.DBLOCK:
            c = server.db()
            c.execute("UPDATE dispositivos SET autorizado=1, nome='Roteador'")
            c.commit()
            c.close()
        r = server.inventario("192.168.0.0/24", sonda=vivos,
                              tabela_arp=[("192.168.0.1", "de:ad:be:ef:00:01")])
        self.assertEqual(len(r["macs_trocados"]), 1)
        novo = [d for d in r["inventario"] if d["mac"] == "de:ad:be:ef:00:01"][0]
        self.assertEqual(novo["autorizado"], 0)
        self.assertEqual(len(server.listar_dispositivos(rid)), 2)  # histórico fica


class TestPcapngSimples(unittest.TestCase):
    def test_simple_packet_herda_horario(self):
        def bloco(tipo, corpo):
            corpo += b"\x00" * ((4 - len(corpo) % 4) % 4)
            n = 12 + len(corpo)
            return struct.pack("<II", tipo, n) + corpo + struct.pack("<I", n)
        p = ip_tcp()
        us = int(1700000000.5 * 1e6)
        dados = (bloco(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
                 + bloco(1, struct.pack("<HHI", 101, 0, 262144))
                 + bloco(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF,
                                        len(p), len(p)) + p)
                 + bloco(3, struct.pack("<I", len(p)) + p))
        pk = server.ler_pcap(dados)
        self.assertEqual(len(pk), 2)
        self.assertAlmostEqual(pk[1][0], 1700000000.5, places=3)


# ------------------------------------------------------------ HTTP (2ª rodada)
class TestHTTP2(TestHTTP):
    """Rotas novas, POST nas varreduras, CSP com nonce e app instalável."""

    def test_varreduras_ativas_exigem_post(self):
        for rota in ("/api/portas", "/api/roteador", "/api/ssdp", "/api/mdns"):
            self.assertEqual(self.req("GET", rota + "?a=192.168.0.1")[0], 405, rota)
        st, d, _ = self.req("POST", "/api/portas", {"a": "8.8.8.8"})
        self.assertEqual(st, 400)  # público continua recusado

    def test_redes_renomear_e_dispositivos(self):
        server.inventario("192.168.0.0/24", sonda={"192.168.0.3"}.__contains__,
                          tabela_arp=[])
        st, d, _ = self.req("GET", "/api/redes")
        r = json.loads(d)
        rid = r["atual"]
        self.assertTrue(r["redes"][0]["atual"])
        self.assertEqual(r["redes"][0]["dispositivos"], 1)
        st, d, _ = self.req("POST", "/api/rede/renomear", {"rede": rid, "nome": "Casa"})
        self.assertEqual(st, 200)
        st, d, _ = self.req("GET", f"/api/dispositivos?rede={rid}")
        j = json.loads(d)
        self.assertEqual((j["rede_nome"], len(j["inventario"])), ("Casa", 1))
        self.assertEqual(self.req("GET", "/api/dispositivos?rede=%27or1")[0], 400)

    def test_autorizar_por_rede(self):
        server.inventario("192.168.0.0/24", sonda={"192.168.0.3"}.__contains__,
                          tabela_arp=[("192.168.0.3", "aa:00:00:00:00:03")])
        casa = server.rede_id_atual()
        na_rede(REDE_CLIENTE)
        server.inventario("192.168.0.0/24", sonda={"192.168.0.3"}.__contains__,
                          tabela_arp=[("192.168.0.3", "bb:00:00:00:00:03")])
        st, _, _ = self.req("POST", "/api/dispositivo/autorizar",
                            {"a": "192.168.0.3", "rede": casa,
                             "mac": "aa:00:00:00:00:03", "nome": "TV"})
        self.assertEqual(st, 200)
        cli = server.listar_dispositivos(server.rede_id_atual())
        self.assertEqual(cli[0]["autorizado"], 0)  # a do cliente não foi tocada

    def test_info_mostra_rede(self):
        st, d, _ = self.req("GET", "/api/info")
        self.assertEqual(json.loads(d)["rede"]["nome"], "CasaHesblan")

    def test_csp_com_nonce_sem_unsafe_inline(self):
        st, d, r = self.req("GET", "/")
        html = d.decode()
        csp = r.getheader("Content-Security-Policy")
        script = re.search(r"script-src ([^;]+)", csp).group(1)
        self.assertNotIn("unsafe-inline", script)
        nonce = re.search(r"'nonce-([^']+)'", script).group(1)
        self.assertIn(f'<script nonce="{nonce}">', html)
        self.assertEqual(html.count("<script"), 1)
        self.assertIsNone(re.search(r"\son[a-z]+=\"", html))  # nada de onclick="..."
        self.assertIn("worker-src 'self'", csp)
        # um nonce novo a cada carregamento
        _, d2, _ = self.req("GET", "/")
        self.assertNotIn(nonce, d2.decode())

    def test_arquivos_do_app_sem_token(self):
        st, d, r = self.req("GET", "/manifest.webmanifest", token=False)
        self.assertEqual(st, 200)
        m = json.loads(d)
        self.assertEqual(m["display"], "standalone")
        tamanhos = {i["sizes"] for i in m["icons"]}
        self.assertTrue({"192x192", "512x512"} <= tamanhos)
        st, d, r = self.req("GET", "/sw.js", token=False)
        self.assertEqual(st, 200)
        self.assertIn("javascript", r.getheader("Content-Type"))
        self.assertIn(b"addEventListener('fetch'", d)
        self.assertNotIn(server.TOKEN.encode(), d)
        st, d, r = self.req("GET", "/icone-192.png", token=False)
        self.assertEqual(st, 200)
        self.assertEqual(d[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", d[16:24]), (192, 192))
        self.assertEqual(self.req("POST", "/sw.js", token=False)[0], 404)

    def test_png_valido(self):
        import zlib as _z
        png = server.icone_png(48)
        i, blocos = 8, {}
        while i < len(png):
            n = struct.unpack(">I", png[i:i + 4])[0]
            tipo = png[i + 4:i + 8]
            crc = struct.unpack(">I", png[i + 8 + n:i + 12 + n])[0]
            self.assertEqual(crc, _z.crc32(png[i + 4:i + 8 + n]) & 0xFFFFFFFF)
            blocos[tipo] = png[i + 8:i + 8 + n]
            i += 12 + n
        cru = _z.decompress(blocos[b"IDAT"])
        self.assertEqual(len(cru), 48 * (1 + 48 * 3))

    def test_abrir_sem_token_e_sem_segredo(self):
        st, d, r = self.req("GET", "/abrir", token=False)
        self.assertEqual(st, 200)
        self.assertIn(b'url=/', d)
        self.assertNotIn(server.TOKEN.encode(), d)
        self.assertIn("script-src 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(self.req("POST", "/abrir", token=False)[0], 404)

    def test_pagina_offline_abre_o_termux(self):
        st, d, _ = self.req("GET", "/sw.js", token=False)
        self.assertIn(server.INTENT_TERMUX.encode(), d)
        self.assertIn("Abrir o Termux".encode(), d)
        self.assertIn(server.VERSAO.encode(), d)  # versão nova troca o SW

    def test_intent_igual_no_index(self):
        with open(os.path.join(AQUI, "index.html"), encoding="utf-8") as f:
            html = f.read()
        self.assertIn(f'const INTENT_TERMUX="{server.INTENT_TERMUX}"', html)
        self.assertIn("/abrir", html)

    def test_cookie_persistente_e_pagina_401_com_formulario(self):
        st, d, r = self.req("GET", f"/?token={server.TOKEN}", token=False)
        self.assertEqual(st, 302)
        ck = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", ck)
        self.assertIn("Max-Age=", ck)
        st, d, _ = self.req("GET", "/", token=False)
        self.assertEqual(st, 401)
        self.assertIn(b"<form", d)
        self.assertNotIn(server.TOKEN.encode(), d)

    def test_alertas_filtrados_pela_rede(self):
        server.alerta("medio", "novo_host", "da casa", rede_id=server.rede_id_atual())
        na_rede(REDE_CLIENTE)
        server.alerta("medio", "novo_host", "do cliente", rede_id=server.rede_id_atual())
        server.alerta("baixo", "inseguro", "da captura")
        msgs = [a["msg"] for a in json.loads(self.req("GET", "/api/alertas")[1])]
        self.assertEqual(sorted(msgs), ["da captura", "do cliente"])
        todas = json.loads(self.req("GET", "/api/alertas?rede=todas")[1])
        self.assertEqual(len(todas), 3)


class TestEmbutidos(unittest.TestCase):
    """dig/whois/cabeçalhos em Python puro, contra servidores locais falsos."""

    def test_dns_monta_e_le(self):
        q = server.dns_montar("exemplo.com", 1, 0x1234)
        cab = q[:2] + struct.pack("!HHHHH", 0x8180, 1, 2, 0, 0)
        a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, 0, 0, 5])
        mx = b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 60, 9) + \
            struct.pack("!H", 10) + b"\x04mail\xc0\x0c"
        rcode, resp = server.dns_respostas(cab + q[12:] + a + mx)
        self.assertEqual(rcode, 0)
        self.assertEqual(resp[0], ("exemplo.com.", 300, "A", "10.0.0.5"))
        self.assertEqual(resp[1], ("exemplo.com.", 60, "MX", "10 mail.exemplo.com."))

    def test_dig_embutido_com_servidor_udp_falso(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        porta = s.getsockname()[1]

        def responde():
            s.settimeout(5)
            try:
                for _ in range(6):
                    q, end = s.recvfrom(512)
                    tipo = struct.unpack("!H", q[-4:-2])[0]
                    an = 1 if tipo == 1 else 0
                    r = q[:2] + struct.pack("!HHHHH", 0x8180, 1, an, 0, 0) + q[12:]
                    if an:
                        r += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + \
                            bytes([192, 168, 0, 9])
                    s.sendto(r, end)
            except OSError:
                pass
        threading.Thread(target=responde, daemon=True).start()
        linhas = list(server.dig_embutido("roteador.casa", "127.0.0.1", porta, 2))
        s.close()
        self.assertIn("roteador.casa.\t30\tIN\tA\t192.168.0.9", linhas)

    def test_whois_segue_indicacao(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        porta = srv.getsockname()[1]
        pedidos = []

        def atende():
            for resposta in (b"refer: 127.0.0.1\n", b"dono: Fulano\n"):
                c, _ = srv.accept()
                pedidos.append(c.recv(100))
                c.sendall(resposta)
                c.close()
        threading.Thread(target=atende, daemon=True).start()
        # a raiz ("localhost") indica 127.0.0.1, que é outro nome: segue
        linhas = list(server.whois_embutido("exemplo.com.br", "localhost", porta))
        srv.close()
        self.assertIn("dono: Fulano", linhas)
        self.assertEqual(pedidos, [b"exemplo.com.br\r\n"] * 2)

    def test_headers_embutido_segue_redirecionamento(self):
        import http.server as hs

        class H(hs.BaseHTTPRequestHandler):
            def do_HEAD(self):
                if self.path == "/":
                    self.send_response(301)
                    self.send_header("Location", "/fim")
                else:
                    self.send_response(200)
                    self.send_header("X-Teste", "ok")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = hs.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            linhas = list(server.headers_embutido(
                f"http://127.0.0.1:{srv.server_port}/"))
        finally:
            srv.shutdown()
        self.assertEqual(linhas[0], "HTTP 301 Moved Permanently")
        self.assertIn("X-Teste: ok", linhas)

    def test_run_stream_usa_embutido_sem_pacote(self):
        class W(list):
            def write(self, b):
                self.append(b)
        antigo = os.environ["PATH"]
        os.environ["PATH"] = tempfile.mkdtemp()
        original = server.EMBUTIDOS["whois"]
        server.EMBUTIDOS["whois"] = lambda a: iter(["simulado " + a])
        try:
            w = W()
            server.run_stream("whois", "x.com", w, lambda: None)
        finally:
            os.environ["PATH"] = antigo
            server.EMBUTIDOS["whois"] = original
        txt = b"".join(w).decode()
        self.assertIn("versão embutida", txt)
        self.assertIn("simulado x.com", txt)
        self.assertNotIn("pkg install", txt)


class TestInstaladorUnico(unittest.TestCase):
    """Gera o instalar-kit.sh (arquivo único) e instala com pkg falso, sem git."""

    def test_arquivo_unico_instala_tudo(self):
        import gerar_instalador
        casa = tempfile.mkdtemp(prefix="kit-unico-")
        prefixo = os.path.join(casa, "usr")
        binarios = os.path.join(prefixo, "bin")
        os.makedirs(binarios)
        for nome, txt in {
            "pkg": "#!/bin/sh\nexit 0\n",
            "python": (f'#!/bin/sh\n[ "$1" = testes.py ] && exit 0\n'
                       f'exec "{sys.executable}" "$@"\n'),
            "git": "#!/bin/sh\necho git nao deveria ser usado\nexit 9\n",
        }.items():
            with open(os.path.join(binarios, nome), "w") as f:
                f.write(txt)
            os.chmod(os.path.join(binarios, nome), 0o755)
        unico = gerar_instalador.gerar(os.path.join(casa, "instalar-kit.sh"))
        amb = dict(os.environ, HOME=casa, PREFIX=prefixo, KIT_NAO_ABRIR="1",
                   PATH=binarios + os.pathsep + os.environ["PATH"])
        try:
            r = subprocess.run(["bash", unico], env=amb, timeout=60,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            for arq in ("server.py", "index.html", "kit.sh"):
                self.assertTrue(os.path.exists(os.path.join(casa, "kit", arq)), arq)
                self.assertTrue(os.path.exists(
                    os.path.join(casa, "kit-de-bolso", arq)), arq)
            self.assertTrue(os.access(os.path.join(binarios, "kit"), os.X_OK))
            self.assertTrue(os.access(
                os.path.join(casa, ".shortcuts", "Kit de Bolso"), os.X_OK))
            self.assertIn("Pronto!", r.stdout)
            self.assertNotIn("git nao deveria", r.stdout + r.stderr)
        finally:
            shutil.rmtree(casa, ignore_errors=True)


# ------------------------------------------------------------ Kit 3.3
def scan_ap(ssid, bssid, cap="[WPA2-PSK-CCMP][ESS]", freq=2437, rssi=-50):
    return {"ssid": ssid, "bssid": bssid, "capabilities": cap,
            "frequency_mhz": freq, "rssi": rssi}


class TestWifi33(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_seguranca_e_canal(self):
        self.assertEqual(server.seguranca_wifi("[WPA2-PSK-SAE][ESS]"), "WPA3")
        self.assertEqual(server.seguranca_wifi("[RSN-PSK-CCMP]"), "WPA2")
        self.assertEqual(server.seguranca_wifi("[WEP][ESS]"), "WEP")
        self.assertEqual(server.seguranca_wifi("[ESS]"), "aberta")
        self.assertEqual(server.canal_wifi(2412), 1)
        self.assertEqual(server.canal_wifi(2462), 11)
        self.assertEqual(server.canal_wifi(5180), 36)

    def test_autoteste_rede_aberta_e_wps(self):
        r = server.avaliar_wifi_proprio("Casa", [scan_ap("Casa", "aa:00:00:00:00:01",
                                                         "[ESS]")])
        self.assertLess(r["nota"], 50)
        r = server.avaliar_wifi_proprio("Casa", [scan_ap(
            "Casa", "aa:00:00:00:00:01", "[WPA2-PSK-CCMP][WPS][ESS]")])
        self.assertTrue(any("WPS" in t for _, t in r["itens"]))
        self.assertEqual(r["nota"], 80)

    def test_autoteste_wpa3_nota_cheia(self):
        r = server.avaliar_wifi_proprio("XYZ", [scan_ap("XYZ", "aa:00:00:00:00:01",
                                                        "[RSN-SAE-CCMP][ESS]")])
        self.assertEqual(r["nota"], 100)

    def test_canais_escolhe_menos_ocupado(self):
        scan = [scan_ap(f"v{i}", f"aa:00:00:00:00:{i:02x}", freq=2412) for i in range(5)]
        scan += [scan_ap("w", "aa:00:00:00:01:01", freq=2437)]
        self.assertEqual(server.analisar_canais(scan)["2.4"]["melhor"], 11)

    def test_evil_twin(self):
        rid = server.rede_id_atual()
        bom = scan_ap("CasaHesblan", "aa:bb:cc:00:00:01")
        self.assertEqual(server.aprender_bssids(rid, "CasaHesblan", [bom],
                                                "aa:bb:cc:00:00:01"), 1)
        falso = scan_ap("CasaHesblan", "de:ad:00:00:00:01", "[ESS]", freq=2462)
        rep = scan_ap("CasaHesblan", "aa:bb:cc:00:00:02")
        r = server.avaliar_evil_twin(rid, "CasaHesblan", [bom, falso, rep])
        niveis = {x["bssid"]: x["nivel"] for x in r["achados"]}
        self.assertEqual(niveis["de:ad:00:00:00:01"], "alto")
        self.assertEqual(niveis["aa:bb:cc:00:00:02"], "medio")
        server.aprender_bssids(rid, "CasaHesblan", [rep], todos=True)
        r = server.avaliar_evil_twin(rid, "CasaHesblan", [bom, rep])
        self.assertEqual(r["achados"], [])

    def test_evil_twin_sem_aprender_avisa(self):
        r = server.avaliar_evil_twin("x", "Casa", [])
        self.assertIn("aviso", r)

    def test_portal_cativo(self):
        self.assertTrue(server.portal_cativo(lambda u: (204, b""))["ok"])
        self.assertFalse(server.portal_cativo(lambda u: (200, b"<html>"))["ok"])


class TestDNS33(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_dns_limpo(self):
        def rede(n):
            return (3, []) if n.startswith("kit-") else (0, ["142.250.1.1"])
        r = server.checar_dns(["google.com"], rede, lambda n: ["142.250.1.1"])
        self.assertEqual(r["resumo"], "ok")

    def test_nxdomain_sequestrado_vira_alerta(self):
        r = server.checar_dns(["google.com"], lambda n: (0, ["200.1.2.3"]),
                              lambda n: ["200.1.2.3"])
        self.assertEqual(r["resumo"], "suspeito")
        tipos = [a["tipo"] for a in server.listar_alertas(server.rede_id_atual())]
        self.assertIn("dns_sequestro", tipos)

    def test_site_publico_com_ip_privado(self):
        def rede(n):
            return (3, []) if n.startswith("kit-") else (0, ["192.168.0.66"])
        r = server.checar_dns(["bb.com.br"], rede, lambda n: ["170.66.1.1"])
        self.assertEqual(r["dominios"][0]["veredito"], "alto")

    def test_dns_a_com_servidor_falso(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))

        def responder():
            q, a = s.recvfrom(512)
            resp = (q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:]
                    + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                    + socket.inet_aton("93.184.216.34"))
            s.sendto(resp, a)
        threading.Thread(target=responder, daemon=True).start()
        rc, ips = server.dns_a("exemplo.com", "127.0.0.1", s.getsockname()[1])
        s.close()
        self.assertEqual((rc, ips), (0, ["93.184.216.34"]))


DESC_IGD = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">
<device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>"""
RESP_MAP = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><u:GetGenericPortMappingEntryResponse xmlns:u="urn:x">
<NewExternalPort>8080</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.0.30</NewInternalClient>
<NewPortMappingDescription>camera</NewPortMappingDescription>
</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""


class TestRoteador33(unittest.TestCase):
    def test_upnp_lista_portas_abertas(self):
        pedidos = []

        def abrir(url, dados=None, cab=None):
            pedidos.append(url)
            if dados is None:
                return 200, DESC_IGD
            return (200, RESP_MAP) if b">0<" in dados else (500, "erro")
        r = server.upnp_mapeamentos("http://192.168.0.1:5000/rootDesc.xml", abrir)
        self.assertTrue(r["igd"])
        self.assertEqual(r["controle"], "http://192.168.0.1:5000/ctl/IPConn")
        self.assertEqual(r["mapeamentos"][0]["interno"], "192.168.0.30")
        self.assertEqual(len(r["mapeamentos"]), 1)

    def test_upnp_recusa_fora_da_rede(self):
        with self.assertRaises(ValueError):
            server.upnp_mapeamentos("http://8.8.8.8/x.xml", lambda *a: (200, ""))

    def test_nota_do_roteador(self):
        ruim = server.avaliar_roteador({
            "portas": [23, 1900], "pagina": {"http": {"servidor": "mini_httpd"},
                                             "https": "recusado"},
            "upnp": {"igd": True, "mapeamentos": [{"externa": "8080"}]}})
        bom = server.avaliar_roteador({"portas": [80, 443], "pagina": {
            "http": {}, "https": {}}, "upnp": {"igd": False}})
        self.assertEqual(ruim["conceito"], "ruim")
        self.assertEqual(bom["nota"], 100)
        self.assertTrue(any("Telnet" in t for _, t in ruim["itens"]))
        self.assertTrue(any("senha de admin" in t for _, t in bom["itens"]))

    def test_auditoria_recusa_ip_publico(self):
        with self.assertRaises(ValueError):
            server.auditoria_roteador("8.8.8.8")


class TestRegistro33(unittest.TestCase):
    def setUp(self):
        limpar_tudo()
        self.notas = []
        server.NOTIFICADOR[0] = lambda t, x: self.notas.append((t, x))

    def tearDown(self):
        server.NOTIFICADOR[0] = None

    def test_bateria_grava_e_alerta_quente(self):
        server.registrar_bateria({"percentage": 80, "temperature": 31.0,
                                  "current": -350000, "status": "DISCHARGING"})
        e = server.registrar_bateria({"percentage": 79, "temperature": 47.5})
        self.assertIsNotNone(e)
        m = server.medidas("bateria")
        self.assertEqual([x["valor"] for x in m], [80, 79])
        self.assertEqual(m[0]["extra"]["corrente_ma"], -350.0)
        self.assertTrue(any("quente" in t for t, _ in self.notas))
        self.assertIsNone(server.registrar_bateria({"erro": "sem api"}))

    def test_queda_para_2g(self):
        lte = [{"type": "lte", "registered": True, "ci": 1, "dbm": -90}]
        gsm = [{"type": "gsm", "registered": True, "cid": 7, "dbm": -60}]
        a, msg = server.analisar_celular(lte)
        self.assertIsNone(msg)
        b, msg = server.analisar_celular(gsm, a)
        self.assertIn("2G", msg)
        self.assertEqual(server.analisar_celular([], a), (None, None))

    def test_notificacao_em_alerta_alto_e_aparelho_novo(self):
        server.alerta("alto", "arp_spoof", "teste")
        server.alerta("baixo", "inseguro", "não notifica")
        server.alerta("medio", "novo_host", "Novo dispositivo")
        self.assertEqual(len(self.notas), 2)
        server.config_set("notificacoes", False)
        server.alerta("alto", "arp_spoof", "desligada")
        self.assertEqual(len(self.notas), 2)

    def test_mapa_de_sinal(self):
        leituras = iter([{"rssi": -50}, {"rssi": -52}, {"rssi": -48},
                         {"rssi": -80}, {"rssi": -82}, {"rssi": -81}])
        server.marcar_sinal("sala", ler=lambda: next(leituras), pausa=0)
        server.marcar_sinal("quarto 2", ler=lambda: next(leituras), pausa=0)
        m = server.mapa_sinal()
        self.assertEqual([x["local"] for x in m["locais"]], ["sala", "quarto 2"])
        self.assertEqual(m["locais"][1]["qualidade"], "ruim")
        self.assertIn("quarto 2", m["dica"])
        with self.assertRaises(ValueError):
            server.marcar_sinal("<script>", ler=lambda: {"rssi": -50}, pausa=0)
        with self.assertRaises(ValueError):
            server.marcar_sinal("sala", ler=lambda: None, pausa=0)

    def test_linha_do_tempo_junta_tudo(self):
        server.alerta("alto", "arp_spoof", "spoof!", rede_id=server.rede_id_atual())
        server.marcar_sinal("sala", ler=lambda: {"rssi": -60}, leituras=1, pausa=0)
        tipos = {e["tipo"] for e in server.linha_do_tempo(server.rede_id_atual())}
        self.assertEqual(tipos, {"alerta", "sinal"})

    def test_csv_e_backup(self):
        server.registrar_bateria({"percentage": 50, "temperature": 30})
        txt = server.csv_texto("bateria")
        self.assertTrue(txt.startswith("ts,rotulo,valor,extra"))
        self.assertIn("50.0", txt)
        with self.assertRaises(ValueError):
            server.csv_texto("senhas")
        self.assertTrue(server.backup_bytes().startswith(b"SQLite format 3"))

    def test_selo_do_relatorio(self):
        import hashlib
        r = server.selar({"a": 1, "b": [2]})
        h = r.pop("integridade")["hash"]
        esperado = hashlib.sha256(json.dumps(r, ensure_ascii=False, sort_keys=True)
                                  .encode()).hexdigest()
        self.assertEqual(h, esperado)


class TestTreino33(unittest.TestCase):
    def setUp(self):
        limpar_tudo()

    def test_cada_cenario_dispara_o_detector_certo(self):
        esperado = {"arp": "arp_spoof", "dhcp": "dhcp_falso", "deauth": "deauth",
                    "varredura": "varredura"}
        for cen, tipo in esperado.items():
            r = server.rodar_treino(cen)
            self.assertIn(tipo, [e["tipo"] for e in r["deteccoes"]], cen)
            self.assertTrue(r["explica"])

    def test_treino_inseguro_marca_senha(self):
        server.rodar_treino("inseguro")
        tipos = [a["tipo"] for a in server.listar_alertas(None)]
        self.assertIn("credencial", tipos)
        self.assertIn("inseguro", tipos)
        with server.LOCK:
            self.assertTrue(any("Telnet" in k for k in server.ST["inseguro_host"]))

    def test_cenario_desconhecido(self):
        with self.assertRaises(ValueError):
            server.gerar_pcap_treino("deauth_no_vizinho")

    def test_ra_falso_e_tunel_dns(self):
        def icmp6_ra(src):
            corpo = b"\x86\x00" + b"\x00" * 14
            return (struct.pack(">IHBB", 0x60000000, len(corpo), 58, 255)
                    + socket.inet_pton(socket.AF_INET6, src)
                    + socket.inet_pton(socket.AF_INET6, "ff02::1") + corpo)
        server.add(1.0, icmp6_ra("fe80::1"), 101)
        server.add(2.0, icmp6_ra("fe80::66"), 101)
        nome = "a" * 50 + ".exfil.com"
        q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + b"".join(bytes([len(p)]) + p.encode() for p in nome.split("."))
             + b"\x00\x00\x01\x00\x01")
        server.add(3.0, ip_udp("192.168.0.10", "8.8.8.8", 5000, 53, q), 101)
        tipos = [e["tipo"] for e in server.DET.resumo()["eventos"]]
        self.assertIn("ra_falso", tipos)
        self.assertIn("dns_tunel", tipos)


class TestIR33(unittest.TestCase):
    def setUp(self):
        self.enviados = []
        server.IR_ENVIADOR[0] = lambda f, p: self.enviados.append((f, p))
        server._IR_ENVIOS.clear()

    def tearDown(self):
        server.IR_ENVIADOR[0] = None

    def test_nec_lg_power(self):
        f, p = server.ir_nec(0x04, 0x08)
        self.assertEqual(f, 38000)
        self.assertEqual(len(p), 67)
        self.assertEqual(p[:2], [9000, 4500])
        bits = sum(1 << i for i in range(32) if p[3 + 2 * i] == 1687)
        self.assertEqual(bits, 0xF708FB04)  # 20DF10EF do LG, lido em ordem LSB

    def test_samsung_sony_rc5(self):
        f, p = server.ir_samsung(0x07, 0x02)
        self.assertEqual((f, len(p), p[0]), (38000, 67, 4500))
        f, p = server.ir_sony(0x01, 0x15)
        self.assertEqual((f, len(p)), (40000, 78))
        f, p = server.ir_rc5(0, 12)
        self.assertEqual(f, 36000)
        self.assertEqual(len(p) % 2, 1)
        self.assertTrue(all(x in (889, 1778) for x in p))

    def test_pronto(self):
        f, p = server.ir_pronto("0000 006D 0002 0000 0157 00AC 0015 0015")
        self.assertAlmostEqual(f, 38029, delta=50)
        self.assertEqual(len(p), 4)
        with self.assertRaises(ValueError):
            server.ir_pronto("0100 006D 0001 0000 0001 0001")

    def test_envio_exige_confirmacao_e_tem_limite(self):
        corpo = {"protocolo": "nec", "endereco": "0x04", "comando": "0x08"}
        with self.assertRaises(ValueError):
            server.ir_enviar(corpo)
        r = server.ir_enviar(dict(corpo, proprio=True))
        self.assertEqual(r["frequencia"], 38000)
        for _ in range(server.IR_MAX_MIN - 1):
            server.ir_enviar(dict(corpo, proprio=True))
        with self.assertRaises(ValueError):
            server.ir_enviar(dict(corpo, proprio=True))
        self.assertEqual(len(self.enviados), server.IR_MAX_MIN)

    def test_frequencias(self):
        self.assertFalse(server.ir_frequencias(lambda: "[]")["tem_ir"])
        r = server.ir_frequencias(lambda: '[{"min":30000,"max":60000}]')
        self.assertTrue(r["tem_ir"])

    def test_base_de_codigos_monta(self):
        for marca, cods in server.IR_CODIGOS.items():
            for prot, end, cmd in cods:
                f, p = server.IR_PROTOCOLOS[prot](end, cmd)
                self.assertTrue(f and p, marca)

    def test_tv_auditar_e_roku(self):
        r = server.tv_auditar("192.168.0.40", varrer=lambda h, ps: [8060, 5555])
        self.assertTrue(r["roku"])
        self.assertEqual({x["nivel"] for x in r["itens"]}, {"alto"})
        with self.assertRaises(ValueError):
            server.tv_auditar("200.200.200.200", varrer=lambda h, ps: [])
        with self.assertRaises(ValueError):
            server.tv_roku("192.168.0.40", "rm -rf")
        urls = []
        server.tv_roku("192.168.0.40", "PowerOff", abrir=urls.append)
        self.assertEqual(urls, ["http://192.168.0.40:8060/keypress/PowerOff"])


class TestHTTP33(unittest.TestCase):
    setUpClass = classmethod(TestHTTP.setUpClass.__func__)
    tearDownClass = classmethod(TestHTTP.tearDownClass.__func__)
    req = TestHTTP.req

    def setUp(self):
        limpar_tudo()

    def test_rotas_novas_exigem_post(self):
        for rota in ("/api/treino", "/api/ir/enviar", "/api/tv/roku",
                     "/api/dnscheck", "/api/auditoria", "/api/config",
                     "/api/sinal/marcar", "/api/eviltwin"):
            self.assertEqual(self.req("GET", rota)[0], 405, rota)

    def test_treino_pela_api(self):
        st, d, _ = self.req("POST", "/api/treino", {"cenario": "dhcp"})
        self.assertEqual(st, 200)
        self.assertIn("dhcp_falso", [e["tipo"] for e in json.loads(d)["deteccoes"]])
        self.assertEqual(self.req("POST", "/api/treino", {"cenario": "x"})[0], 400)

    def test_ir_sem_confirmacao_400(self):
        st, d, _ = self.req("POST", "/api/ir/enviar",
                            {"protocolo": "nec", "endereco": "4", "comando": "8"})
        self.assertEqual(st, 400)
        self.assertIn("seu", json.loads(d)["erro"])

    def test_ir_codigo_e_padrao(self):
        st, d, _ = self.req("GET", "/api/ir/codigo?marca=LG&i=0&tecla=vol%2B")
        r = json.loads(d)
        self.assertEqual((st, r["comando"]), (200, "0x2"))
        st, d, _ = self.req("GET", "/api/ir/padrao?protocolo=sony&endereco=1&comando=21")
        self.assertEqual(json.loads(d)["frequencia"], 40000)

    def test_config_e_csv_e_relatorio_selado(self):
        st, d, _ = self.req("POST", "/api/config", {"registro": False})
        self.assertFalse(json.loads(d)["registro"])
        st, d, r = self.req("GET", "/api/csv?tipo=alertas")
        self.assertEqual(st, 200)
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        st, d, _ = self.req("GET", "/api/relatorio")
        rel = json.loads(d)
        self.assertEqual(len(rel["integridade"]["hash"]), 64)
        self.assertIn("mapa_sinal", rel)

    def test_linha_do_tempo_e_medidas(self):
        server.alerta("alto", "arp_spoof", "x", rede_id=server.rede_id_atual())
        st, d, _ = self.req("GET", "/api/linha-tempo")
        self.assertEqual(json.loads(d)[0]["titulo"], "possível ARP spoofing")
        self.assertEqual(self.req("GET", "/api/medidas?tipo=senha")[0], 400)

    def test_index_tem_tutorial_e_abas_novas(self):
        st, d, _ = self.req("GET", "/")
        html = d.decode()
        for txt in ("ajudaB", "PASSOS", "GLOSS", "'Emissão':", "Bancada:",
                    "Estudo:", "Defesa:", "explicar"):
            self.assertIn(txt, html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
