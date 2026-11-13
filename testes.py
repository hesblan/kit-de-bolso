#!/usr/bin/env python3
"""Testes do Kit (stdlib unittest). Rode: python testes.py

Não há Android no ambiente de teste, então tudo é SIMULADO:
  - pacotes PCAP sintéticos (IP puro, Ethernet/ARP, DHCP, 802.11/radiotap);
  - injeção desses pacotes na porta UDP, igual ao Exportador do PCAPdroid;
  - faixas de rede fictícias com sonda e tabela ARP mockadas;
  - servidor HTTP real numa porta livre, com banco SQLite temporário;
  - redes (casa, cliente) simuladas trocando o coletor de rede;
  - o atalho "kit" executado de verdade com um servidor falso lento.
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
        for t in ("alertas", "dispositivos", "varreduras", "config", "arp", "redes"):
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
    with open(os.path.join(AQUI, "instalar.sh"), encoding="utf-8") as f:
        txt = f.read()
    ini = txt.index("<<'X'\n") + len("<<'X'\n")
    return txt[ini:txt.index("\nX\n", ini)]


SERVIDOR_LENTO = r"""
import http.server, os, sys, time
porta = int(sys.argv[sys.argv.index("--porta") + 1])
time.sleep(1.6)  # aparelho lento: o token só aparece depois de 1,6 s
with open(".token", "w") as f:
    f.write("token-lento")
srv = http.server.HTTPServer(("127.0.0.1", porta), http.server.SimpleHTTPRequestHandler)
srv.timeout = 0.2
fim = time.time() + 4
while time.time() < fim:
    srv.handle_request()
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("curl"),
                     "precisa de bash e curl")
class TestAtalho(unittest.TestCase):
    def test_espera_token_e_servidor(self):
        casa = tempfile.mkdtemp(prefix="kit-home-")
        kit = os.path.join(casa, "kit")
        binarios = os.path.join(casa, "bin")
        os.makedirs(kit)
        os.makedirs(binarios)
        with open(os.path.join(kit, "server.py"), "w") as f:
            f.write(SERVIDOR_LENTO)
        aberto = os.path.join(casa, "url_aberta")
        with open(os.path.join(binarios, "termux-open-url"), "w") as f:
            f.write(f'#!/bin/sh\necho "$1" > "{aberto}"\n')
        with open(os.path.join(binarios, "python"), "w") as f:
            f.write(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        for n in ("termux-open-url", "python"):
            os.chmod(os.path.join(binarios, n), 0o755)
        atalho = os.path.join(casa, "kit.sh")
        with open(atalho, "w") as f:
            f.write(_atalho_do_instalador())
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            porta = s.getsockname()[1]
        amb = dict(os.environ, HOME=casa, PATH=binarios + os.pathsep + os.environ["PATH"])
        subprocess.run(["bash", atalho, "--porta", str(porta)], env=amb,
                       timeout=30, capture_output=True)
        with open(aberto) as f:
            url = f.read().strip()
        self.assertEqual(url, f"http://127.0.0.1:{porta}/?token=token-lento")
        shutil.rmtree(casa, ignore_errors=True)

    def test_atalho_documenta_novo_token(self):
        self.assertIn("--novo-token", _atalho_do_instalador())


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
