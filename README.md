# 🛠️ Kit de Bolso do Técnico

Ferramenta de **diagnóstico e auditoria defensiva de rede e hardware** que roda
direto no celular Android, sem root. Uma interface web única, servida por um
pequeno servidor em Python no próprio aparelho (via Termux), reúne análise de
rede, captura de pacotes no estilo Wireshark, inventário de dispositivos com
detecção de intrusos e testes de hardware.

> Ferramenta de trabalho e aprendizado para técnicos e desenvolvedores.
> **Uso estritamente defensivo** — veja [Ética e uso](#️-ética-e-uso-responsável).

![status](https://img.shields.io/badge/status-ativo-brightgreen) ![plataforma](https://img.shields.io/badge/plataforma-Android%20%2F%20Termux-blue) ![licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green)

---

## ⚡ Instalação rápida

**Jeito mais fácil (um arquivo só, sem git):** copie o `instalar-kit.sh`
para o celular (WhatsApp, cabo, Drive…) e, no Termux, rode:

```bash
termux-setup-storage   # só na primeira vez, para o Termux ver a pasta Download
bash ~/storage/downloads/instalar-kit.sh
```

O arquivo já traz o Kit inteiro. O único download que sobra é o Python e as
ferramentas extras pelo `pkg`, feito sozinho pelo instalador. DNS, WHOIS e
Cabeçalhos têm versão embutida e funcionam mesmo sem esses pacotes.
Para gerar o arquivo a partir do repositório: `python gerar_instalador.py`.

**Pelo git (Termux):**

```bash
pkg update -y && pkg install -y git
git clone https://github.com/hesblan/kit-de-bolso.git
bash kit-de-bolso/instalar.sh
```

Pronto: o instalador já liga o Kit e abre a tela no navegador. Daqui em
diante o servidor **liga sozinho** quando você abre o Termux (e quando o
celular liga, se tiver o Termux:Boot). Veja [Abrir sem digitar nada](#-abrir-sem-digitar-nada).

**Como app:** com o Kit aberto pelo comando `kit`, toque em **⬇ Instalar app**
no topo da tela (ou no menu ⋮ do Chrome → *Instalar app*). O ícone vai para a
tela inicial e o Kit abre em tela cheia. Se o servidor estiver desligado, o app
mostra o botão **▶ Abrir o Termux**: com o modo automático, abrir o Termux já
liga o Kit, e o app volta sozinho em até 3 s.

**Só no navegador (sem Termux):** abra o `index.html` direto no navegador. As
ferramentas que rodam no próprio aparelho funcionam (tela, touch, som,
microfone, câmera, lanterna, Morse, sensores, GPS, NFC, Bluetooth, QR,
velocidade, sub-rede). Rede, captura e inventário precisam do servidor; a
página mostra como ligá-lo, avisa quando ele aparece e leva ao Kit completo
com um toque.

---

## 🆕 Novidades da 3.3

Toque em **❓ Ajuda** (canto de cima) a qualquer momento: tem o passo a passo de
primeiro uso, a explicação da tela aberta e um glossário. Na primeira vez ela abre
sozinha. Cada alerta tem um botão **❔** que explica o que ele quer dizer.

- **Defesa** (aba nova): autoteste do seu Wi-Fi com nota (a força da senha é
  medida só na tela), detector de Wi-Fi falso (evil twin) e de portal no caminho,
  checagem de DNS sequestrado (compara com DNS seguro por HTTPS), auditoria
  completa do roteador (inclui as portas que o UPnP abriu para a internet),
  tráfego sem criptografia por aparelho, linha do tempo, notificações do Android
  e exportação CSV/backup.
- **Bancada** (aba nova): lei de Ohm, cores de resistor, divisor de tensão,
  resistor de LED, conversor dec/hex/bin/texto, consumo em kWh, gerador de
  sinais (onda, varredura, ruído, DTMF), registro de bateria e temperatura,
  mapa de sinal por cômodo, canais do Wi-Fi, nível de bolha e estroboscópio.
- **Emissão** (aba nova): controle universal por infravermelho para os **seus**
  aparelhos. Descobre o código da sua TV marca por marca, com confirmação a cada
  passo, salva em "Meus aparelhos" e tem "Desligar os meus". Funciona pelo
  emissor IR do celular (Termux:API) ou por um adaptador IR de fone. Também
  audita a TV na rede e controla TVs Roku. Não existe modo de disparo contínuo.
- **Estudo** (aba nova): laboratório que gera ataques de mentira (ARP, DHCP,
  deauth, senha sem criptografia, varredura) dentro do Kit e mostra o alerta;
  fichas, glossário e a lista do que o Kit não faz e por quê.
- **Detectores novos** na captura: varredura de portas, roteador IPv6 falso e
  túnel por DNS. Alertas de bateria quente e de queda do celular para 2G.
- **Relatório** com selo SHA-256, mapa de sinal e linha do tempo.

## ✨ Recursos

| Aba | O que faz |
|-----|-----------|
| **Painel** | KPIs ao vivo, gráfico de tráfego, protocolos, top domínios, conexões inseguras e atalhos (varrer, detecções, relatório, JSON, .pcap) |
| **Captura** | Tabela de pacotes ao vivo com filtro e download `.pcap` (abre no Wireshark). Integra com o PCAPdroid. **Analisa arquivos `.pcap`/`.pcapng`** da sua rede (Ethernet, 802.11, radiotap) |
| **Rede** | `nmap`, `ping`, `traceroute`, `mtr`, DNS, WHOIS, certificado SSL, descoberta UPnP/mDNS, Wake-on-LAN, calculadora de sub-rede, fabricante por MAC |
| **Segurança** | Inventário **separado por rede** (casa, cliente…) com **alerta de novo dispositivo** e de **MAC trocado**, **detecções** (deauth, ARP spoofing, DHCP falso, tráfego inseguro), **histórico hoje × ontem**, **varredura agendada** presa à rede em que foi salva, vigilância de ARP, auditoria do roteador e central de alertas |
| **Wi-Fi** | Redes próximas e canais, monitor de sinal (RSSI), info de célula 4G/5G, teste de velocidade |
| **Aparelho** | Bateria (Termux:API), NFC (suas tags), Bluetooth LE (seus aparelhos), leitor de QR/código de barras, GPS, rastreador da ISS, sensores, estresse de CPU |
| **Testes** | Tela (pixel morto), touch, alto-falante, microfone, câmeras, lanterna, **sinalização Morse** (lanterna ou tela), vibração |
| **Relatório** | Documento consolidado da rede escolhida (rede, inventário, alertas, histórico, varreduras, detecções, captura): **PDF** pela impressão, **JSON** completo e **.pcap** |

---

## 📦 Requisitos

Todos gratuitos. **Importante:** instale o Termux e o Termux:API pela **mesma
loja** (os dois pelo [F-Droid](https://f-droid.org)); se vierem de lojas
diferentes, o `termux-api` não funciona por diferença de assinatura.

- **[Termux](https://f-droid.org/packages/com.termux/)** — terminal Linux
- **[Termux:API](https://f-droid.org/packages/com.termux.api/)** — acesso a Wi-Fi/celular (opcional)
- **[Termux:Widget](https://f-droid.org/packages/com.termux.widget/)** — atalho "Kit de Bolso" na tela inicial (opcional)
- **[Termux:Boot](https://f-droid.org/packages/com.termux.boot/)** — liga o Kit quando o celular liga (opcional)
- **[PCAPdroid](https://f-droid.org/packages/com.emanuelef.remote_capture/)** — captura de pacotes sem root (opcional)

> A versão do Termux da Play Store está desatualizada. Use a do F-Droid.
> O scan de Wi-Fi exige conceder a permissão de **Localização** ao Termux:API.

---

## 🚀 Instalação

```bash
# No Termux:
pkg update -y && pkg install -y git
cd ~
git clone https://github.com/hesblan/kit-de-bolso.git
bash kit-de-bolso/instalar.sh
```

Depois, para abrir a qualquer momento:

```bash
kit                 # liga em segundo plano (se precisar) e abre a tela
kit --parar         # desliga o servidor
kit --status        # está ligado? em que porta?
kit --log           # últimas linhas do registro do servidor
kit --automatico liga|desliga   # ligar sozinho ao abrir o Termux / ligar o celular
kit --primeiro-plano            # roda preso ao terminal (Ctrl+C encerra)
kit --lan           # acessível por outros aparelhos da rede local
kit --porta 8090    # porta HTTP alternativa
kit --agendar 30    # inventário automático a cada 30 min, só na rede atual (0 desliga)
kit --novo-token    # gera um token novo e invalida o antigo
kit --relatorio     # grava o relatório JSON (em Downloads, se houver) e sai
kit --testes        # roda os testes simulados
```

A interface abre sozinha no navegador, já autenticada pelo token. O servidor
fica em **segundo plano**: pode fechar o Termux que ele continua. Se o Kit já
estiver ligado, `kit` só abre a tela (não sobe outro). `--lan`, `--novo-token`
e `--agendar` reiniciam o servidor com a opção nova. O atalho espera até 15 s
o servidor subir antes de abrir (aparelhos lentos).

---

## 📲 Abrir sem digitar nada

O `instalar.sh` deixa tudo pronto. São três jeitos, do mais simples ao mais
completo:

1. **Abrir o Termux** — o modo automático (ligado pelo instalador) liga o
   servidor assim que o Termux abre. Depois é só tocar no ícone do app do Kit.
2. **Ícone na tela inicial (Termux:Widget)** — instale o Termux:Widget do
   F-Droid, segure na tela inicial → *Widgets* → *Termux:Widget* e escolha
   **Kit de Bolso**. Um toque liga e abre o Kit. O atalho **Desligar Kit**
   também fica disponível.
3. **Ligar com o celular (Termux:Boot)** — instale o Termux:Boot do F-Droid e
   abra-o **uma vez**. A partir daí o servidor liga sozinho quando o celular
   termina de ligar (só em `127.0.0.1`, protegido por token), e a varredura
   agendada volta a rodar sem você fazer nada.

Para não ligar sozinho: `kit --automatico desliga` (ou instale com
`KIT_SEM_AUTO=1 bash instalar.sh`). O registro do servidor fica em
`~/kit/kit.log`.

> **Dica:** nas configurações do Android, deixe o Termux **sem restrição de
> bateria**; senão o sistema pode encerrar o servidor em segundo plano.

**Para atualizar:**

```bash
cd ~/kit-de-bolso && git pull && bash instalar.sh
```

---

## 🔐 Segurança e token

O servidor exige um **token de acesso** em todas as rotas da API. Ele é gerado
na primeira execução e salvo em `~/kit/.token` (permissão 600). O atalho `kit`
já abre o navegador com o token embutido, então no uso normal é transparente.

Por que isso importa: qualquer página aberta no navegador do celular consegue
disparar requisições para `127.0.0.1:8080`. Sem o token, um site malicioso
poderia acionar a ferramenta (CSRF). Proteções aplicadas:

- Token obrigatório em toda a API (cabeçalho `X-Kit-Token` ou cookie
  `HttpOnly; SameSite=Strict`).
- Validação do cabeçalho `Host` (bloqueia DNS rebinding).
- Ações que mudam estado aceitam apenas `POST`.
- Alvos de varredura validados; `nmap` e inventário só rodam em **faixas
  privadas** (sua rede).
- A porta de captura (UDP 5123) ouve só em `127.0.0.1`.

- A página usa CSP sem `'unsafe-inline'` em scripts (nonce por carregamento),
  então um texto malicioso vindo da rede não vira código.

### Modo `--lan` (atenção)

O `--lan` serve a interface por **HTTP sem criptografia**. Qualquer pessoa na
mesma rede pode capturar o token no tráfego. Use `--lan` **só na sua própria
rede** e, ao terminar, troque o token:

```bash
kit --novo-token
```

Se o IP do celular mudar enquanto o `--lan` estiver ligado (novo DHCP), o Kit
percebe em até 30 s e mostra o endereço novo no terminal.

### Quando usar `--novo-token`

Depois de usar `--lan`, se o link com o token foi compartilhado ou se você
emprestou o celular. O token antigo, os links e os cookies antigos deixam de
valer na hora. Na tela de acesso negado dá para colar o token novo (ele fica em
`~/kit/.token`).

---

## 🗺️ Redes separadas

Cada rede tem seu próprio inventário, histórico, alertas e tabela ARP. O Kit
identifica a rede pelo **gateway + MAC do gateway (quando o Android deixa ler)
+ SSID** (ou BSSID, se o SSID estiver oculto). Assim, visitar a casa A e depois
o cliente B, ambos em `192.168.0.0/24`, **não** gera falsos "novo dispositivo"
nem "MAC trocado", e o "hoje × ontem" nunca compara redes diferentes.

- A rede atual aparece no topo da tela.
- Na aba **Segurança** e no **Relatório** você escolhe qual rede ver e pode
  **renomeá-la** (ex.: "Casa", "Cliente João").
- Dados da versão anterior ficam na rede "Dados antigos".
- Sem Termux:API (sem SSID) e sem o MAC do gateway, duas redes com o mesmo
  gateway não se distinguem. Instale o Termux:API para separar bem.

### Agenda presa à rede

A varredura agendada só roda **na rede em que foi salva**. Se o celular entrar
no Wi-Fi de um café ou de um cliente, a agenda fica **pausada** ("agenda
pausada: rede diferente"), nada é varrido e isso aparece na interface. Ao
voltar à rede original, ela retoma sozinha.

---

## 🦈 Captura de pacotes (estilo Wireshark)

1. Abra o **PCAPdroid**.
2. **Ajustes → Modo de despejo**: `Exportador UDP`, IP `127.0.0.1`, porta `5123`, formato `PCAP`.
3. Toque em **Iniciar** no PCAPdroid.
4. Os pacotes aparecem ao vivo na aba **Captura**. O botão **.pcap** gera um
   arquivo que abre direto no Wireshark do PC.

### Detecções defensivas

Todo pacote (ao vivo ou de um arquivo importado) passa pelos detectores. Cada
arquivo importado é analisado **separadamente** (ARP e DHCP de um arquivo não
são comparados com os de outro), e na captura ao vivo as entradas sem
novidade há mais de 1 h expiram.

| Detecção | Como funciona | Quando aparece |
|---|---|---|
| **Deauth/disassoc** | ≥ 15 quadros de desautenticação em 10 s | Arquivo 802.11/radiotap (adaptador em modo monitor) |
| **ARP spoofing** | Um IP passa a responder com outro MAC | Captura Ethernet (tcpdump no roteador/OpenWrt) |
| **DHCP falso** | Mais de um servidor DHCP oferecendo endereço | Captura Ethernet |
| **Tráfego inseguro** | Telnet, FTP, HTTP, POP3, IMAP, SNMP, SMB | Qualquer captura |
| **Senha em HTTP** | `senha=`, `password=`, `Authorization: Basic` em texto puro | Qualquer captura |

Os alertas ficam gravados no SQLite (`kit.db`) e aparecem no Painel, na
Segurança e no Relatório. O Kit **só detecta**: não envia deauth, não
responde ARP e não oferece DHCP.

Para analisar um arquivo: aba **Captura → Analisar arquivo .pcap/.pcapng**
(até 25 MB).

> O celular captura apenas o **próprio tráfego** (por app, via VPN local). Para
> ver toda a rede, use um roteador com OpenWrt ou um notebook com adaptador
> Wi-Fi em modo monitor.

---

## ⚠️ Limitações sem root

O Android, sem root, limita algumas funções — a ferramenta detecta e avisa:

- O `traceroute` usa o modo UDP padrão, que funciona sem root. O `mtr` pode exigir root.
- A tabela ARP (`ip neigh`) vem vazia no Android 10+ sem root; use o **Inventário** (varredura ativa) no lugar.
- **Deauth, ARP spoofing e DHCP falso só aparecem em `.pcap` importado.** O
  PCAPdroid sem root vê apenas o tráfego do próprio aparelho (VPN local), sem
  quadros Wi-Fi nem ARP/DHCP dos outros. Capture no roteador (tcpdump/OpenWrt)
  ou num adaptador em modo monitor e importe o arquivo no Kit.
- O inventário usa `ping` e portas comuns. Aparelhos que bloqueiam ping e não
  têm porta aberta podem não aparecer.
- O app instalável só funciona aberto em `http://127.0.0.1` (o navegador exige
  contexto seguro). Pelo IP da rede (`--lan`) a interface funciona, mas não
  instala.
- A varredura agendada roda enquanto o servidor estiver ligado (o atalho segura
  o `termux-wake-lock`). Com o Termux:Boot ela volta sozinha depois de
  reiniciar o celular.
- Uma página da web não consegue ligar o servidor sozinha (o Android não
  deixa). Por isso o botão **Abrir o Termux** + modo automático: um toque.

---

## 🧱 Arquitetura

```
┌─────────────────┐     HTTP+token   ┌──────────────────┐
│  Navegador      │ ◄──────────────► │  server.py       │
│  (index.html)   │   :8080          │  (Python stdlib) │
└─────────────────┘                  └───────┬──────────┘
                                             │ chama
                                 nmap · ping · dig · whois · mtr
                                             │
                                      ┌──────┴───────┐
                                      │  kit.db      │  redes, dispositivos,
                                      │  (SQLite)    │  alertas, varreduras
                                      └──────────────┘
         ▲ UDP :5123 (só 127.0.0.1)
         │ formato PCAP
   ┌─────┴──────┐
   │ PCAPdroid  │  captura o tráfego do aparelho
   └────────────┘
```

---

## 🗂️ Estrutura

```
kit-de-bolso/
├── server.py        # servidor, lógica de rede e arquivos do app (manifest,
│                    # service worker e ícones gerados em Python)
├── index.html       # interface web (única página)
├── instalar.sh      # instalador para Termux (comando, atalhos, automático)
├── kit.sh           # o comando "kit" (vai para $PREFIX/bin/kit)
├── testes.py        # testes (python testes.py)
├── README.md
├── LICENSE          # MIT
├── SECURITY.md      # uso responsável e token
└── .gitignore
```

Rodar os testes: `python testes.py` (ou `kit --testes`). Os testes não precisam
de Android: geram pacotes PCAP sintéticos, enviam pela porta UDP como o
PCAPdroid faria, simulam redes diferentes (casa e cliente) na mesma faixa,
executam o atalho `kit` de verdade com um servidor de mentira (segundo plano,
"já ligado", parar, duas partidas juntas, modo automático), rodam o
`instalar.sh` com um `pkg` falso e sobem o servidor HTTP de verdade com um
banco temporário.

O banco guarda no máximo 5000 alertas e 90 dias de varreduras (limpeza ao
iniciar e a cada varredura).

---

## ⚖️ Ética e uso responsável

Ferramenta **defensiva**, de diagnóstico e aprendizado. **Não** inclui ataques
ativos (deauth, MITM, captura de credenciais, spoofing).

Varreduras ativas (`nmap`, inventário) e auditorias só devem ser executadas em
**redes e dispositivos de sua propriedade** ou com **autorização expressa** do
responsável. Varrer redes de terceiros sem permissão pode ser ilegal. Veja
[SECURITY.md](SECURITY.md).

## 📄 Licença

[MIT](LICENSE).
