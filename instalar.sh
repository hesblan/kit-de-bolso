#!/data/data/com.termux/files/usr/bin/bash
# Instalação do Kit de Bolso do Técnico no Termux.
set -e
DIR="$(dirname "$(realpath "$0")")"
echo "== Kit de Bolso do Técnico =="

pkg update -y || true

echo "-- Instalando Python (obrigatório)…"
if ! pkg install -y python; then
  echo "ERRO: não foi possível instalar o python. Abortando." >&2
  exit 1
fi

echo "-- Instalando opcionais (sem abortar se algum falhar)…"
FALHOU=""
for pacote in nmap dnsutils inetutils traceroute whois curl mtr iproute2 termux-api iperf3; do
  if pkg install -y "$pacote" >/dev/null 2>&1; then
    echo "   ok: $pacote"
  else
    echo "   falhou: $pacote"
    FALHOU="$FALHOU $pacote"
  fi
done
[ -n "$FALHOU" ] && echo "Pacotes que não instalaram:$FALHOU (dá para instalar depois)."

DEST="$HOME/kit"
mkdir -p "$DEST"
cp "$DIR/server.py" "$DIR/index.html" "$DIR/testes.py" "$DEST/"
# NÃO sobrescreve o banco existente ao reinstalar.
[ -f "$DEST/kit.db" ] && echo "Banco existente preservado."

cat > "$PREFIX/bin/kit" <<'X'
#!/data/data/com.termux/files/usr/bin/bash
# Atalho do Kit de Bolso. Exemplos:
#   kit                      abre a interface (só neste aparelho)
#   kit --lan                acessível pela rede local (HTTP sem criptografia:
#                            use só na sua rede e depois rode kit --novo-token)
#   kit --porta 8090         porta HTTP alternativa
#   kit --novo-token         gera um token novo e invalida o antigo
#   kit --agendar 30         inventário automático a cada 30 min (preso à rede atual)
#   kit --relatorio          grava o relatório JSON e sai (sem servidor)
#   kit --testes             roda os testes simulados
cd "$HOME/kit" || { echo "Kit não instalado em ~/kit. Rode: bash instalar.sh"; exit 1; }
case " $* " in
  *" --testes "*) exec python testes.py ;;
  *" --relatorio "*|*" --relatorio="*)
    ARQ="$(echo "$* " | sed -n 's/.*--relatorio[ =]\([^ -][^ ]*\).*/\1/p')"
    if [ -z "$ARQ" ]; then
      # Downloads do Android se o termux-setup-storage já foi feito.
      DIRREL="$HOME/storage/downloads"; [ -d "$DIRREL" ] || DIRREL="$HOME/kit"
      ARQ="$DIRREL/relatorio-kit-$(date +%Y%m%d-%H%M%S).json"
    fi
    exec python server.py --relatorio "$ARQ" ;;
esac
termux-wake-lock 2>/dev/null || true
PORTA="$(echo "$* " | sed -n 's/.*--porta[ =]\([0-9][0-9]*\).*/\1/p')"
[ -z "$PORTA" ] && PORTA=8080
python server.py "$@" &
SRV=$!
trap 'kill $SRV 2>/dev/null; termux-wake-unlock 2>/dev/null || true' EXIT INT TERM
# Espera (até 10 s) o servidor responder; só então o token está garantido no
# arquivo. Em aparelho lento a primeira execução demora mais que 1 s.
PRONTO=""
for _ in $(seq 1 40); do
  kill -0 "$SRV" 2>/dev/null || break      # servidor saiu (porta em uso etc.)
  if [ -s "$HOME/kit/.token" ]; then
    if ! command -v curl >/dev/null 2>&1 || \
       curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORTA/"; then
      PRONTO=1; break
    fi
  fi
  sleep 0.25
done
if [ -n "$PRONTO" ]; then
  TOKEN="$(cat "$HOME/kit/.token")"
  termux-open-url "http://127.0.0.1:$PORTA/?token=$TOKEN" 2>/dev/null || \
    echo "Abra no navegador: http://127.0.0.1:$PORTA/?token=$TOKEN"
elif kill -0 "$SRV" 2>/dev/null; then
  echo "O servidor demorou a responder; abra manualmente quando aparecer o endereço acima."
fi
wait $SRV
X
chmod +x "$PREFIX/bin/kit"

echo "-- Conferindo a instalação com os testes simulados…"
if (cd "$DEST" && python testes.py >/dev/null 2>&1); then
  echo "   testes ok"
else
  echo "   AVISO: algum teste falhou. Rode: kit --testes"
fi

echo
echo "Pronto! Para abrir:  kit        (rede: kit --lan | porta: kit --porta 8090)"
echo "Instalar como app:   abra com kit e toque em 'Instalar app' no topo da tela"
echo "Trocar o token:      kit --novo-token  (faça isso depois de usar --lan)"
echo "Automação:           kit --agendar 30   |   kit --relatorio"
echo "Para atualizar:      cd ~/kit-de-bolso && git pull && bash instalar.sh"
