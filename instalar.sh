#!/data/data/com.termux/files/usr/bin/bash
# Instalação do Kit de Bolso do Técnico no Termux.
# Uso: bash instalar.sh            (instala, liga o automático e abre o Kit)
#      KIT_SEM_AUTO=1 bash instalar.sh   (não liga sozinho ao abrir o Termux/celular)
#      KIT_NAO_ABRIR=1 bash instalar.sh  (não abre o navegador no final)
set -e
DIR="$(dirname "$(realpath "$0")")"
echo "== Kit de Bolso do Técnico =="

pkg update -y || true

echo "-- Instalando Python (obrigatório)…"
if ! pkg install -y python; then
  echo "ERRO: não foi possível instalar o python. Abortando." >&2
  exit 1
fi

echo "-- Instalando as ferramentas extras de uma vez (sem abortar se alguma falhar)…"
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

# Se uma versão antiga estiver ligada em segundo plano, desliga para a nova
# entrar no lugar (ela é religada no final).
ESTAVA_LIGADO=""
if [ -x "$PREFIX/bin/kit" ] && [ -s "$HOME/kit/.servidor" ]; then
  bash "$PREFIX/bin/kit" --parar >/dev/null 2>&1 && ESTAVA_LIGADO=1 || true
fi

DEST="$HOME/kit"
mkdir -p "$DEST"
cp "$DIR/server.py" "$DIR/index.html" "$DIR/testes.py" "$DIR/kit.sh" "$DEST/"
# NÃO sobrescreve o banco existente ao reinstalar.
[ -f "$DEST/kit.db" ] && echo "Banco existente preservado."

echo "-- Instalando o comando 'kit'…"
cp "$DIR/kit.sh" "$PREFIX/bin/kit"
chmod +x "$PREFIX/bin/kit"

echo "-- Criando atalhos para a tela inicial (app Termux:Widget)…"
mkdir -p "$HOME/.shortcuts"
cat > "$HOME/.shortcuts/Kit de Bolso" <<W
#!/data/data/com.termux/files/usr/bin/bash
# Liga o Kit (se precisar) e abre a interface no navegador.
exec "$PREFIX/bin/kit"
W
cat > "$HOME/.shortcuts/Desligar Kit" <<W
#!/data/data/com.termux/files/usr/bin/bash
exec "$PREFIX/bin/kit" --parar
W
chmod 700 "$HOME/.shortcuts/Kit de Bolso" "$HOME/.shortcuts/Desligar Kit"

if [ -z "$KIT_SEM_AUTO" ]; then
  echo "-- Ligando o modo automático…"
  bash "$PREFIX/bin/kit" --automatico liga | sed 's/^/   /'
else
  echo "-- Modo automático NÃO ligado (KIT_SEM_AUTO). Para ligar: kit --automatico liga"
fi

echo "-- Conferindo a instalação com os testes simulados…"
if (cd "$DEST" && python testes.py >/dev/null 2>&1); then
  echo "   testes ok"
else
  echo "   AVISO: algum teste falhou. Rode: kit --testes"
fi

echo
echo "Pronto! O Kit fica ligado em segundo plano; para abrir a tela: kit"
echo "Desligar:            kit --parar        (situação: kit --status)"
echo "Tela inicial:        widget do Termux:Widget -> 'Kit de Bolso'"
echo "Ligar com o celular: instale o Termux:Boot (F-Droid) e abra-o uma vez"
echo "Instalar como app:   na tela do Kit, toque em 'Instalar app' no topo"
echo "Rede/porta:          kit --lan | kit --porta 8090 | kit --novo-token"
echo "Automação:           kit --agendar 30   |   kit --relatorio"
echo "Para atualizar:      bash instalar-kit.sh (arquivo novo)  ou  git pull && bash instalar.sh"
echo "Sem internet:        DNS, WHOIS e Cabeçalhos têm versão embutida (não dependem de pacote)"
echo

if [ -z "$KIT_NAO_ABRIR" ]; then
  echo "-- Abrindo o Kit…"
  bash "$PREFIX/bin/kit" || true
elif [ -n "$ESTAVA_LIGADO" ]; then
  bash "$PREFIX/bin/kit" --fundo --quieto || true
fi
