#!/data/data/com.termux/files/usr/bin/bash
# Atalho do Kit de Bolso. O instalar.sh copia este arquivo para $PREFIX/bin/kit.
#
#   kit                      liga o Kit em segundo plano e abre o navegador
#                            (se já estiver ligado, só abre o navegador)
#   kit --parar              desliga o servidor
#   kit --status             diz se está ligado, em que porta e o PID
#   kit --log                mostra as últimas linhas do registro do servidor
#   kit --fundo              só garante o servidor ligado, sem abrir o navegador
#                            (usado pelo Termux:Boot e ao abrir o Termux)
#   kit --automatico liga    liga sozinho ao abrir o Termux e ao ligar o celular
#   kit --automatico desliga desfaz o item acima
#   kit --primeiro-plano     roda preso ao terminal, como antes (Ctrl+C encerra)
#   kit --lan                acessível pela rede local (HTTP sem criptografia:
#                            use só na sua rede e depois rode kit --novo-token)
#   kit --porta 8090         porta HTTP alternativa
#   kit --novo-token         gera um token novo e invalida o antigo
#   kit --agendar 30         inventário automático a cada 30 min (preso à rede atual)
#   kit --relatorio          grava o relatório JSON e sai (sem servidor)
#   kit --testes             roda os testes simulados

KIT="$HOME/kit"
ESTADO="$KIT/.servidor"      # "PID PORTA" do servidor em segundo plano
LOG="$KIT/kit.log"
BOOT="$HOME/.termux/boot/kit-de-bolso"
RC="$HOME/.bashrc"
MARCA_INI="# >>> kit de bolso: liga o servidor ao abrir o Termux >>>"
MARCA_FIM="# <<< kit de bolso <<<"

cd "$KIT" 2>/dev/null || { echo "Kit não instalado em ~/kit. Rode: bash instalar.sh"; exit 1; }
umask 077   # log e estado só para o dono (o log mostra o endereço com token)

# Responde 0 se quem atende na porta $1 é o Kit (e não outro programa).
kit_vivo() {
  python - "$1" <<'PY' 2>/dev/null
import sys, urllib.request
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/manifest.webmanifest",
                                timeout=1) as r:
        sys.exit(0 if b"Kit de Bolso" in r.read() else 1)
except Exception:
    sys.exit(1)
PY
}

ler_estado() {
  PID_SALVO=""; PORTA_SALVA=""
  [ -s "$ESTADO" ] && read -r PID_SALVO PORTA_SALVA < "$ESTADO"
  if [ -n "$PID_SALVO" ] && ! kill -0 "$PID_SALVO" 2>/dev/null; then
    PID_SALVO=""; PORTA_SALVA=""; rm -f "$ESTADO"
  fi
}

abrir_navegador() {
  local url="http://127.0.0.1:$1/?token=$(cat "$KIT/.token")"
  if [ -n "$KIT_NAO_ABRIR" ]; then
    return 0
  fi
  termux-open-url "$url" 2>/dev/null || echo "Abra no navegador: $url"
}

parar() {
  ler_estado
  if [ -n "$PID_SALVO" ]; then
    kill "$PID_SALVO" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$PID_SALVO" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$PID_SALVO" 2>/dev/null
    rm -f "$ESTADO"
    termux-wake-unlock 2>/dev/null || true
    echo "Kit desligado."
    return 0
  fi
  echo "O Kit não estava ligado em segundo plano."
  return 1
}

automatico() {
  case "$1" in
    liga)
      mkdir -p "$(dirname "$BOOT")"
      cat > "$BOOT" <<B
#!/data/data/com.termux/files/usr/bin/sh
# Termux:Boot: liga o servidor do Kit quando o celular termina de ligar.
termux-wake-lock
exec "$PREFIX/bin/kit" --fundo
B
      chmod 700 "$BOOT"
      if ! grep -qF "$MARCA_INI" "$RC" 2>/dev/null; then
        {
          echo "$MARCA_INI"
          echo '[ -x "$PREFIX/bin/kit" ] && [ -z "$KIT_SEM_AUTO" ] && ( "$PREFIX/bin/kit" --fundo --quieto & )'
          echo "$MARCA_FIM"
        } >> "$RC"
      fi
      echo "Automático ligado: o Kit liga sozinho ao abrir o Termux e ao ligar"
      echo "o celular (este último precisa do app Termux:Boot, do F-Droid)." ;;
    desliga)
      rm -f "$BOOT"
      if [ -f "$RC" ]; then
        awk -v i="$MARCA_INI" -v f="$MARCA_FIM" \
          '$0==i{p=1;next} $0==f{p=0;next} !p' "$RC" > "$RC.kit" && mv "$RC.kit" "$RC"
      fi
      echo "Automático desligado. Use 'kit' para ligar quando quiser." ;;
    *)
      echo "Use: kit --automatico liga   ou   kit --automatico desliga"; return 2 ;;
  esac
}

# ------------------------------------------------------------ comandos simples
case " $* " in
  *" --testes "*) exec python testes.py ;;
  *" --relatorio "*|*" --relatorio="*)
    ARQ="$(echo "$* " | sed -n 's/.*--relatorio[ =]\([^ -][^ ]*\).*/\1/p')"
    if [ -z "$ARQ" ]; then
      # Downloads do Android se o termux-setup-storage já foi feito.
      DIRREL="$HOME/storage/downloads"; [ -d "$DIRREL" ] || DIRREL="$KIT"
      ARQ="$DIRREL/relatorio-kit-$(date +%Y%m%d-%H%M%S).json"
    fi
    exec python server.py --relatorio "$ARQ" ;;
  *" --parar "*) parar; exit $? ;;
  *" --automatico "*)
    QUAL="$(echo "$* " | sed -n 's/.*--automatico[ =]\([a-z]*\).*/\1/p')"
    automatico "$QUAL"; exit $? ;;
  *" --log "*) tail -n 40 "$LOG" 2>/dev/null || echo "Ainda não há registro."; exit 0 ;;
  *" --status "*)
    ler_estado
    if [ -n "$PID_SALVO" ] && kit_vivo "$PORTA_SALVA"; then
      echo "Kit ligado na porta $PORTA_SALVA (PID $PID_SALVO)."
    elif kit_vivo 8080; then
      echo "Kit ligado na porta 8080 (aberto em outro terminal)."
    else
      echo "Kit desligado. Para ligar: kit"
    fi
    [ -f "$BOOT" ] && echo "Automático: ligado." || echo "Automático: desligado."
    exit 0 ;;
esac

# Separa as opções do atalho das que vão para o server.py.
FUNDO=""; QUIETO=""; PRIMEIRO=""; ARGS=()
for a in "$@"; do
  case "$a" in
    --fundo) FUNDO=1 ;;
    --quieto) QUIETO=1 ;;
    --primeiro-plano) PRIMEIRO=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
[ -n "$FUNDO" ] && KIT_NAO_ABRIR=1
diga() { [ -n "$QUIETO" ] || echo "$@"; }

PORTA="$(echo "${ARGS[*]} " | sed -n 's/.*--porta[ =]\([0-9][0-9]*\).*/\1/p')"
ler_estado
[ -z "$PORTA" ] && PORTA="${PORTA_SALVA:-8080}"

# Opções que mudam o servidor exigem reiniciá-lo; o resto só reabre a tela.
MUDA=""
for a in "${ARGS[@]}"; do
  case "$a" in --lan|--novo-token|--agendar|--agendar=*|--faixa|--faixa=*) MUDA=1 ;; esac
done

if [ -z "$PRIMEIRO" ] && [ -z "$MUDA" ] && kit_vivo "$PORTA"; then
  diga "O Kit já está ligado (porta $PORTA). Abrindo…"
  abrir_navegador "$PORTA"
  exit 0
fi
if [ -n "$MUDA" ] && [ -n "$PID_SALVO" ]; then
  diga "Reiniciando o Kit com as novas opções…"
  parar >/dev/null
fi

# Trava contra duas partidas juntas (ex.: Termux:Boot e abrir o Termux).
LOCK="$KIT/.ligando"
[ -n "$(find "$LOCK" -maxdepth 0 -mmin +1 2>/dev/null)" ] && rmdir "$LOCK" 2>/dev/null
if ! mkdir "$LOCK" 2>/dev/null; then
  diga "O Kit já está sendo ligado; aguardando…"
  FIM=$(( $(date +%s) + 15 ))
  while [ "$(date +%s)" -le "$FIM" ]; do
    if kit_vivo "$PORTA"; then abrir_navegador "$PORTA"; exit 0; fi
    sleep 0.5
  done
  echo "O Kit não respondeu. Veja: kit --log"; exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

termux-wake-lock 2>/dev/null || true

if [ -n "$PRIMEIRO" ]; then
  python server.py "${ARGS[@]}" &
  SRV=$!
  trap 'rmdir "$LOCK" 2>/dev/null; kill $SRV 2>/dev/null; termux-wake-unlock 2>/dev/null || true' EXIT INT TERM
else
  # Sessão própria (setsid): fechar o Termux ou o atalho não derruba o servidor.
  echo "--- $(date '+%Y-%m-%d %H:%M:%S') kit ${ARGS[*]}" >> "$LOG"
  nohup python -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    python server.py "${ARGS[@]}" >> "$LOG" 2>&1 < /dev/null &
  SRV=$!
fi

# Espera (até 15 s) o servidor responder; só então o token está garantido no
# arquivo. Em aparelho lento a primeira execução demora.
PRONTO=""
FIM=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -le "$FIM" ]; do
  kill -0 "$SRV" 2>/dev/null || break      # servidor saiu (porta em uso etc.)
  if [ -s "$KIT/.token" ] && kit_vivo "$PORTA"; then
    PRONTO=1; break
  fi
  sleep 0.25
done

if [ -n "$PRONTO" ]; then
  rmdir "$LOCK" 2>/dev/null
  if [ -z "$PRIMEIRO" ]; then
    echo "$SRV $PORTA" > "$ESTADO"
    diga "Kit ligado em segundo plano (porta $PORTA). Pode fechar o Termux."
    diga "Para desligar: kit --parar"
  fi
  abrir_navegador "$PORTA"
elif kill -0 "$SRV" 2>/dev/null; then
  diga "O servidor demorou a responder. Veja: kit --log"
else
  rm -f "$ESTADO"
  termux-wake-unlock 2>/dev/null || true
  echo "O Kit não conseguiu ligar. Últimas linhas do registro:"
  tail -n 5 "$LOG" 2>/dev/null
  exit 1
fi

[ -n "$PRIMEIRO" ] && wait "$SRV"
exit 0
