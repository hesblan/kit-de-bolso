#!/usr/bin/env python3
"""Gera o instalar-kit.sh: UM arquivo só, com o Kit inteiro dentro.

Uso: python gerar_instalador.py   (cria instalar-kit.sh nesta pasta)

No celular basta copiar o instalar-kit.sh (WhatsApp, cabo, Drive…) e, no
Termux, rodar:  bash ~/storage/downloads/instalar-kit.sh
Não precisa de git nem de baixar o repositório.
"""
import base64
import io
import os
import tarfile

AQUI = os.path.dirname(os.path.abspath(__file__))
ARQUIVOS = ["server.py", "index.html", "testes.py", "kit.sh", "instalar.sh",
            "README.md", "SECURITY.md", "LICENSE"]

CABECALHO = r"""#!/data/data/com.termux/files/usr/bin/bash
# Kit de Bolso do Técnico: instalador de arquivo único.
# Uso no Termux:  bash instalar-kit.sh
# Extrai o Kit em ~/kit-de-bolso e roda o instalar.sh (o mesmo do repositório).
set -e
DESTINO="${KIT_ORIGEM:-$HOME/kit-de-bolso}"
mkdir -p "$DESTINO"
echo "-- Extraindo o Kit em $DESTINO…"
sed '1,/^__PACOTE__$/d' "$0" | base64 -d | tar -xzf - -C "$DESTINO"
cd "$DESTINO"
exec bash instalar.sh
__PACOTE__
"""


def gerar(destino=None):
    destino = destino or os.path.join(AQUI, "instalar-kit.sh")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for nome in ARQUIVOS:
            caminho = os.path.join(AQUI, nome)
            if os.path.exists(caminho):
                info = tar.gettarinfo(caminho, arcname=nome)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with open(caminho, "rb") as f:
                    tar.addfile(info, f)
    corpo = base64.encodebytes(buf.getvalue()).decode()
    with open(destino, "w", newline="\n") as f:
        f.write(CABECALHO + corpo)
    os.chmod(destino, 0o755)
    return destino


if __name__ == "__main__":
    print("Gerado:", gerar())
