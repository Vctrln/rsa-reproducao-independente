#!/usr/bin/env bash
# Baixa as dependências da reprodução do artigo que NÃO vêm do apt, com verificação de integridade.
# Tudo vai para paper_repro/vendor/ (recriável; não faz parte dos resultados).
#
#   Node.js 20.19.0 (versão citada no artigo, §3.2)   -> SHA-256 conferido contra SHASUMS256.txt oficial
#   node-forge 1.3.1                                   -> SHA-512 conferido contra dist.integrity do registro npm
#   Bouncy Castle bcprov-jdk18on 1.79 (versão do pom.xml dos autores) -> SHA-1 conferido contra o .sha1 do Maven Central
#   PyCryptodome 3.21.0 (pip, no .venv do projeto)     -> hash conferido pelo pip a partir do índice
#
# Os SHA-256 efetivos de cada artefato ficam em paper_repro/vendor/deps.lock.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$HERE/vendor"
ROOT="$(cd "$HERE/.." && pwd)"
mkdir -p "$VENDOR"
cd "$VENDOR"
LOCK="$VENDOR/deps.lock"
: > "$LOCK.new"

NODE_VER=20.19.0
FORGE_VER=1.3.1
BC_VER=1.79
PYCRYPTODOME_VER=3.21.0

# ---- Node.js
NODE_TGZ="node-v${NODE_VER}-linux-x64.tar.xz"
if [ ! -x "node-v${NODE_VER}-linux-x64/bin/node" ]; then
  curl -fsSLO "https://nodejs.org/dist/v${NODE_VER}/${NODE_TGZ}"
  curl -fsSL "https://nodejs.org/dist/v${NODE_VER}/SHASUMS256.txt" -o node-SHASUMS256.txt
  grep " ${NODE_TGZ}\$" node-SHASUMS256.txt | sha256sum -c -
  tar -xJf "$NODE_TGZ"
  rm -f "$NODE_TGZ"
fi
echo "nodejs ${NODE_VER} $(sha256sum "node-v${NODE_VER}-linux-x64/bin/node" | cut -d' ' -f1) (binário; tarball conferido com SHASUMS256.txt)" >> "$LOCK.new"

# ---- node-forge
if [ ! -f "node_modules/node-forge/package.json" ]; then
  FORGE_TGZ="node-forge-${FORGE_VER}.tgz"
  curl -fsSLO "https://registry.npmjs.org/node-forge/-/${FORGE_TGZ}"
  EXPECTED=$(curl -fsSL "https://registry.npmjs.org/node-forge/${FORGE_VER}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["dist"]["integrity"])')
  GOT="sha512-$(openssl dgst -sha512 -binary "$FORGE_TGZ" | base64 -w0)"
  [ "$EXPECTED" = "$GOT" ] || { echo "node-forge: integridade NÃO confere" >&2; exit 1; }
  mkdir -p node_modules/node-forge
  tar -xzf "$FORGE_TGZ" -C node_modules/node-forge --strip-components=1
  echo "node-forge ${FORGE_VER} ${GOT}" > node-forge.integrity
  rm -f "$FORGE_TGZ"
fi
echo "node-forge ${FORGE_VER} $(cat node-forge.integrity | cut -d' ' -f3) (tarball; conferido com dist.integrity do npm)" >> "$LOCK.new"

# ---- Bouncy Castle
BC_JAR="bcprov-jdk18on-${BC_VER}.jar"
if [ ! -f "$BC_JAR" ]; then
  BASE="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/${BC_VER}"
  curl -fsSLO "$BASE/$BC_JAR"
  SHA1=$(curl -fsSL "$BASE/$BC_JAR.sha1" | cut -c1-40)
  echo "$SHA1  $BC_JAR" | sha1sum -c -
fi
echo "bcprov-jdk18on ${BC_VER} $(sha256sum "$BC_JAR" | cut -d' ' -f1) (conferido com .sha1 do Maven Central)" >> "$LOCK.new"

# ---- PyCryptodome (no .venv do projeto)
# `python -m pip` (não `.venv/bin/pip`): o script pip do .venv pode ter shebang de outro caminho se a pasta
# do projeto foi copiada, e instalaria no venv errado.
"$ROOT/.venv/bin/python" -m pip install -q "pycryptodome==${PYCRYPTODOME_VER}"
echo "pycryptodome ${PYCRYPTODOME_VER} $("$ROOT/.venv/bin/python" -c 'import Crypto,os;print(Crypto.__version__)') (pip)" >> "$LOCK.new"

mv "$LOCK.new" "$LOCK"
echo "Dependências prontas em $VENDOR"
cat "$LOCK"
