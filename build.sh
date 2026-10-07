#!/bin/sh
# Regenerates json2dir.mal.xz from json2dir.c:
#   C --(ELVM 8cc)--> EIR --(ELVM elc -hell)--> HeLL --(LMFAO)--> Malbolge Unshackled
# MALBOLGE_TOOLCHAIN must contain elvm/ (built: out/8cc, out/elc) and LMFAO/ (built: lmfao).
set -eu
src=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tc=${MALBOLGE_TOOLCHAIN:?set MALBOLGE_TOOLCHAIN}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' 0
"$tc/elvm/out/8cc" -S -I"$tc/elvm" -I"$tc/elvm/libc" -o "$tmp/json2dir.eir" "$src/json2dir.c"
"$tc/elvm/out/elc" -hell "$tmp/json2dir.eir" > "$tmp/json2dir.hell"
"$tc/LMFAO/lmfao" "$tmp/json2dir.hell" -o "$tmp/json2dir.mal" > /dev/null
xz -9 -T0 -c "$tmp/json2dir.mal" > "$src/json2dir.mal.xz"
xz -dc "$src/json2dir.mal.xz" > "$src/json2dir.mal"
