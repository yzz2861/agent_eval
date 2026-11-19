#!/usr/bin/env bash
# Regenerate the three-slot micro fixtures (requires a clang with ELF targets).
set -euo pipefail
cd "$(dirname "$0")/.."
CLANG="${CLANG:-clang}"
PY="${PY:-python3}"

$CLANG --target=i386-unknown-none -ffreestanding -fno-pic -c fixtures/micro_ftab.c -o fixtures/micro_ftab_rel_i386.o
$CLANG --target=x86_64-unknown-none -ffreestanding -fno-pic -c fixtures/micro_ftab.c -o fixtures/micro_ftab_rela_x86_64.o
$CLANG --target=i386-unknown-none -ffreestanding -fno-pic -c fixtures/overlap_ftab.c -o fixtures/overlap_ftab_rel_i386.o
$PY tools/build_ar.py fixtures/micro_ftab.a fixtures/micro_ftab_rel_i386.o fixtures/micro_ftab_rela_x86_64.o
