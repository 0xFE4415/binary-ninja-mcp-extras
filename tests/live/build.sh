#!/usr/bin/env bash
# Rebuilds fixture.o with GCC (fixture.c uses the GCC-only noipa attribute) and records
# the toolchain in fixture.compiler. The object is compiled but never linked.
# After a rebuild, update fixture.sha256 in playbook.json and re-check every pinned
# address and count in it against the new binary.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

{
    gcc --version | sed -n 1p
    as --version | sed -n 1p
} | tee "$here/fixture.compiler"
gcc -O2 -fno-pie -fcf-protection=none -fno-asynchronous-unwind-tables \
    -fno-stack-protector -g0 -Wall -Wextra -c \
    -o "$here/fixture.o" "$here/fixture.c"
sha256sum "$here/fixture.o"
