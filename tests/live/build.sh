#!/usr/bin/env bash
# Rebuilds fixture.elf and records the compiler. Re-pin fixture_sha256 in playbook.json after a rebuild.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

gcc --version | head -n 1 | tee "$here/fixture.compiler"
gcc -O2 -fno-pie -no-pie -fcf-protection=none -fno-asynchronous-unwind-tables \
    -fno-stack-protector -g0 -Wl,--build-id=none -Wl,-z,norelro -Wall -Wextra \
    -o "$here/fixture.elf" "$here/fixture.c"
sha256sum "$here/fixture.elf"
