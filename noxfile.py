import fnmatch
import os
from collections.abc import Iterator
from pathlib import Path

import nox

nox.options.default_venv_backend = "uv|virtualenv"
# mutation is slow and opt-in: run it explicitly with `nox -s mutation`.
nox.options.sessions = ["format", "ruff", "size", "ty", "test", "native", "check"]

# Ratchet on file size, like the mutant gate: it may be raised only deliberately,
# never to quietly admit growth. Set to 1.5x the largest file in the gate's tree at
# introduction (tests/test_tools/test_decompile.py), rounded up to the next 50.
SIZE_LIMIT_BYTES = 51350

# Entry names excluded from the size walk wherever they appear: generated or cached
# output, not authored source.
SIZE_SKIPPED = (".nox", "target", "mutants*", "*.egg-info", "__pycache__")


@nox.session
def format(session: nox.Session) -> None:
    session.install("ruff>=0.6")
    session.run("ruff", "format", "--check", "src", "tests")


@nox.session
def ruff(session: nox.Session) -> None:
    session.install("ruff>=0.6")
    session.run("ruff", "check", "src", "tests")


def _walk_authored_files(root: str) -> Iterator[Path]:
    """Yield every file under root, pruning generated/cached directories on the way down."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if not _skipped_entry(name)]
        yield from (Path(dirpath) / filename for filename in filenames)


def _skipped_entry(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in SIZE_SKIPPED)


@nox.session(python=False)
def size(session: nox.Session) -> None:
    """Fail if any authored file in src/, tests/, or native/src/ exceeds SIZE_LIMIT_BYTES."""
    oversized = sorted(
        (
            path
            for root in ("src", "tests", "native/src")
            for path in _walk_authored_files(root)
            if path.stat().st_size > SIZE_LIMIT_BYTES
        ),
        key=lambda path: path.stat().st_size,
        reverse=True,
    )
    for path in oversized:
        session.log(f"{path.stat().st_size}\t{path}")
    if oversized:
        session.error(
            f"{len(oversized)} file(s) exceed the {SIZE_LIMIT_BYTES}-byte limit listed above; "
            "split them instead of raising the ratchet casually"
        )


@nox.session
def ty(session: nox.Session) -> None:
    session.install("ty>=0.0.1")
    session.install("-e", ".[dev]")
    session.run("ty", "check", "--error", "all", "src", "tests")


@nox.session
def test(session: nox.Session) -> None:
    session.install("-e", ".[test]")
    session.run("pytest", *session.posargs)


@nox.session
def mutation(session: nox.Session) -> None:
    session.install("-e", ".[dev]")
    stats = Path("mutants/mutmut-cicd-stats.json")
    stats.unlink(missing_ok=True)
    session.run("mutmut", "run", env={"HYPOTHESIS_PROFILE": "mutmut"})
    session.run("mutmut", "export-cicd-stats")
    session.run(
        "jq",
        "-e",
        ".total > 0 and (.killed + .survived + .timeout) == .total"
        " and (.survived + .timeout) == 0",
        stats.as_posix(),
        external=True,
    )


@nox.session(python=False)
def mutation_native(session: nox.Session) -> None:
    """cargo-mutants in stub-core mode; exit 2/3 only report survivors, jq gates the count."""
    session.chdir("native")
    outcomes = Path("mutants.out/outcomes.json")
    outcomes.unlink(missing_ok=True)
    session.run("cargo", "mutants", "-j", "4", success_codes=[0, 2, 3], external=True)
    session.run(
        "jq",
        "-e",
        ".total_mutants > 0"
        " and (.caught + .missed + .timeout + .unviable) == .total_mutants"
        " and (.missed + .timeout) == 0",
        outcomes.as_posix(),
        external=True,
    )


@nox.session(python=False)
def native(session: nox.Session) -> None:
    """Rust gates in stub-core mode, so they run without a Binary Ninja install.

    The stub mode compiles a stub binaryninjacore via cmake (needs clang, cmake,
    ninja); tests are pure logic and never call the core, so they are valid in
    both modes. The real-core build happens at install time
    (native/scripts/install.sh).
    """
    session.chdir("native")
    # Prefer the rustup toolchain when present: some distros ship a system
    # cargo of a different build, and mixing compilers in one target/ fails
    # with E0514 (artifacts compiled by an incompatible rustc). rustup reads
    # native/rust-toolchain.toml to pick the pinned channel.
    env = dict(os.environ)
    rustup_bin = Path.home() / ".cargo" / "bin"
    if rustup_bin.is_dir():
        env["PATH"] = f"{rustup_bin}:{env['PATH']}"
    session.run("cargo", "fmt", "--check", external=True, env=env)
    session.run(
        "cargo",
        "clippy",
        "--all-targets",
        "--no-default-features",
        "--",
        "-D",
        "warnings",
        external=True,
        env=env,
    )
    session.run("cargo", "test", "--no-default-features", external=True, env=env)


@nox.session
def check(session: nox.Session) -> None:
    session.notify("format")
    session.notify("ruff")
    session.notify("size")
    session.notify("ty")
    session.notify("test")
