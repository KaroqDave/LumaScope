# Repository Guidelines

## Project Structure & Module Organization

LumaScope is a pure-Python RGB protocol reverse-engineering harness. Source lives in `lumascope/`: `capture/` records Frida or USBPcap traffic, `decode/` infers protocol structure, `stimulus/` drives device state, `emit/` renders specs/C++ skeletons, `view.py`/`annotate.py` render captured bytes as annotated hex, `devices.py` discovers hardware, and `cli.py` exposes commands. Tests live in `tests/`, with fixtures under `tests/fixtures/`. Committed demo captures live in `samples/` and are referenced by the README quickstart — keep them working. Real capture artifacts such as `*.jsonl` and `*.pcapng` may appear at the repo root; treat them as research data, not library code. Protocol notes and worked examples belong in `docs/`.

## Build, Test, and Development Commands

- `lumascope doctor` (or `python -m lumascope.cli doctor`): report available optional tooling.
- `lumascope selftest`: run the stdlib-only decode round-trip examples.
- `lumascope show --frames samples/aura-red.frames.jsonl`: check the annotated-dump rendering.
- `python -m pytest -q`: run the full test suite; Windows/Frida-specific tests skip when unavailable.
- `python -m compileall -q lumascope tests`: syntax/import sanity check without running tests.
- `pip install -e .[dev]`: install the package locally with pytest.
- `pip install -e .[frida]`, `.[stimulus]`, or `.[image]`: install optional capture/stimulus extras only when needed.

## Coding Style & Naming Conventions

Use Python 3.10+ syntax, four-space indentation, type hints, dataclasses for shared models, and short module-level docstrings. Keep core decode logic stdlib-only. Prefer explicit converters for JSON formats instead of broad `asdict()` dumps when stable on-disk shape matters. Names should be descriptive and snake_case for functions, variables, and modules; classes use PascalCase.

User-facing output is part of the product. Terminal output must be pure ASCII by default (legacy Windows consoles) with colour only via `lumascope.view`, which honours `NO_COLOR`/`FORCE_COLOR` and `--color`. Anything a user can get wrong should raise `LumaScopeError` with a suggested command rather than a traceback; commentary and "Next:" hints go to stderr so stdout stays machine-readable.

## Testing Guidelines

Tests use `pytest` and are named `tests/test_*.py`. Add focused regression tests with every behavioral fix, especially around byte-level protocol encoding, chunking, checksums, replay safety, and serializers. Prefer synthetic fixtures or mock backends over hardware-dependent tests. Hardware or platform-specific tests must skip cleanly when dependencies are absent.

## Commit & Pull Request Guidelines

Recent history uses concise Conventional Commit prefixes such as `feat:`, `fix:`, and `docs:`. Keep commits scoped and mention the command or protocol affected when helpful. Pull requests should include a short problem statement, summary of changes, test results, and any hardware/protocol assumptions. Link related issues or capture notes when applicable.

## Safety & Configuration Tips

Replay is the only device-writing path. Keep it dry-run by default, require explicit confirmation for writes, and do not add blind probing behavior. Never auto-probe SMBus addresses. Optional native dependencies should stay behind extras so decode, emit, and tests remain portable.
