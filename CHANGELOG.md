# Changelog

All notable changes to LumaScope are recorded here. Versions follow
[semantic versioning](https://semver.org/); while the project is pre-1.0 the CLI surface
may still change between minor releases.

## [0.2.1] — 2026-08-06

First release verified against live hardware: Frida attached to SignalRGB driving an ASUS
Aura controller (`0B05:19AF`), 75,627 frames in 15 seconds, of which 1,338 were the
`EC 40` colour stream. Capture, command-class grouping, chunk reassembly, colour buffers
and cadence were all confirmed end to end on a physical device.

That run found three bugs. None of them could have been caught by the bundled samples,
which are single-device captures with near-uniform chunk sizes.

### Fixed

- **Chunk framing was not inferred on devices whose channels differ in length.** Each
  channel ends in a short final chunk, so the count column holds a mix (20/8/4 on the
  test device) and the *modal* count is a partial chunk that no offset stride can match —
  a device that plainly streams inferred nothing at all. The chunk size is the stride
  between chunks, so the maximum is now considered alongside the mode.

  Accepting the maximum is guarded: without it, one non-zero outlier in an unrelated
  column can define a chunk size and make a single-packet protocol decode as chunked. A
  count column is positive throughout in any real stream, so a mostly-zero column is
  rejected. Checked against every example spec at every prefix length and both sweep
  profiles, with no false positives.
- **Chunk analysis silently targeted the wrong device on a busy host.** It runs on the
  largest command class present, which is often not the one you care about; the report
  then said "not chunked" about a device that streams. It was also unfixable from the
  command line, because `--vid`/`--pid` can only filter frames whose VID:PID resolved,
  and some applications write through driver handles the capture hook never observes
  being opened — leaving every frame unidentified.

### Added

- **`--command HEX`** on `analyze`, `inspect`, `show`, `reassemble` and `cadence`, to
  select a command class by its leading bytes. Prefer it over `--vid`/`--pid` when a
  capture could not resolve VID:PID. When chunk analysis finds nothing, the report now
  lists the command classes actually present instead of reporting a bare negative.

## [0.2.0] — 2026-08-05

The usability release. 0.1.0 worked, but it assumed you already knew how RGB protocol
reverse engineering goes; this one is meant to be usable by someone meeting the problem
for the first time.

### Added

- **Annotated byte rendering.** Captured packets now print with an offset ruler, a
  per-byte field-tag row naming what each byte is, colour payload rendered in its actual
  colour, `^^` markers on columns that changed, and repeated rows collapsed. The
  annotations are derived from what the decoder inferred, so a dump explains itself
  instead of needing a second tool to interpret it.
- **`show`** — read packets as annotated hex. `--leds` renders the reassembled colour
  buffer as run-collapsed LED runs; `--spec`/`--example` render a protocol's packet
  layout, which is the fastest way to check what a decode concluded.
- **`devices`** — lists connected HID devices with VID:PID, ranked so the lighting
  controller comes first, plus any vendor lighting process currently running, and the
  exact capture command for the top candidate. Pure ctypes, no dependencies.
- **`guide`** — the end-to-end workflow as a walkthrough.
- **`samples/`** — real ASUS Aura captures, so every read-only path works on a fresh
  clone with no hardware and no Windows.
- **Sweep profiles.** `--profile quick` (the default for `--driver manual`) is ~46 steps
  whatever the LED count, against 535 for a 120-LED board on `full`. `sweep` now prints
  a step count and time estimate up front and confirms before a long manual session.
- **Sweep checkpointing.** The corpus is written after every step, and stopping early —
  `Ctrl-C`, or the new `q` at the prompt — keeps everything captured.
- CI now runs on Windows as well as Linux, across Python 3.10–3.12.

### Changed

- **Errors explain themselves.** Missing files, mixed-up capture formats and mistyped
  commands produce an explanation and a suggested command instead of a traceback.
  Capture files are identified by content, not extension.
- **`doctor`** reports capabilities — what you can do now, what is blocked, and the exact
  command that unblocks it — rather than a flat list of packages.
- **Grouped help**, and a starting point on bare invocation. Commands that write a file
  suggest the next one. Hints go to stderr, so piped stdout stays machine-readable.
- The manual sweep prompt shows position, percentage and estimated time remaining, and
  describes each target the way a vendor GUI phrases it.
- `run_sweep` opens the capture backend before engaging the driver, so a missing
  dependency fails immediately instead of first inviting an operator into a session that
  cannot record.
- The README leads with a 60-second quickstart on the bundled samples.
- The package version has a single source of truth (`lumascope.__version__`).

### Fixed

- **`replay` refuses to write while a vendor lighting app is running** (`--force` to
  override). Vendor apps hold an exclusive device handle, and concurrent access is the
  real brick risk — previously this was only a warning in prose.
- **The frida extra is installable on Python 3.10 again.** frida 17 does
  `from typing import NotRequired`, which needs 3.11, so `pip install -e ".[frida]"`
  produced a capture backend that raised on import. Python 3.10 is now held on the 16.x
  line. `capture`, `sweep` and `doctor` also distinguish "not installed" from "installed
  but unimportable", which need different fixes.
- **HID enumeration on 64-bit Windows.** Without explicit ctypes `argtypes`, SetupAPI
  handles were truncated and the walk raised, which `list_devices` swallowed into an
  empty list — the failure looked like "no devices present".
- The documented first command, `cd lumascope`, entered the package directory and failed
  with `ModuleNotFoundError`. The `lumascope` console script is now documented at all,
  and extras are quoted so they work in zsh.
- Terminal output is pure ASCII unless colour is enabled, so legacy Windows consoles
  render it intact. Colour honours `NO_COLOR`/`FORCE_COLOR` and `--color`.

### Known limitations

- Captures taken by hand cannot be decoded into a spec however many you collect —
  decoding needs to observe individual LEDs change, which is what `sweep` sets up.
- Live capture, device enumeration and replay are Windows-only. The decode and emit half
  runs anywhere.
- Nothing in this release has been verified against live hardware; the protocol work it
  is built on was, and the bundled samples are real captures.

## [0.1.0]

Initial release: the capture → decode → emit engine, Frida and USBPcap capture backends,
chunked-protocol reassembly, checksum/stride/encoding recovery, the OpenRGB C++ emitter,
and the ASUS Aura `EC 40` protocol write-up.
