# LumaScope

[![Tests](https://github.com/KaroqDave/LumaScope/actions/workflows/tests.yml/badge.svg)](https://github.com/KaroqDave/LumaScope/actions/workflows/tests.yml)
[![Latest release](https://img.shields.io/github/v/release/KaroqDave/LumaScope?label=release)](https://github.com/KaroqDave/LumaScope/releases/latest)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://github.com/KaroqDave/LumaScope#install)
[![Platforms](https://img.shields.io/badge/engine-Windows%20%7C%20Linux%20%7C%20macOS-blue)](https://github.com/KaroqDave/LumaScope#install)
[![Capture](https://img.shields.io/badge/live%20capture-Windows-lightgrey)](https://github.com/KaroqDave/LumaScope#reversing-a-real-device-windows)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Automated RGB-protocol reverse-engineering harness.**

Adding a vendor RGB device to a control app means knowing its wire protocol. Today that's done
by hand: run the vendor app, capture USB traffic in Wireshark, change one setting, then
eyeball-diff 64-byte hex dumps in a spreadsheet. Every prior project (OpenRGB, OpenRazer,
SignalRGB) documents that exact manual loop. LumaScope automates it:

```
 drive the vendor app  ->  capture device traffic  ->  auto-diff into a protocol spec  ->  emit
    (stimulus)              (Frida / USBPcap)              (decode)             (JSON + C++ skeleton)
```

The harness is disposable research tooling; its **output** - a machine-readable protocol spec and
an OpenRGB-style C++ `RGBController` skeleton - is the deliverable. It was built to feed the
[**LumaCore**](https://github.com/KaroqDave/LumaCore) RGB product, but nothing ties it to one
consumer.

## Quickstart (60 seconds, no hardware)

```bash
git clone https://github.com/KaroqDave/LumaScope && cd LumaScope
pip install -e .
lumascope
```

Bare `lumascope` prints a three-step path for newcomers. The interesting one is reading real
captured bytes from an ASUS motherboard, bundled in [`samples/`](samples/):

```bash
lumascope show --frames samples/aura-red.frames.jsonl
```

```
frame 0  [usbpcap  65 bytes]
        00 01 02 03  04 05 06 07  08 09 10 11  12 13 14 15
     0  ec 40 84 00  02 ff 00 00  ff 00 00 00  00 00 00 00  |.@..............|
        id cm ch of  ct R  G  B   R  G  B  --  -- -- -- --
    16  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  |................|
        *  (2 identical rows omitted)
  id=report id  cm=command  ch=channel  of=offset  ct=count  R/G/B=LED colour data

  offset  field             bytes              value
  0       report id         ec                 0xec (236)
  1       command           40                 0x40 (64)
  2       channel           84                 channel 4  + final-chunk flag 0x80
  3       offset            00                 starts at LED 0 (byte 0 of the buffer)
  4       count             02                 2 LED(s) in this chunk
  5..10   LED colour data   ff 00 00 ff 00 00  2 LED(s)
  11..64  unused / padding  00 00 00 00 00 ..  54 byte(s)
```

**The dump explains itself.** Every byte is tagged with what it is, colour bytes render in their
actual colour on a colour terminal, repeated rows collapse, and offsets are decimal so they match
the byte indices every other command reports. You should never need a second tool to read a dump.

Then see what those packets add up to, and get the full structural report:

```bash
lumascope show --frames samples/aura-red.frames.jsonl --leds
lumascope analyze --frames samples/aura-red.frames.jsonl
```

[`samples/README.md`](samples/README.md) walks through more, including a real single-variable
diff that proves a negative: the ASUS rainbow effect has **no speed field** on the wire.

The same rendering works on a protocol rather than a capture, which is the quickest way to
check what a decode concluded — here the `G R B` tag row shows the recovered wire order:

```bash
lumascope show --example interleaved
```

```
     0  cc 24 00 ff  00 ff 00 00  00 00 ff ff  ff ff 00 ff  |.$..............|
        id == G  R   B  G  R  B   G  R  B  G   R  B  G  R
```

## Install

The **decode + emit core is pure Python stdlib**. Capture and stimulus backends are optional
extras (native wheels); install only what you use. Quote the extras — `zsh` on macOS treats
bare brackets as a glob.

```bash
pip install -e .                 # the engine + CLI
lumascope doctor                 # what works here, and the command to fix what doesn't

pip install -e ".[dev]" && pytest    # run the test suite
pip install -e ".[frida]"            # optional: Frida in-process capture (HID/WinUSB)
pip install -e ".[stimulus]"         # optional: OpenRGB driver + GUI automation
pip install -e ".[usb]"              # optional: pyusb for guarded USB control replay
# USBPcap capture additionally needs Wireshark (tshark) + USBPcap installed system-wide
```

Requires Python 3.10+. Windows is the primary target for live capture (HID/WinUSB/USBPcap); the
decode/emit engine and everything in `samples/` runs anywhere.

Every command also works as `python -m lumascope.cli <command>` if you'd rather not install.

## Commands

Run `lumascope <command> --help` for options, or `lumascope guide` for the whole workflow.

| Command | What it does | Hardware? |
|---|---|---|
| `doctor` | what this machine can do, and the exact command to unlock the rest | no |
| `devices` | list connected devices with VID:PID, plus vendor lighting processes | no |
| `guide` | the end-to-end reverse-engineering workflow | no |
| `demo <example>` | full synth -> decode -> validate -> C++ pipeline on one example | no |
| `selftest` | prove the decoder recovers the built-in example specs | no |
| `show` | read packets as annotated hex (`--leds` for the buffer, `--spec` for a layout) | no |
| `analyze` | one-shot report: command classes, chunk framing, effect timing | no |
| `inspect` | group by command class, or diff two single-variable captures | no |
| `reassemble` | rebuild a chunked/streamed capture into per-channel buffers | no |
| `cadence` | measure a streamed effect's speed from packet timing | no |
| `decode` | decode a labeled corpus -> protocol spec (+ optional C++) | no |
| `emit` | render a protocol spec -> JSON or C++ skeleton | no |
| `capture` | record device writes - Frida hook or USBPcap sniff | yes |
| `sweep` | drive a stimulus matrix, capture, pair into a labeled corpus | yes |
| `replay` | replay a decoded spec to verify it (dry-run by default, safety-gated) | yes |

## File types

Three formats, distinguished by content rather than extension — pass the wrong one and the tool
tells you which command takes it.

| Suffix | What it holds | Written by |
|---|---|---|
| `.frames.jsonl` | raw packets straight off the device | `capture` |
| `.corpus.json` | packets **paired with the state that caused them** | `sweep` |
| `.spec.json` | the decoded protocol | `decode`, `emit` |

Only a corpus can be decoded: decoding needs to know what each packet *meant*.

## Reversing a real device (Windows)

`lumascope guide` prints this as a walkthrough. The short version:

```bash
# 1. what can this machine do, and what am I targeting?
lumascope doctor
lumascope devices           # VID:PID, ranked; plus vendor processes running now

# 2. record the vendor app driving the device (run elevated for USBPcap / SYSTEM services)
lumascope capture --attach LightingService.exe --duration 20 --out red.frames.jsonl
#    ...or sniff the bus when the colour buffer never appears in-process:
lumascope capture --backend usbpcap --vid 0x0b05 --pid 0x19af \
    --duration 20 --out red.frames.jsonl

# 3. read what you caught
lumascope show --frames red.frames.jsonl
lumascope analyze --frames red.frames.jsonl

# 4. change ONE thing, capture again, and diff to localize the byte that carries it
lumascope inspect --frames red.frames.jsonl --diff green.frames.jsonl

# 5. a guided sweep produces a *labeled* corpus and decodes it in one shot
lumascope sweep --led-count 120 --driver manual --attach LightingService.exe \
    --out aura.corpus.json --decode --emit-cpp AuraController.cpp

# 6. check what the decoder concluded, as a labelled packet
lumascope show --spec aura.spec.json

# 7. (optional) verify the decoded spec by replaying it - vendor app CLOSED first
lumascope replay --spec aura.spec.json --device-path "<path>"          # dry-run
lumascope replay --spec aura.spec.json --device-path "<path>" --write --yes
```

Captures you take by hand can be read, diffed and reassembled, but they cannot be *decoded*
into a spec — decoding needs to watch individual LEDs change, which is what step 5 sets up.

### Sweep profiles

A sweep step under `--driver manual` is a human setting a state in a vendor GUI, so the
matrix size decides whether the session takes minutes or an evening:

| Profile | 8 LEDs | 30 LEDs | 120 LEDs |
|---|---|---|---|
| `quick` (default for `--driver manual`) | 46 steps | 46 steps | 46 steps |
| `full` (default for `--driver openrgb`) | 87 steps | 175 steps | 535 steps |

`quick` probes a contiguous run of the first few LEDs instead of every one, and still
recovers layout, stride, channel order, scaling and checksum — pinned by
`tests/test_matrix_profiles.py` for both interleaved and planar devices at 30 and 120 LEDs.
`full` probes every LED and is the right choice when a driver applies the states for you.
LumaScope asks for confirmation before starting a manual sweep longer than 80 steps.

**The corpus is written after every step.** Ctrl-C, or `q` at the prompt, keeps everything
captured up to that point rather than discarding the session.

## Proven on real hardware

LumaScope reverse-engineered an **ASUS Aura motherboard controller** (USB `VID_0B05 PID_19AF`)
end-to-end on a live machine:

1. **Mapped the stack** with the Frida backend: Armoury Crate GUI -> `LightingService` (JSON-RPC
   over a named pipe) -> `ArmouryCrate.Service` (custom kernel-driver IOCTLs).
2. **Captured the wire bytes** with the USBPcap fallback - necessary because the colour buffer is
   passed *by reference* through a kernel driver, invisible to in-process hooks (exactly the case
   the bus-sniffing fallback exists for).
3. **Decoded** the `EC 40` chunked direct-colour protocol: report `0xEC`, command `0x40`, 3
   channels of up to 120 LEDs, RGB order, 20 LEDs/packet, apply-flag on the final chunk.
4. **Characterised the effects** with `inspect` (single-variable command-class diffs): every mode -
   static, breathing, colour-cycle, rainbow, fixed *and* addressable - is host-streamed over that
   same `EC 40` path. Armoury Crate uses **no** native effect command (`EC 35`/`EC 36` never appear).
5. **Measured effect speed** with `cadence` (per-frame timing): speed is not a wire field but a
   host-side phase rate - the rainbow's cycle period spans ~1.6 s (fast) to ~16.5 s (slow) at a
   fixed ~180-200 Hz refresh.

A controlled single-colour capture confirmed **RGB** order, and the result - written up in
[docs/asus-aura-pid19af-protocol.md](docs/asus-aura-pid19af-protocol.md) - matches LumaCore's
existing encoder, locked by a passing golden test. That doc is the best worked example of the
whole loop, and the methodological punchline: because Armoury Crate streams everything, an Aura
capture cannot reach the `EC 35`/`EC 36` path (that needs an OpenRGB capture or a guarded write).

## Architecture

```
                 orchestrate.py  (drive -> capture window -> pair -> Corpus)
                 ┌──────────────┬──────────────┬──────────────┐
            STIMULUS         CAPTURE         DECODE          EMIT
       matrix / manual /  frida_backend  chunked -> diff   spec_json
       openrgb + sync     usbpcap_backend  stride/checksum  openrgb_cpp
                          -> CaptureFrame   encoding/spec    (JSON + C++)
```

- **`model.py`** - the shared vocabulary every module speaks: `CaptureFrame`, `SweepStep`,
  `Corpus`, `ProtocolSpec`.
- **`codec.py`** - the single reference encoder (`spec + colors -> wire bytes`), shared by the
  synthetic generator, the decoder's validation round-trip, and mirrored by the C++ emitter.
- **`capture/`** - `frida_backend` spawns/attaches a process and injects `agent.js` to hook
  `WriteFile` / `DeviceIoControl` / `HidD_*` / `WinUsb_*` (with handle->VID:PID correlation and a
  binary channel); `usbpcap_backend` parses `tshark -T json` from a USBPcap bus capture. Both emit
  a common `CaptureFrame`. `serialize` defines the on-disk formats and identifies them by content.
- **`decode/`** - passes over a labeled `Corpus`: `chunked` reassembles streamed protocols first;
  `diff` localizes fields + recovers scaling; `stride` recovers layout/stride/channel-order;
  `checksum` recovers sum/xor/CRC; `encoding` finds brightness; `spec` assembles and validates by
  re-encoding every frame byte-for-byte.
- **`view.py` / `annotate.py`** - the reader-facing half: `annotate` turns an inferred framing or a
  decoded spec into a per-byte field map, and `view` renders it as annotated, colour-coded hex.
- **`stimulus/`** - `matrix` generates the one-thing-at-a-time sweep; `manual` (operator-guided)
  and `openrgb` drivers apply each step; `sync` windows the capture.
- **`emit/`** - `spec_json` (canonical JSON) and `openrgb_cpp` (a drop-in `RGBController` skeleton).
- **`devices.py`** - read-only HID enumeration (pure ctypes) + vendor-process detection.

## Layout

```
lumascope/
  cli.py            the command line; grouped help, guided errors
  model.py          CaptureFrame, SweepStep, Corpus, ProtocolSpec dataclasses
  codec.py          reference encoder: spec + colors -> wire bytes
  view.py           annotated hex dumps, colour swatches, LED tables
  annotate.py       framing/spec -> per-byte field maps
  devices.py        HID device + vendor-process discovery
  errors.py         user-facing errors with a suggested fix
  synthetic.py      generate labeled captures from a known spec (no hardware)
  examples.py       built-in ground-truth specs for selftest/tests
  doctor.py         environment check, reported as capabilities
  orchestrate.py    drive -> capture -> pair -> Corpus
  replay.py         safety-gated device-write verification
  capture/          base, agent.js, frida_backend, usbpcap_backend, serialize
  stimulus/         base, manual, openrgb_driver, matrix, sync
  decode/           diff, stride, checksum, encoding, spec, chunked, inspect, cadence
  emit/             spec_json, openrgb_cpp
samples/            real ASUS Aura captures - the zero-hardware starting point
tests/              decode/emit/orchestrate/chunked/replay/usbpcap/view + frida capture
docs/               asus-aura-pid19af-protocol.md  (worked example)
```

## Development

```bash
pip install -e ".[dev]"
pytest -q                 # full suite; capture tests skip without Windows + frida
```

The core is intentionally pure-stdlib so the engine and most tests run on any Python 3.10+ with no
native deps. The Frida capture tests require Windows + `frida`; they `skip` cleanly elsewhere (so
CI on Linux exercises decode/emit/chunked/orchestrate/replay/parser). CI runs `pytest` on each
push (`.github/workflows/tests.yml`).

Terminal output honours `NO_COLOR` / `FORCE_COLOR`, and every rendering command takes
`--color auto|always|never`. Set `LUMASCOPE_NO_HINTS=1` to silence the "Next:" suggestions.
Hints and progress notes go to stderr, so piping stdout stays machine-readable.

## Safety

Capture-only / passive by default - the tool never issues device writes during research, and
**never auto-probes SMBus addresses** (blind SMBus access has bricked real boards: Gigabyte Z390,
MSI Mystic Light). The `replay` command is the only writer: it is **dry-run by default**, a real
write requires explicit `--write --yes`, and LumaScope actively checks for a running vendor
lighting app and refuses to write while one is detected (override with `--force` only if you are
certain it does not own the device). Vendor apps hold an exclusive device handle, and concurrent
access is the brick risk.

## License

MIT - see [LICENSE](LICENSE). Note that emitted C++ skeletons are modelled on OpenRGB's
`RGBController` shape; if you ship them inside a GPL project (e.g. LumaCore), that project's license
governs the integrated result.
