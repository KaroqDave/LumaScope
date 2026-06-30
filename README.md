# LumaScope

**Automated RGB-protocol reverse-engineering harness.**

Adding a vendor RGB device to a control app means knowing its wire protocol. Today that's done
by hand: run the vendor app, capture USB traffic in Wireshark, change one setting, then
eyeball-diff 64-byte hex dumps in a spreadsheet. Every prior project (OpenRGB, OpenRazer,
SignalRGB) documents that exact manual loop. LumaScope automates it:

```
 drive the vendor app  →  capture device traffic  →  auto-diff into a protocol spec  →  emit
    (stimulus)              (Frida / USBPcap)              (decode)             (JSON + C++ skeleton)
```

The harness is disposable research tooling; its **output** — a machine-readable protocol spec and
an OpenRGB-style C++ `RGBController` skeleton — is the deliverable. It was built to feed the
[**LumaCore**](https://github.com/KaroqDave/LumaCore) RGB product, but nothing ties it to one
consumer.

## Proven on real hardware

LumaScope reverse-engineered an **ASUS Aura motherboard controller** (USB `VID_0B05 PID_19AF`)
end-to-end on a live machine:

1. **Mapped the stack** with the Frida backend: Armoury Crate GUI → `LightingService` (JSON-RPC
   over a named pipe) → `ArmouryCrate.Service` (custom kernel-driver IOCTLs).
2. **Captured the wire bytes** with the USBPcap fallback — necessary because the colour buffer is
   passed *by reference* through a kernel driver, invisible to in-process hooks (exactly the case
   the bus-sniffing fallback exists for).
3. **Decoded** the `EC 40` chunked direct-colour protocol: report `0xEC`, command `0x40`, 3
   channels of up to 120 LEDs, RGB order, 20 LEDs/packet, apply-flag on the final chunk.

A controlled single-colour capture confirmed **RGB** order, and the result — written up in
[docs/asus-aura-pid19af-protocol.md](docs/asus-aura-pid19af-protocol.md) — matches LumaCore's
existing encoder, locked by a passing golden test. That doc is the best worked example of the
whole loop.

## Install

The **decode + emit core is pure Python stdlib** — no install needed to run the engine or its
tests. Capture and stimulus backends are optional extras (native wheels); install only what you
use.

```bash
cd lumascope
python -m lumascope.cli doctor          # report what's installed / runnable here
pip install -e .[dev] && pytest         # run the test suite

pip install -e .[frida]                 # optional: Frida in-process capture (HID/WinUSB)
pip install -e .[stimulus]              # optional: OpenRGB driver + GUI automation
# USBPcap capture additionally needs Wireshark (tshark) + USBPcap installed system-wide
```

Requires Python 3.10+. Windows is the primary target for live capture (HID/WinUSB/USBPcap); the
decode/emit engine runs anywhere.

## Commands

Run `python -m lumascope.cli <command> --help` for options.

| Command | What it does | Hardware? |
|---|---|---|
| `doctor` | report installed tools + which phases are runnable here | no |
| `selftest` | prove the decoder recovers the built-in example specs | no |
| `demo <example>` | full synth → decode → validate → C++ pipeline on one example | no |
| `decode` | decode a saved capture corpus → protocol spec (+ optional C++) | no |
| `reassemble` | reassemble a chunked/streamed capture into per-channel buffers | no |
| `emit` | render a protocol spec → JSON or C++ skeleton | no |
| `capture` | record device writes — Frida hook (`--backend frida`) or USBPcap sniff (`--backend usbpcap`) | yes |
| `sweep` | drive a stimulus through the matrix, capture, pair into a labeled corpus, optionally decode + emit | yes |
| `replay` | replay a decoded spec to the device to verify it (dry-run by default, safety-gated) | yes |

## Workflows

### No hardware — prove the engine
```bash
python -m lumascope.cli selftest        # recover interleaved/planar/gamma/CRC example specs
python -m lumascope.cli demo gamma      # synth → decode → validate → C++ for one example
```

### Real device — reverse a protocol (Windows)
See [docs/asus-aura-pid19af-protocol.md](docs/asus-aura-pid19af-protocol.md) for a full worked
example. The shape of the loop:

```bash
# 1. find the device + the process that writes to it (run elevated to see SYSTEM services)
python -m lumascope.cli doctor

# 2a. capture passively while you change colours in the vendor app (in-process hook):
python -m lumascope.cli capture --attach <VendorService> --duration 30 --out caps.jsonl
# 2b. ...or sniff the USB bus when the bytes aren't visible in-process (needs USBPcap + admin):
python -m lumascope.cli capture --backend usbpcap --interface \\.\USBPcap1 --duration 30 --out caps.jsonl

# 3. inspect the structure; for streamed/chunked protocols, reassemble per-channel buffers:
python -m lumascope.cli reassemble --frames caps.jsonl --triplets

# 4. a guided sweep produces a *labeled* corpus and decodes it in one shot:
python -m lumascope.cli sweep --led-count <N> --driver manual --attach <VendorService> \
    --out corpus.json --decode --emit-cpp Device.cpp

# 5. (optional) verify the decoded spec by replaying it — vendor app CLOSED first:
python -m lumascope.cli replay --spec <decoded>.json --device-path "<path>"          # dry-run
python -m lumascope.cli replay --spec <decoded>.json --device-path "<path>" --write --yes
```

## Architecture

```
                 orchestrate.py  (drive → capture window → pair → Corpus)
                 ┌──────────────┬──────────────┬──────────────┐
            STIMULUS         CAPTURE         DECODE          EMIT
       matrix / manual /  frida_backend  chunked → diff   spec_json
       openrgb + sync     usbpcap_backend  stride/checksum  openrgb_cpp
                          → CaptureFrame   encoding/spec    (JSON + C++)
```

- **`model.py`** — the shared vocabulary every module speaks: `CaptureFrame`, `SweepStep`,
  `Corpus`, `ProtocolSpec`.
- **`codec.py`** — the single reference encoder (`spec + colors → wire bytes`), shared by the
  synthetic generator, the decoder's validation round-trip, and mirrored by the C++ emitter.
- **`capture/`** — `frida_backend` spawns/attaches a process and injects `agent.js` to hook
  `WriteFile` / `DeviceIoControl` / `HidD_*` / `WinUsb_*` (with handle→VID:PID correlation and a
  binary channel); `usbpcap_backend` parses `tshark -T json` from a USBPcap bus capture. Both emit
  a common `CaptureFrame`. `serialize` defines the on-disk frame/corpus JSON.
- **`decode/`** — passes over a labeled `Corpus`: `chunked` reassembles streamed protocols first;
  `diff` localizes fields + recovers scaling; `stride` recovers layout/stride/channel-order;
  `checksum` recovers sum/xor/CRC; `encoding` finds brightness; `spec` assembles and validates by
  re-encoding every frame byte-for-byte.
- **`stimulus/`** — `matrix` generates the one-thing-at-a-time sweep; `manual` (operator-guided)
  and `openrgb` drivers apply each step; `sync` windows the capture.
- **`emit/`** — `spec_json` (canonical JSON) and `openrgb_cpp` (a drop-in `RGBController` skeleton).

## Layout

```
lumascope/
  cli.py            doctor|selftest|demo|capture|sweep|decode|reassemble|emit|replay
  model.py          CaptureFrame, SweepStep, Corpus, ProtocolSpec dataclasses
  codec.py          reference encoder: spec + colors -> wire bytes
  synthetic.py      generate labeled captures from a known spec (no hardware)
  examples.py       built-in ground-truth specs for selftest/tests
  doctor.py         environment check
  orchestrate.py    drive -> capture -> pair -> Corpus
  replay.py         safety-gated device-write verification
  capture/          base, agent.js, frida_backend, usbpcap_backend, serialize
  stimulus/         base, manual, openrgb_driver, matrix, sync
  decode/           diff, stride, checksum, encoding, spec, chunked
  emit/             spec_json, openrgb_cpp
tests/              decode/emit/orchestrate/chunked/replay/usbpcap + frida capture (skips off-Windows)
docs/               asus-aura-pid19af-protocol.md  (worked example)
```

## Development

```bash
pip install -e .[dev]
pytest -q                 # full suite; capture tests skip without Windows + frida
```

The core is intentionally pure-stdlib so the engine and most tests run on any Python 3.10+ with no
native deps. The Frida capture tests require Windows + `frida`; they `skip` cleanly elsewhere (so
CI on Linux exercises decode/emit/chunked/orchestrate/replay/parser). CI runs `pytest` on each
push (`.github/workflows/tests.yml`).

## Safety

Capture-only / passive by default — the tool never issues device writes during research, and
**never auto-probes SMBus addresses** (blind SMBus access has bricked real boards: Gigabyte Z390,
MSI Mystic Light). The `replay` command is the only writer: it is **dry-run by default**, a real
write requires explicit `--write --yes`, and it must be run with the vendor app/service **closed**
(they hold an exclusive device handle, and concurrent access is the brick risk).

## License

MIT — see [LICENSE](LICENSE). Note that emitted C++ skeletons are modelled on OpenRGB's
`RGBController` shape; if you ship them inside a GPL project (e.g. LumaCore), that project's license
governs the integrated result.
