# LumaScope

Automated RGB protocol reverse-engineering harness for the **LumaCore** project.

Adding a vendor RGB device to LumaCore means knowing its wire protocol. Today that is done
by hand: run the vendor app, capture USB traffic in Wireshark, change one setting, then
eyeball-diff 64-byte hex dumps in a spreadsheet. Every prior project (OpenRGB, OpenRazer,
SignalRGB) documents that exact manual loop — and nobody has automated it.

LumaScope closes the loop:

```
  drive the vendor app  →  capture device traffic  →  auto-diff into a protocol spec
       (stimulus)              (capture)                     (decode)
                                                                 │
                                                                 ▼
                                                  protocol-spec JSON  +  OpenRGB-style
                                                                         C++ skeleton
```

The harness is disposable research tooling; its **output** — a machine-readable protocol
spec and a C++ `RGBController` skeleton — is what feeds the LumaCore product.

## Status

| Phase | Component | State |
|------:|-----------|-------|
| 0 | Scaffold + `doctor` | done (verified here) |
| 1 | Decode engine + synthetic harness | done (verified here) |
| 5 | Emit (JSON + C++) | done (verified here) |
| 2 | Frida capture backend | done (verified here, no hardware) |
| 4 | Stimulus + orchestrator (manual/OpenRGB) | done (verified here; live needs a device) |
| 3 | USBPcap/tshark fallback | parser done (verified here); live needs USBPcap+admin |
| 6 | SMBus backend (optional) | deferred |

## Layout

```
lumascope/
  cli.py            lumascope doctor|sweep|capture|decode|emit|replay
  model.py          CaptureFrame, ProtocolSpec, SweepStep dataclasses
  codec.py          reference encoder: spec + colors -> wire bytes (shared by synth/validate)
  synthetic.py      generate labeled captures from a known spec (no hardware needed)
  doctor.py         environment check
  capture/          frida_backend, usbpcap_backend, smbus_backend (+ agent.js)
  stimulus/         openrgb/signalrgb/chroma/uia/image drivers, matrix, sync
  decode/           diff, stride, checksum, encoding, spec
  emit/             spec_json, openrgb_cpp
tests/              synthetic round-trip, parser fixtures, emitter snapshots
```

## Quick start (decode engine — no hardware, no native deps)

```bash
cd lumascope
python -m lumascope.cli doctor        # what's installed on this machine
pip install -e .[dev] && pytest       # prove the decoder recovers known specs
```

## Safety

Capture-only / passive by default. The tool never issues device writes during research,
and **never auto-probes SMBus addresses** — blind SMBus access has bricked real boards
(Gigabyte Z390, MSI Mystic Light). Any replay step used to *verify* a decoded spec is
explicit, opt-in, and sequenced only after the vendor app is closed (vendor services hold
exclusive device handles).
