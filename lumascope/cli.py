"""LumaScope command-line interface.

Commands are grouped by what you are trying to do rather than by internal module, and
every command that writes a file prints the command you would run next (on stderr, so
piping stdout stays clean). Anything the user can get wrong raises
:class:`~lumascope.errors.LumaScopeError`, which :func:`main` renders as an explanation
plus a suggested command -- never a traceback.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import sys

from . import __version__
from .errors import LumaScopeError, MissingDependency

# --------------------------------------------------------------------------- #
# Help text
# --------------------------------------------------------------------------- #
COMMAND_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("START HERE", [
        ("doctor", "check what this machine can do, and what to install"),
        ("devices", "list connected RGB devices and vendor lighting processes"),
        ("guide", "the whole reverse-engineering workflow, start to finish"),
    ]),
    ("TRY IT (no hardware needed)", [
        ("demo", "run the full pipeline on a built-in example protocol"),
        ("selftest", "prove the decoder recovers known protocols"),
        ("show", "read captured packets as annotated, colour-coded hex"),
    ]),
    ("READ A CAPTURE", [
        ("analyze", "one-shot report: command classes, chunking, timing"),
        ("inspect", "group packets by command, or diff two captures"),
        ("reassemble", "rebuild streamed chunks into per-channel LED buffers"),
        ("cadence", "measure an effect's speed from packet timing"),
    ]),
    ("RECORD FROM HARDWARE (Windows)", [
        ("capture", "record what the vendor app sends to the device"),
        ("sweep", "drive a guided sweep and capture a labeled corpus"),
    ]),
    ("PRODUCE OUTPUT", [
        ("decode", "turn a labeled corpus into a protocol spec"),
        ("emit", "render a spec as JSON or an OpenRGB C++ skeleton"),
        ("replay", "verify a spec by replaying it (dry-run by default)"),
    ]),
]

ALL_COMMANDS = [name for _group, items in COMMAND_GROUPS for name, _desc in items]


def help_text() -> str:
    lines = [
        "LumaScope - automated RGB protocol reverse engineering.",
        "",
        "Usage:  lumascope <command> [options]",
        "",
    ]
    width = max(len(n) for n in ALL_COMMANDS)
    for group, items in COMMAND_GROUPS:
        lines.append(group)
        for name, desc in items:
            lines.append(f"  {name.ljust(width)}  {desc}")
        lines.append("")
    lines += [
        "Run `lumascope <command> --help` for that command's options,",
        "or `lumascope guide` for the end-to-end workflow.",
    ]
    return "\n".join(lines)


def start_here_text() -> str:
    return """LumaScope - automated RGB protocol reverse engineering.

New here? Run these three, in order:

  1.  lumascope doctor
      What this machine can already do, and what to install for the rest.

  2.  lumascope demo gamma
      Watch a whole protocol get reverse-engineered end to end. No hardware.

  3.  lumascope show --frames samples/aura-red.frames.jsonl
      Read real captured bytes from an ASUS motherboard, annotated so every
      byte says what it is.

Then `lumascope guide` for the hardware workflow, or `lumascope --help` for
every command."""


GUIDE = r"""LumaScope: reversing a device, start to finish
=============================================

The goal is a protocol spec: which bytes carry colour, in what order, with what
checksum. You get there by changing ONE thing at a time and watching which bytes move.


STEP 0  --  Can this machine do it?

    lumascope doctor

  Capture needs either Frida (hooks the vendor app from inside) or USBPcap +
  Wireshark (sniffs the USB bus). Doctor tells you which you have and how to get
  the other. USBPcap capture needs an elevated terminal.


STEP 1  --  What am I targeting?

    lumascope devices

  Lists connected devices with their VID:PID, ranked so the lighting controller
  comes first, plus any vendor lighting process that is currently running. Note
  the VID:PID -- every later command takes it as a filter.


STEP 2  --  Record the vendor app talking to the device

  Start the vendor app (Armoury Crate, iCUE, Synapse...). Then either hook the
  process directly:

    lumascope capture --attach LightingService.exe --duration 20 \
        --out red.frames.jsonl

  ...or sniff the bus, which is what you need when the colour buffer is passed
  by reference through a kernel driver and never appears in-process:

    lumascope capture --backend usbpcap --vid 0x0b05 --pid 0x19af \
        --duration 20 --out red.frames.jsonl

  While the capture window is open, set a colour you can describe -- all red.


STEP 3  --  Look at what you caught

    lumascope show --frames red.frames.jsonl
    lumascope analyze --frames red.frames.jsonl

  `show` prints annotated hex: each byte tagged with what it is, colour data
  rendered in its actual colour. `analyze` reports the command classes, the
  chunk framing, and the effect timing in one pass.


STEP 4  --  Change one thing, diff it

  Capture again with a single change -- all green instead of all red:

    lumascope capture ... --out green.frames.jsonl
    lumascope inspect --frames red.frames.jsonl --diff green.frames.jsonl

  The changed byte columns are marked with ^^ under the hex. That is the whole
  trick, done rigorously: one variable, one diff.


STEP 5  --  Produce a spec

  A spec needs LABELED captures -- packets paired with the state that caused
  them. Captures you take by hand cannot be decoded, however many you collect:
  the decoder needs to see individual LEDs change, which is what `sweep` sets
  up. It walks a matrix of states, prompts you to set each one in the vendor
  GUI, and records the traffic per step.

    lumascope sweep --led-count 120 --driver manual \
        --attach LightingService.exe --out aura.corpus.json \
        --decode --emit-cpp AuraController.cpp

  Manual sweeps default to the 'quick' profile: ~46 steps whatever the LED
  count, versus 535 for a 120-LED board on 'full'. Quick probes fewer LEDs and
  still recovers layout, stride, channel order, scaling and checksum. Use
  --profile full when a driver applies the states for you and steps are cheap.

  The corpus is saved after every step, so Ctrl-C (or `q` at the prompt) keeps
  everything captured so far. Re-running resumes nothing -- but you can decode
  a partial corpus and see how far it gets.

  The decoder validates itself by re-encoding every captured frame byte for
  byte. If validation passes, the spec is right.

    lumascope show --spec aura.spec.json

  ...renders the decoded protocol as a packet with every byte labelled, which
  is the fastest way to sanity-check what the decoder concluded.


STEP 6  --  Verify on the hardware

  CLOSE the vendor app first -- it holds an exclusive handle, and concurrent
  access is the real brick risk.

    lumascope replay --spec aura.spec.json --device-path "<path from devices>"
    lumascope replay --spec aura.spec.json --device-path "<path>" --write --yes

  Without --write it is a dry run that only prints the packets it would send.


FILES
  <name>.frames.jsonl   raw packets            written by `capture`
  <name>.corpus.json    packets + what caused them   written by `sweep`
  <name>.spec.json      the decoded protocol   written by `decode` / `emit`

SAFETY
  LumaScope never writes to a device except through `replay`, never probes SMBus,
  and defaults to dry-run. Blind SMBus probing has bricked real motherboards."""


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
def _note(message: str) -> None:
    """Write an aside to stderr, after flushing stdout.

    Without the flush, block-buffered stdout arrives after unbuffered stderr whenever
    output is piped, and the commentary appears above the thing it comments on.
    """
    sys.stdout.flush()
    print(message, file=sys.stderr)


def _next(*commands: str) -> None:
    """Suggest what to run next. Goes to stderr so piped stdout stays machine-readable."""
    if os.environ.get("LUMASCOPE_NO_HINTS"):
        return
    _note("\nNext:")
    for c in commands:
        print(f"  {c}", file=sys.stderr)


# Above this many manual steps, ask before committing the operator to the session.
_CONFIRM_ABOVE_STEPS = 80


def _frida_error(exc: Exception) -> LumaScopeError:
    """Tell "frida is missing" apart from "frida is installed but unusable".

    They need different fixes, and the second is easy to hit: frida 17 installs happily on
    Python 3.10 and then fails to import, so "it is not installed" would be both wrong and
    unactionable.
    """
    import importlib.util

    why = ("Frida hooks the vendor process to record device writes.\n"
           "The USBPcap backend needs no Python package, only Wireshark + USBPcap.")
    if importlib.util.find_spec("frida") is None:
        return MissingDependency("frida", "frida", why=why)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    return LumaScopeError(
        f"frida is installed but cannot be imported ({exc})",
        detail=f"Usually a version mismatch -- frida 17 requires Python 3.11+, and you are\n"
               f"on Python {version}. Either install the older line, or sniff the bus instead.",
        commands=['pip install "frida<17"',
                  "lumascope capture --backend usbpcap --out capture.frames.jsonl"],
    )


def _use_color(args) -> bool:
    from .view import resolve_color
    return resolve_color(getattr(args, "color", "auto"))


def _add_render_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                   help="colourise output (default: auto -- on for a terminal)")
    p.add_argument("--width", type=int, default=16, metavar="N",
                   help="bytes per hex-dump row (default: 16)")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _cmd_guide(_args) -> int:
    print(GUIDE)
    return 0


def _cmd_doctor(args) -> int:
    from . import doctor
    print(doctor.report(verbose=args.verbose))
    return 0


def _cmd_devices(args) -> int:
    from . import devices
    print(devices.report(all_devices=args.all))
    return 0


def _spec_mismatches(truth, got) -> list[str]:
    """Structural diff between a ground-truth spec and a recovered one (key fields)."""
    out: list[str] = []

    def cmp(label, a, b):
        if a != b:
            out.append(f"{label}: expected {a!r}, got {b!r}")

    cmp("packet_len", truth.packet_len, got.packet_len)
    cmp("transport", truth.transport, got.transport)
    cmp("report_id", truth.report_id, got.report_id)
    cmp("leds.count", truth.leds.count, got.leds.count)
    cmp("leds.layout", truth.leds.layout, got.leds.layout)
    cmp("leds.base_offset", truth.leds.base_offset, got.leds.base_offset)
    cmp("leds.channel_order", truth.leds.channel_order, got.leds.channel_order)
    cmp("leds.scaling.type", truth.leds.scaling.type, got.leds.scaling.type)
    if truth.leds.layout == "interleaved":
        cmp("leds.stride", truth.leds.stride, got.leds.stride)
    cmp("brightness.present", truth.brightness.present, got.brightness.present)
    if truth.brightness.present:
        cmp("brightness.offset", truth.brightness.offset, got.brightness.offset)
    cmp("checksum.kind", truth.checksum.kind, got.checksum.kind)
    cmp("checksum.offset", truth.checksum.offset, got.checksum.offset)
    cmp("checksum.range", truth.checksum.range, got.checksum.range)
    return out


def _cmd_selftest(_args) -> int:
    from . import examples, synthetic
    from .decode import decode

    print("LumaScope decode self-test")
    print("=" * 26)
    all_ok = True
    for factory in examples.ALL:
        truth = factory()
        corpus = synthetic.generate_corpus(truth)
        result = decode(corpus, name=truth.name)
        mism = _spec_mismatches(truth, result.spec)
        ok = result.validation.ok and not mism
        all_ok = all_ok and ok
        flag = "PASS" if ok else "FAIL"
        print(f"\n  [{flag}] {truth.name}")
        print(f"        {result.validation.summary()}  ({len(corpus)} frames)")
        print(f"        layout={result.spec.leds.layout} order={result.spec.leds.channel_order} "
              f"stride={result.spec.leds.stride} scaling={result.spec.leds.scaling.type} "
              f"checksum={result.spec.checksum.kind}")
        for m in mism:
            print(f"        - structural mismatch: {m}")
        for label, got, exp in result.validation.failures[:3]:
            print(f"        - frame mismatch [{label}] got {got} != {exp}")
    print("\n" + ("All specs recovered." if all_ok else "Some specs FAILED."))
    if all_ok:
        _next("lumascope demo gamma      # watch one run end to end",
              "lumascope devices         # find a real device to reverse")
    return 0 if all_ok else 1


def _resolve_example(name: str):
    from . import examples
    if name not in examples.BY_NAME:
        raise LumaScopeError(
            f"unknown example '{name}'",
            detail="Built-in examples are synthetic protocols with known answers,\n"
                   "used to prove the decoder works without any hardware.",
            commands=[f"lumascope demo {n}" for n in examples.BY_NAME],
        )
    return examples.BY_NAME[name]()


def _cmd_decode(args) -> int:
    from .capture.serialize import load_corpus
    from .decode import decode
    from .emit import render_cpp, spec_to_json

    corpus = load_corpus(args.corpus)
    if not corpus.frames:
        raise LumaScopeError(
            f"{args.corpus} contains no labeled frames",
            detail="A corpus needs packets paired with the state that produced them.\n"
                   "If `sweep` captured nothing, it was probably attached to the wrong\n"
                   "process -- the writer is often a background service, not the GUI.",
            commands=["lumascope devices"],
        )
    result = decode(corpus, name=args.name)
    print(result.validation.summary(), file=sys.stderr)

    spec_json = spec_to_json(result.spec)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(spec_json)
        print(f"wrote spec -> {args.out}", file=sys.stderr)
    else:
        print(spec_json)

    if args.emit_cpp:
        cpp = render_cpp(result.spec)
        with open(args.emit_cpp, "w", encoding="utf-8") as fh:
            fh.write(cpp)
        print(f"wrote C++  -> {args.emit_cpp}", file=sys.stderr)

    if args.out:
        _next(f"lumascope emit --spec {args.out} --lang cpp --out Controller.cpp",
              f"lumascope replay --spec {args.out} --device-path \"<path>\"   # dry run")
    return 0 if result.validation.ok else 1


def _load_example_or_spec(args):
    from .emit import spec_json as sj
    if getattr(args, "example", None):
        return _resolve_example(args.example)
    if getattr(args, "spec", None):
        return sj.load_spec(args.spec)
    raise LumaScopeError(
        "no protocol given",
        detail="Point this at a decoded spec, or at a built-in example to see the shape.",
        commands=["lumascope emit --example gamma", "lumascope emit --spec my.spec.json"],
    )


def _cmd_emit(args) -> int:
    from .emit import render_cpp, spec_to_json
    spec = _load_example_or_spec(args)
    text = render_cpp(spec) if args.lang == "cpp" else spec_to_json(spec)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.lang} -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def _cmd_demo(args) -> int:
    """Full pipeline on a built-in example: synth -> decode -> validate -> C++."""
    from . import synthetic
    from .decode import decode
    from .emit import render_cpp

    truth = _resolve_example(args.example)
    corpus = synthetic.generate_corpus(truth)
    result = decode(corpus, name=truth.name)
    print(f"# decoded {truth.name} from {len(corpus)} synthetic frames", file=sys.stderr)
    print(f"# {result.validation.summary()}", file=sys.stderr)
    print(render_cpp(result.spec))
    if result.validation.ok:
        _next("lumascope show --frames samples/aura-red.frames.jsonl   # real captured bytes",
              "lumascope devices                                      # reverse your own device")
    return 0 if result.validation.ok else 1


def _cmd_capture(args) -> int:
    from .capture.serialize import frames_to_jsonl

    duration = args.duration
    if args.backend == "usbpcap":
        from .capture.usbpcap_backend import UsbpcapBackend
        backend = UsbpcapBackend(interface=args.interface, address=args.address, pcap=args.pcap)
        if args.pcap:
            duration = 0.0  # offline: no live window to wait on
    else:
        from .capture.frida_backend import FridaBackend
        if not args.spawn and not args.attach:
            raise LumaScopeError(
                "the frida backend needs a process to hook",
                detail="Frida records writes from inside the vendor app. Tell it which one --\n"
                       "usually a background service rather than the GUI you clicked.",
                commands=["lumascope devices        # lists vendor processes running now",
                          "lumascope capture --attach LightingService.exe --out capture.frames.jsonl",
                          "lumascope capture --backend usbpcap --out capture.frames.jsonl"],
            )
        backend = FridaBackend(spawn=args.spawn, attach=args.attach, vid=args.vid, pid=args.pid)

    try:
        frames = backend.capture(duration=duration)
    except ImportError as exc:
        raise _frida_error(exc) from None
    except RuntimeError as exc:
        raise LumaScopeError(f"capture failed: {exc}") from None

    for level, msg in backend.logs:
        if level in ("error", "ready", "warn", "detached"):
            print(f"# agent {level}: {msg}", file=sys.stderr)
    print(f"# captured {len(frames)} frame(s)", file=sys.stderr)

    if not frames:
        print("# nothing captured. The device may be driven by another process, or the\n"
              "# colour buffer may never cross the hook (try --backend usbpcap).",
              file=sys.stderr)

    if args.out:
        frames_to_jsonl(frames, args.out)
        print(f"wrote frames -> {args.out}", file=sys.stderr)
        if frames:
            _next(f"lumascope show --frames {args.out}      # read the bytes, annotated",
                  f"lumascope analyze --frames {args.out}   # structure, chunking, timing")
    else:
        for f in frames:
            tag = f"{f.api}/{f.transfer}"
            ids = f"vid={f.vid:#06x} pid={f.pid:#06x}" if f.vid and f.pid else "vid/pid=?"
            print(f"{tag:28} {ids}  {f.hex}")
    return 0


def _cmd_sweep(args) -> int:
    from . import orchestrate
    from .capture.frida_backend import FridaBackend
    from .capture.serialize import save_corpus
    from .stimulus import matrix

    manual = args.driver != "openrgb"
    # A manual step is a human in a GUI (~20s); an API step is milliseconds. Defaulting
    # manual sweeps to `full` would mean over an hour of clicking on a 120-LED board.
    profile = args.profile or (matrix.QUICK if manual else matrix.FULL)
    seconds = 20.0 if manual else 0.6
    summary = matrix.describe(args.led_count, profile, seconds_per_step=seconds)

    if args.driver == "openrgb":
        from .stimulus.openrgb_driver import OpenRGBDriver
        driver = OpenRGBDriver(device_index=args.device_index)
    else:
        from .stimulus.manual import ManualDriver
        driver = ManualDriver()

    steps = matrix.generate(args.led_count, profile=profile)
    print(f"# sweep profile '{profile}': {summary}", file=sys.stderr)
    if manual and len(steps) > _CONFIRM_ABOVE_STEPS and not args.yes:
        raise LumaScopeError(
            f"this is a {summary} manual sweep",
            detail="Every step needs you to set a state in the vendor app by hand.\n"
                   "The 'quick' profile probes fewer LEDs and still recovers layout,\n"
                   "stride, channel order, scaling and checksum.",
            commands=[
                f"lumascope sweep --profile quick --led-count {args.led_count} "
                f"--out {args.out} ...",
                "...or add --yes to run the long one anyway",
            ],
        )

    backend = FridaBackend(spawn=args.spawn, attach=args.attach, vid=args.vid, pid=args.pid)

    def checkpoint(partial) -> None:
        save_corpus(partial, args.out)

    try:
        corpus, _raw = orchestrate.run_sweep(
            backend, driver, args.led_count, steps=steps,
            device_name=args.name, vid=args.vid, pid=args.pid,
            chunked=(False if args.no_reassemble else "auto"), channel=args.channel,
            log=lambda m: print(f"# {m}", file=sys.stderr),
            checkpoint=checkpoint,
        )
    except ImportError as exc:
        raise _frida_error(exc) from None

    for level, msg in backend.logs:
        if level in ("error", "warn", "detached"):
            print(f"# agent {level}: {msg}", file=sys.stderr)

    save_corpus(corpus, args.out)
    print(f"# {len(corpus.frames)} labeled frame(s) -> {args.out}", file=sys.stderr)
    if not corpus.frames:
        raise LumaScopeError(
            "the sweep captured no frames",
            detail="Nothing was recorded while the states were applied. Usually the hook is\n"
                   "on the wrong process: vendor GUIs often hand lighting to a service.",
            commands=["lumascope devices", "lumascope capture --backend usbpcap --out test.frames.jsonl"],
        )

    if args.decode:
        from .decode import decode
        from .emit import render_cpp, spec_to_json
        result = decode(corpus, name=args.name)
        print(f"# {result.validation.summary()}", file=sys.stderr)
        if args.spec_out:
            with open(args.spec_out, "w", encoding="utf-8") as fh:
                fh.write(spec_to_json(result.spec))
            print(f"# wrote spec -> {args.spec_out}", file=sys.stderr)
        if args.emit_cpp:
            with open(args.emit_cpp, "w", encoding="utf-8") as fh:
                fh.write(render_cpp(result.spec))
            print(f"# wrote C++  -> {args.emit_cpp}", file=sys.stderr)
        return 0 if result.validation.ok else 1
    _next(f"lumascope decode --corpus {args.out} --out device.spec.json")
    return 0


def _cmd_replay(args) -> int:
    from . import replay

    spec = _load_example_or_spec(args)
    steps = replay.build_replay_sequence(spec)

    device_path = args.device_path
    if not device_path and args.corpus:
        from .capture.serialize import load_corpus
        corpus = load_corpus(args.corpus)
        device_path = next((lf.frame.path for lf in corpus.frames if lf.frame.path), None)

    if args.write:
        if not args.yes:
            raise LumaScopeError(
                "refusing to write without --yes",
                detail="Close the vendor app or service FIRST. It holds an exclusive handle on\n"
                       "the device, and concurrent access is the real brick risk.",
                commands=[f"lumascope replay --spec {args.spec or '<spec>'} "
                          f"--device-path \"{device_path or '<path>'}\" --write --yes"],
            )
        if not args.force:
            holders = replay.vendor_apps_running()
            if holders:
                raise LumaScopeError(
                    f"a vendor lighting app is still running: {', '.join(holders)}",
                    detail="It holds the device open, so the write would either fail or race it.\n"
                           "Close it (including its background service) and try again.\n"
                           "Use --force only if you are certain it does not own this device.",
                )

    try:
        replay.write_sequence(
            spec, steps, device_path=device_path,
            confirm=args.yes, dry_run=not args.write,
            out=lambda m: print(m),
        )
    except (OSError, RuntimeError) as exc:
        raise LumaScopeError(f"replay failed: {exc}") from None
    if not args.write:
        _next("Add --write --yes to send these for real (vendor app CLOSED first).")
    return 0


def _cmd_reassemble(args) -> int:
    from .annotate import describe_framing
    from .capture.serialize import load_frames
    from .decode.chunked import reassemble_capture
    from . import view

    color = _use_color(args)
    frames = load_frames(args.frames)
    framing, channels = reassemble_capture(frames)
    if framing is None:
        raise LumaScopeError(
            "no chunked command class detected in this capture",
            detail="Reassembly is for protocols that stream one state across many packets.\n"
                   "If this device sends one packet per state, there is nothing to reassemble.",
            commands=[f"lumascope inspect --frames {args.frames}",
                      f"lumascope show --frames {args.frames}"],
        )
    print(describe_framing(framing), file=sys.stderr)
    print(file=sys.stderr)
    for ch in sorted(channels):
        buf = channels[ch]
        print(f"channel {ch}: {len(buf)} bytes (~{len(buf)//3} LEDs)")
        bar = view.color_bar(buf, color=color)
        if bar:
            print(f"  {bar}")
        print(view.led_table(buf, color=color))
        if args.triplets:
            shown = " ".join(buf[i:i + 3].hex() for i in range(0, min(len(buf), 30), 3))
            print(f"  raw: {shown}{' ...' if len(buf) > 30 else ''}")
        print()
    return 0


def _cmd_inspect(args) -> int:
    from .capture.serialize import load_frames
    from .decode import inspect as ins

    color = _use_color(args)
    frames = load_frames(args.frames)
    direction = None if args.direction == "any" else args.direction
    if args.diff:
        other = load_frames(args.diff)
        diffs = ins.diff_captures(
            frames, other, sig_len=args.sig_len, direction=direction,
            vid=args.vid, pid=args.pid,
        )
        print(ins.format_diff(diffs, args.frames, args.diff, color=color, width=args.width))
        return 0
    groups = ins.group_frames(
        frames, sig_len=args.sig_len, direction=direction, vid=args.vid, pid=args.pid,
    )
    if not groups:
        raise LumaScopeError(
            "no packets matched the filter",
            detail=f"Looked for direction={args.direction}"
                   + (f", vid={args.vid:#06x}" if args.vid else "")
                   + (f", pid={args.pid:#06x}" if args.pid else "")
                   + ".\nDrop the filters to see everything the capture contains.",
            commands=[f"lumascope inspect --frames {args.frames} --direction any",
                      f"lumascope show --frames {args.frames}"],
        )
    print(ins.format_groups(groups, color=color, width=args.width))
    _next(f"lumascope show --frames {args.frames}      # full annotated dump",
          f"lumascope inspect --frames {args.frames} --diff <other>.frames.jsonl")
    return 0


def _cmd_cadence(args) -> int:
    from .capture.serialize import load_frames
    from .decode.cadence import analyze_cadence, format_cadence

    for path in args.frames:
        frames = load_frames(path)
        c = analyze_cadence(frames, channel=args.channel, vid=args.vid, pid=args.pid)
        if c is None:
            print(f"# {path}: no outbound streamed frames matched", file=sys.stderr)
            continue
        print(format_cadence(c, name=path))
    return 0


def _cmd_analyze(args) -> int:
    from .analyze import analyze_frames, format_analysis
    from .capture.serialize import load_frames

    color = _use_color(args)
    frames = load_frames(args.frames)
    report = analyze_frames(
        frames,
        sig_len=args.sig_len,
        direction=(None if args.direction == "any" else args.direction),
        vid=args.vid,
        pid=args.pid,
        channel=args.channel,
    )
    # A Markdown file should never contain terminal escape codes.
    text = format_analysis(report, name=args.frames, color=color and not args.out,
                           width=args.width)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote analysis -> {args.out}", file=sys.stderr)
    else:
        print(text)
    _next(f"lumascope show --frames {args.frames}     # byte-level view",
          "lumascope sweep --help                    # capture a labeled corpus to decode")
    return 0


def _show_spec(spec, *, color: bool, width: int, table: bool) -> int:
    """Render a decoded spec as the packet it produces, with every field named."""
    from . import codec, view
    from .annotate import fields_from_spec

    n = spec.leds.count
    # A recognisable pattern: red, green, blue, then white, so each wire channel is
    # visibly distinct in the dump and the channel order reads straight off the tags.
    palette = [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255)]
    colors = [palette[i % len(palette)] for i in range(n)]
    data = codec.encode_frame(spec, colors, brightness=255)
    fmap = fields_from_spec(spec, data)

    header = (f"{spec.name}  --  {spec.transport}, {spec.packet_len} bytes, "
              f"{n} LED(s) {spec.leds.layout} {spec.leds.channel_order}")
    print(view.render_packet(data, fields=fmap, title=header, color=color,
                             width=width, table=table))
    print()
    print(f"  shown encoding LED 0=red, 1=green, 2=blue, 3=white, repeating")
    _next("lumascope emit --spec <file> --lang cpp    # the C++ controller skeleton",
          "lumascope replay --spec <file>             # dry-run the packets it would send")
    return 0


def _cmd_show(args) -> int:
    """Read packets as annotated hex -- the command that replaces squinting at dumps."""
    from .annotate import fields_from_framing, fields_from_spec
    from .capture.serialize import load_corpus, load_frames
    from .decode.chunked import dominant_command_class, infer_framing, reassemble_capture
    from . import view

    color = _use_color(args)
    if not args.frames and not args.corpus and not args.spec and not args.example:
        raise LumaScopeError(
            "nothing to show",
            detail="Point `show` at a capture, or at a protocol spec to see its layout.",
            commands=["lumascope show --frames samples/aura-red.frames.jsonl",
                      "lumascope show --example gamma",
                      "lumascope show --corpus <your>.corpus.json"],
        )

    spec = None
    if args.example:
        spec = _resolve_example(args.example)
    elif args.spec:
        from .emit import spec_json as sj
        spec = sj.load_spec(args.spec)

    # A spec on its own is a layout, not a capture: render one representative packet so
    # you can see what the decoder concluded without hunting through JSON.
    if spec is not None and not args.frames and not args.corpus:
        return _show_spec(spec, color=color, width=args.width, table=not args.no_table)

    if args.corpus:
        corpus = load_corpus(args.corpus)
        entries = [(lf.step.describe(), lf.frame) for lf in corpus.frames]
    else:
        frames = load_frames(args.frames)
        entries = [(f"frame {i}", f) for i, f in enumerate(frames)]

    if not entries:
        raise LumaScopeError(f"{args.frames or args.corpus} contains no packets")

    all_frames = [f for _label, f in entries]

    if args.leds:
        framing, channels = reassemble_capture(all_frames)
        if framing is None:
            raise LumaScopeError(
                "this capture is not a chunked/streamed protocol",
                detail="--leds rebuilds a streamed colour buffer. Show the packets instead.",
                commands=[f"lumascope show --frames {args.frames}"],
            )
        for ch in sorted(channels):
            buf = channels[ch]
            print(f"channel {ch}  --  {len(buf)} bytes, {len(buf)//3} LED(s)")
            bar = view.color_bar(buf, color=color)
            if bar:
                print(f"  {bar}")
            print(view.led_table(buf, color=color))
            print()
        return 0

    framing = None if spec else infer_framing(dominant_command_class(all_frames))

    if args.index is not None:
        if not 0 <= args.index < len(entries):
            raise LumaScopeError(
                f"--index {args.index} is out of range (capture has {len(entries)} packets)",
                commands=[f"lumascope show --frames {args.frames} --index 0"],
            )
        selected = [entries[args.index]]
    elif args.all:
        selected = entries
    else:
        selected = entries[:args.limit]

    for label, frame in selected:
        if spec is not None:
            fmap = fields_from_spec(spec, frame.data)
        elif framing is not None and framing.matches(frame.data):
            fmap = fields_from_framing(framing, frame.data)
        else:
            fmap = None
        meta = []
        if frame.vid is not None and frame.pid is not None:
            meta.append(f"{frame.vid:04x}:{frame.pid:04x}")
        if frame.api:
            meta.append(frame.api)
        meta.append(f"{len(frame.data)} bytes")
        title = f"{label}  [{'  '.join(meta)}]"
        print(view.render_packet(frame.data, fields=fmap, title=title, color=color,
                                 width=args.width, table=not args.no_table))
        print()

    if not args.all and len(selected) < len(entries):
        _note(f"# showing {len(selected)} of {len(entries)} packets "
              f"(--all, or --limit N, or --index N)")
    if framing is not None and not args.leds:
        _next(f"lumascope show --frames {args.frames} --leds   # the assembled colour buffer",
              f"lumascope analyze --frames {args.frames}       # structure + timing report")
    return 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class _TopParser(argparse.ArgumentParser):
    """Top-level parser with hand-written grouped help and did-you-mean errors."""

    def format_help(self) -> str:
        return help_text()

    def error(self, message: str):
        m = re.search(r"invalid choice: '([^']+)'", message)
        if m:
            bad = m.group(1)
            near = difflib.get_close_matches(bad, ALL_COMMANDS, n=1)
            err = LumaScopeError(
                f"unknown command '{bad}'",
                detail="Run `lumascope --help` for the full list.",
                commands=[f"lumascope {near[0]}"] if near else [],
            )
            print(err.render(), file=sys.stderr)
            raise SystemExit(2)
        print(f"lumascope: {message}\n", file=sys.stderr)
        print("Run `lumascope --help` for usage.", file=sys.stderr)
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    p = _TopParser(prog="lumascope", add_help=True)
    p.add_argument("--version", action="version", version=f"lumascope {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    def add(name: str, **kw) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=argparse.SUPPRESS, **kw)

    add("guide", description="The end-to-end reverse-engineering workflow.").set_defaults(
        func=_cmd_guide)

    p_doc = add("doctor", description="Report what LumaScope can do on this machine.")
    p_doc.add_argument("--verbose", action="store_true", help="show every check, including passing ones")
    p_doc.set_defaults(func=_cmd_doctor)

    p_dev = add("devices", description="List connected devices and vendor lighting processes.")
    p_dev.add_argument("--all", action="store_true", help="show every HID device, not just likely controllers")
    p_dev.set_defaults(func=_cmd_devices)

    add("selftest", description="Prove the decoder recovers known protocols.").set_defaults(
        func=_cmd_selftest)

    p_decode = add("decode", description="Decode a labeled capture corpus into a protocol spec.")
    p_decode.add_argument("--corpus", required=True, help="path to a .corpus.json file (from `sweep`)")
    p_decode.add_argument("--name", default=None, help="override device name")
    p_decode.add_argument("--out", default=None, help="write spec JSON here (else stdout)")
    p_decode.add_argument("--emit-cpp", default=None, dest="emit_cpp", help="also write a C++ skeleton here")
    p_decode.set_defaults(func=_cmd_decode)

    p_emit = add("emit", description="Render a protocol spec as JSON or a C++ skeleton.")
    p_emit.add_argument("--spec", default=None, help="path to a .spec.json file")
    p_emit.add_argument("--example", default=None, help="built-in example: interleaved|gamma|planar|nochecksum")
    p_emit.add_argument("--lang", choices=("cpp", "json"), default="cpp")
    p_emit.add_argument("--out", default=None, help="write here (else stdout)")
    p_emit.set_defaults(func=_cmd_emit)

    p_demo = add("demo", description="Run the full pipeline on a built-in example protocol.")
    p_demo.add_argument("example", nargs="?", default="gamma",
                        help="interleaved|gamma|planar|nochecksum (default: gamma)")
    p_demo.set_defaults(func=_cmd_demo)

    p_show = add("show", description="Read captured packets as annotated, colour-coded hex.")
    p_show.add_argument("--frames", default=None, help="a .frames.jsonl capture")
    p_show.add_argument("--corpus", default=None, help="a .corpus.json capture (shows step labels)")
    p_show.add_argument("--spec", default=None,
                        help="a decoded spec: shows its packet layout, or annotates a capture")
    p_show.add_argument("--example", default=None,
                        help="show a built-in example protocol's layout")
    p_show.add_argument("--index", type=int, default=None, metavar="N", help="show only packet N")
    p_show.add_argument("--limit", type=int, default=3, metavar="N", help="how many packets (default: 3)")
    p_show.add_argument("--all", action="store_true", help="show every packet")
    p_show.add_argument("--leds", action="store_true", help="show the reassembled LED buffers instead")
    p_show.add_argument("--no-table", action="store_true", dest="no_table",
                        help="hex only, without the decoded-field table")
    _add_render_flags(p_show)
    p_show.set_defaults(func=_cmd_show)

    p_capture = add("capture", description="Record what the vendor app sends to the device.")
    p_capture.add_argument("--backend", choices=("frida", "usbpcap"), default="frida",
                           help="frida (in-process hook, default) or usbpcap (USB bus sniff)")
    src = p_capture.add_mutually_exclusive_group()
    src.add_argument("--spawn", nargs="+", metavar="PROG",
                     help="[frida] program (and args) to launch under capture")
    src.add_argument("--attach", metavar="PID|NAME", help="[frida] attach to a running process")
    p_capture.add_argument("--vid", type=lambda s: int(s, 0), default=None,
                           help="filter to this USB vendor id (e.g. 0x0b05)")
    p_capture.add_argument("--pid", type=lambda s: int(s, 0), default=None,
                           help="filter to this USB product id (e.g. 0x19af)")
    p_capture.add_argument("--interface", default=r"\\.\USBPcap1", help="[usbpcap] USBPcap interface")
    p_capture.add_argument("--address", type=int, default=None, help="[usbpcap] device address filter")
    p_capture.add_argument("--pcap", default=None, help="[usbpcap] parse an existing .pcap offline")
    p_capture.add_argument("--duration", type=float, default=5.0, help="capture window seconds")
    p_capture.add_argument("--out", default=None, help="write frame JSONL here (else stdout)")
    p_capture.set_defaults(func=_cmd_capture)

    p_sweep = add("sweep", description="Drive a guided sweep and capture a labeled corpus.")
    p_sweep.add_argument("--led-count", type=int, required=True, dest="led_count",
                         help="how many LEDs the device exposes")
    p_sweep.add_argument("--driver", choices=("manual", "openrgb"), default="manual",
                         help="how to drive device state (default: manual/operator-guided)")
    p_sweep.add_argument("--profile", choices=("quick", "full"), default=None,
                         help="how much of the matrix to run (default: quick for manual, "
                              "full for openrgb)")
    p_sweep.add_argument("--yes", action="store_true",
                         help="skip the confirmation for a long manual sweep")
    src = p_sweep.add_mutually_exclusive_group(required=True)
    src.add_argument("--spawn", nargs="+", metavar="PROG", help="launch a program under capture")
    src.add_argument("--attach", metavar="PID|NAME", help="attach to a running process/service")
    p_sweep.add_argument("--vid", type=lambda s: int(s, 0), default=None, help="USB vendor id filter")
    p_sweep.add_argument("--pid", type=lambda s: int(s, 0), default=None, help="USB product id filter")
    p_sweep.add_argument("--name", default="unknown", help="device name for the corpus/spec")
    p_sweep.add_argument("--device-index", type=int, default=0, dest="device_index",
                         help="OpenRGB device index (openrgb driver)")
    p_sweep.add_argument("--channel", type=int, default=None,
                         help="chunked devices: which reassembled channel to decode (default: auto)")
    p_sweep.add_argument("--no-reassemble", action="store_true", dest="no_reassemble",
                         help="treat capture as single-packet (disable chunked reassembly)")
    p_sweep.add_argument("--out", required=True, help="write the labeled corpus JSON here")
    p_sweep.add_argument("--decode", action="store_true", help="decode the corpus after capture")
    p_sweep.add_argument("--spec-out", default=None, dest="spec_out", help="write decoded spec JSON here")
    p_sweep.add_argument("--emit-cpp", default=None, dest="emit_cpp", help="write decoded C++ skeleton here")
    p_sweep.set_defaults(func=_cmd_sweep)

    p_re = add("reassemble", description="Rebuild streamed chunks into per-channel LED buffers.")
    p_re.add_argument("--frames", required=True, help="a .frames.jsonl capture")
    p_re.add_argument("--triplets", action="store_true", help="also print the raw RGB triplets")
    _add_render_flags(p_re)
    p_re.set_defaults(func=_cmd_reassemble)

    p_ins = add("inspect", description="Group packets by command class, or diff two captures.")
    p_ins.add_argument("--frames", required=True, help="a .frames.jsonl capture")
    p_ins.add_argument("--diff", default=None, metavar="OTHER",
                       help="second capture: report which byte columns changed per command class")
    p_ins.add_argument("--sig-len", type=int, default=2, dest="sig_len",
                       help="how many leading bytes define a command class (default: 2 = report+command)")
    p_ins.add_argument("--direction", choices=("out", "in", "any"), default="out",
                       help="filter by transfer direction (default: out = host->device)")
    p_ins.add_argument("--vid", type=lambda s: int(s, 0), default=None, help="filter to this USB vendor id")
    p_ins.add_argument("--pid", type=lambda s: int(s, 0), default=None, help="filter to this USB product id")
    _add_render_flags(p_ins)
    p_ins.set_defaults(func=_cmd_inspect)

    p_cad = add("cadence", description="Measure an effect's speed from packet timing.")
    p_cad.add_argument("--frames", required=True, nargs="+", help="one or more captures (compared side by side)")
    p_cad.add_argument("--channel", type=int, default=None, help="reference channel to track (default: auto)")
    p_cad.add_argument("--vid", type=lambda s: int(s, 0), default=None, help="filter to this USB vendor id")
    p_cad.add_argument("--pid", type=lambda s: int(s, 0), default=None, help="filter to this USB product id")
    p_cad.set_defaults(func=_cmd_cadence)

    p_an = add("analyze", description="One-shot report: command classes, chunking, timing.")
    p_an.add_argument("--frames", required=True, help="a .frames.jsonl capture")
    p_an.add_argument("--out", default=None, help="write a Markdown report here (else stdout)")
    p_an.add_argument("--sig-len", type=int, default=2, dest="sig_len",
                      help="how many leading bytes define a command class")
    p_an.add_argument("--direction", choices=("out", "in", "any"), default="out",
                      help="filter all analysis sections by transfer direction")
    p_an.add_argument("--channel", type=int, default=None,
                      help="cadence reference channel (default: auto)")
    p_an.add_argument("--vid", type=lambda s: int(s, 0), default=None, help="filter to this USB vendor id")
    p_an.add_argument("--pid", type=lambda s: int(s, 0), default=None, help="filter to this USB product id")
    _add_render_flags(p_an)
    p_an.set_defaults(func=_cmd_analyze)

    p_replay = add("replay", description="Verify a spec by replaying it (dry-run by default).")
    p_replay.add_argument("--spec", default=None, help="path to a .spec.json file")
    p_replay.add_argument("--example", default=None, help="built-in example name (dry-run demo)")
    p_replay.add_argument("--corpus", default=None, help="capture corpus to read the device path from")
    p_replay.add_argument("--device-path", default=None, dest="device_path",
                          help="device path to write to (else taken from --corpus)")
    p_replay.add_argument("--write", action="store_true", help="actually write (default: dry-run)")
    p_replay.add_argument("--yes", action="store_true", help="confirm writes (vendor app CLOSED first)")
    p_replay.add_argument("--force", action="store_true",
                          help="write even though a vendor lighting app appears to be running")
    p_replay.set_defaults(func=_cmd_replay)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        print(start_here_text())
        return 0
    try:
        return args.func(args)
    except LumaScopeError as exc:
        print(exc.render(), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
