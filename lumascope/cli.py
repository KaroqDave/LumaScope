"""LumaScope command-line entry point.

    lumascope doctor      report what's installed / runnable on this machine
    lumascope selftest    prove the decode engine recovers known specs (no hardware)
    lumascope decode      decode a saved capture corpus -> protocol spec  (Phase 3/4)
    lumascope emit        render a protocol spec -> JSON / C++ skeleton    (Phase 5)
    lumascope sweep       drive a device through the sweep matrix          (Phase 4)
    lumascope capture     run a capture backend                           (Phase 2/3)
    lumascope replay      replay a decoded spec to verify it              (Phase 4)
"""

from __future__ import annotations

import argparse
import sys

from . import __version__


def _cmd_doctor(_args) -> int:
    from . import doctor
    print(doctor.report())
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
    return 0 if all_ok else 1


def _cmd_decode(args) -> int:
    from .capture.serialize import load_corpus
    from .decode import decode
    from .emit import render_cpp, spec_to_json

    corpus = load_corpus(args.corpus)
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
    return 0 if result.validation.ok else 1


def _load_example_or_spec(args):
    from . import examples
    from .emit import spec_json as sj
    if args.example:
        if args.example not in examples.BY_NAME:
            raise SystemExit(f"unknown example '{args.example}'; choose from {list(examples.BY_NAME)}")
        return examples.BY_NAME[args.example]()
    if args.spec:
        return sj.load_spec(args.spec)
    raise SystemExit("provide --example NAME or --spec PATH")


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
    from . import examples, synthetic
    from .decode import decode
    from .emit import render_cpp

    if args.example not in examples.BY_NAME:
        raise SystemExit(f"unknown example '{args.example}'; choose from {list(examples.BY_NAME)}")
    truth = examples.BY_NAME[args.example]()
    corpus = synthetic.generate_corpus(truth)
    result = decode(corpus, name=truth.name)
    print(f"# decoded {truth.name} from {len(corpus)} synthetic frames", file=sys.stderr)
    print(f"# {result.validation.summary()}", file=sys.stderr)
    print(render_cpp(result.spec))
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
            print("frida backend needs --spawn PROG or --attach PID|NAME", file=sys.stderr)
            return 2
        backend = FridaBackend(spawn=args.spawn, attach=args.attach, vid=args.vid, pid=args.pid)

    try:
        frames = backend.capture(duration=duration)
    except ImportError:
        print("frida is not installed  ->  pip install -e .[frida]", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"capture error: {exc}", file=sys.stderr)
        return 2

    for level, msg in backend.logs:
        if level in ("error", "ready", "warn", "detached"):
            print(f"# agent {level}: {msg}", file=sys.stderr)
    print(f"# captured {len(frames)} frame(s)", file=sys.stderr)

    if args.out:
        frames_to_jsonl(frames, args.out)
        print(f"wrote frames -> {args.out}", file=sys.stderr)
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

    if args.driver == "openrgb":
        from .stimulus.openrgb_driver import OpenRGBDriver
        driver = OpenRGBDriver(device_index=args.device_index)
    else:
        from .stimulus.manual import ManualDriver
        driver = ManualDriver()

    backend = FridaBackend(spawn=args.spawn, attach=args.attach, vid=args.vid, pid=args.pid)
    try:
        corpus, _raw = orchestrate.run_sweep(
            backend, driver, args.led_count,
            device_name=args.name, vid=args.vid, pid=args.pid,
            chunked=(False if args.no_reassemble else "auto"), channel=args.channel,
            log=lambda m: print(f"# {m}", file=sys.stderr),
        )
    except ImportError as exc:
        print(f"missing dependency: {exc}  (frida / openrgb-python)", file=sys.stderr)
        return 2

    for level, msg in backend.logs:
        if level in ("error", "warn", "detached"):
            print(f"# agent {level}: {msg}", file=sys.stderr)

    save_corpus(corpus, args.out)
    print(f"# {len(corpus.frames)} labeled frame(s) -> {args.out}", file=sys.stderr)
    if not corpus.frames:
        print("# no frames captured - wrong process? try --attach <vendor-service>", file=sys.stderr)
        return 1

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

    if args.write and not args.yes:
        print("Refusing to write without --yes.  CLOSE THE VENDOR APP/SERVICE FIRST "
              "(it holds an exclusive device handle; concurrent access can brick boards).",
              file=sys.stderr)
        return 2

    try:
        replay.write_sequence(
            spec, steps, device_path=device_path,
            confirm=args.yes, dry_run=not args.write,
            out=lambda m: print(m),
        )
    except (OSError, RuntimeError) as exc:
        print(f"replay error: {exc}", file=sys.stderr)
        return 2
    return 0


def _cmd_reassemble(args) -> int:
    from .capture.serialize import load_frames
    from .decode.chunked import reassemble_capture

    frames = load_frames(args.frames)
    framing, channels = reassemble_capture(frames)
    if framing is None:
        print("no chunked command class detected in this capture", file=sys.stderr)
        return 1
    print(f"# framing: prefix={framing.prefix.hex()} channel@{framing.channel_pos}"
          f"(mask {framing.channel_mask:#x}) offset@{framing.offset_pos} count@{framing.count_pos}"
          f" payload@{framing.payload_start}", file=sys.stderr)
    for ch in sorted(channels):
        buf = channels[ch]
        line = f"channel {ch}: {len(buf):4} bytes (~{len(buf)//3} LEDs)"
        if args.triplets:
            shown = " ".join(buf[i:i + 3].hex() for i in range(0, min(len(buf), 30), 3))
            line += f"  [{shown}{' ...' if len(buf) > 30 else ''}]"
        print(line)
    return 0


def _cmd_inspect(args) -> int:
    from .capture.serialize import load_frames
    from .decode import inspect as ins

    frames = load_frames(args.frames)
    if args.diff:
        other = load_frames(args.diff)
        diffs = ins.diff_captures(
            frames, other, sig_len=args.sig_len,
            direction=(None if args.direction == "any" else args.direction),
            vid=args.vid, pid=args.pid,
        )
        print(ins.format_diff(diffs, args.frames, args.diff))
        return 0
    groups = ins.group_frames(
        frames, sig_len=args.sig_len,
        direction=(None if args.direction == "any" else args.direction),
        vid=args.vid, pid=args.pid,
    )
    if not groups:
        print("no frames matched the filter (wrong vid/pid/direction?)", file=sys.stderr)
        return 1
    print(ins.format_groups(groups))
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


def _cmd_stub(phase: str):
    def run(args) -> int:
        print(f"`{args.command}` is not implemented yet (lands in {phase}).", file=sys.stderr)
        return 2
    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lumascope", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"lumascope {__version__}")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("doctor", help="report installed tools / runnable phases").set_defaults(func=_cmd_doctor)
    sub.add_parser("selftest", help="prove the decoder recovers known specs").set_defaults(func=_cmd_selftest)

    p_decode = sub.add_parser("decode", help="decode a saved capture corpus -> protocol spec")
    p_decode.add_argument("--corpus", required=True, help="path to a corpus JSON file")
    p_decode.add_argument("--name", default=None, help="override device name")
    p_decode.add_argument("--out", default=None, help="write spec JSON here (else stdout)")
    p_decode.add_argument("--emit-cpp", default=None, dest="emit_cpp", help="also write a C++ skeleton here")
    p_decode.set_defaults(func=_cmd_decode)

    p_emit = sub.add_parser("emit", help="render a protocol spec -> JSON / C++ skeleton")
    p_emit.add_argument("--spec", default=None, help="path to a spec JSON file")
    p_emit.add_argument("--example", default=None, help="built-in example: interleaved|gamma|planar|nochecksum")
    p_emit.add_argument("--lang", choices=("cpp", "json"), default="cpp")
    p_emit.add_argument("--out", default=None, help="write here (else stdout)")
    p_emit.set_defaults(func=_cmd_emit)

    p_demo = sub.add_parser("demo", help="synth -> decode -> validate -> C++ for a built-in example")
    p_demo.add_argument("example", help="interleaved|gamma|planar|nochecksum")
    p_demo.set_defaults(func=_cmd_demo)

    p_capture = sub.add_parser("capture", help="record device writes (Frida hook or USBPcap sniff)")
    p_capture.add_argument("--backend", choices=("frida", "usbpcap"), default="frida",
                           help="frida (in-process hook, default) or usbpcap (USB bus sniff)")
    src = p_capture.add_mutually_exclusive_group()
    src.add_argument("--spawn", nargs="+", metavar="PROG",
                     help="[frida] program (and args) to launch under capture")
    src.add_argument("--attach", metavar="PID|NAME", help="[frida] attach to a running process")
    p_capture.add_argument("--vid", type=lambda s: int(s, 0), default=None,
                           help="[frida] filter to this USB vendor id (e.g. 0x1532)")
    p_capture.add_argument("--pid", type=lambda s: int(s, 0), default=None,
                           help="[frida] filter to this USB product id (e.g. 0x0226)")
    p_capture.add_argument("--interface", default=r"\\.\USBPcap1", help="[usbpcap] USBPcap interface")
    p_capture.add_argument("--address", type=int, default=None, help="[usbpcap] device address filter")
    p_capture.add_argument("--pcap", default=None, help="[usbpcap] parse an existing .pcap offline")
    p_capture.add_argument("--duration", type=float, default=5.0, help="capture window seconds")
    p_capture.add_argument("--out", default=None, help="write frame JSONL here (else stdout)")
    p_capture.set_defaults(func=_cmd_capture)

    p_sweep = sub.add_parser("sweep", help="drive a sweep, capture, and pair into a labeled corpus")
    p_sweep.add_argument("--led-count", type=int, required=True, dest="led_count",
                         help="how many LEDs the device exposes")
    p_sweep.add_argument("--driver", choices=("manual", "openrgb"), default="manual",
                         help="how to drive device state (default: manual/operator-guided)")
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

    p_re = sub.add_parser("reassemble", help="reassemble a chunked/streamed capture into per-channel buffers")
    p_re.add_argument("--frames", required=True, help="frame JSONL from `capture`")
    p_re.add_argument("--triplets", action="store_true", help="show buffers as RGB triplets")
    p_re.set_defaults(func=_cmd_reassemble)

    p_ins = sub.add_parser("inspect", help="group a capture by command class, or diff two single-variable captures")
    p_ins.add_argument("--frames", required=True, help="frame JSONL from `capture`")
    p_ins.add_argument("--diff", default=None, metavar="OTHER",
                       help="second capture: report which byte columns changed per command class")
    p_ins.add_argument("--sig-len", type=int, default=2, dest="sig_len",
                       help="how many leading bytes define a command class (default: 2 = report+command)")
    p_ins.add_argument("--direction", choices=("out", "in", "any"), default="out",
                       help="filter by transfer direction (default: out = host->device)")
    p_ins.add_argument("--vid", type=lambda s: int(s, 0), default=None, help="filter to this USB vendor id")
    p_ins.add_argument("--pid", type=lambda s: int(s, 0), default=None, help="filter to this USB product id")
    p_ins.set_defaults(func=_cmd_inspect)

    p_cad = sub.add_parser("cadence", help="measure a streamed effect's timing (frame rate + colour-cycle period = speed)")
    p_cad.add_argument("--frames", required=True, nargs="+", help="one or more frame JSONL files (compared side by side)")
    p_cad.add_argument("--channel", type=int, default=None, help="reference channel to track (default: auto)")
    p_cad.add_argument("--vid", type=lambda s: int(s, 0), default=None, help="filter to this USB vendor id")
    p_cad.add_argument("--pid", type=lambda s: int(s, 0), default=None, help="filter to this USB product id")
    p_cad.set_defaults(func=_cmd_cadence)

    p_replay = sub.add_parser("replay", help="replay a decoded spec to verify it on the device")
    p_replay.add_argument("--spec", default=None, help="path to a spec JSON file")
    p_replay.add_argument("--example", default=None, help="built-in example name (dry-run demo)")
    p_replay.add_argument("--corpus", default=None, help="capture corpus to read the device path from")
    p_replay.add_argument("--device-path", default=None, dest="device_path",
                          help="device path to write to (else taken from --corpus)")
    p_replay.add_argument("--write", action="store_true", help="actually write (default: dry-run)")
    p_replay.add_argument("--yes", action="store_true", help="confirm writes (vendor app CLOSED first)")
    p_replay.set_defaults(func=_cmd_replay)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
