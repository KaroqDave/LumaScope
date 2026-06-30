"""Checksum / CRC recovery.

A checksum byte is the one that (a) varies with the payload yet (b) is a deterministic
function of the *rest* of the packet. We exploit (b) directly: for each varying column,
try to reproduce it from a contiguous range of the other bytes. A real data byte (an
independent input we swept) can't be reproduced this way, so it never false-positives.

Order, per the research: cheap schemes first (sum/xor/two's-complement/ones-complement),
then a catalog of common CRCs, then — only if installed — shell out to ``reveng`` for an
exotic polynomial. We conclude "no checksum" rather than force-fit noise.
"""

from __future__ import annotations

import shutil
import subprocess

from .. import codec
from ..model import ChecksumModel, LabeledFrame
from .diff import varying_offsets

SIMPLE_KINDS = ("sum8", "xor8", "twos8", "onescomp8")

# (name, width, poly, init, refin, refout, xorout)
CRC8_CATALOG = [
    ("CRC-8", 8, 0x07, 0x00, False, False, 0x00),
    ("CRC-8/MAXIM", 8, 0x31, 0x00, True, True, 0x00),
    ("CRC-8/SMBUS", 8, 0x07, 0x00, False, False, 0x00),
    ("CRC-8/ITU", 8, 0x07, 0x00, False, False, 0x55),
    ("CRC-8/ROHC", 8, 0x07, 0xFF, True, True, 0x00),
]
CRC16_CATALOG = [
    ("CRC-16/ARC", 16, 0x8005, 0x0000, True, True, 0x0000),
    ("CRC-16/MODBUS", 16, 0x8005, 0xFFFF, True, True, 0x0000),
    ("CRC-16/USB", 16, 0x8005, 0xFFFF, True, True, 0xFFFF),
    ("CRC-16/XMODEM", 16, 0x1021, 0x0000, False, False, 0x0000),
    ("CRC-16/CCITT-FALSE", 16, 0x1021, 0xFFFF, False, False, 0x0000),
]


def _simple(kind: str, data: bytes) -> int:
    return codec.compute_checksum_value(ChecksumModel(kind=kind), data)


def _crc(entry, data: bytes) -> int:
    _name, width, poly, init, refin, refout, xorout = entry
    return codec.crc_compute(data, width, poly, init, refin, refout, xorout)


def _ranges(start_candidates: tuple[int, ...], end: int) -> list[tuple[int, int]]:
    return [(s, end) for s in start_candidates if s < end]


def detect(
    frames: list[LabeledFrame],
    length: int,
    *,
    has_report_id: bool,
) -> ChecksumModel:
    """Return the recovered :class:`ChecksumModel`, or a ``present=False`` model."""
    if len(frames) < 3:
        return ChecksumModel(present=False, kind="none")

    var = sorted(varying_offsets(frames, length))
    start_candidates = (0, 1) if has_report_id else (0,)

    # Width 1 first (most common), then width 2.
    for c in var:
        model = _try_width1(frames, c, start_candidates)
        if model:
            return model
    for c in var:
        if c + 1 < length:
            model = _try_width2(frames, c, start_candidates)
            if model:
                return model
    return ChecksumModel(present=False, kind="none")


def _try_width1(frames, c: int, start_candidates) -> ChecksumModel | None:
    targets = [lf.data[c] for lf in frames]
    for s, e in _ranges(start_candidates, c):
        slices = [lf.data[s:e] for lf in frames]
        for kind in SIMPLE_KINDS:
            if all(_simple(kind, d) == t for d, t in zip(slices, targets)):
                return ChecksumModel(present=True, kind=kind, offset=c, width=1, range=(s, e))
        for entry in CRC8_CATALOG:
            if all(_crc(entry, d) == t for d, t in zip(slices, targets)):
                return _crc_model(entry, c, 1, "little", (s, e))
    # exotic CRC fallback via reveng (8-bit)
    return _reveng(frames, c, 1, start_candidates)


def _try_width2(frames, c: int, start_candidates) -> ChecksumModel | None:
    for s, e in _ranges(start_candidates, c):
        slices = [lf.data[s:e] for lf in frames]
        for endian in ("little", "big"):
            targets = [int.from_bytes(lf.data[c : c + 2], endian) for lf in frames]
            if all((sum(d) & 0xFFFF) == t for d, t in zip(slices, targets)):
                return ChecksumModel(
                    present=True, kind="sum16", offset=c, width=2, endian=endian, range=(s, e)
                )
            for entry in CRC16_CATALOG:
                if all(_crc(entry, d) == t for d, t in zip(slices, targets)):
                    return _crc_model(entry, c, 2, endian, (s, e))
    return _reveng(frames, c, 2, start_candidates)


def _crc_model(entry, offset: int, width: int, endian: str, rng) -> ChecksumModel:
    name, w, poly, init, refin, refout, xorout = entry
    return ChecksumModel(
        present=True,
        kind="crc",
        offset=offset,
        width=width,
        endian=endian,
        range=rng,
        params={
            "name": name,
            "width": w,
            "poly": poly,
            "init": init,
            "refin": refin,
            "refout": refout,
            "xorout": xorout,
        },
    )


def _reveng(frames, c: int, width: int, start_candidates) -> ChecksumModel | None:
    """Escalate to the external `reveng` tool for non-catalog polynomials, if available.

    Best-effort: reveng must agree across the whole corpus, and we re-verify the
    recovered model with our own CRC implementation before trusting it.
    """
    exe = shutil.which("reveng")
    if exe is None:
        return None
    for s, e in _ranges(start_candidates, c):
        samples = []
        for lf in frames:
            payload = lf.data[s:e]
            crc = lf.data[c : c + width]
            samples.append((payload + crc).hex())
        try:
            proc = subprocess.run(
                [exe, "-w", str(width * 8), "-l", "-s", *samples],
                capture_output=True, text=True, timeout=30,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        line = proc.stdout.strip().splitlines()
        if not line:
            continue
        model = _parse_reveng(line[0], width)
        if model is None:
            continue
        entry = (
            model["name"], width * 8, model["poly"], model["init"],
            model["refin"], model["refout"], model["xorout"],
        )
        targets = [int.from_bytes(lf.data[c : c + width], "little") for lf in frames]
        if all(_crc(entry, lf.data[s:e]) == t for lf, t in zip(frames, targets)):
            return _crc_model(entry, c, width, "little", (s, e))
    return None


def _parse_reveng(line: str, width: int) -> dict | None:
    """Parse a `reveng -s` model line:  width=16  poly=0x8005  init=0x0000 ..."""
    fields: dict[str, str] = {}
    for tok in line.split():
        if "=" in tok:
            key, _, val = tok.partition("=")
            fields[key] = val
    try:
        return {
            "name": f"reveng-0x{int(fields['poly'], 16):x}",
            "poly": int(fields["poly"], 16),
            "init": int(fields["init"], 16),
            "refin": fields.get("refin", "false").lower() == "true",
            "refout": fields.get("refout", "false").lower() == "true",
            "xorout": int(fields["xorout"], 16),
        }
    except (KeyError, ValueError):
        return None
