"""Human-readable rendering of captured bytes.

Reverse engineering means staring at hex, and a bare ``ec4084000 2ff0000...`` tells a
human nothing. Everything in this module exists to remove a step the reader would
otherwise do in their head:

* an **offset ruler** and decimal offsets, so "the byte at 11" never has to be counted;
* a **field-tag row** printed directly under the hex, naming each byte inline;
* **true-colour** hex digits, so an RGB payload literally looks like the colours it sets;
* a **change marker row** (``^^``), so "which byte carries the thing I changed" is visual;
* **run-collapsed LED tables**, so a 120-LED buffer is four lines, not 120.

Rendering degrades on purpose. Colour is emitted only to a capable TTY (honouring
``NO_COLOR``/``FORCE_COLOR``), and the default character set is pure ASCII so a legacy
Windows console renders every glyph intact.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field as dc_field
from typing import Iterable, Optional, Sequence

# --------------------------------------------------------------------------- #
# Colour support
# --------------------------------------------------------------------------- #
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
GREEN = "\033[32m"
RED = "\033[31m"
WHITE = "\033[97m"

_VT_ENABLED: Optional[bool] = None


def _enable_windows_vt() -> bool:
    """Turn on ANSI escape processing for the Windows console (idempotent)."""
    global _VT_ENABLED
    if _VT_ENABLED is not None:
        return _VT_ENABLED
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            _VT_ENABLED = False
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        _VT_ENABLED = True
    except Exception:
        _VT_ENABLED = False
    return _VT_ENABLED


def supports_color(stream=None) -> bool:
    """True when it is safe to emit ANSI escapes to ``stream``."""
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if sys.platform == "win32":
        return _enable_windows_vt()
    return True


def resolve_color(setting: str, stream=None) -> bool:
    """Map an ``auto|always|never`` CLI flag to a boolean."""
    if setting == "always":
        if sys.platform == "win32":
            _enable_windows_vt()
        return True
    if setting == "never":
        return False
    return supports_color(stream)


def _legible(r: int, g: int, b: int) -> tuple[int, int, int]:
    """Brighten a colour just enough to stay readable as foreground text on a dark or
    light terminal. Pure black stays grey rather than vanishing."""
    peak = max(r, g, b)
    if peak == 0:
        return (110, 110, 110)
    if peak >= 110:
        return (r, g, b)
    scale = 110 / peak
    return (min(255, int(r * scale)), min(255, int(g * scale)), min(255, int(b * scale)))


def fg(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


def bg(r: int, g: int, b: int) -> str:
    return f"\033[48;2;{r};{g};{b}m"


def swatch(rgb: tuple[int, int, int], *, color: bool, cells: int = 2) -> str:
    """A colour chip. Uses background-coloured spaces (pure ASCII) when colour is on,
    and falls back to a shaded ASCII ramp keyed to brightness when it is off."""
    r, g, b = rgb
    if color:
        return f"{bg(r, g, b)}{' ' * cells}{RESET}"
    level = (r + g + b) / 765
    ch = " " if level < 0.08 else "." if level < 0.3 else "+" if level < 0.6 else "#"
    return ch * cells


# --------------------------------------------------------------------------- #
# Field maps
# --------------------------------------------------------------------------- #
KIND_HEADER = "header"
KIND_PAYLOAD = "payload"
KIND_CHECKSUM = "checksum"
KIND_BRIGHTNESS = "brightness"
KIND_PAD = "pad"
KIND_UNKNOWN = "unknown"

_KIND_COLOR = {
    KIND_HEADER: CYAN,
    KIND_CHECKSUM: MAGENTA,
    KIND_BRIGHTNESS: YELLOW,
    KIND_PAD: DIM,
    KIND_UNKNOWN: DIM,
}


@dataclass
class Field:
    """One named span of a packet.

    ``cycle_tags`` labels a repeating structure per byte -- an RGB payload uses
    ``("R", "G", "B")`` so every byte in the buffer says which channel it drives.
    """

    start: int
    end: int  # exclusive
    name: str
    tag: str = ""
    detail: str = ""
    kind: str = KIND_HEADER
    cycle_tags: tuple[str, ...] = ()

    def __contains__(self, i: int) -> bool:
        return self.start <= i < self.end

    @property
    def width(self) -> int:
        return self.end - self.start


@dataclass
class FieldMap:
    """The named spans of one packet, plus a lookup by byte index."""

    fields: list[Field] = dc_field(default_factory=list)

    def at(self, i: int) -> Optional[Field]:
        for f in self.fields:
            if i in f:
                return f
        return None

    def tag_at(self, i: int) -> str:
        f = self.at(i)
        if f is None:
            return "  "
        if f.cycle_tags:
            tag = f.cycle_tags[(i - f.start) % len(f.cycle_tags)]
        else:
            tag = f.tag or f.name[:2]
        return f"{tag:<2}"[:2]

    def legend(self) -> str:
        """``tag = name`` pairs, deduplicated, in packet order."""
        seen: list[tuple[str, str]] = []
        for f in self.fields:
            if f.cycle_tags:
                pair = ("/".join(f.cycle_tags), f.name)
            else:
                pair = ((f.tag or f.name[:2]).strip(), f.name)
            if pair not in seen:
                seen.append(pair)
        return "  ".join(f"{t}={n}" for t, n in seen if t)

    def __bool__(self) -> bool:
        return bool(self.fields)


# --------------------------------------------------------------------------- #
# Hex dump
# --------------------------------------------------------------------------- #
def _lay(cells: Sequence[str], group: int, ncols: int) -> str:
    """Join fixed-width cells with a wider gap every ``group`` columns.

    Cells may carry ANSI escapes; separators are added positionally so the hex row,
    tag row, marker row and ruler stay aligned regardless of colouring.
    """
    out: list[str] = []
    for j, cell in enumerate(cells):
        out.append(cell)
        out.append(" ")
        if group and (j + 1) % group == 0 and j != ncols - 1:
            out.append(" ")
    return "".join(out)




def _payload_rgb(data: bytes, fmap: Optional[FieldMap], i: int) -> Optional[tuple[int, int, int]]:
    """The colour of the triplet byte ``i`` belongs to, if it is inside an RGB payload."""
    if fmap is None:
        return None
    f = fmap.at(i)
    if f is None or not f.cycle_tags or len(f.cycle_tags) != 3:
        return None
    base = f.start + ((i - f.start) // 3) * 3
    if base + 3 > len(data):
        return None
    triplet = data[base:base + 3]
    order = "".join(f.cycle_tags).upper()
    try:
        r = triplet[order.index("R")]
        g = triplet[order.index("G")]
        b = triplet[order.index("B")]
    except ValueError:
        r, g, b = triplet[0], triplet[1], triplet[2]
    return (r, g, b)


def hexdump(
    data: bytes,
    *,
    fields: Optional[FieldMap] = None,
    vary: Iterable[int] = (),
    width: int = 16,
    group: int = 4,
    color: bool = False,
    ascii_gutter: bool = True,
    indent: str = "  ",
    ruler: bool = True,
    max_rows: Optional[int] = None,
    collapse: bool = True,
) -> str:
    """Render ``data`` as an annotated hex dump.

    Offsets are decimal so they line up with the byte indices every other LumaScope
    command reports. When ``fields`` is given, each hex row is followed by a tag row
    naming its bytes; ``vary`` adds a ``^^`` marker row under the columns that changed.
    ``collapse`` folds stretches of identical rows into a ``*`` line, which matters here
    because vendor packets are mostly zero padding.
    """
    vary = set(vary)
    lines: list[str] = []
    gutter = " " * 6

    if ruler:
        head = [f"{j:02d}" for j in range(width)]
        lines.append(indent + gutter + (DIM if color else "") + _lay(head, group, width).rstrip()
                     + (RESET if color else ""))

    rows = range(0, len(data), width)
    truncated = False
    if max_rows is not None and len(data) > max_rows * width:
        rows = range(0, max_rows * width, width)
        truncated = True

    prev_chunk: Optional[bytes] = None
    folded = 0

    def flush_folded() -> None:
        nonlocal folded
        if folded:
            plural = "s" if folded > 1 else ""
            lines.append(f"{indent}{gutter}*  ({folded} identical row{plural} omitted)")
            folded = 0

    for off in rows:
        chunk = data[off:off + width]
        # Always render the final row so the reader sees where the packet ends.
        is_last = off + width >= len(data)
        if collapse and chunk == prev_chunk and not is_last:
            folded += 1
            continue
        flush_folded()
        prev_chunk = chunk
        hex_cells: list[str] = []
        for k, byte in enumerate(chunk):
            i = off + k
            cell = f"{byte:02x}"
            if color:
                rgb = _payload_rgb(data, fields, i)
                if rgb is not None:
                    cell = f"{fg(*_legible(*rgb))}{cell}{RESET}"
                else:
                    f_ = fields.at(i) if fields else None
                    tint = _KIND_COLOR.get(f_.kind, "") if f_ else ""
                    if i in vary:
                        tint = BOLD + (tint or WHITE)
                    if tint:
                        cell = f"{tint}{cell}{RESET}"
                    elif i in vary:
                        cell = f"{BOLD}{cell}{RESET}"
            hex_cells.append(cell)

        pad = ["  "] * (width - len(chunk))
        laid = _lay(hex_cells + pad, group, width)
        if ascii_gutter:
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            # Short rows are padded to the full column count before layout, so `laid` has a
            # constant visible width and the gutter lines up on every row including the last.
            row = indent + f"{off:>4}  " + laid + f" |{text}|"
        else:
            row = (indent + f"{off:>4}  " + laid).rstrip()
        lines.append(row)

        if fields:
            tags = [fields.tag_at(off + k) for k in range(len(chunk))]
            tag_row = indent + gutter + _lay(tags, group, width).rstrip()
            if tag_row.strip():
                lines.append((DIM + tag_row + RESET) if color else tag_row)

        if vary:
            marks = ["^^" if (off + k) in vary else "  " for k in range(len(chunk))]
            mark_row = indent + gutter + _lay(marks, group, width).rstrip()
            if mark_row.strip():
                lines.append((BOLD + mark_row + RESET) if color else mark_row)

    flush_folded()
    if truncated:
        rest = len(data) - (max_rows or 0) * width
        lines.append(f"{indent}{gutter}... {rest} more byte(s)")
    return "\n".join(lines)


def field_table(data: bytes, fmap: FieldMap, *, indent: str = "  ", color: bool = False) -> str:
    """A decoded-field table: offset, name, raw bytes, and the human value."""
    if not fmap:
        return ""
    rows: list[tuple[str, str, str, str]] = []
    for f in fmap.fields:
        raw = data[f.start:f.end]
        span = f"{f.start}" if f.width == 1 else f"{f.start}..{f.end - 1}"
        shown = raw[:6].hex(" ") + (" .." if len(raw) > 6 else "")
        detail = f.detail
        if not detail and f.width == 1 and raw:
            detail = str(raw[0])
        rows.append((span, f.name, shown, detail))

    w0 = max(len(r[0]) for r in rows + [("offset", "", "", "")])
    w1 = max(len(r[1]) for r in rows + [("", "field", "", "")])
    w2 = max(len(r[2]) for r in rows + [("", "", "bytes", "")])
    head = f"{indent}{'offset'.ljust(w0)}  {'field'.ljust(w1)}  {'bytes'.ljust(w2)}  value"
    out = [(DIM + head + RESET) if color else head]
    for span, name, shown, detail in rows:
        out.append(f"{indent}{span.ljust(w0)}  {name.ljust(w1)}  {shown.ljust(w2)}  {detail}")
    return "\n".join(out)


def render_packet(
    data: bytes,
    *,
    fields: Optional[FieldMap] = None,
    vary: Iterable[int] = (),
    title: str = "",
    color: bool = False,
    width: int = 16,
    group: int = 4,
    table: bool = True,
    max_rows: Optional[int] = None,
) -> str:
    """Title + annotated hex dump + legend + decoded-field table."""
    parts: list[str] = []
    if title:
        parts.append((BOLD + title + RESET) if color else title)
    parts.append(hexdump(data, fields=fields, vary=vary, width=width, group=group,
                         color=color, max_rows=max_rows))
    if fields:
        legend = fields.legend()
        if legend:
            parts.append(("  " + DIM + legend + RESET) if color else "  " + legend)
        if table:
            parts.append("")
            parts.append(field_table(data, fields, color=color))
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# LED buffers
# --------------------------------------------------------------------------- #
def led_runs(buf: bytes, order: str = "RGB") -> list[tuple[int, int, tuple[int, int, int]]]:
    """Collapse an RGB buffer into ``(first_led, last_led, rgb)`` runs of equal colour."""
    n = len(buf) // 3
    runs: list[tuple[int, int, tuple[int, int, int]]] = []
    order = order.upper()
    for i in range(n):
        triplet = buf[i * 3:i * 3 + 3]
        try:
            rgb = (triplet[order.index("R")], triplet[order.index("G")], triplet[order.index("B")])
        except ValueError:
            rgb = (triplet[0], triplet[1], triplet[2])
        if runs and runs[-1][2] == rgb:
            runs[-1] = (runs[-1][0], i, rgb)
        else:
            runs.append((i, i, rgb))
    return runs


def led_table(
    buf: bytes,
    *,
    order: str = "RGB",
    color: bool = False,
    indent: str = "  ",
    max_runs: int = 12,
) -> str:
    """Render an assembled LED buffer as colour runs -- 120 identical LEDs become one line."""
    runs = led_runs(buf, order)
    if not runs:
        return f"{indent}(empty buffer)"
    lines: list[str] = []
    for first, last, rgb in runs[:max_runs]:
        span = f"LED {first}" if first == last else f"LED {first}..{last}"
        count = last - first + 1
        chip = swatch(rgb, color=color, cells=3)
        raw = bytes(buf[first * 3:first * 3 + 3]).hex(" ")
        tail = f"  (x{count})" if count > 1 else ""
        lines.append(f"{indent}{chip} {span:<16} {raw}  rgb({rgb[0]:>3},{rgb[1]:>3},{rgb[2]:>3}){tail}")
    if len(runs) > max_runs:
        lines.append(f"{indent}    ... {len(runs) - max_runs} more colour run(s)")
    return "\n".join(lines)


def color_bar(buf: bytes, *, order: str = "RGB", color: bool = False, cells: int = 60) -> str:
    """A one-line strip preview of a whole LED buffer, sampled to ``cells`` columns."""
    n = len(buf) // 3
    if n == 0:
        return ""
    order = order.upper()
    ncell = min(cells, n)
    out: list[str] = []
    for c in range(ncell):
        i = c * n // ncell
        triplet = buf[i * 3:i * 3 + 3]
        if len(triplet) < 3:
            break
        try:
            rgb = (triplet[order.index("R")], triplet[order.index("G")], triplet[order.index("B")])
        except ValueError:
            rgb = (triplet[0], triplet[1], triplet[2])
        out.append(swatch(rgb, color=color, cells=1))
    return "".join(out)


# --------------------------------------------------------------------------- #
# Side-by-side byte comparison
# --------------------------------------------------------------------------- #
def compare(
    a: bytes,
    b: bytes,
    *,
    a_label: str = "A",
    b_label: str = "B",
    width: int = 16,
    group: int = 4,
    color: bool = False,
    fields: Optional[FieldMap] = None,
    indent: str = "  ",
) -> str:
    """Two packets stacked with a ``^^`` marker under every differing column.

    This is the rigorous version of eyeballing two hex dumps side by side: the marker
    row points at the bytes that actually moved, and the field row names them.
    """
    n = max(len(a), len(b))
    diff = {i for i in range(n)
            if (a[i] if i < len(a) else None) != (b[i] if i < len(b) else None)}
    label_w = max(len(a_label), len(b_label), 4)
    lines: list[str] = []

    head = [f"{j:02d}" for j in range(width)]
    lines.append(indent + " " * (label_w + 8) + (DIM if color else "")
                 + _lay(head, group, width).rstrip() + (RESET if color else ""))

    for off in range(0, n, width):
        for label, data in ((a_label, a), (b_label, b)):
            chunk = data[off:off + width]
            cells = []
            for k, byte in enumerate(chunk):
                cell = f"{byte:02x}"
                if color and (off + k) in diff:
                    cell = f"{BOLD}{YELLOW}{cell}{RESET}"
                cells.append(cell)
            pad = ["  "] * (width - len(chunk))
            lines.append(f"{indent}{label:<{label_w}}  {off:>4}  "
                         + _lay(cells + pad, group, width).rstrip())
        marks = ["^^" if (off + k) in diff else "  " for k in range(min(width, n - off))]
        mark_row = indent + " " * (label_w + 8) + _lay(marks, group, width).rstrip()
        if mark_row.strip():
            lines.append((BOLD + mark_row + RESET) if color else mark_row)
        if fields:
            tags = [fields.tag_at(off + k) for k in range(min(width, n - off))]
            tag_row = indent + " " * (label_w + 8) + _lay(tags, group, width).rstrip()
            if tag_row.strip():
                lines.append((DIM + tag_row + RESET) if color else tag_row)
    return "\n".join(lines)
