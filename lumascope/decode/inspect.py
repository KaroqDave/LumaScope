"""Command-packet inspection: group a raw capture by command class, and diff two captures.

The chunked reassembler (:mod:`lumascope.decode.chunked`) answers *"what is the colour
buffer?"* for streamed direct-colour protocols. This pass answers the other RE question:
*"what command packets does the vendor app send, and which byte carries the variable I just
changed?"* — the rigorous version of eyeballing two hex dumps side by side.

Two views:

* **group** — bucket outbound frames by their leading command bytes (e.g. ASUS ``EC 40`` /
  ``EC 35`` / ``EC 36``); for each class show the count, a representative packet, and which
  byte columns are constant vs. varying *within* the class.
* **diff** — given two single-variable captures (e.g. *breathing-red* vs *breathing-green*),
  report, per shared command class, exactly which byte columns changed and their old→new
  value sets. Structure that is invariant between the two captures (report id, command,
  per-chunk offsets) cancels out; only the bytes that track the changed variable remain. That
  is how you localise a colour / speed / mode field without guessing.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Optional

from ..model import CaptureFrame


def command_signature(data: bytes, sig_len: int) -> tuple[int, ...]:
    """The grouping key: the leading ``sig_len`` bytes (report id + command for ASUS Aura)."""
    return tuple(data[:sig_len])


def _passes(f: CaptureFrame, direction: Optional[str], vid: Optional[int], pid: Optional[int]) -> bool:
    if direction and f.direction != direction:
        return False
    if vid is not None and f.vid is not None and f.vid != vid:
        return False
    if pid is not None and f.pid is not None and f.pid != pid:
        return False
    return True


@dataclass
class CommandGroup:
    """All frames sharing a leading command signature."""

    signature: tuple[int, ...]
    frames: list[CaptureFrame]

    @property
    def count(self) -> int:
        return len(self.frames)

    @property
    def datas(self) -> list[bytes]:
        return [f.data for f in self.frames]

    @property
    def representative(self) -> bytes:
        """The modal full packet (most common exact bytes) — the canonical form of this class."""
        return Counter(self.datas).most_common(1)[0][0]

    @property
    def width(self) -> int:
        """Number of byte columns common to every packet in the group."""
        return min(len(d) for d in self.datas)

    def varying_columns(self) -> list[int]:
        """Column indices (within the common width) that are not constant across the group."""
        w = self.width
        return [i for i in range(w) if len({d[i] for d in self.datas}) > 1]

    def column_values(self, i: int) -> list[int]:
        return sorted({d[i] for d in self.datas if i < len(d)})


def group_frames(
    frames: list[CaptureFrame],
    *,
    sig_len: int = 2,
    direction: Optional[str] = "out",
    vid: Optional[int] = None,
    pid: Optional[int] = None,
    min_len: int = 2,
) -> list[CommandGroup]:
    """Bucket frames by command signature, most-frequent class first.

    ``direction``/``vid``/``pid`` filter out unrelated bus traffic; ``min_len`` drops runt
    packets too short to carry a signature.
    """
    buckets: dict[tuple[int, ...], list[CaptureFrame]] = {}
    for f in frames:
        if len(f.data) < max(min_len, sig_len):
            continue
        if not _passes(f, direction, vid, pid):
            continue
        buckets.setdefault(command_signature(f.data, sig_len), []).append(f)
    groups = [CommandGroup(sig, fs) for sig, fs in buckets.items()]
    groups.sort(key=lambda g: (-g.count, g.signature))
    return groups


@dataclass
class ColumnDiff:
    index: int
    a_values: list[int]
    b_values: list[int]


@dataclass
class GroupDiff:
    """Per-command-class comparison of two captures.

    ``rep_a``/``rep_b`` keep each side's representative packet so the result can be
    rendered as a real side-by-side dump, not just a list of column indices.
    """

    signature: tuple[int, ...]
    in_a: bool
    in_b: bool
    changed: list[ColumnDiff]
    rep_a: bytes = b""
    rep_b: bytes = b""
    framing: object = None  # Optional[ChunkFraming], if this class is a chunked stream

    @property
    def shared(self) -> bool:
        return self.in_a and self.in_b


def diff_captures(
    a: list[CaptureFrame],
    b: list[CaptureFrame],
    *,
    sig_len: int = 2,
    direction: Optional[str] = "out",
    vid: Optional[int] = None,
    pid: Optional[int] = None,
) -> list[GroupDiff]:
    """Localise the changed variable between two single-variable captures.

    For every command class present in both captures, a column is reported as *changed* when
    its set of observed byte values differs between A and B. Columns whose value set is
    identical in both (constant headers, the same swept chunk offsets) are silently dropped —
    what remains is the field that tracks whatever single thing you varied between the runs.
    """
    ga = {g.signature: g for g in group_frames(a, sig_len=sig_len, direction=direction, vid=vid, pid=pid)}
    gb = {g.signature: g for g in group_frames(b, sig_len=sig_len, direction=direction, vid=vid, pid=pid)}
    out: list[GroupDiff] = []
    for sig in sorted(set(ga) | set(gb)):
        in_a, in_b = sig in ga, sig in gb
        changed: list[ColumnDiff] = []
        if in_a and in_b:
            width = min(ga[sig].width, gb[sig].width)
            for i in range(width):
                av, bv = ga[sig].column_values(i), gb[sig].column_values(i)
                if av != bv:
                    changed.append(ColumnDiff(index=i, a_values=av, b_values=bv))
        from .chunked import infer_framing
        out.append(GroupDiff(
            signature=sig, in_a=in_a, in_b=in_b, changed=changed,
            rep_a=ga[sig].representative if in_a else b"",
            rep_b=gb[sig].representative if in_b else b"",
            framing=infer_framing(ga[sig].frames) if in_a else None,
        ))
    return out


# --------------------------------------------------------------------------- #
# Pretty-printing (CLI)
# --------------------------------------------------------------------------- #
def _sig_str(sig: tuple[int, ...]) -> str:
    return " ".join(f"{b:02x}" for b in sig)


def compress_columns(cols: list[int]) -> str:
    """Render an index list compactly: ``[2,3,4,7] -> '2..4,7'``."""
    if not cols:
        return "-"
    cols = sorted(cols)
    runs: list[str] = []
    start = prev = cols[0]
    for i in cols[1:]:
        if i == prev + 1:
            prev = i
            continue
        runs.append(str(start) if start == prev else f"{start}..{prev}")
        start = prev = i
    runs.append(str(start) if start == prev else f"{start}..{prev}")
    return ",".join(runs)


_DIFF_COLUMN_CAP = 12
_VALUE_CAP = 6


def _values(values: list[int]) -> str:
    """A byte-value set, capped. A streamed effect can put 200 values in one column, and
    printing them all buries the finding."""
    shown = " ".join(f"{v:02x}" for v in values[:_VALUE_CAP])
    if len(values) > _VALUE_CAP:
        shown += f" ... ({len(values)} distinct)"
    return shown


def _fields_for(frames: list[CaptureFrame], packet: bytes):
    """Best available field map for a command class: whatever framing it reveals."""
    from ..annotate import fields_from_framing
    from .chunked import infer_framing

    framing = infer_framing(frames)
    if framing is not None and framing.matches(packet):
        return fields_from_framing(framing, packet)
    return None


def format_groups(groups: list[CommandGroup], *, color: bool = False, width: int = 16,
                  annotate: bool = True) -> str:
    """Render each command class as an annotated dump of its representative packet.

    Columns that vary *within* the class are marked, which is what tells you where the
    per-packet variables (chunk offset, last-chunk flag, colour) live.
    """
    from ..view import BOLD, RESET, render_packet

    total = sum(g.count for g in groups)
    lines = [f"# {total} packet(s) in {len(groups)} command class(es)"]
    for g in groups:
        rep = g.representative
        vary = g.varying_columns()
        fmap = _fields_for(g.frames, rep) if annotate else None
        head = (f"{_sig_str(g.signature)}  --  {g.count} packet(s), "
                f"{g.width} bytes each")
        lines.append("")
        lines.append((BOLD + head + RESET) if color else head)
        lines.append(render_packet(rep, fields=fmap, vary=vary, color=color,
                                   width=width, table=bool(fmap)))
        lines.append(f"  varies within this class: [{compress_columns(vary)}]"
                     "   (^^ above; constant everywhere else)")
    return "\n".join(lines)


def format_diff(diffs: list[GroupDiff], a_name: str, b_name: str, *,
                color: bool = False, width: int = 16) -> str:
    """Render a two-capture diff as stacked packets with the moved bytes marked.

    Only columns whose value set differs are marked, so structure that is invariant
    between the runs cancels out and what remains is the field you varied.
    """
    from ..view import BOLD, RESET, compare

    lines = [f"# diff   A = {a_name}", f"#        B = {b_name}"]
    for d in diffs:
        head = _sig_str(d.signature)
        if not d.shared:
            where = "only in A" if d.in_a else "only in B"
            lines.append("")
            lines.append(f"{head}  --  {where}")
            continue
        if not d.changed:
            lines.append("")
            lines.append(f"{head}  --  unchanged between the two captures")
            continue
        title = f"{head}  --  {len(d.changed)} byte column(s) changed"
        lines.append("")
        lines.append((BOLD + title + RESET) if color else title)
        fmap = None
        if d.framing is not None and d.framing.matches(d.rep_a):
            from ..annotate import fields_from_framing
            fmap = fields_from_framing(d.framing, d.rep_a)
        lines.append(compare(d.rep_a, d.rep_b, a_label="A", b_label="B",
                             width=width, color=color, fields=fmap))
        lines.append("")
        lines.append(f"  changed columns: [{compress_columns([c.index for c in d.changed])}]")
        for c in d.changed[:_DIFF_COLUMN_CAP]:
            lines.append(f"  byte {c.index:>3}:  A = {_values(c.a_values):<34}"
                         f"  B = {_values(c.b_values)}")
        if len(d.changed) > _DIFF_COLUMN_CAP:
            lines.append(f"  ... and {len(d.changed) - _DIFF_COLUMN_CAP} more changed column(s)")
    return "\n".join(lines)
