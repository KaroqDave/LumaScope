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
    """Per-command-class comparison of two captures."""

    signature: tuple[int, ...]
    in_a: bool
    in_b: bool
    changed: list[ColumnDiff]

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
        out.append(GroupDiff(signature=sig, in_a=in_a, in_b=in_b, changed=changed))
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


def _hex_capped(data: bytes, cap: int = 24) -> str:
    head = data[:cap].hex(" ")
    return head + (" …" if len(data) > cap else "")


def format_groups(groups: list[CommandGroup]) -> str:
    total = sum(g.count for g in groups)
    lines = [f"# {total} frame(s) in {len(groups)} command class(es)"]
    for g in groups:
        lines.append(
            f"  {_sig_str(g.signature):8} x{g.count:5}  len {g.width:<4} "
            f"vary [{compress_columns(g.varying_columns())}]"
        )
        lines.append(f"           rep: {_hex_capped(g.representative)}")
    return "\n".join(lines)


def format_diff(diffs: list[GroupDiff], a_name: str, b_name: str) -> str:
    lines = [f"# diff  A={a_name}  B={b_name}"]
    for d in diffs:
        if not d.shared:
            where = "A only" if d.in_a else "B only"
            lines.append(f"  {_sig_str(d.signature):8} [{where}]")
            continue
        if not d.changed:
            lines.append(f"  {_sig_str(d.signature):8} unchanged")
            continue
        lines.append(f"  {_sig_str(d.signature):8} {len(d.changed)} changed column(s):")
        for c in d.changed:
            av = " ".join(f"{v:02x}" for v in c.a_values)
            bv = " ".join(f"{v:02x}" for v in c.b_values)
            lines.append(f"      [{c.index:>3}]  A: {av:<20}  B: {bv}")
    return "\n".join(lines)
