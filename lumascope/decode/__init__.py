"""Decode engine: turn a labeled capture corpus into a :class:`ProtocolSpec`.

Pipeline (see :func:`lumascope.decode.spec.decode`):

1. **base analysis** — modal packet length, constant vs varying byte columns.
2. **checksum** (:mod:`.checksum`) — find the field reproducible from the rest of the packet.
3. **field localization** (:mod:`.diff`) — per-channel sweeps pin each LED-0 R/G/B byte
   and recover the value->byte scaling (identity / linear / gamma).
4. **layout** (:mod:`.stride`) — multi-LED offsets give base/stride/channel-order/layout.
5. **brightness** (:mod:`.encoding`) — a global brightness byte, if present.
6. **assemble + validate** — re-encode every frame and assert byte-for-byte equality.
"""

from .spec import DecodeResult, Validation, decode

__all__ = ["decode", "DecodeResult", "Validation"]
