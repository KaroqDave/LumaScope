"""Canonical JSON (de)serialization for :class:`ProtocolSpec`.

Explicit converters (not ``dataclasses.asdict``) so tuples stay tuples on the way back
and the on-disk shape is stable enough to diff in code review.
"""

from __future__ import annotations

import json
from typing import Any

from ..model import (
    BrightnessField,
    ChecksumModel,
    ChunkingModel,
    HeaderField,
    LedLayout,
    ProtocolSpec,
    Scaling,
)


def spec_to_dict(s: ProtocolSpec) -> dict[str, Any]:
    return {
        "name": s.name,
        "transport": s.transport,
        "report_id": s.report_id,
        "packet_len": s.packet_len,
        "vid": s.vid,
        "pid": s.pid,
        "header": {
            "constant_bytes": [[o, v] for o, v in s.header.constant_bytes],
            "command_offset": s.header.command_offset,
            "mode_offset": s.header.mode_offset,
        },
        "leds": {
            "count": s.leds.count,
            "layout": s.leds.layout,
            "base_offset": s.leds.base_offset,
            "stride": s.leds.stride,
            "channel_order": s.leds.channel_order,
            "scaling": {"type": s.leds.scaling.type, "k": s.leds.scaling.k, "gamma": s.leds.scaling.gamma},
            "explicit_offsets": (
                [list(t) for t in s.leds.explicit_offsets] if s.leds.explicit_offsets else None
            ),
        },
        "brightness": {
            "present": s.brightness.present,
            "offset": s.brightness.offset,
            "min": s.brightness.min,
            "max": s.brightness.max,
        },
        "checksum": {
            "present": s.checksum.present,
            "kind": s.checksum.kind,
            "offset": s.checksum.offset,
            "width": s.checksum.width,
            "endian": s.checksum.endian,
            "range": list(s.checksum.range) if s.checksum.range else None,
            "params": s.checksum.params,
        },
        "chunking": {
            "present": s.chunking.present,
            "packet_len": s.chunking.packet_len,
            "prefix": list(s.chunking.prefix),
            "channel": s.chunking.channel,
            "channel_pos": s.chunking.channel_pos,
            "channel_mask": s.chunking.channel_mask,
            "final_flag": s.chunking.final_flag,
            "offset_pos": s.chunking.offset_pos,
            "count_pos": s.chunking.count_pos,
            "payload_start": s.chunking.payload_start,
            "unit": s.chunking.unit,
            "chunk_count": s.chunking.chunk_count,
        },
        "notes": s.notes,
    }


def spec_from_dict(d: dict[str, Any]) -> ProtocolSpec:
    h = d.get("header", {})
    le = d.get("leds", {})
    sc = le.get("scaling", {})
    br = d.get("brightness", {})
    cs = d.get("checksum", {})
    ch = d.get("chunking", {})
    return ProtocolSpec(
        name=d.get("name", "unknown"),
        transport=d.get("transport", "hid_feature"),
        report_id=d.get("report_id"),
        packet_len=d.get("packet_len", 0),
        vid=d.get("vid"),
        pid=d.get("pid"),
        header=HeaderField(
            constant_bytes=[(o, v) for o, v in h.get("constant_bytes", [])],
            command_offset=h.get("command_offset"),
            mode_offset=h.get("mode_offset"),
        ),
        leds=LedLayout(
            count=le.get("count", 0),
            layout=le.get("layout", "interleaved"),
            base_offset=le.get("base_offset", 0),
            stride=le.get("stride", 3),
            channel_order=le.get("channel_order", "RGB"),
            scaling=Scaling(
                type=sc.get("type", "identity"), k=sc.get("k", 1.0), gamma=sc.get("gamma", 1.0)
            ),
            explicit_offsets=(
                [tuple(t) for t in le["explicit_offsets"]] if le.get("explicit_offsets") else None
            ),
        ),
        brightness=BrightnessField(
            present=br.get("present", False),
            offset=br.get("offset"),
            min=br.get("min", 0),
            max=br.get("max", 255),
        ),
        checksum=ChecksumModel(
            present=cs.get("present", False),
            kind=cs.get("kind", "none"),
            offset=cs.get("offset"),
            width=cs.get("width", 1),
            endian=cs.get("endian", "little"),
            range=tuple(cs["range"]) if cs.get("range") else None,
            params=cs.get("params", {}),
        ),
        chunking=ChunkingModel(
            present=ch.get("present", False),
            packet_len=ch.get("packet_len", 0),
            prefix=bytes(ch.get("prefix", [])),
            channel=ch.get("channel", 0),
            channel_pos=ch.get("channel_pos", 0),
            channel_mask=ch.get("channel_mask", 0xFF),
            final_flag=ch.get("final_flag", 0),
            offset_pos=ch.get("offset_pos", 0),
            count_pos=ch.get("count_pos", 0),
            payload_start=ch.get("payload_start", 0),
            unit=ch.get("unit", 1),
            chunk_count=ch.get("chunk_count", 0),
        ),
        notes=d.get("notes", []),
    )


def spec_to_json(s: ProtocolSpec, *, indent: int = 2) -> str:
    return json.dumps(spec_to_dict(s), indent=indent)


def save_spec(s: ProtocolSpec, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(spec_to_json(s))


def load_spec(path: str) -> ProtocolSpec:
    with open(path, encoding="utf-8") as fh:
        return spec_from_dict(json.load(fh))
