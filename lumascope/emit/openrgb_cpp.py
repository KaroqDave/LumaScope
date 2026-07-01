"""Render a :class:`ProtocolSpec` to an OpenRGB-style C++ controller skeleton.

The generated class mirrors the reference codec (:mod:`lumascope.codec`) in C++: it packs
per-LED colors at the recovered offsets/stride/order, applies the recovered scaling and
brightness, and computes the recovered checksum. It is a faithful drop-in starting point
for a LumaCore device module — the dev fills in device discovery and modes.

A spec that round-trips in the Python validation loop produces packing logic here that is
byte-identical to it, so the emitted code matches captured hardware traffic.
"""

from __future__ import annotations

from ..model import ChecksumModel, ProtocolSpec

_VALUE_VAR = {"R": "r", "G": "g", "B": "b"}


def _class_name(name: str) -> str:
    parts = "".join(c if c.isalnum() else " " for c in name).split()
    return "".join(p[:1].upper() + p[1:] for p in parts) + "Controller"


def _led_offset_expr(spec: ProtocolSpec, wire_pos: int) -> str:
    le = spec.leds
    if le.explicit_offsets is not None:
        return f"LED_OFFSETS[i][{wire_pos}]"
    if le.layout == "planar":
        return f"{le.base_offset} + {wire_pos}*LED_COUNT + i"
    return f"{le.base_offset} + i*STRIDE + {wire_pos}"


def _scale_body(spec: ProtocolSpec) -> str:
    sc = spec.leds.scaling
    if sc.type == "linear":
        return f"    return clamp8((int)std::lround(v * {sc.k!r}));"
    if sc.type == "gamma":
        return (
            "    // gamma correction recovered from capture\n"
            f"    return clamp8((int)std::lround(255.0 * std::pow(v / 255.0, {sc.gamma!r})));"
        )
    return "    return clamp8(v);  // identity"


def _explicit_offset_table(spec: ProtocolSpec) -> str:
    offsets = spec.leds.explicit_offsets
    if offsets is None:
        return ""
    rows = ",\n".join(
        "            {" + ", ".join(str(v) for v in row) + "}" for row in offsets
    )
    return f"        static const int LED_OFFSETS[LED_COUNT][3] = {{\n{rows}\n        }};\n"


def _reflect_helpers(width: int, refin: bool, refout: bool) -> str:
    if not (refin or refout):
        return ""
    out = []
    if refin:
        out.append(
            "static uint8_t reflect8(uint8_t b) {\n"
            "    uint8_t r = 0;\n"
            "    for (int i = 0; i < 8; i++) if (b & (1u << i)) r |= 1u << (7 - i);\n"
            "    return r;\n"
            "}"
        )
    if refout:
        t = "uint16_t" if width == 16 else "uint8_t"
        out.append(
            f"static {t} reflect{width}({t} v) {{\n"
            f"    {t} r = 0;\n"
            f"    for (int i = 0; i < {width}; i++) if (v & (1u << i)) r |= 1u << ({width} - 1 - i);\n"
            "    return r;\n"
            "}"
        )
    return "\n".join(out) + "\n\n"


def _checksum_section(cs: ChecksumModel) -> tuple[str, str]:
    """Return (free-function definitions, in-BuildPacket apply snippet)."""
    if not cs.present or cs.offset is None or cs.range is None:
        return "", "    // (device has no checksum)\n"
    start, end = cs.range
    rng = f"&buf[{start}], {end - start}"

    if cs.kind in ("sum8", "twos8", "onescomp8", "xor8"):
        op = {
            "sum8": "sum = (uint8_t)(sum + buf[i]);",
            "twos8": "sum = (uint8_t)(sum + buf[i]);",
            "onescomp8": "sum = (uint8_t)(sum + buf[i]);",
            "xor8": "sum ^= buf[i];",
        }[cs.kind]
        final = {
            "sum8": "return sum;",
            "twos8": "return (uint8_t)(-sum);",
            "onescomp8": "return (uint8_t)(~sum);",
            "xor8": "return sum;",
        }[cs.kind]
        defn = (
            "static uint8_t Checksum(const std::vector<uint8_t>& buf) {\n"
            "    uint8_t sum = 0;\n"
            f"    for (size_t i = {start}; i < {end}; i++) {op}\n"
            f"    {final}\n"
            "}"
        )
        apply = f"    buf[{cs.offset}] = Checksum(buf);\n"
        return defn + "\n", apply

    if cs.kind == "sum16":
        defn = (
            "static uint16_t Checksum(const std::vector<uint8_t>& buf) {\n"
            "    uint16_t sum = 0;\n"
            f"    for (size_t i = {start}; i < {end}; i++) sum = (uint16_t)(sum + buf[i]);\n"
            "    return sum;\n"
            "}"
        )
        if cs.endian == "little":
            apply = (
                f"    {{ uint16_t cs = Checksum(buf);\n"
                f"      buf[{cs.offset}] = cs & 0xFF; buf[{cs.offset + 1}] = (cs >> 8) & 0xFF; }}\n"
            )
        else:
            apply = (
                f"    {{ uint16_t cs = Checksum(buf);\n"
                f"      buf[{cs.offset}] = (cs >> 8) & 0xFF; buf[{cs.offset + 1}] = cs & 0xFF; }}\n"
            )
        return defn + "\n", apply

    # CRC
    p = cs.params
    width = p["width"]
    ctype = "uint16_t" if width == 16 else "uint8_t"
    helpers = _reflect_helpers(width, p["refin"], p["refout"])
    body = [
        f"static {ctype} Checksum(const std::vector<uint8_t>& buf) {{",
        f"    // {p.get('name', 'CRC')}: poly=0x{p['poly']:X} init=0x{p['init']:X} "
        f"refin={str(p['refin']).lower()} refout={str(p['refout']).lower()} xorout=0x{p['xorout']:X}",
        f"    {ctype} crc = 0x{p['init']:X};",
        f"    for (size_t i = {start}; i < {end}; i++) {{",
        "        uint8_t b = buf[i];",
    ]
    if p["refin"]:
        body.append("        b = reflect8(b);")
    body.append(f"        crc ^= ({ctype})b << {width - 8};")
    body.append("        for (int k = 0; k < 8; k++)")
    body.append(
        f"            crc = (crc & 0x{1 << (width - 1):X}) ? "
        f"(crc << 1) ^ 0x{p['poly']:X} : (crc << 1);"
    )
    body.append("    }")
    if p["refout"]:
        body.append(f"    crc = reflect{width}(crc);")
    body.append(f"    return crc ^ 0x{p['xorout']:X};")
    body.append("}")
    defn = helpers + "\n".join(body)

    if cs.endian == "little":
        apply = (
            f"    {{ {ctype} cs = Checksum(buf);\n"
            f"      buf[{cs.offset}] = cs & 0xFF; buf[{cs.offset + 1}] = (cs >> 8) & 0xFF; }}\n"
        )
    else:
        apply = (
            f"    {{ {ctype} cs = Checksum(buf);\n"
            f"      buf[{cs.offset}] = (cs >> 8) & 0xFF; buf[{cs.offset + 1}] = cs & 0xFF; }}\n"
        )
    return defn + "\n", apply


def _raw_send_call(spec: ProtocolSpec, var: str, *, indent: str = "    ") -> str:
    if spec.transport == "hid_feature":
        return f"{indent}hid_send_feature_report(dev, {var}.data(), {var}.size());"
    if spec.transport in ("hid_output", "hid_interrupt"):
        return f"{indent}hid_write(dev, {var}.data(), {var}.size());"
    if spec.transport == "usb_control":
        return f'{indent}throw std::runtime_error("usb_control replay is not implemented");'
    return f'{indent}throw std::runtime_error("SMBus replay is not implemented");'


def _send_packet_body(spec: ProtocolSpec) -> str:
    ch = spec.chunking
    if not ch.present:
        return _raw_send_call(spec, "buf")

    capacity = ch.packet_len - ch.payload_start
    capacity_payload = capacity - (capacity % ch.unit) if ch.unit else 0
    max_payload = min(ch.chunk_count * ch.unit if ch.chunk_count else capacity_payload, capacity_payload)
    prefix_lines = "\n".join(
        f"            pkt[{i}] = 0x{b:02X};" for i, b in enumerate(ch.prefix)
    ) or "            // (no chunk prefix bytes)"
    send = _raw_send_call(spec, "pkt", indent="            ")
    return f"""    const size_t max_payload = {max_payload};
    if (max_payload == 0) throw std::runtime_error("invalid chunk payload capacity");
    for (size_t offset = 0; offset < buf.size(); offset += max_payload) {{
        const size_t payload_len = std::min(max_payload, buf.size() - offset);
        const bool last = (offset + payload_len) >= buf.size();
        std::vector<uint8_t> pkt(CHUNK_PACKET_LEN, 0x00);
{prefix_lines}
        pkt[CHUNK_CHANNEL_POS] = (uint8_t)(CHUNK_CHANNEL | (last ? CHUNK_FINAL_FLAG : 0));
        pkt[CHUNK_OFFSET_POS] = (uint8_t)(offset / CHUNK_UNIT);
        pkt[CHUNK_COUNT_POS] = (uint8_t)(payload_len / CHUNK_UNIT);
        for (size_t j = 0; j < payload_len; j++) pkt[CHUNK_PAYLOAD_START + j] = buf[offset + j];
{send}
    }}"""


def render_cpp(spec: ProtocolSpec) -> str:
    cls = _class_name(spec.name)
    cs_defs, cs_apply = _checksum_section(spec.checksum)
    le = spec.leds

    if spec.chunking.present:
        report_line = "    // (report id / command bytes live in the chunk prefix)\n"
    else:
        report_line = (
            f"    buf[0] = REPORT_ID;\n" if spec.report_id is not None else "    // (no HID report id)\n"
        )
    header_lines = "".join(
        f"    buf[{o}] = 0x{v:02X};\n" for o, v in spec.header.constant_bytes
    ) or "    // (no fixed header bytes)\n"

    # per-LED packing assignments, in wire order
    pack_lines = []
    for wire_pos, ch in enumerate(le.channel_order):
        pack_lines.append(
            f"        buf[{_led_offset_expr(spec, wire_pos)}] = "
            f"scale(RGBGet{ch}Value(colors[i]));"
        )
    pack_block = "\n".join(pack_lines)
    offset_table = _explicit_offset_table(spec)

    if spec.brightness.present and spec.brightness.offset is not None:
        b = spec.brightness
        bright_line = (
            f"    buf[{b.offset}] = clamp8((int)({b.min} + "
            f"std::lround(brightness * ({b.max} - {b.min}) / 255.0)));\n"
        )
    else:
        bright_line = "    // (no global brightness byte)\n"

    vid = f"0x{spec.vid:04X}" if spec.vid is not None else "0x0000"
    pid = f"0x{spec.pid:04X}" if spec.pid is not None else "0x0000"
    rid = f"0x{spec.report_id:02X}" if spec.report_id is not None else "0x00"

    summary = (
        f"transport={spec.transport} vid={vid} pid={pid} packet_len={spec.packet_len} "
        f"leds={le.count} layout={le.layout} order={le.channel_order} "
        f"stride={le.stride} scaling={le.scaling.type} checksum={spec.checksum.kind}"
        f"{' chunked' if spec.chunking.present else ''}"
    )
    ch = spec.chunking
    chunk_constants = ""
    if ch.present:
        chunk_constants = (
            f"    static constexpr int      CHUNK_PACKET_LEN    = {ch.packet_len};\n"
            f"    static constexpr uint8_t  CHUNK_CHANNEL       = 0x{ch.channel:02X};\n"
            f"    static constexpr uint8_t  CHUNK_FINAL_FLAG    = 0x{ch.final_flag:02X};\n"
            f"    static constexpr int      CHUNK_CHANNEL_POS   = {ch.channel_pos};\n"
            f"    static constexpr int      CHUNK_OFFSET_POS    = {ch.offset_pos};\n"
            f"    static constexpr int      CHUNK_COUNT_POS     = {ch.count_pos};\n"
            f"    static constexpr int      CHUNK_PAYLOAD_START = {ch.payload_start};\n"
            f"    static constexpr int      CHUNK_UNIT          = {ch.unit};\n"
            f"    static constexpr int      CHUNK_COUNT         = {ch.chunk_count};\n"
        )
    send_body = _send_packet_body(spec)

    return f"""// ---------------------------------------------------------------------------
// {cls}  --  generated by LumaScope
// {summary}
//
// Drop-in skeleton for a LumaCore device module. Fill in device discovery and modes;
// the packet packing below is the protocol LumaScope recovered and validated.
// ---------------------------------------------------------------------------
#include <hidapi.h>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <cmath>

#ifndef RGBGetRValue
typedef unsigned int RGBColor;          // LumaCore/OpenRGB: 0x00BBGGRR
#define RGBGetRValue(c) ((c) & 0xFF)
#define RGBGetGValue(c) (((c) >> 8) & 0xFF)
#define RGBGetBValue(c) (((c) >> 16) & 0xFF)
#endif

class {cls} {{
public:
    static constexpr uint16_t VID        = {vid};
    static constexpr uint16_t PID        = {pid};
    static constexpr uint8_t  REPORT_ID  = {rid};
    static constexpr int      LED_COUNT  = {le.count};
    static constexpr int      STRIDE     = {le.stride};
    static constexpr int      PACKET_LEN = {spec.packet_len};
{chunk_constants}

    explicit {cls}(hid_device* dev) : dev(dev) {{}}

    void UpdateLEDs(const std::vector<RGBColor>& colors, uint8_t brightness = 255) {{
        std::vector<uint8_t> buf(PACKET_LEN, 0x00);
{report_line}{header_lines}
{offset_table}
        for (int i = 0; i < LED_COUNT && i < (int)colors.size(); i++) {{
{pack_block}
        }}
{bright_line}{cs_apply}        SendPacket(buf);
    }}

private:
    hid_device* dev;

    static uint8_t clamp8(int v) {{
        return (uint8_t)(v < 0 ? 0 : (v > 255 ? 255 : v));
    }}

    static uint8_t scale(int v) {{
{_scale_body(spec)}
    }}

    {cs_defs.rstrip()}

    void SendPacket(std::vector<uint8_t>& buf) {{
{send_body}
    }}
}};
"""
