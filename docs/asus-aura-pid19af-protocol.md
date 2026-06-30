# ASUS AURA LED Controller — wire protocol (`VID_0B05 / PID_19AF`)

Reverse-engineered with LumaScope from a live capture on an ASUS motherboard running
Armoury Crate / Aura Sync. This is the **USB wire protocol** a native LumaCore module would
speak directly to the device (bypassing Armoury Crate entirely).

## How it was obtained

The software stack was mapped with the Frida backend, then the wire bytes were captured with
USBPcap (the in-process layers don't carry the raw bytes — see "Stack" below):

```
Armoury Crate GUI
  → LightingService        (named pipe, JSON: {"method":"CDCSSetLedColors", colors:[AARRGGBB]})
  → ArmouryCrate.Service    (custom kernel-driver IOCTLs 0x9c40xxxx; color passed BY REFERENCE)
  → [kernel driver]
  → USB control OUT         ← captured here with USBPcap (the actual wire protocol)
  → AURA LED Controller
```

## Transport

- **Device:** USB `VID_0B05 PID_19AF`, "AURA LED Controller" (composite; the controller is
  interface `MI_00`).
- **Endpoint:** control OUT transfers, **65-byte** reports.
- **Report ID:** `0xEC`.

## Direct LED color command (`0x40`)

```
offset  field            value / meaning
------  ---------------  ------------------------------------------------------------
  0     report id        0xEC
  1     command          0x40   (direct LED color)
  2     channel | flag   low bits = channel index (0,1,2 = three zones/headers);
                         bit 7 (0x80) set = LAST chunk for this channel
  3     LED offset       start LED index for this chunk, in LEDs (0,20,40,60,80,100)
  4     LED count        LEDs in this packet, in LEDs (0x14 = 20; payload = count*3 bytes)
  5..   color data       RGB, 3 bytes per LED  (wire order = Red, Green, Blue)
```

A full channel update streams 20-LED chunks (60 bytes each) at increasing LED offsets; the
packet that writes the final chunk has **bit 7 set** in byte 2. After all channels are
streamed, an apply/commit is sent:

```
EC 40 84 00 02 ...        (0x84 = commit; observed once per full update)
```

- **Channel order:** **RGB** — confirmed by a CONTROLLED single-color capture (board set to pure
  red → wire triplet `ff 00 00`, i.e. red in position 0). NOTE: an earlier *passive* red→green→blue
  capture led me to wrongly conclude GRB; the controlled single-variable test corrected it. Always
  vary one thing at a time.
- **Offset/count are in LEDs, not bytes** (payload = count*3). 3 channels, up to ~120 LEDs each
  (max offset 100 + 20 = 120 LEDs = 360 bytes).
- **Checksum:** none observed (direct color writes are raw RGB bytes).
- **Scaling:** identity at the wire (Armoury Crate applies brightness upstream; full red = 0xFF).

This matches LumaCore's existing `appendDirectColorReports` exactly (report 0xEC, cmd 0x40,
`(apply?0x80:0)|channel`, offset/count in LEDs, payload at byte 5, RGB, 20 LEDs/packet) — so
the capture **validates** LumaCore's implementation rather than contradicting it.

## Worked example (one channel, solid red)

```
EC 40 00 00 14  ff0000 ff0000 ff0000 ...   (chunk @ LED 0,   20 LEDs = 60 bytes)
EC 40 00 14 14  ff0000 ...                 (chunk @ LED 20)
EC 40 00 28 14  ff0000 ...                 (chunk @ LED 40)
EC 40 00 3c 14  ff0000 ...                 (chunk @ LED 60)
EC 40 00 50 14  ff0000 ...                 (chunk @ LED 80)
EC 40 80 64 14  ff0000 ...                 (chunk @ LED 100, bit7 = last)
EC 40 84 00 02  ...                        (commit)
```

## Note for LumaCore / LumaScope

This is a **chunked, channel-based, streamed** protocol — one logical LED state spans many
packets. LumaScope's core `decode` engine models single-packet-per-state protocols, so the
**chunked-reassembly pass** (`lumascope/decode/chunked.py`) bridges the gap: it infers the
chunk framing from a raw capture and reassembles the chunks into dense per-channel buffers,
which then feed the normal field/stride/encoding analysis.

Reproduce the reassembly from a capture:

```bash
lumascope reassemble --frames aura_red.jsonl --triplets
# -> framing: prefix=ec40 channel@2(mask 0x7f) offset@3 count@4 payload@5
#    channel 0/1/2: 360 bytes (~120 LEDs, all ff0000)   channel 4: commit
```

`infer_framing` recovered this exact layout autonomously from the real capture. The reassembly
is also wired into the **sweep** path: `sweep --decode` auto-detects chunking, reassembles each
step into a full per-channel buffer, picks the LED-data channel, and decodes — producing a full
`ProtocolSpec` + C++ for chunked devices end-to-end (override with `--channel N` /
`--no-reassemble`).
