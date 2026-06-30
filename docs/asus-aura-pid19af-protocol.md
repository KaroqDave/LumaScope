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
packet that writes the final chunk has **bit 7 set** in byte 2 (apply-on-last). Channels 0/1/2
are the three 120-LED addressable headers; **channel 4** (`0x84 = 0x80 | 0x04`) is a small
**2-LED zone** written at the end of each update:

```
EC 40 84 00 02 ...        (channel 4, 2 LEDs, apply bit set — closes the update)
```

> Earlier this `EC 40 84 00 02` packet was described as a standalone "commit." A later
> full-vocabulary `inspect` showed it is simply the channel-4 write carrying the `0x80` apply
> bit; there is no separate dummy commit opcode. The apply bit on the last write per update is
> the commit — which is exactly what LumaCore already does.

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

## Effects are host-streamed — there is no native colored-effect command

A second controlled capture set out to find the "effect" protocol (an `EC 35` mode-set +
`EC 36` effect-color, by analogy with OpenRGB's mainboard path). **It found neither.** On an
**addressable** header, *Breathing* and even *Static* are both driven entirely over the already-
known `EC 40` direct-color path — Armoury Crate renders the animation **in software** and streams
frames:

| capture (single-variable) | outbound command classes | what changes frame-to-frame |
|---|---|---|
| `breathe_red`  | `EC 40` × **2432** | the **R** byte of every LED ramps `0→…→255→…→0`; G/B stay `00` |
| `breathe_green`| `EC 40` × 2399     | the **G** byte ramps; R/B stay `00`  → **RGB order** re-confirmed |
| `static_red`   | `EC 40` × **171**  | nothing — a constant `ff0000` buffer, re-asserted periodically |

No `EC 35` and no `EC 36` packet appears in any capture. *Static* vs *Breathing* differ **only in
the payload values streamed**, never in a mode byte. The recovered breathing brightness envelope is
a 42-step gamma curve: `0,2,4,6,10,14,19,24,31,37,45,52,61,70,78,88,98,107,118,127,128,137,…,251,253,255`.

This was localized with the `inspect` command (the rigorous "diff two single-variable captures"):

```bash
lumascope inspect --frames breathe_red.jsonl --vid 0x0b05 --pid 0x19af          # only EC40 present
lumascope inspect --frames breathe_red.jsonl --diff breathe_green.jsonl         # R cols ↔ G cols
lumascope inspect --frames static_red.jsonl  --diff breathe_red.jsonl           # steady vs ramped payload
```

**Implication.** Colored breathing on these addressable channels is not a missing/native protocol —
it is host-side animation over the *same* `EC 40` writer this doc already specifies (and that
LumaCore already implements and golden-tests). The only "unlock" needed is a streaming animation
loop, which is a product/scope choice, not a reverse-engineering gap. **Still uncaptured** (a
different experiment, on a *fixed* RGB header): whether fixed headers use `EC 35`/`EC 36`, and how
the autonomous hardware effects (color-cycle `0x04`, rainbow `0x05`) are commanded.

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
#    channel 0/1/2: 360 bytes (~120 LEDs, all ff0000)   channel 4: 6 bytes (2-LED zone)
```

`infer_framing` recovered this exact layout autonomously from the real capture. The reassembly
is also wired into the **sweep** path: `sweep --decode` auto-detects chunking, reassembles each
step into a full per-channel buffer, picks the LED-data channel, and decodes — producing a full
`ProtocolSpec` + C++ for chunked devices end-to-end (override with `--channel N` /
`--no-reassemble`).
