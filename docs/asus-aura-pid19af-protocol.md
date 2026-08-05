# ASUS AURA LED Controller - wire protocol (`VID_0B05 / PID_19AF`)

Reverse-engineered with LumaScope from a live capture on an ASUS motherboard running
Armoury Crate / Aura Sync. This is the **USB wire protocol** a native LumaCore module would
speak directly to the device (bypassing Armoury Crate entirely).

## How it was obtained

The software stack was mapped with the Frida backend, then the wire bytes were captured with
USBPcap (the in-process layers don't carry the raw bytes - see "Stack" below):

```
Armoury Crate GUI
  -> LightingService        (named pipe, JSON: {"method":"CDCSSetLedColors", colors:[AARRGGBB]})
  -> ArmouryCrate.Service    (custom kernel-driver IOCTLs 0x9c40xxxx; color passed BY REFERENCE)
  -> [kernel driver]
  -> USB control OUT         <- captured here with USBPcap (the actual wire protocol)
  -> AURA LED Controller
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
  2     channel | flag   low bits = channel index (0,1,2 = zones/headers; 4 = small zone);
                         bit 7 (0x80) set = LAST chunk for this channel
  3     LED offset       start LED index for this chunk, in LEDs (0,20,40,... in steps of 20)
  4     LED count        LEDs in this packet (0x14 = 20 for a full chunk; payload = count*3
                         bytes). The FINAL chunk of a channel is short when that channel's
                         length is not a multiple of 20 - see "Channel lengths" below.
  5..   color data       RGB, 3 bytes per LED  (wire order = Red, Green, Blue)
```

A channel update streams 20-LED chunks (60 bytes each) at increasing LED offsets; the packet
that writes the final chunk has **bit 7 set** in byte 2 (apply-on-last). Channels 0/1/2 are
addressable headers and **channel 4** (`0x84 = 0x80 | 0x04`) is a small zone written at the end
of each update. In the Armoury Crate captures below the headers carry 120 LEDs each and channel
4 carries 2, but **those lengths are configuration, not protocol** - see "Channel lengths":

```
EC 40 84 00 02 ...        (channel 4, 2 LEDs, apply bit set - closes the update)
```

> Earlier this `EC 40 84 00 02` packet was described as a standalone "commit." A later
> full-vocabulary `inspect` showed it is simply the channel-4 write carrying the `0x80` apply
> bit; there is no separate dummy commit opcode. The apply bit on the last write per update is
> the commit - which is exactly what LumaCore already does.

- **Channel order:** **RGB** - confirmed by a CONTROLLED single-color capture (board set to pure
  red -> wire triplet `ff 00 00`, i.e. red in position 0). NOTE: an earlier *passive* red->green->blue
  capture led me to wrongly conclude GRB; the controlled single-variable test corrected it. Always
  vary one thing at a time.
- **Offset/count are in LEDs, not bytes** (payload = count*3). Up to 3 addressable channels
  plus channel 4; each channel's length is whatever that machine is configured for, and a
  120-LED header is 6 full chunks (max offset 100 + 20 = 120 LEDs = 360 bytes).
- **Checksum:** none observed (direct color writes are raw RGB bytes).
- **Scaling:** identity at the wire (Armoury Crate applies brightness upstream; full red = 0xFF).

This matches LumaCore's existing `appendDirectColorReports` exactly (report 0xEC, cmd 0x40,
`(apply?0x80:0)|channel`, offset/count in LEDs, payload at byte 5, RGB, 20 LEDs/packet) - so
the capture **validates** LumaCore's implementation rather than contradicting it.

## Worked example (one channel, solid red)

```
EC 40 00 00 14  ff0000 ff0000 ff0000 ...   (chunk @ LED 0,   20 LEDs = 60 bytes)
EC 40 00 14 14  ff0000 ...                 (chunk @ LED 20)
EC 40 00 28 14  ff0000 ...                 (chunk @ LED 40)
EC 40 00 3c 14  ff0000 ...                 (chunk @ LED 60)
EC 40 00 50 14  ff0000 ...                 (chunk @ LED 80)
EC 40 80 64 14  ff0000 ...                 (chunk @ LED 100, bit7 = last)
EC 40 84 00 02  ...                        (channel 4 write, apply bit - closes the update)
```

## Channel lengths are configuration, not protocol

Every capture above came from Armoury Crate on a board whose headers were configured for 120
LEDs. 120 is 6 x 20, so *every* chunk in those captures is exactly 20 LEDs and the count byte
is effectively constant. That is a property of the configuration, not of `EC 40`.

A second capture of the **same device driven by a different host** (SignalRGB, hooked with
`lumascope capture --attach signalrgb.exe`) shows the general shape - 1,338 `EC 40` packets
over a 15.0 s window, ~268 updates:

| channel | chunks `(offset, count)` | total | apply bit |
|---|---|---|---|
| 0 | `(0,20) (20,20) (40,8)` | 48 LEDs = 144 bytes | on the `(40,8)` chunk |
| 1 | `(0,8)`                 | 8 LEDs = 24 bytes   | on its only chunk |
| 4 | `(0,4)`                 | 4 LEDs = 12 bytes   | on its only chunk |

Three things generalise from this:

- **A channel's final chunk is short** whenever its length is not a multiple of 20. Channel 0
  ends with an 8-LED chunk. Only a length that divides by 20 produces uniform counts.
- **Channel 4 is not fixed at 2 LEDs** - here it carries 4. Nor is channel 2 always present;
  this machine drives 0, 1 and 4 only.
- **The apply bit is per channel, not per update.** Each channel sets `0x80` on its own last
  chunk - 268, 268 and 267 times respectively, the odd one out being the update the capture
  window clipped - so it is that channel's write being closed, not the update as a whole.

Nothing here contradicts the Armoury Crate findings: it is the same command, the same field
layout, the same apply semantics. What changes is that count is genuinely variable.

### Why this matters when decoding

A decoder that assumes the *most common* count is the chunk size gets this device wrong. Across
the SignalRGB capture the counts are 20/8/4, and the mode is **8** - a partial chunk that no
offset stride can ever match, so framing inference finds nothing at all and reports a device
that plainly streams as "not chunked".

The chunk size is the **stride between consecutive offsets**, which is the *maximum* count, not
the modal one. LumaScope inferred no framing here until 0.2.1; the file
`tests/fixtures/aura_ec40_mixed_chunk_sizes.jsonl` is a slice of this capture, kept as the
regression case.

This is also the argument for capturing from **more than one host application**. Armoury Crate
alone could not have surfaced it, because its uniform 120-LED configuration hides the variable
that matters.

## Armoury Crate drives everything via `EC 40` - there is no native-effect command

Two controlled capture sets set out to find an "effect" protocol (an `EC 35` mode-set + `EC 36`
effect-color, by analogy with OpenRGB's mainboard path). **Neither exists in Armoury Crate.**
Across **seven** captures spanning every lighting mode the app offers - static, breathing,
color-cycle, rainbow, on both fixed and addressable zones - the **only** ASUS color command class
is `EC 40`. Armoury Crate renders every animation **in software** and streams frames:

| capture (single-variable) | ASUS command classes | what changes frame-to-frame |
|---|---|---|
| `static_red`   | `EC 40` x 171   | nothing - a constant `ff0000` buffer, re-asserted periodically |
| `breathe_red`  | `EC 40` x 2432  | the **R** byte of every LED ramps `0->...->255->...->0`; G/B stay `00` |
| `breathe_green`| `EC 40` x 2545  | the **G** byte ramps; R/B stay `00`  -> **RGB order** re-confirmed |
| `cycle`        | `EC 40` x 4119  | the whole payload cycles through hues, frame by frame |
| `rainbow`      | `EC 40` x 4367  | a spatial gradient is streamed (e.g. LED0 `97 00 ff` -> LED1 `f6 00 ff`) |
| `fixed_red`    | `EC 40` x 114   | constant `ff0000` on channels 0/1/2 (+ 2-LED channel 4) |
| `fixed_green`  | `EC 40` x 114   | constant `00ff00`  -> `fixed_red`<->`fixed_green` diff = R col <-> G col |

A raw scan of all seven files for `EC 35 / EC 36 / EC 30 / EC B0 / EC 52` returns **zero** matches.
*Static* vs *Breathing* vs *Cycle* vs *Rainbow* differ **only in the payload values streamed**,
never in a mode byte. (The recovered breathing envelope is a 42-step gamma curve:
`0,2,4,6,10,14,19,24,31,37,45,52,61,70,78,88,98,107,118,127,128,...,251,253,255`.) Even the "fixed"
zone reassembles to the same `EC 40` channels - this controller exposes no separate fixed-header
color path under Armoury Crate.

Localized with the `inspect` command (the rigorous "diff two single-variable captures"):

```bash
lumascope inspect --frames breathe_red.jsonl --diff breathe_green.jsonl   # R cols <-> G cols (RGB)
lumascope inspect --frames cycle.jsonl        --vid 0x0b05 --pid 0x19af    # only EC40, no EC35
lumascope inspect --frames fixed_red.jsonl    --diff fixed_green.jsonl     # fixed color still in EC40 payload
```

### Effect *speed* is a phase step, not a wire field

Because the effect is streamed, **speed has no byte** - it is the rate the streamed colour
advances. Capturing the rainbow at three speed-slider positions and measuring the timing
(`lumascope cadence`, which reads per-frame timestamps) shows the mechanism cleanly:

| slider | frame rate | cycle period | hue rate | hue advance per update |
|---|---|---|---|---|
| min  | 180 fps | 16.5 s | 22  deg/s  | 2.3  deg |
| mid  | 203 fps |  3.2 s | 113  deg/s | 10.6  deg |
| max  | 204 fps |  1.6 s | 222  deg/s | 20.6  deg |

Slow->fast the cycle period changes **10x** and the per-update hue step changes **~9x**, while the
stream frame rate barely moves (**1.14x**). So Armoury Crate holds a fixed ~180-200 Hz refresh and
advances the animation phase further each frame - speed is a host-side phase increment. For a
consumer that host-streams the same effect, "speed" is therefore just its animation-timer rate;
matching Armoury Crate's range means a cycle period of ~1.6 s (fast) to ~16.5 s (slow). There is no
speed payload byte to encode.

**Implication - and the limit of Armoury Crate as a reference.** Every effect on this controller is
host-side animation over the *same* `EC 40` writer this doc specifies (and that LumaCore already
implements and golden-tests). So Armoury Crate is a **direct-streaming implementation** and will
never exercise an `EC 35`/`EC 36` path, regardless of which mode is chosen - capturing it further
cannot confirm or deny that path.

This does **not** mean the controller lacks `EC 35`/`EC 36`. OpenRGB's AuraUSB controller (also
owned-hardware-derived) *does* use `EC 35` (mode), `EC 36` (effect color), and the `EC B0`/`EC 30`
config-table probe - for **hardware-persistent** effects that keep running after the app closes, a
capability Armoury Crate simply doesn't use. Validating that path on owned hardware therefore
requires a *different* reference than Armoury Crate: a capture of **OpenRGB** driving the board, or a
guarded write test from the consuming app. What these captures *do* establish is that the full
Armoury Crate feature set - all effects, fixed and addressable - is reproducible over the
already-validated `EC 40` streaming path alone.

## Note for LumaCore / LumaScope

This is a **chunked, channel-based, streamed** protocol - one logical LED state spans many
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
step into a full per-channel buffer, picks the LED-data channel, and decodes - producing a full
`ProtocolSpec` + C++ for chunked devices end-to-end (override with `--channel N` /
`--no-reassemble`).
