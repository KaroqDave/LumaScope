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
- **Offset/count are in LEDs, not bytes** (payload = count*3). 3 channels, up to ~120 LEDs each
  (max offset 100 + 20 = 120 LEDs = 360 bytes).
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
