# Sample captures

Real USB traffic recorded from an **ASUS Aura motherboard controller** (`VID 0x0B05`,
`PID 0x19AF`) with the USBPcap backend while Armoury Crate drove the lighting. They are
here so you can use every read-only part of LumaScope before you have hardware, a capture
setup, or Windows.

Nothing here is synthetic. These are the captures the
[protocol write-up](../docs/asus-aura-pid19af-protocol.md) was derived from.

| File | What it is |
|---|---|
| `aura-red.frames.jsonl` | Every LED set to solid red. The clearest possible starting point: you know the intended colour, so you can find it in the bytes. |
| `aura-rainbow-fast.frames.jsonl` | The rainbow effect at its fastest speed setting. |
| `aura-rainbow-medium.frames.jsonl` | The same effect at medium speed. |
| `aura-rainbow-slow.frames.jsonl` | The same effect at its slowest speed setting. |

## Things to try

Read the packets, with every byte labelled:

```bash
lumascope show --frames samples/aura-red.frames.jsonl
```

See the colour buffer those packets add up to (120 LEDs of red across 3 channels):

```bash
lumascope show --frames samples/aura-red.frames.jsonl --leds
```

Get the whole structural report in one pass:

```bash
lumascope analyze --frames samples/aura-red.frames.jsonl
```

Compare two captures that differ by exactly one variable. The three rainbow files differ
only in the speed slider:

```bash
lumascope inspect --frames samples/aura-rainbow-fast.frames.jsonl \
    --diff samples/aura-rainbow-slow.frames.jsonl
```

Read the result carefully, because it teaches the most useful lesson in the project.
Plenty of bytes differ — but **every one of them is inside the colour payload**, which is
expected, since the two captures caught the animation at different moments. The header
(bytes 0–4: report id, command, channel, offset, count) is byte-identical between fast
and slow.

So there is no speed field. **Speed is not in the protocol at all** — the host streams
every frame itself and simply changes how fast it sends them. Confirm that positively by
measuring the timing instead:

```bash
lumascope cadence --frames samples/aura-rainbow-slow.frames.jsonl \
    samples/aura-rainbow-medium.frames.jsonl \
    samples/aura-rainbow-fast.frames.jsonl
```

The cycle period comes out around 15 s, 3 s, and 1.6 s — a 10x range — while the update
rate stays roughly constant at 9–11/s. The device is being fed at the same speed
throughout; only the size of the colour step between frames changes. Speed lives in the
host's phase increment, not on the wire.
