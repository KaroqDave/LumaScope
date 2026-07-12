# Code review — multi-target chunked encoding, `usb_control` replay, Frida child-following

**Scope:** last commit `HEAD~1..HEAD` (`feat: add capture analysis and multi-channel replay`) plus the
uncommitted working-tree changes to `lumascope/capture/agent.js` and `lumascope/capture/frida_backend.py`.

**Method:** 9 finder angles → 1-vote/3-state verification → gap sweep, at extra-high effort (recall mode).
15 findings survived. One candidate (agent.js double-*capture* on non-JMP kernel32↔KernelBase aliases) was
**refuted** for modern x64, because export forwarders and `jmp`-thunks are already collapsed; the related
trampoline re-hook survives as finding 6.

**Legend:** Verdict is `CONFIRMED` (inputs + wrong output/crash named) or `PLAUSIBLE` (mechanism real,
trigger timing/config/edge-dependent).

## Summary

| # | File:line | Severity | Verdict | One-liner |
|---|-----------|----------|---------|-----------|
| 1 | codec.py:213 | High | CONFIRMED | Unconditional full-frame encode crashes multi-target specs |
| 2 | emit/openrgb_cpp.py:405 | High | CONFIRMED | Generated multi-target C++ writes out of bounds |
| 3 | capture/frida_backend.py:167 | High | CONFIRMED | Gated child resumed unconditionally → data loss / orphan |
| 4 | emit/openrgb_cpp.py:399 | Med-High | CONFIRMED | Multi-target C++ omits explicit-offset table → won't compile |
| 5 | codec.py:244 | Medium | CONFIRMED | Per-target sub_spec keeps full-frame checksum/brightness offsets |
| 6 | capture/agent.js:301 | Medium | PLAUSIBLE | Hook dedup can re-attach inside a Frida trampoline |
| 7 | analyze.py:38 | Medium | CONFIRMED | Cadence reads hardcoded Aura columns, not inferred framing |
| 8 | emit/openrgb_cpp.py:374 | Low-Med | CONFIRMED | `_update_body` branches on `targets` vs siblings' `present` |
| 9 | codec.py:243 | Low | PLAUSIBLE | Falsy-zero `payload_len` diverges from C++ |
| 10 | codec.py:73 | Low | PLAUSIBLE | `logical_payload_len` `max()` on empty offsets → ValueError |
| 11 | analyze.py:38 | Low | PLAUSIBLE | `--direction in\|any` ignored by 2 of 3 report sections |
| 12 | capture/frida_backend.py:157 | Cleanup | — | `_state_lock` held across blocking Frida IPC |
| 13 | emit/openrgb_cpp.py:65 | Cleanup | — | `_logical_payload_len` duplicates `codec.logical_payload_len` |
| 14 | capture/frida_backend.py:139 | Cleanup | — | Dead write-only `self._session`/`self._script` |
| 15 | replay.py:147 | Cleanup | — | `_w_value` duplicates emitted wValue logic and has drifted |

---

## Correctness

### 1. `encode_packets` crashes on valid multi-target specs — `lumascope/codec.py:213` · CONFIRMED

`frame = encode_frame(spec, colors, …)` runs unconditionally at the top of `encode_packets`, but in the
`if ch.targets:` branch that `frame` is discarded — each target builds its own buffer via
`encode_chunk_target_payload`. For a multi-target spec the top-level `spec.packet_len` is vestigial, so it is
commonly left small or at the default `0`.

- **Failure:** `encode_frame` allocates `bytearray(spec.packet_len)` and writes per-LED/header bytes at
  `spec.leds`-derived offsets. A multi-target spec with `packet_len` smaller than
  `logical_payload_len(spec.leds, spec.leds.count)` (e.g. the default `0`) raises
  `IndexError: bytearray index out of range` on the header/first-LED write — *before any target is emitted* —
  even though every per-target payload is independently valid. Reached via
  `build_replay_sequence → _replay_step → encode_packets`.
- **Why the tests miss it:** the multi-target test inherits `packet_len=24` from `no_checksum_identity()`,
  which happens to be large enough for its 6 LEDs.
- **Fix:** compute `frame` only inside the two branches that use it (`if not ch.present:` and the final
  single-target return), so the multi-target path never evaluates it.

### 2. Generated multi-target C++ writes out of bounds — `lumascope/emit/openrgb_cpp.py:405` · CONFIRMED

The multi-target branch of `_update_body` sizes `std::vector<uint8_t> buf(target.payload_len, 0x00)`
(line 399 — the small per-target LED region) but the interpolated `{header_lines}` (line 400) and
`{bright_line}{cs_apply}` (line 405) index `buf[...]` at full-frame **absolute** offsets — the same strings
the non-target branch uses against a `PACKET_LEN`-sized buffer.

- **Failure:** any multi-target spec whose header constant offset, `brightness.offset`, or checksum
  `offset`/`range` end lands `>= target.payload_len` produces `std::vector::operator[]` access past
  `buf.size()` → undefined behaviour / heap corruption in the shipped controller (unchecked `operator[]`,
  not `.at()`).
- **Fix:** size the per-target buffer to include the trailing header/brightness/checksum region, or
  recompute those offsets relative to the target buffer.

### 3. Gated child resumed unconditionally → data loss or orphaned process — `lumascope/capture/frida_backend.py:167` · CONFIRMED

`_on_child_added` calls `self._device.resume(pid)` in a `finally`, so the gated child is always released:

- **(a) Instrumentation failure (data loss):** if `_instrument_process(pid)` throws (child exits during
  attach, or the agent script fails to load in that child), the `except` only appends an `error` log line and
  the `finally` still resumes the child → it runs **uninstrumented** and all its device I/O is silently lost,
  defeating the documented child-gating invariant. `capture()` can still report success from other pids.
- **(b) Close race (orphan):** `close()` calls `self._device.off("child-added", …)` *before* taking the lock,
  then snapshots `pids = list(self._spawned_pids)` and kills only that snapshot. A `child-added` already
  dispatched on Frida's reactor thread before `off()` can run *after* the snapshot: it adds the pid too late,
  skips instrumentation (`_closing` is True), but still resumes the child → an uninstrumented process that is
  never killed, violating `kill_on_close`.
- **Fix:** only `resume` on successful instrumentation (leave a failed/late child gated so `kill` can still
  terminate it); have `close()` re-snapshot and kill pids added after `_closing` was set.

### 4. Multi-target C++ omits the explicit-offset table — `lumascope/emit/openrgb_cpp.py:399` · CONFIRMED

The multi-target branch never interpolates `{offset_table}` (only the non-target branch does, at line 377).
But `target_pack = _pack_block(spec, …)` emits `buf[LED_OFFSETS[i][k]] = …` whenever
`spec.leds.explicit_offsets is not None` (via `_led_offset_expr`).

- **Failure:** a spec with `explicit_offsets` **and** `chunking.targets` (a matrix keyboard split into zones)
  generates C++ that references an undeclared `LED_OFFSETS` array → does not compile. Python's
  `encode_chunk_target_payload` handles that combination, so emit and codec diverge.
- **Fix:** interpolate `offset_table` into the multi-target branch too (or factor a shared "pack colors into
  buf" emitter that carries its own offset-table dependency).

### 5. Per-target `sub_spec` keeps full-frame checksum/brightness/header offsets — `lumascope/codec.py:244` · CONFIRMED (low trigger)

`encode_chunk_target_payload` builds `sub_spec = replace(spec, report_id=None, packet_len=payload_len,
leds=layout, chunking=replace(…present=False, targets=[]))` — it shrinks `packet_len` to the per-target size
but inherits `spec.checksum`, `spec.brightness`, and `spec.header.constant_bytes` unchanged.

- **Failure:** a multi-target chunked spec with any of those set beyond a target's `payload_len` →
  `encode_frame` either raises `IndexError` (integer-index write for header/brightness) or **silently
  misplaces the checksum**: `buf[cs.offset : cs.offset+width] = …` is a slice assignment, which past the end
  *appends* and grows the buffer, producing a wrong-length, wrong-position wire packet with no error.
- **Trigger likelihood:** low for the motivating ASUS Aura case (its logical payload is pure RGB; the header
  lives in the chunk prefix), but the silent-corruption path is the dangerous one if a decoded/hand-authored
  spec ever carries those fields.
- **Fix:** when building `sub_spec`, clear/relocate checksum, brightness, and header offsets that fall outside
  the per-target payload.

### 6. Hook dedup ignores already-hooked intermediate hops → trampoline re-attach — `lumascope/capture/agent.js:301` · PLAUSIBLE

`claimFileExport` checks the export's raw address and its **final** resolved target against
`hookedFileExports`; `resolveExportTarget` never inspects the addresses it walks *through*.

- **Failure:** in the early-spawn ordering where the synchronous `WATCHED.forEach` sees neither DLL and the
  module observer hooks `kernelbase.dll` before `kernel32.dll` (dependency order), resolving the
  `kernel32!WriteFile` `jmp`-thunk follows KernelBase's already-rewritten prologue *into Frida's trampoline*.
  The final target is the trampoline (not in the dedup set — the stored key is the real KernelBase address),
  so a second `Interceptor.attach` lands inside the trampoline. This is worse than a duplicate frame: the
  file's own comment notes double-attach "breaks Frida's onLeave handling" → expect corruption/crash.
- **Masked when:** in attach mode, or any spawn where both DLLs are already mapped when the sync loop runs,
  the deterministic kernel32-first order makes `claimFileExport` short-circuit on the raw-key check.
- **Fix:** also check each intermediate hop in `resolveExportTarget` against `hookedFileExports`, or record
  every hop's address as claimed.

### 7. `analyze` cadence reads hardcoded Aura columns, not the inferred framing — `lumascope/analyze.py:38` · CONFIRMED

`analyze_frames` gets `framing` back from `reassemble_capture` (line 33) with inferred
`channel_pos`/`offset_pos`/`payload_start`/`channel_mask`, but then calls
`analyze_cadence(frames, channel=channel, vid=vid, pid=pid)` (line 38) without those positions, so cadence
falls back to its ASUS-Aura defaults (2 / 3 / 5).

- **Failure:** for any device whose inferred framing differs from Aura defaults, the "Chunking" section prints
  the correct inferred layout while "Cadence" reads hue/offset from the wrong byte columns and reports garbage
  cycle-period / hue-rate numbers with no error. The two passes also key their dominant command class
  differently (chunked uses `(len, b0, b1)`; cadence uses `(b0, b1)`), so they can report different commands.
- **Fix:** thread `framing.channel_pos`/`offset_pos`/`payload_start`/`channel_mask` into `analyze_cadence`
  (it already accepts them as parameters).

### 8. `_update_body` branches on `targets` while siblings gate on `present` — `lumascope/emit/openrgb_cpp.py:374` · CONFIRMED (malformed-spec trigger)

`_update_body` selects its multi-target body with `if not spec.chunking.targets`, but `send_signature`
(lines 302–304) uses `ch.present and ch.targets`, and `_send_packet_body` (line 211) plus `chunk_constants`
(line 278) gate on `ch.present`.

- **Failure:** a spec with `chunking.present == False` and a non-empty `chunking.targets` list (constructible
  via `spec_from_dict` — no validation clears it) emits a 2-arg `SendPacket(buf, target.channel)` call against
  the 1-arg `void SendPacket(std::vector<uint8_t>& buf)` declaration → C++ arity mismatch, won't compile.
  Python's `encode_packets` returns early on `not ch.present` and ignores `targets`, so the two also diverge.
- **Fix:** make `_update_body` gate on `ch.present and ch.targets` like its siblings, or normalize/reject
  `present=False` + non-empty `targets` when loading a spec.

### 9. Falsy-zero `payload_len` — `lumascope/codec.py:243` · PLAUSIBLE (low trigger)

`payload_len = target.payload_len or logical_payload_len(...)` treats an explicit `payload_len == 0` as unset
and recomputes, while the C++ emitter uses `t.payload_len if t.payload_len is not None else …`. A zero-length
target diverges between the reference codec and the generated controller. **Fix:** use
`target.payload_len if target.payload_len is not None else logical_payload_len(...)`.

### 10. `logical_payload_len` unguarded `max()` on empty offsets — `lumascope/codec.py:73` · PLAUSIBLE (low trigger)

`max(max(row) for row in layout.explicit_offsets[:count]) + 1` raises
`ValueError: max() arg is an empty sequence` when `explicit_offsets` is an empty list with `count > 0`
(reachable because the `count <= 0` guard runs first). The C++ twin `_logical_payload_len` guards this with
`if rows else 0`. **Fix:** guard the empty case (and reconcile with the C++ twin — see finding 13).

### 11. `--direction in|any` is honored only by command grouping — `lumascope/analyze.py:38` · PLAUSIBLE (UX)

`analyze_frames` passes `direction` to `group_frames`, but `reassemble_capture` (via
`dominant_command_class`) and `analyze_cadence` hardcode `direction == "out"`. So `--direction in` or
`--direction any` is silently ignored by two of the three report sections. (The CLI arg's help text scopes it
to grouping, so this is a UX inconsistency more than a hard bug.) **Fix:** thread `direction` into all three
passes, or document the scope in the help text.

---

## Cleanup / efficiency

### 12. `_state_lock` held across blocking Frida IPC — `lumascope/capture/frida_backend.py:157`

`_on_child_added` holds `self._state_lock` across `_instrument_process` (attach → create_script → `load()`)
and `resume()`. Child instrumentation is fully serialized, and any concurrent `close()`/message handler that
needs the lock blocks for the entire per-child script load. Only the small dict store needs the lock.

### 13. `_logical_payload_len` duplicates `codec.logical_payload_len` — `lumascope/emit/openrgb_cpp.py:65`

Same buffer-length formula, second copy (`openrgb_cpp` does not import `codec`). They already diverge on the
`led_count <= 0` + `explicit_offsets` ordering, and the emitted C++ buffer size must match the reference
codec. Prefer `from ..codec import logical_payload_len` and call `logical_payload_len(spec.leds, led_count)`.

### 14. Dead write-only `self._session` / `self._script` — `lumascope/capture/frida_backend.py:139`

The singular fields are only ever assigned (lines 70–71, 139–140, 147–148, 281, 295) and never read — now
redundant with the `_sessions`/`_scripts` dicts. Every mutation site must keep both in sync (via
`if pid == self._pid` guards and extra None-assignments) for no benefit. Delete them, or derive a primary as
`self._scripts.get(self._pid)`.

### 15. `_w_value` duplicates the emitted wValue convention and has drifted — `lumascope/replay.py:147`

`(0x03 << 8) | (report_id & 0xFF)` re-implements the C++ `0x0300 | buf[0]` in `_raw_send_call`, with no shared
constant. They have drifted: Python derives the low byte from `spec.report_id` (fallback `data[0]`), the
emitted C++ uses `buf[0]` directly. For a chunked `usb_control` spec where `buf[0]` is the chunk-prefix byte
and `report_id` is set, the offline verifier and the shipped controller send different control setups from the
same spec.

---

*Findings 2, 4, and 8 were re-verified against the current `lumascope/emit/openrgb_cpp.py` source during a
fact-check pass.*
