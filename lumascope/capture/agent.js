'use strict';

/*
 * LumaScope Frida capture agent.
 *
 * Injected into a target process (the vendor RGB app or, more usually, its background
 * service) it hooks the Win32 calls that carry RGB packets to the device and ships each
 * buffer to the Python host over Frida's binary `send(meta, ArrayBuffer)` channel.
 *
 * Hook set (from the RE research, validated against a local harness):
 *   - WriteFile / DeviceIoControl / ReadFile: hook every unique kernel32 and KernelBase
 *     export address. Some Windows builds expose distinct entry points, while others alias
 *     them; address-level hook deduplication handles both cases without duplicate frames.
 *   - HidD_SetFeature / HidD_SetOutputReport / HidD_GetFeature (hid.dll).
 *   - WinUsb_WritePipe / WinUsb_ControlTransfer (winusb.dll). Their handle is an *interface*
 *     handle, so WinUsb_Initialize chains interface-handle -> device-handle -> VID:PID, and
 *     WinUsb_Free evicts it.
 *   - CreateFileW/A build the HANDLE -> path -> VID:PID map; CloseHandle/NtClose evict it so a
 *     recycled HANDLE value can't mislabel a later unrelated write.
 *
 * Config (injected by the host as the global `LUMASCOPE_CONFIG`):
 *   { vid, pid, keepUnmapped, maxLen }  -- all optional.
 *
 * frida 17 API notes (verified on 17.15.3): exports resolve module-scoped
 * (`Process.findModuleByName(n).getExportByName(s)`); buffers read with `ptr.readByteArray(n)`;
 * lazily-loaded DLLs hooked via `Process.attachModuleObserver` (which also fires onAdded for
 * already-loaded modules -> guard against double-hooking, which breaks onLeave).
 */

const CFG = (typeof LUMASCOPE_CONFIG !== 'undefined') ? LUMASCOPE_CONFIG : {};
const TARGET_VID = (CFG.vid !== undefined && CFG.vid !== null) ? CFG.vid : null;
const TARGET_PID = (CFG.pid !== undefined && CFG.pid !== null) ? CFG.pid : null;
const KEEP_UNMAPPED = (CFG.keepUnmapped !== false);   // default true (attach-to-running case)
const MAX_LEN = CFG.maxLen || 65536;

const INVALID_HANDLE = ptr('-1');

function log(msg) { send({ type: 'log', msg: String(msg) }); }

function exportOf(mod, sym) {
  try { if (typeof mod.getExportByName === 'function') return mod.getExportByName(sym); } catch (e) {}
  try { if (typeof mod.findExportByName === 'function') return mod.findExportByName(sym); } catch (e) {}
  return null;
}

// PE exports may be tiny unconditional-jump thunks. Resolve the common x64 forms before
// deduplicating so kernel32 -> KernelBase aliases get one interceptor, while genuinely distinct
// implementations still each get hooked. Check every hop before reading its prologue: an
// interceptor installed through an earlier export may already have rewritten that prologue.
function resolveExportTarget(addr, isClaimed) {
  if (!addr) return { target: null, hops: [] };
  let current = addr;
  const seen = new Set();
  const hops = [];
  try {
    for (let depth = 0; depth <= 4; depth++) {
      const key = current.toString();
      if (seen.has(key)) break;
      seen.add(key);
      if (isClaimed(current)) return { target: null, hops: hops };
      hops.push(current);
      if (Process.arch !== 'x64' || depth === 4) break;
      const op = current.readU8();
      if (op === 0xff && current.add(1).readU8() === 0x25) { // jmp qword ptr [rip+rel32]
        const displacement = current.add(2).readS32();
        current = current.add(6 + displacement).readPointer();
      } else if (op === 0xe9) {                              // jmp rel32
        current = current.add(5 + current.add(1).readS32());
      } else {
        break;
      }
    }
  } catch (e) {
    // Falling back to the export itself is safe; retain every address already visited so a
    // later alias cannot walk through an interceptor installed by this claim.
    return { target: addr, hops: hops.length ? hops : [addr] };
  }
  return { target: current, hops: hops };
}

// --------------------------------------------------------------------------- //
// HANDLE -> {path, vid, pid} correlation
// --------------------------------------------------------------------------- //
const handleMap = {};         // CreateFile handle string -> {path, vid, pid}
const winusbIface = {};        // WinUSB interface handle string -> device handle string

function parseVidPid(path) {
  const out = { vid: null, pid: null };
  if (!path) return out;
  const low = path.toLowerCase();
  let m = low.match(/vid[_&]?([0-9a-f]{4})/);
  if (m) out.vid = parseInt(m[1], 16);
  m = low.match(/pid[_&]?([0-9a-f]{4})/);
  if (m) out.pid = parseInt(m[1], 16);
  return out;
}

function infoFor(handleStr) {
  if (handleMap[handleStr]) return handleMap[handleStr];
  const dev = winusbIface[handleStr];          // WinUSB interface handle -> device handle
  if (dev && handleMap[dev]) return handleMap[dev];
  return { path: null, vid: null, pid: null };
}

function evict(handleStr) {
  if (handleMap[handleStr]) { delete handleMap[handleStr]; }
  if (winusbIface[handleStr]) { delete winusbIface[handleStr]; }
}

function passesFilter(info) {
  if (TARGET_VID === null && TARGET_PID === null) return true;     // no filter -> keep all
  if (info.vid === null && info.pid === null) return KEEP_UNMAPPED; // unknown handle
  if (TARGET_VID !== null && info.vid !== TARGET_VID) return false;
  if (TARGET_PID !== null && info.pid !== TARGET_PID) return false;
  return true;
}

function emit(api, transfer, direction, handleStr, abuf, n, extra) {
  if (abuf === null) { log(api + ' unreadable buffer @ handle ' + handleStr); return; }
  const info = infoFor(handleStr);
  if (!passesFilter(info)) return;
  const meta = {
    type: 'frame', api: api, transfer: transfer, direction: direction || 'out',
    handle: handleStr, path: info.path, vid: info.vid, pid: info.pid, n: n,
  };
  if (extra) for (const k in extra) meta[k] = extra[k];
  send(meta, abuf);
}

// --------------------------------------------------------------------------- //
// CreateFile / CloseHandle (handle map lifecycle)
// --------------------------------------------------------------------------- //
function hookCreateFile(mod, sym, wide, target) {
  const addr = target || exportOf(mod, sym);
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      try { this.path = wide ? args[0].readUtf16String() : args[0].readAnsiString(); }
      catch (e) { this.path = null; }
    },
    onLeave(retval) {
      if (!this.path) return;
      if (retval.isNull() || retval.equals(INVALID_HANDLE)) return;
      const low = this.path.toLowerCase();
      // Only track device paths (HID/USB); ignore ordinary file opens.
      if (low.indexOf('hid#') === -1 && low.indexOf('usb#') === -1 &&
          low.indexOf('vid_') === -1 && low.indexOf('vid&') === -1) return;
      const vp = parseVidPid(this.path);
      handleMap[retval.toString()] = { path: this.path, vid: vp.vid, pid: vp.pid };
    },
  });
  log('hooked ' + mod.name + '!' + sym);
}

function hookClose(fileMod) {
  const ch = claimFileExport('CloseHandle', exportOf(fileMod, 'CloseHandle'));
  if (ch) {
    Interceptor.attach(ch, { onEnter(args) { evict(args[0].toString()); } });
    log('hooked ' + fileMod.name + '!CloseHandle');
  }
  // NtClose catches closes that bypass kernel32/KernelBase.
  const ntdll = Process.findModuleByName('ntdll.dll');
  if (ntdll) {
    const nc = claimFileExport('NtClose', exportOf(ntdll, 'NtClose'));
    if (nc) {
      Interceptor.attach(nc, { onEnter(args) { evict(args[0].toString()); } });
      log('hooked ntdll!NtClose');
    }
  }
}

// --------------------------------------------------------------------------- //
// Buffer hooks (writes captured at onEnter, reads at onLeave). Over-length
// transfers are truncated to MAX_LEN and flagged rather than dropped.
// --------------------------------------------------------------------------- //
function hookWrite(label, addr, spec) {
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        const full = args[spec.lenIdx].toUInt32();
        if (full <= 0) return;
        const n = full > MAX_LEN ? MAX_LEN : full;
        const abuf = args[spec.bufIdx].readByteArray(n);
        const handleStr = args[spec.handleIdx !== undefined ? spec.handleIdx : 0].toString();
        const extra = {};
        if (spec.pipeIdx !== undefined) extra.endpoint = args[spec.pipeIdx].toInt32() & 0xff;
        if (spec.ioctlIdx !== undefined) extra.ioctl = args[spec.ioctlIdx].toUInt32() >>> 0;
        if (full > MAX_LEN) { extra.truncated = true; extra.full_len = full; }
        emit(spec.api, spec.transfer, 'out', handleStr, abuf, full, extra);
      } catch (e) { log(spec.api + ' onEnter err ' + e.message); }
    },
  });
  log('hooked ' + label + ' @ ' + addr);
  return true;
}

function hookRead(label, addr, spec) {
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter(args) {
      this.buf = args[spec.bufIdx];
      this.handleStr = args[spec.handleIdx !== undefined ? spec.handleIdx : 0].toString();
      this.lenPtr = spec.lenPtrIdx !== undefined ? args[spec.lenPtrIdx] : null;
      this.fixedLen = spec.lenIdx !== undefined ? args[spec.lenIdx].toUInt32() : 0;
    },
    onLeave(retval) {
      try {
        if (retval.isNull()) return;        // failed call
        // Reads only matter on device handles; gating here avoids capturing (huge) reads of
        // ordinary files. In attach mode a pre-injection device handle is unmapped, so device
        // input reports may be missed -- a documented limitation (prefer spawn mode for reads).
        if (spec.onlyMapped && infoFor(this.handleStr).path === null) return;
        let full = this.fixedLen;
        if (this.lenPtr && !this.lenPtr.isNull()) full = this.lenPtr.readU32();
        if (full <= 0) return;
        const n = full > MAX_LEN ? MAX_LEN : full;
        const abuf = this.buf.readByteArray(n);
        const extra = full > MAX_LEN ? { truncated: true, full_len: full } : null;
        emit(spec.api, spec.transfer, 'in', this.handleStr, abuf, full, extra);
      } catch (e) { log(spec.api + ' onLeave err ' + e.message); }
    },
  });
  log('hooked ' + label + ' @ ' + addr);
  return true;
}

// --------------------------------------------------------------------------- //
// WinUSB interface-handle correlation + control transfers
// --------------------------------------------------------------------------- //
function hookWinusbInitialize(mod) {
  const addr = exportOf(mod, 'WinUsb_Initialize');
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) { this.devHandle = args[0].toString(); this.outPtr = args[1]; },
    onLeave(retval) {
      try {
        if (retval.toInt32() === 0) return;          // FALSE
        if (this.outPtr.isNull()) return;
        winusbIface[this.outPtr.readPointer().toString()] = this.devHandle;
      } catch (e) {}
    },
  });
  log('hooked ' + mod.name + '!WinUsb_Initialize');
}

function hookWinusbFree(mod) {
  const addr = exportOf(mod, 'WinUsb_Free');
  if (!addr) return;
  Interceptor.attach(addr, { onEnter(args) { delete winusbIface[args[0].toString()]; } });
  log('hooked ' + mod.name + '!WinUsb_Free');
}

// WinUsb_ControlTransfer(Iface, WINUSB_SETUP_PACKET by value, Buffer, Length, *Transferred, Ovl)
// The 8-byte setup packet is passed by value in a register (RDX) on x64 -- read it as a value,
// not a pointer. Direction comes from bmRequestType bit 7 (1 = device->host).
function hookWinusbControl(mod) {
  const addr = exportOf(mod, 'WinUsb_ControlTransfer');
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        const v = args[1];
        const lo = v.and(0xffffffff).toUInt32() >>> 0;
        const hi = v.shr(32).and(0xffffffff).toUInt32() >>> 0;
        const bytes = [lo & 0xff, (lo >>> 8) & 0xff, (lo >>> 16) & 0xff, (lo >>> 24) & 0xff,
                       hi & 0xff, (hi >>> 8) & 0xff, (hi >>> 16) & 0xff, (hi >>> 24) & 0xff];
        this.setupHex = bytes.map((b) => ('0' + b.toString(16)).slice(-2)).join('');
        this.isIn = (bytes[0] & 0x80) !== 0;
        this.handleStr = args[0].toString();
        this.buf = args[2];
        this.full = args[3].toUInt32();
        if (!this.isIn && this.full > 0) {           // OUT: data valid now
          const n = this.full > MAX_LEN ? MAX_LEN : this.full;
          const extra = { setup: this.setupHex };
          if (this.full > MAX_LEN) { extra.truncated = true; extra.full_len = this.full; }
          emit('WinUsb_ControlTransfer', 'control', 'out', this.handleStr, this.buf.readByteArray(n), this.full, extra);
        }
      } catch (e) { log('WinUsb_ControlTransfer onEnter err ' + e.message); }
    },
    onLeave(retval) {
      try {
        if (!this.isIn || retval.toInt32() === 0 || this.full <= 0) return;  // IN, succeeded
        const n = this.full > MAX_LEN ? MAX_LEN : this.full;
        const extra = { setup: this.setupHex };
        if (this.full > MAX_LEN) { extra.truncated = true; extra.full_len = this.full; }
        emit('WinUsb_ControlTransfer', 'control', 'in', this.handleStr, this.buf.readByteArray(n), this.full, extra);
      } catch (e) { log('WinUsb_ControlTransfer onLeave err ' + e.message); }
    },
  });
  log('hooked ' + mod.name + '!WinUsb_ControlTransfer');
}

// --------------------------------------------------------------------------- //
// Module wiring
// --------------------------------------------------------------------------- //
// attachModuleObserver fires onAdded for already-loaded modules too, so guard against
// double-hooking (attaching the same address twice breaks Frida's onLeave handling).
const hookedModules = new Set();
const hookedFileExports = new Set();

function claimFileExport(sym, addr) {
  if (!addr) return null;
  const keyOf = (hop) => sym + '@' + hop.toString();
  const resolved = resolveExportTarget(addr, (hop) => hookedFileExports.has(keyOf(hop)));
  if (!resolved.target) return null;
  resolved.hops.forEach((hop) => hookedFileExports.add(keyOf(hop)));
  // The final target is normally the last hop, but include it explicitly for fallback/cycle
  // cases so every address that may receive an interceptor is claimed.
  hookedFileExports.add(keyOf(resolved.target));
  return resolved.target;
}

function hookFileApis(mod) {
  let addr = claimFileExport('CreateFileW', exportOf(mod, 'CreateFileW'));
  if (addr) hookCreateFile(mod, 'CreateFileW', true, addr);
  addr = claimFileExport('CreateFileA', exportOf(mod, 'CreateFileA'));
  if (addr) hookCreateFile(mod, 'CreateFileA', false, addr);
  addr = claimFileExport('WriteFile', exportOf(mod, 'WriteFile'));
  if (addr) hookWrite(mod.name + '!WriteFile', addr,
    { api: 'WriteFile', transfer: 'output', bufIdx: 1, lenIdx: 2 });
  addr = claimFileExport('DeviceIoControl', exportOf(mod, 'DeviceIoControl'));
  if (addr) hookWrite(mod.name + '!DeviceIoControl', addr,
    { api: 'DeviceIoControl', transfer: 'control', bufIdx: 2, lenIdx: 3, ioctlIdx: 1 });
  addr = claimFileExport('ReadFile', exportOf(mod, 'ReadFile'));
  if (addr) hookRead(mod.name + '!ReadFile', addr,
    { api: 'ReadFile', transfer: 'input', bufIdx: 1, lenPtrIdx: 3, onlyMapped: true });
  hookClose(mod);
}

function hookModule(mod) {
  const name = mod.name.toLowerCase();
  if (hookedModules.has(name)) return;
  hookedModules.add(name);
  if (name === 'kernel32.dll' || name === 'kernelbase.dll') {
    hookFileApis(mod);
  } else if (name === 'hid.dll') {
    hookWrite('hid!HidD_SetFeature', exportOf(mod, 'HidD_SetFeature'),
      { api: 'HidD_SetFeature', transfer: 'feature', bufIdx: 1, lenIdx: 2 });
    hookWrite('hid!HidD_SetOutputReport', exportOf(mod, 'HidD_SetOutputReport'),
      { api: 'HidD_SetOutputReport', transfer: 'output', bufIdx: 1, lenIdx: 2 });
    // HidD_GetFeature is inherently device-only (never called on files) -> no onlyMapped gate.
    hookRead('hid!HidD_GetFeature', exportOf(mod, 'HidD_GetFeature'),
      { api: 'HidD_GetFeature', transfer: 'feature', bufIdx: 1, lenIdx: 2 });
  } else if (name === 'winusb.dll') {
    hookWinusbInitialize(mod);
    hookWinusbFree(mod);
    hookWrite('winusb!WinUsb_WritePipe', exportOf(mod, 'WinUsb_WritePipe'),
      { api: 'WinUsb_WritePipe', transfer: 'output', bufIdx: 2, lenIdx: 3, pipeIdx: 1 });
    hookWinusbControl(mod);
  }
}

const WATCHED = ['kernel32.dll', 'kernelbase.dll', 'hid.dll', 'winusb.dll'];

WATCHED.forEach((n) => {
  const m = Process.findModuleByName(n);
  if (m) hookModule(m);
});

Process.attachModuleObserver({
  onAdded(mod) {
    if (WATCHED.indexOf(mod.name.toLowerCase()) !== -1) hookModule(mod);
  },
});

send({ type: 'ready', vid: TARGET_VID, pid: TARGET_PID, keepUnmapped: KEEP_UNMAPPED });
