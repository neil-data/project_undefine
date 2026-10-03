"""
hook_installer.py — Generates the guest-side instrumentation.

Emits a Frida JavaScript agent that installs Interceptor hooks on the monitored
API surface and streams normalized call records back to the host.

THREE THINGS THIS FILE GETS RIGHT THAT NAIVE HOOKING GETS WRONG
---------------------------------------------------------------

1. Sensitive arguments never leave the guest.
   Buffers are hashed in-guest and only the digest and length are sent.
   Credential parameters are replaced with a marker before serialization. An
   isolated lab is not an excuse to pipe a victim's documents and passwords
   across the wire into an evidence store.

2. Hooks are reentrancy-guarded.
   The hook body itself calls into the CRT, which may call a hooked API. Without
   a per-thread guard that recurses until the guest stack overflows. This is the
   single most common way homegrown hooking harnesses crash the VM.

3. Output is batched and rate-limited in-guest.
   Sending one message per call for GetProcAddress — which fires thousands of
   times a second — saturates the transport and slows the guest enough to be
   detectable by timing checks. Batching keeps the guest's observable behavior
   close to unhooked.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .api_catalog import (
    API_CATALOG,
    ANDROID_MONITORED_APIS,
    ApiHook,
    MONITORED_APIS,
    WINDOWS_MONITORED_APIS,
)


# ============================================================================
# Frida agent
# ============================================================================

_FRIDA_PREAMBLE = r"""
/*
 * SentinelScan API monitor (generated — do not edit in the guest)
 *
 * Streams normalized API call records to the host over Frida's message
 * channel. Design constraints, in priority order:
 *   1. Never crash the guest        (reentrancy guards, defensive reads)
 *   2. Never leak sensitive data    (hash buffers, redact credentials)
 *   3. Stay cheap enough to be undetectable by timing (batch + rate limit)
 */

'use strict';

var CONFIG = __CONFIG__;

// --- reentrancy guard -------------------------------------------------------
// The hook body calls into the CRT, which can re-enter a hooked API. Without a
// per-thread depth guard this recurses until the guest stack dies.
var inHook = {};

function guardEnter(tid) {
    if (inHook[tid]) return false;
    inHook[tid] = true;
    return true;
}
function guardExit(tid) { inHook[tid] = false; }

// --- batching ---------------------------------------------------------------
var batch = [];
var lastFlush = Date.now();

function emit(record) {
    batch.push(record);
    var now = Date.now();
    if (batch.length >= CONFIG.batch_size || (now - lastFlush) >= CONFIG.flush_ms) {
        flush();
    }
}

function flush() {
    if (batch.length === 0) return;
    try { send({ type: 'api_batch', calls: batch }); } catch (e) { /* transport down */ }
    batch = [];
    lastFlush = Date.now();
}

setInterval(flush, CONFIG.flush_ms);

// --- in-guest rate limiting -------------------------------------------------
// GetProcAddress fires thousands of times a second. Sending each one saturates
// the channel and slows the guest enough for the sample to notice.
var rateState = {};

function rateLimited(api, limit) {
    var now = Date.now();
    var st = rateState[api];
    if (!st || (now - st.start) >= 1000) {
        rateState[api] = { start: now, count: 1, dropped: 0 };
        return false;
    }
    st.count++;
    if (st.count > limit) { st.dropped++; return true; }
    return false;
}

// --- safe argument readers --------------------------------------------------
// Every read is defensive: a malformed pointer from the sample must not take
// down the monitor.

function readStr(ptr_, wide) {
    try {
        if (ptr_ === null || ptr_.isNull()) return null;
        var s = wide ? ptr_.readUtf16String() : ptr_.readAnsiString();
        if (s === null) return null;
        return s.length > CONFIG.max_string ? s.substring(0, CONFIG.max_string) + '...' : s;
    } catch (e) { return null; }
}

function readInt(v) {
    try { return v.toInt32(); } catch (e) { return null; }
}

function readPtr(v) {
    try { return v.toString(); } catch (e) { return null; }
}

// FNV-1a. Buffer contents are never transmitted — only this digest and the
// length. Enough to prove "the same block was encrypted 900 times" without
// copying the victim's files into the evidence store.
function hashBuf(ptr_, len) {
    try {
        if (ptr_ === null || ptr_.isNull() || !len || len <= 0) return null;
        var n = Math.min(len, CONFIG.max_hash_bytes);
        var bytes = ptr_.readByteArray(n);
        if (bytes === null) return null;
        var view = new Uint8Array(bytes);
        var h = 0x811c9dc5;
        var zeros = 0;
        for (var i = 0; i < view.length; i++) {
            if (view[i] === 0) zeros++;
            h ^= view[i];
            h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
        }
        return {
            hash: ('00000000' + h.toString(16)).slice(-8),
            length: len,
            sampled: n,
            // Cheap entropy proxy: a near-total absence of zero bytes across a
            // sizeable block is characteristic of encrypted or compressed data,
            // which is how an encrypt-in-place shows up.
            zero_ratio: view.length ? (zeros / view.length) : 0
        };
    } catch (e) { return null; }
}

function currentPid() {
    try { return Process.id; } catch (e) { return 0; }
}

// Resolve a process HANDLE to a PID. This is what separates self-modification
// (unremarkable) from injection (the whole point), so it is worth the call.
var _getProcessId = null;
try {
    var gpi = Module.findExportByName('kernel32.dll', 'GetProcessId');
    if (gpi !== null) {
        _getProcessId = new NativeFunction(gpi, 'uint32', ['pointer']);
    }
} catch (e) { }

function handleToPid(h) {
    try {
        if (_getProcessId === null || h === null || h.isNull()) return null;
        // Pseudo-handle for "current process"
        if (h.toInt32() === -1) return currentPid();
        var pid = _getProcessId(h);
        return pid === 0 ? null : pid;
    } catch (e) { return null; }
}

function record(api, rawName, module_, args, ret, targetPid) {
    return {
        api: rawName,
        canonical: api,
        module: module_,
        pid: currentPid(),
        tid: Process.getCurrentThreadId(),
        timestamp: new Date().toISOString(),
        args: args,
        'return': ret,
        target_pid: targetPid === undefined ? null : targetPid
    };
}

function attach(module_, exportName, canonical, limit, onEnterFn, onLeaveFn) {
    var addr = null;
    try { addr = Module.findExportByName(module_, exportName); } catch (e) { }
    if (addr === null) return false;

    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var tid = Process.getCurrentThreadId();
                if (!guardEnter(tid)) return;
                try {
                    if (rateLimited(canonical, limit)) { this.skip = true; return; }
                    this.captured = onEnterFn ? onEnterFn(args, this) : {};
                } catch (e) {
                    this.captured = {};
                } finally {
                    guardExit(tid);
                }
            },
            onLeave: function (retval) {
                if (this.skip) return;
                var tid = Process.getCurrentThreadId();
                if (!guardEnter(tid)) return;
                try {
                    var ret = null;
                    try { ret = retval.toInt32(); } catch (e) { }
                    if (onLeaveFn) onLeaveFn(retval, this);
                    emit(record(canonical, exportName, module_,
                                this.captured || {}, ret,
                                this.targetPid));
                } catch (e) {
                } finally {
                    guardExit(tid);
                }
            }
        });
        return true;
    } catch (e) {
        return false;
    }
}

var installed = [];
var failed = [];

function install(module_, exportName, canonical, limit, onEnterFn, onLeaveFn) {
    if (attach(module_, exportName, canonical, limit, onEnterFn, onLeaveFn)) {
        installed.push(module_ + '!' + exportName);
    } else {
        failed.push(module_ + '!' + exportName);
    }
}
"""


_FRIDA_HOOKS = r"""
// ============================================================================
// Filesystem
// ============================================================================

install('kernel32.dll', 'CreateFileW', 'CreateFile', __RL_CreateFile__, function (args) {
    return {
        lpFileName: readStr(args[0], true),
        dwDesiredAccess: readInt(args[1]),
        dwCreationDisposition: readInt(args[4])
    };
});

install('kernel32.dll', 'CreateFileA', 'CreateFile', __RL_CreateFile__, function (args) {
    return {
        lpFileName: readStr(args[0], false),
        dwDesiredAccess: readInt(args[1]),
        dwCreationDisposition: readInt(args[4])
    };
});

install('kernel32.dll', 'ReadFile', 'ReadFile', __RL_ReadFile__, function (args, ctx) {
    ctx.bufPtr = args[1];
    ctx.bufLen = readInt(args[2]);
    return {
        hFile: readInt(args[0]),
        nNumberOfBytesToRead: ctx.bufLen
    };
}, function (retval, ctx) {
    // Hash on the way out — the buffer is only populated after the call.
    var h = hashBuf(ctx.bufPtr, ctx.bufLen);
    if (h) { ctx.captured.buffer = h; }
});

install('kernel32.dll', 'WriteFile', 'WriteFile', __RL_WriteFile__, function (args) {
    var len = readInt(args[2]);
    return {
        hFile: readInt(args[0]),
        nNumberOfBytesToWrite: len,
        buffer: hashBuf(args[1], len)
    };
});

install('kernel32.dll', 'DeleteFileW', 'DeleteFile', __RL_DeleteFile__, function (args) {
    return { lpFileName: readStr(args[0], true) };
});

install('kernel32.dll', 'DeleteFileA', 'DeleteFile', __RL_DeleteFile__, function (args) {
    return { lpFileName: readStr(args[0], false) };
});

// ============================================================================
// Registry
// ============================================================================

install('advapi32.dll', 'RegCreateKeyExW', 'RegCreateKey', __RL_RegCreateKey__, function (args, ctx) {
    ctx.phkResult = args[7];
    return {
        hKey: readInt(args[0]),
        lpSubKey: readStr(args[1], true)
    };
}, function (retval, ctx) {
    // The created key handle is an out-parameter; capture it so RegSetValue
    // can be resolved back to a full key path on the host.
    try {
        if (ctx.phkResult && !ctx.phkResult.isNull()) {
            ctx.captured.hkResult = ctx.phkResult.readPointer().toInt32();
        }
    } catch (e) { }
});

install('advapi32.dll', 'RegSetValueExW', 'RegSetValue', __RL_RegSetValue__, function (args) {
    var type = readInt(args[3]);
    var out = {
        hKey: readInt(args[0]),
        lpValueName: readStr(args[1], true),
        dwType: type
    };
    // REG_SZ (1) and REG_EXPAND_SZ (2) hold the dropped payload path, which is
    // the single most useful value in a persistence finding.
    if (type === 1 || type === 2) {
        out.lpData = readStr(args[4], true);
    } else {
        out.lpData = hashBuf(args[4], readInt(args[5]));
    }
    return out;
});

// ============================================================================
// Network
// ============================================================================

install('wininet.dll', 'InternetConnectW', 'InternetConnect', __RL_InternetConnect__, function (args) {
    return {
        lpszServerName: readStr(args[1], true),
        nServerPort: readInt(args[2]),
        // Credentials are redacted in-guest. Their presence is recorded
        // because embedded credentials are themselves a finding; the values
        // are not, because they must never reach the evidence store.
        lpszUserName: args[3].isNull() ? null : '[REDACTED]',
        lpszPassword: args[4].isNull() ? null : '[REDACTED]'
    };
});

install('wininet.dll', 'InternetConnectA', 'InternetConnect', __RL_InternetConnect__, function (args) {
    return {
        lpszServerName: readStr(args[1], false),
        nServerPort: readInt(args[2]),
        lpszUserName: args[3].isNull() ? null : '[REDACTED]',
        lpszPassword: args[4].isNull() ? null : '[REDACTED]'
    };
});

install('winhttp.dll', 'WinHttpSendRequest', 'WinHttpSendRequest', __RL_WinHttpSendRequest__, function (args) {
    var totalLen = readInt(args[5]);
    return {
        hRequest: readInt(args[0]),
        lpszHeaders: readStr(args[1], true),
        dwTotalLength: totalLen,
        lpOptional: hashBuf(args[3], readInt(args[4]))
    };
});

// ============================================================================
// Process / execution
// ============================================================================

install('kernel32.dll', 'CreateProcessW', 'CreateProcess', __RL_CreateProcess__, function (args) {
    return {
        lpApplicationName: readStr(args[0], true),
        lpCommandLine: readStr(args[1], true),
        dwCreationFlags: readInt(args[5])
    };
});

install('kernel32.dll', 'CreateProcessA', 'CreateProcess', __RL_CreateProcess__, function (args) {
    return {
        lpApplicationName: readStr(args[0], false),
        lpCommandLine: readStr(args[1], false),
        dwCreationFlags: readInt(args[5])
    };
});

install('shell32.dll', 'ShellExecuteW', 'ShellExecute', __RL_ShellExecute__, function (args) {
    return {
        lpOperation: readStr(args[2], true),
        lpFile: readStr(args[3], true),
        lpParameters: readStr(args[4], true)
    };
});

install('shell32.dll', 'ShellExecuteA', 'ShellExecute', __RL_ShellExecute__, function (args) {
    return {
        lpOperation: readStr(args[2], false),
        lpFile: readStr(args[3], false),
        lpParameters: readStr(args[4], false)
    };
});

// ============================================================================
// Memory
// ============================================================================

install('kernel32.dll', 'VirtualAlloc', 'VirtualAlloc', __RL_VirtualAlloc__, function (args) {
    return {
        lpAddress: readPtr(args[0]),
        dwSize: readInt(args[1]),
        flAllocationType: readInt(args[2]),
        flProtect: readInt(args[3])
    };
});

// VirtualAllocEx targets another process — the allocation half of injection.
install('kernel32.dll', 'VirtualAllocEx', 'VirtualAlloc', __RL_VirtualAlloc__, function (args, ctx) {
    ctx.targetPid = handleToPid(args[0]);
    return {
        lpAddress: readPtr(args[1]),
        dwSize: readInt(args[2]),
        flAllocationType: readInt(args[3]),
        flProtect: readInt(args[4]),
        cross_process: true
    };
});

install('kernel32.dll', 'VirtualProtect', 'VirtualProtect', __RL_VirtualProtect__, function (args) {
    return {
        lpAddress: readPtr(args[0]),
        dwSize: readInt(args[1]),
        flNewProtect: readInt(args[2])
    };
});

install('kernel32.dll', 'VirtualProtectEx', 'VirtualProtect', __RL_VirtualProtect__, function (args, ctx) {
    ctx.targetPid = handleToPid(args[0]);
    return {
        lpAddress: readPtr(args[1]),
        dwSize: readInt(args[2]),
        flNewProtect: readInt(args[3]),
        cross_process: true
    };
});

// ============================================================================
// Injection
// ============================================================================

// Hooked at the ntdll layer so that callers bypassing WriteProcessMemory are
// still caught — malware routinely calls the Nt* form directly for exactly
// that reason.
install('ntdll.dll', 'NtWriteVirtualMemory', 'NtWriteVirtualMemory', __RL_NtWriteVirtualMemory__, function (args, ctx) {
    ctx.targetPid = handleToPid(args[0]);
    var len = readInt(args[3]);
    return {
        ProcessHandle: readInt(args[0]),
        BaseAddress: readPtr(args[1]),
        NumberOfBytesToWrite: len,
        Buffer: hashBuf(args[2], len)
    };
});

install('kernel32.dll', 'WriteProcessMemory', 'NtWriteVirtualMemory', __RL_NtWriteVirtualMemory__, function (args, ctx) {
    ctx.targetPid = handleToPid(args[0]);
    var len = readInt(args[3]);
    return {
        ProcessHandle: readInt(args[0]),
        BaseAddress: readPtr(args[1]),
        NumberOfBytesToWrite: len,
        Buffer: hashBuf(args[2], len)
    };
});

install('kernel32.dll', 'CreateRemoteThread', 'CreateRemoteThread', __RL_CreateRemoteThread__, function (args, ctx) {
    ctx.targetPid = handleToPid(args[0]);
    return {
        hProcess: readInt(args[0]),
        lpStartAddress: readPtr(args[3]),
        lpParameter: readPtr(args[4])
    };
});

install('kernel32.dll', 'CreateRemoteThreadEx', 'CreateRemoteThread', __RL_CreateRemoteThread__, function (args, ctx) {
    ctx.targetPid = handleToPid(args[0]);
    return {
        hProcess: readInt(args[0]),
        lpStartAddress: readPtr(args[3]),
        lpParameter: readPtr(args[4])
    };
});

// ============================================================================
// Dynamic resolution
// ============================================================================

install('kernel32.dll', 'LoadLibraryW', 'LoadLibrary', __RL_LoadLibrary__, function (args) {
    return { lpLibFileName: readStr(args[0], true) };
});

install('kernel32.dll', 'LoadLibraryA', 'LoadLibrary', __RL_LoadLibrary__, function (args) {
    return { lpLibFileName: readStr(args[0], false) };
});

install('kernel32.dll', 'LoadLibraryExW', 'LoadLibrary', __RL_LoadLibrary__, function (args) {
    return { lpLibFileName: readStr(args[0], true) };
});

install('kernel32.dll', 'GetProcAddress', 'GetProcAddress', __RL_GetProcAddress__, function (args) {
    var name = null;
    try {
        // Ordinal imports arrive as a small integer in the pointer slot rather
        // than a string; dereferencing that as a string reads garbage.
        var raw = args[1];
        if (raw.compare(ptr(0x10000)) < 0) {
            name = '#' + raw.toInt32();
        } else {
            name = readStr(raw, false);
        }
    } catch (e) { }
    return { hModule: readInt(args[0]), lpProcName: name };
});

// ============================================================================
// Crypto
// ============================================================================

install('advapi32.dll', 'CryptEncrypt', 'CryptEncrypt', __RL_CryptEncrypt__, function (args, ctx) {
    var len = 0;
    try { if (!args[5].isNull()) len = args[5].readU32(); } catch (e) { }
    ctx.bufPtr = args[4];
    ctx.bufLen = len;
    return {
        hKey: readInt(args[0]),
        pdwDataLen: len,
        pbData: hashBuf(args[4], len)
    };
});

install('advapi32.dll', 'CryptDecrypt', 'CryptDecrypt', __RL_CryptDecrypt__, function (args, ctx) {
    ctx.bufPtr = args[4];
    try { ctx.bufLen = args[5].isNull() ? 0 : args[5].readU32(); } catch (e) { ctx.bufLen = 0; }
    return { hKey: readInt(args[0]), pdwDataLen: ctx.bufLen };
}, function (retval, ctx) {
    // Hash the plaintext result on the way out. The digest lets the host
    // correlate decrypted config blocks without ever holding the plaintext.
    var h = hashBuf(ctx.bufPtr, ctx.bufLen);
    if (h) { ctx.captured.pbData = h; }
});

// ============================================================================
// Device
// ============================================================================

install('kernel32.dll', 'DeviceIoControl', 'DeviceIoControl', __RL_DeviceIoControl__, function (args) {
    var inLen = readInt(args[3]);
    return {
        hDevice: readInt(args[0]),
        dwIoControlCode: readInt(args[1]),
        lpInBuffer: hashBuf(args[2], inLen)
    };
});

// ============================================================================
// Services  (5.1 — Monitor Services)
// ============================================================================
// Service installation/modification is a primary Windows persistence channel.
// The three-call chain OpenSCManager → CreateService → StartService represents
// the complete service-based persistence attack pattern.

install('advapi32.dll', 'OpenSCManagerW', 'OpenSCManager', __RL_OpenSCManager__, function (args) {
    return {
        lpMachineName: readStr(args[0], true),   // null = local machine
        dwDesiredAccess: readInt(args[2])          // 0x0002 = SC_MANAGER_CREATE_SERVICE
    };
});

install('advapi32.dll', 'OpenSCManagerA', 'OpenSCManager', __RL_OpenSCManager__, function (args) {
    return {
        lpMachineName: readStr(args[0], false),
        dwDesiredAccess: readInt(args[2])
    };
});

install('advapi32.dll', 'CreateServiceW', 'CreateService', __RL_CreateService__, function (args) {
    return {
        lpServiceName: readStr(args[1], true),
        lpDisplayName: readStr(args[2], true),
        dwServiceType: readInt(args[4]),      // 0x1=KERNEL_DRIVER, 0x10=WIN32_OWN_PROCESS
        dwStartType: readInt(args[5]),         // 0x2=AUTO_START, 0x3=DEMAND_START
        lpBinaryPathName: readStr(args[8], true)   // Primary IOC: the dropped binary path
    };
});

install('advapi32.dll', 'CreateServiceA', 'CreateService', __RL_CreateService__, function (args) {
    return {
        lpServiceName: readStr(args[1], false),
        lpDisplayName: readStr(args[2], false),
        dwServiceType: readInt(args[4]),
        dwStartType: readInt(args[5]),
        lpBinaryPathName: readStr(args[8], false)
    };
});

install('advapi32.dll', 'ChangeServiceConfigW', 'ChangeServiceConfig', __RL_ChangeServiceConfig__, function (args) {
    return {
        hService: readInt(args[0]),
        dwStartType: readInt(args[2]),
        // New binary path — if this points to AppData/Temp, service was hijacked
        lpBinaryPathName: readStr(args[5], true)
    };
});

install('advapi32.dll', 'ChangeServiceConfigA', 'ChangeServiceConfig', __RL_ChangeServiceConfig__, function (args) {
    return {
        hService: readInt(args[0]),
        dwStartType: readInt(args[2]),
        lpBinaryPathName: readStr(args[5], false)
    };
});

install('advapi32.dll', 'StartServiceW', 'StartService', __RL_StartService__, function (args) {
    return { hService: readInt(args[0]) };
});

install('advapi32.dll', 'StartServiceA', 'StartService', __RL_StartService__, function (args) {
    return { hService: readInt(args[0]) };
});

// ============================================================================
// Drivers  (5.2 — Monitor Drivers)
// ============================================================================
// NtLoadDriver is the user-mode gateway to kernel-mode driver loading.
// Calling this from a non-system path is the rootkit/BYOVD signal.

install('ntdll.dll', 'NtLoadDriver', 'NtLoadDriver', __RL_NtLoadDriver__, function (args) {
    // DriverServiceName is a UNICODE_STRING pointer. The string data sits at
    // offset 4 (Buffer pointer) within the struct on both 32 and 64-bit.
    var us = args[0];
    var driverPath = '';
    try {
        // UNICODE_STRING: USHORT Length, USHORT MaximumLength, PWSTR Buffer
        var bufPtr = Process.pointerSize === 8 ? us.add(8).readPointer() : us.add(4).readPointer();
        if (!bufPtr.isNull()) {
            driverPath = bufPtr.readUtf16String();
        }
    } catch (e) { driverPath = '[read error]'; }
    return { DriverServiceName: driverPath };
});

// ZwLoadDriver is the same syscall stub — alias handled in catalog
install('ntdll.dll', 'ZwLoadDriver', 'NtLoadDriver', __RL_NtLoadDriver__, function (args) {
    var us = args[0];
    var driverPath = '';
    try {
        var bufPtr = Process.pointerSize === 8 ? us.add(8).readPointer() : us.add(4).readPointer();
        if (!bufPtr.isNull()) { driverPath = bufPtr.readUtf16String(); }
    } catch (e) { driverPath = '[read error]'; }
    return { DriverServiceName: driverPath };
});

install('ntdll.dll', 'NtSetSystemInformation', 'NtSetSystemInformation', __RL_NtSetSystemInformation__, function (args) {
    return {
        // Class 38 = SystemLoadAndCallImage (alternate driver-load path used by rootkits)
        SystemInformationClass: readInt(args[0]),
        SystemInformationLength: readInt(args[2])
    };
});

// ============================================================================
// Privilege Escalation  (5.3 — Privilege Escalation Detector)
// ============================================================================
// Token manipulation is a user-space technique to gain SYSTEM privileges
// without triggering kernel exploits. The sequence:
//   OpenProcessToken(SYSTEM proc) → DuplicateTokenEx → CreateProcessWithToken
// achieves full privilege escalation silently.

install('advapi32.dll', 'OpenProcessToken', 'OpenProcessToken', __RL_OpenProcessToken__, function (args) {
    return {
        ProcessHandle: readInt(args[0]),
        // TOKEN_DUPLICATE=0x2, TOKEN_ADJUST_PRIVILEGES=0x20, TOKEN_ALL_ACCESS=0xF01FF
        DesiredAccess: readInt(args[1])
    };
});

install('advapi32.dll', 'AdjustTokenPrivileges', 'AdjustTokenPrivileges', __RL_AdjustTokenPrivileges__, function (args) {
    // NewState points to a TOKEN_PRIVILEGES struct with LUID_AND_ATTRIBUTES.
    // We capture whether DisableAllPrivileges=FALSE (actual adjustment requested)
    // and record the attribute flags — 0x2=SE_PRIVILEGE_ENABLED is the one that matters.
    var disableAll = readInt(args[1]);
    var newStatePtr = args[2];
    var privilegeCount = 0;
    var firstLuid = null;
    try {
        if (!newStatePtr.isNull()) {
            privilegeCount = newStatePtr.readU32();
            // LUID starts at offset 4; low part of LUID at offset 4, attrs at offset 12
            if (privilegeCount > 0) {
                firstLuid = newStatePtr.add(4).readU64().toString();
            }
        }
    } catch (e) { }
    return {
        TokenHandle: readInt(args[0]),
        DisableAllPrivileges: disableAll !== 0,
        PrivilegeCount: privilegeCount,
        FirstLuid: firstLuid    // LUID 0x14 = SeDebugPrivilege (credential-dump precondition)
    };
});

install('advapi32.dll', 'DuplicateTokenEx', 'DuplicateTokenEx', __RL_DuplicateTokenEx__, function (args) {
    return {
        hExistingToken: readInt(args[0]),
        dwDesiredAccess: readInt(args[1]),
        // SecurityImpersonation=2, SecurityDelegation=3
        ImpersonationLevel: readInt(args[4]),
        // TokenPrimary=1 means it can be used to create a new process
        TokenType: readInt(args[5])
    };
});

install('advapi32.dll', 'ImpersonateLoggedOnUser', 'ImpersonateLoggedOnUser', __RL_ImpersonateLoggedOnUser__, function (args) {
    return {
        hToken: readInt(args[0])    // Whose identity is being assumed
    };
});

install('advapi32.dll', 'CreateProcessWithTokenW', 'CreateProcessWithToken', __RL_CreateProcessWithToken__, function (args) {
    return {
        hToken: readInt(args[0]),       // The stolen token used for elevation
        lpApplicationName: readStr(args[2], true),
        lpCommandLine: readStr(args[3], true)   // What executes at elevated privilege
    };
});

// ============================================================================
// Ready
// ============================================================================

send({
    type: 'hooks_installed',
    installed: installed,
    failed: failed,
    total: installed.length
});
"""


def generate_frida_agent(
    batch_size: int = 64,
    flush_ms: int = 500,
    max_string: int = 512,
    max_hash_bytes: int = 4096,
    rate_limits: Optional[Dict[str, int]] = None,
) -> str:
    """
    Build the Frida agent JavaScript.

    Rate limits default to each API's catalog value, so the noisy APIs
    (GetProcAddress, ReadFile) are throttled without the caller having to know
    which ones those are.
    """
    config = {
        "batch_size": batch_size,
        "flush_ms": flush_ms,
        "max_string": max_string,
        "max_hash_bytes": max_hash_bytes,
    }

    script = _FRIDA_PREAMBLE.replace("__CONFIG__", json.dumps(config))
    hooks = _FRIDA_HOOKS

    limits = dict(rate_limits or {})
    for name, hook in API_CATALOG.items():
        limit = limits.get(name, hook.rate_limit_per_sec)
        hooks = hooks.replace(f"__RL_{name}__", str(limit))

    return script + hooks


# ============================================================================
# CAPE
# ============================================================================

def generate_cape_config() -> Dict[str, object]:
    """
    CAPE monitor configuration for the same API surface.

    CAPE hooks in its own kernel-adjacent monitor rather than via Frida, so it
    takes a declarative list instead of a script. Both paths normalize to the
    same event shape on the host, which is what lets hook_engine.py stay
    agnostic about which sandbox produced a call.
    """
    return {
        "api_hooks": [
            {
                "name": hook.name,
                "module": hook.module,
                "category": hook.category.value,
                "capture_args": [a.name for a in hook.args],
                "hash_only_args": [a.name for a in hook.args if a.hash_only],
                "redact_args": [a.name for a in hook.args if a.redact],
                "capture_return": hook.capture_return,
                "rate_limit": hook.rate_limit_per_sec,
            }
            # Windows only — CAPE's monitor hooks native exports, and would
            # reject Java class names outright.
            for hook in API_CATALOG.values() if hook.platform == "windows"
        ],
        "batching": {"size": 64, "flush_ms": 500},
        "limits": {"max_string": 512, "max_hash_bytes": 4096},
    }


def _generate_frida_android_agent_base() -> str:
    """
    Base Android agent — filesystem, persistence (SharedPrefs), network,
    execution, dynamic DEX loading, and crypto. The full agent is produced
    by generate_frida_android_agent() which appends the Phase 6 extended hooks.
    """
    return r"""
'use strict';

var batch = [];
function emit(r) {
    batch.push(r);
    if (batch.length >= 64) { send({ type: 'api_batch', calls: batch }); batch = []; }
}
setInterval(function () {
    if (batch.length) { send({ type: 'api_batch', calls: batch }); batch = []; }
}, 500);

function rec(api, args) {
    return {
        api: api,
        pid: Process.id,
        tid: Process.getCurrentThreadId(),
        timestamp: new Date().toISOString(),
        args: args
    };
}

Java.perform(function () {

    // --- filesystem (CreateFile / ReadFile / WriteFile / DeleteFile) --------
    var File = Java.use('java.io.File');
    File.delete.implementation = function () {
        emit(rec('DeleteFile', { lpFileName: this.getAbsolutePath() }));
        return this.delete();
    };

    var FOS = Java.use('java.io.FileOutputStream');
    FOS.$init.overload('java.io.File', 'boolean').implementation = function (f, append) {
        emit(rec('CreateFile', { lpFileName: f.getAbsolutePath(), dwDesiredAccess: 0x40000000 }));
        return this.$init(f, append);
    };

    var FIS = Java.use('java.io.FileInputStream');
    FIS.$init.overload('java.io.File').implementation = function (f) {
        emit(rec('CreateFile', { lpFileName: f.getAbsolutePath(), dwDesiredAccess: 0x80000000 }));
        return this.$init(f);
    };

    // --- persistence (RegSetValue analogue) --------------------------------
    // SharedPreferences is where Android malware stores its configuration and
    // its "already installed" flags, so it fills the role the registry plays
    // on Windows.
    var SPEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    SPEditor.putString.implementation = function (k, v) {
        emit(rec('RegSetValue', { lpValueName: k, lpData: v }));
        return this.putString(k, v);
    };

    // --- network (InternetConnect / WinHttpSendRequest) --------------------
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
        emit(rec('InternetConnect', {
            lpszServerName: this.getHost(),
            nServerPort: this.getPort()
        }));
        return this.openConnection();
    };

    // --- execution (CreateProcess / ShellExecute) --------------------------
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        emit(rec('CreateProcess', { lpCommandLine: cmd }));
        return this.exec(cmd);
    };

    var Ctx = Java.use('android.content.ContextWrapper');
    Ctx.startActivity.overload('android.content.Intent').implementation = function (i) {
        emit(rec('ShellExecute', { lpFile: i.toString() }));
        return this.startActivity(i);
    };

    // --- dynamic resolution (LoadLibrary / GetProcAddress) -----------------
    var System = Java.use('java.lang.System');
    System.loadLibrary.implementation = function (name) {
        emit(rec('LoadLibrary', { lpLibFileName: name }));
        return this.loadLibrary(name);
    };

    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function (dexPath, odex, libs, parent) {
        // Runtime dex loading is Android's equivalent of unpacking: the real
        // code was not present in the APK that was scanned.
        emit(rec('LoadLibrary', { lpLibFileName: dexPath, dynamic_dex: true }));
        return this.$init(dexPath, odex, libs, parent);
    };

    // --- crypto (CryptEncrypt / CryptDecrypt) ------------------------------
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (data) {
        var mode = this.getOpmode ? 0 : 0;
        emit(rec('CryptEncrypt', {
            hKey: 0,
            pdwDataLen: data ? data.length : 0,
            algorithm: this.getAlgorithm()
        }));
        return this.doFinal(data);
    };

    send({ type: 'hooks_installed', platform: 'android' });
});
"""


# Eagerly evaluate so the string is ready without calling a function.
_ANDROID_BASE_AGENT: str = _generate_frida_android_agent_base()


# ============================================================================
# Android Extended Monitors (Phase 6.1 – 6.9)
# ============================================================================
# These hooks are appended to the base android agent at runtime via
# generate_frida_android_agent(). Each section is a self-contained monitor
# following the same emit/rec pattern as the base agent.

_ANDROID_EXTENDED_HOOKS = r"""

Java.perform(function () {

    // ========================================================================
    // 6.1 — Permission Monitor
    // Intercepts runtime permission requests and checks to build a map of
    // what the app actually uses vs. what it declared in the manifest.
    // ========================================================================

    try {
        var Activity = Java.use('android.app.Activity');
        Activity.requestPermissions.implementation = function (permissions, requestCode) {
            var perms = [];
            try {
                for (var i = 0; i < permissions.length; i++) perms.push(permissions[i]);
            } catch(e) {}
            emit(rec('RequestPermissions', {
                permissions: perms,
                requestCode: requestCode,
                dangerous: perms.filter(function(p) {
                    return p.indexOf('READ_SMS') >= 0 || p.indexOf('ACCESS_FINE_LOCATION') >= 0 ||
                           p.indexOf('READ_CONTACTS') >= 0 || p.indexOf('RECORD_AUDIO') >= 0 ||
                           p.indexOf('CAMERA') >= 0 || p.indexOf('READ_CALL_LOG') >= 0 ||
                           p.indexOf('ACCESS_BACKGROUND_LOCATION') >= 0;
                })
            }));
            return this.requestPermissions(permissions, requestCode);
        };
    } catch(e) {}

    try {
        var ContextCompat = Java.use('androidx.core.content.ContextCompat');
        ContextCompat.checkSelfPermission.implementation = function (ctx, permission) {
            var result = this.checkSelfPermission(ctx, permission);
            emit(rec('CheckPermission', { permission: permission, result: result }));
            return result;
        };
    } catch(e) {}

    // ========================================================================
    // 6.2 — SMS Monitor
    // Tracks SMS reads (OTP/credential harvest) and sends (smishing, premium).
    // ========================================================================

    try {
        var SmsManager = Java.use('android.telephony.SmsManager');
        SmsManager.sendTextMessage.implementation = function (dest, sc, text, sent, delivery) {
            emit(rec('SendSMS', {
                destinationAddress: dest,
                scAddress: sc,
                // Message body hashed — content never leaves guest in plaintext
                messageBodyHash: text ? text.length.toString() + ':' + text.hashCode() : null
            }));
            return this.sendTextMessage(dest, sc, text, sent, delivery);
        };

        SmsManager.sendMultipartTextMessage.implementation = function (dest, sc, parts, sent, delivery) {
            emit(rec('SendMultipartSMS', {
                destinationAddress: dest,
                numParts: parts ? parts.size() : 0
            }));
            return this.sendMultipartTextMessage(dest, sc, parts, sent, delivery);
        };
    } catch(e) {}

    // SMS content provider read — OTP/inbox scraping
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload(
            'android.net.Uri',
            '[Ljava.lang.String;',
            'android.os.Bundle',
            'android.os.CancellationSignal'
        ).implementation = function (uri, projection, queryArgs, cancellationSignal) {
            var uriStr = uri ? uri.toString() : '';
            if (uriStr.indexOf('sms') >= 0 || uriStr.indexOf('mms') >= 0) {
                emit(rec('ReadSMS', { uri: uriStr, projection: projection ? projection.toString() : null }));
            } else if (uriStr.indexOf('contacts') >= 0 || uriStr.indexOf('phone') >= 0) {
                // 6.4 — Contact read (shared ContentResolver hook)
                emit(rec('ReadContacts', { uri: uriStr, projection: projection ? projection.toString() : null }));
            }
            return this.query(uri, projection, queryArgs, cancellationSignal);
        };
    } catch(e) {}

    // ========================================================================
    // 6.3 — Location Monitor
    // Detects covert GPS tracking and fine-location exfiltration.
    // ========================================================================

    try {
        var LocationManager = Java.use('android.location.LocationManager');
        LocationManager.requestLocationUpdates.overload(
            'java.lang.String', 'long', 'float', 'android.location.LocationListener'
        ).implementation = function (provider, minTime, minDistance, listener) {
            emit(rec('RequestLocationUpdates', {
                provider: provider,
                minTimeMs: minTime.toString(),
                minDistanceM: minDistance,
                // < 10s interval from a background service = covert tracking
                highFrequency: minTime < 10000
            }));
            return this.requestLocationUpdates(provider, minTime, minDistance, listener);
        };

        LocationManager.getLastKnownLocation.implementation = function (provider) {
            var loc = this.getLastKnownLocation(provider);
            emit(rec('GetLastKnownLocation', {
                provider: provider,
                hasResult: loc !== null
            }));
            return loc;
        };
    } catch(e) {}

    // Fused Location Provider (Google Play Services)
    try {
        var FusedLocationClient = Java.use('com.google.android.gms.location.FusedLocationProviderClient');
        FusedLocationClient.requestLocationUpdates.overload(
            'com.google.android.gms.location.LocationRequest',
            'com.google.android.gms.location.LocationCallback',
            'android.os.Looper'
        ).implementation = function (request, callback, looper) {
            var interval = 0;
            try { interval = request.getInterval(); } catch(e) {}
            emit(rec('FusedLocationUpdates', {
                intervalMs: interval,
                highFrequency: interval > 0 && interval < 10000
            }));
            return this.requestLocationUpdates(request, callback, looper);
        };
    } catch(e) {}

    // ========================================================================
    // 6.4 — Contact Monitor (ContentResolver hook above captures reads)
    // Additional: detect bulk contact enumeration pattern.
    // ========================================================================

    // Contact reads are captured in the ContentResolver.query hook above (6.2).
    // Here we also hook ContactsContract for direct field access.
    try {
        var PhoneLookup = Java.use('android.provider.ContactsContract$PhoneLookup');
        // Static field access logging — bulk CONTENT_URI query pattern
        emit(rec('ContactsContractAccess', { type: 'PhoneLookup' }));
    } catch(e) {}

    // ========================================================================
    // 6.5 — Clipboard Monitor
    // Detects credential theft and crypto-address hijacking.
    // ========================================================================

    try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');

        ClipboardManager.getPrimaryClip.implementation = function () {
            var clip = this.getPrimaryClip();
            var text = null;
            try {
                if (clip !== null && clip.getItemCount() > 0) {
                    var item = clip.getItemAt(0);
                    if (item !== null) text = item.getText();
                }
            } catch(e) {}
            emit(rec('ClipboardRead', {
                hasContent: clip !== null,
                // Detect crypto address pattern in clipboard (length heuristic)
                possibleCryptoAddress: text !== null && (
                    text.toString().length >= 26 && text.toString().length <= 62
                )
            }));
            return clip;
        };

        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            var text = null;
            try {
                if (clip !== null && clip.getItemCount() > 0) {
                    var item = clip.getItemAt(0);
                    if (item !== null) text = item.getText();
                }
            } catch(e) {}
            emit(rec('ClipboardWrite', {
                // Hijacking: app wrote to clipboard without user interaction
                textLength: text !== null ? text.toString().length : 0
            }));
            return this.setPrimaryClip(clip);
        };

        ClipboardManager.hasPrimaryClip.implementation = function () {
            var result = this.hasPrimaryClip();
            emit(rec('ClipboardCheck', { hasClip: result }));
            return result;
        };
    } catch(e) {}

    // ========================================================================
    // 6.6 — Camera Monitor
    // Detects covert video/photo capture (spyware, RAT).
    // ========================================================================

    try {
        var CameraManager = Java.use('android.hardware.camera2.CameraManager');
        CameraManager.openCamera.implementation = function (cameraId, callback, handler) {
            emit(rec('CameraOpen', {
                cameraId: cameraId,
                // Facing: 0=BACK, 1=FRONT (front camera = selfie-cam surveillance risk)
                facing: cameraId
            }));
            return this.openCamera(cameraId, callback, handler);
        };
    } catch(e) {}

    // Legacy Camera API (API < 21)
    try {
        var Camera = Java.use('android.hardware.Camera');
        Camera.open.overload('int').implementation = function (cameraId) {
            emit(rec('CameraOpen', { cameraId: cameraId, api: 'legacy' }));
            return this.open(cameraId);
        };
        Camera.startPreview.implementation = function () {
            emit(rec('CameraStartPreview', {}));
            return this.startPreview();
        };
    } catch(e) {}

    // MediaRecorder video capture
    try {
        var MediaRecorder = Java.use('android.media.MediaRecorder');
        var origStart = MediaRecorder.start;
        MediaRecorder.start.implementation = function () {
            emit(rec('MediaRecorderStart', { type: 'unknown' }));
            return this.start();
        };
        MediaRecorder.setVideoSource.implementation = function (source) {
            emit(rec('MediaRecorderVideoSource', { source: source }));
            return this.setVideoSource(source);
        };
    } catch(e) {}

    // ========================================================================
    // 6.7 — Microphone Monitor
    // Detects covert audio recording — banking trojans, stalkerware, RATs.
    // ========================================================================

    try {
        var AudioRecord = Java.use('android.media.AudioRecord');
        AudioRecord.startRecording.implementation = function () {
            emit(rec('AudioRecordStart', {
                // AudioSource.MIC=1, VOICE_COMMUNICATION=7, CAMCORDER=5
            }));
            return this.startRecording();
        };
        AudioRecord.read.overload('[B', 'int', 'int').implementation = function (buf, off, size) {
            // Track read volume — sustained reads = active recording session
            emit(rec('AudioRecordRead', { sizeBytes: size }));
            return this.read(buf, off, size);
        };
    } catch(e) {}

    try {
        // MediaRecorder audio — captures MIC source setting
        var MR2 = Java.use('android.media.MediaRecorder');
        MR2.setAudioSource.implementation = function (source) {
            emit(rec('MediaRecorderAudioSource', {
                source: source,
                // source=1 is MIC — recording ambient audio
                isMic: source === 1
            }));
            return this.setAudioSource(source);
        };
    } catch(e) {}

    // ========================================================================
    // 6.8 — Accessibility Monitor
    // Accessibility is the most powerful Android permission for malware:
    // it allows reading any on-screen content and auto-clicking UI elements.
    // Banking trojans use it to steal credentials and confirm payments.
    // ========================================================================

    try {
        var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');
        AccessibilityService.onAccessibilityEvent.implementation = function (event) {
            var pkgName = null;
            var eventType = 0;
            try {
                pkgName = event.getPackageName();
                eventType = event.getEventType();
            } catch(e) {}
            emit(rec('AccessibilityEvent', {
                packageName: pkgName ? pkgName.toString() : null,
                eventType: eventType,
                // TYPE_VIEW_TEXT_CHANGED=16 = credential field monitoring
                // TYPE_WINDOW_STATE_CHANGED=32 = app-switch detection
                // TYPE_VIEW_CLICKED=4 = auto-click logging
                isTextChange: eventType === 16,
                isWindowChange: eventType === 32
            }));
            return this.onAccessibilityEvent(event);
        };
    } catch(e) {}

    try {
        // AccessibilityNodeInfo.findAccessibilityNodeInfosByText — used to
        // locate password/PIN fields by label text for auto-fill attacks.
        var NodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');
        NodeInfo.findAccessibilityNodeInfosByText.implementation = function (text) {
            emit(rec('AccessibilityFindByText', {
                searchText: text,
                // Searching for 'password', 'pin', 'cvv' = credential extraction
                sensitiveSearch: text !== null && (
                    text.toLowerCase().indexOf('password') >= 0 ||
                    text.toLowerCase().indexOf('pin') >= 0 ||
                    text.toLowerCase().indexOf('cvv') >= 0 ||
                    text.toLowerCase().indexOf('otp') >= 0
                )
            }));
            return this.findAccessibilityNodeInfosByText(text);
        };
    } catch(e) {}

    // ========================================================================
    // 6.9 — Overlay Monitor
    // Window overlays drawn over banking/payment apps capture credentials
    // by presenting a fake UI that looks identical to the legitimate app.
    // ========================================================================

    try {
        var WindowManager = Java.use('android.view.WindowManager');
        // WindowManager is an interface; hook via WindowManagerImpl
        var WMImpl = Java.use('android.view.WindowManagerImpl');
        WMImpl.addView.implementation = function (view, params) {
            var windowType = 0;
            var flags = 0;
            try {
                windowType = params.type;
                flags = params.flags;
            } catch(e) {}
            emit(rec('OverlayWindowAdded', {
                windowType: windowType,
                flags: flags,
                // TYPE_APPLICATION_OVERLAY=2038 (API 26+)
                // TYPE_SYSTEM_ALERT=2003 (legacy, still used on older devices)
                isOverlay: windowType === 2038 || windowType === 2003,
                // FLAG_NOT_FOCUSABLE=8 + FLAG_NOT_TOUCHABLE=16 = invisible layer
                // used to log taps without user awareness
                invisibleTapLogger: (flags & 8) !== 0 && (flags & 16) !== 0
            }));
            return this.addView(view, params);
        };
    } catch(e) {}

    // Also hook LayoutInflater to detect when overlay views are inflated from
    // malicious layouts that mimic banking app UIs.
    try {
        var LayoutInflater = Java.use('android.view.LayoutInflater');
        LayoutInflater.inflate.overload('int', 'android.view.ViewGroup', 'boolean').implementation = function (resource, root, attachToRoot) {
            emit(rec('LayoutInflate', { resourceId: resource }));
            return this.inflate(resource, root, attachToRoot);
        };
    } catch(e) {}

    send({ type: 'hooks_installed', platform: 'android', extended: true });
});
"""


def generate_frida_android_agent() -> str:
    """
    Android equivalent, hooking the Java-layer analogues of the Windows APIs.

    Includes the base agent (filesystem, persistence, network, execution,
    dynamic DEX, crypto) plus the Phase 6 extended monitors:
      6.1  Permission Monitor
      6.2  SMS Monitor
      6.3  Location Monitor
      6.4  Contact Monitor
      6.5  Clipboard Monitor
      6.6  Camera Monitor
      6.7  Microphone Monitor
      6.8  Accessibility Monitor
      6.9  Overlay Monitor

    The behavioral questions are identical to Windows — what did it read,
    where did it connect, what did it install — but the API surface is
    entirely different, so this is a separate script.
    """
    return _ANDROID_BASE_AGENT + _ANDROID_EXTENDED_HOOKS


def installation_manifest() -> Dict[str, object]:
    """What the generated agent covers — used by tests and the deployment check."""
    return {
        "monitored_apis": sorted(MONITORED_APIS),
        "api_count": len(MONITORED_APIS),
        # Split by guest: the Win32 agent and the Java agent install disjoint
        # sets, and a deployment check that conflates them cannot tell a
        # missing Android monitor from a missing Windows one.
        "windows_apis": sorted(WINDOWS_MONITORED_APIS),
        "windows_api_count": len(WINDOWS_MONITORED_APIS),
        "android_apis": sorted(ANDROID_MONITORED_APIS),
        "android_api_count": len(ANDROID_MONITORED_APIS),
        "modules": sorted({h.module for h in API_CATALOG.values()}),
        "categories": sorted({h.category.value for h in API_CATALOG.values()}),
        "hash_only_args": {
            name: [a.name for a in hook.args if a.hash_only]
            for name, hook in API_CATALOG.items()
            if any(a.hash_only for a in hook.args)
        },
        "redacted_args": {
            name: [a.name for a in hook.args if a.redact]
            for name, hook in API_CATALOG.items()
            if any(a.redact for a in hook.args)
        },
        # Phase 5 — Windows coverage
        "windows_phase5": {
            "service_monitor": ["OpenSCManager", "CreateService", "ChangeServiceConfig", "StartService"],
            "driver_monitor": ["NtLoadDriver", "NtSetSystemInformation"],
            "privilege_escalation": [
                "OpenProcessToken", "AdjustTokenPrivileges", "DuplicateTokenEx",
                "ImpersonateLoggedOnUser", "CreateProcessWithToken",
            ],
        },
        # Phase 6 — Android coverage (Frida Java hooks)
        "android_phase6": {
            "permission_monitor": ["Activity.requestPermissions", "ContextCompat.checkSelfPermission"],
            "sms_monitor": ["SmsManager.sendTextMessage", "SmsManager.sendMultipartTextMessage",
                            "ContentResolver.query(sms://)"],
            "location_monitor": ["LocationManager.requestLocationUpdates",
                                 "LocationManager.getLastKnownLocation",
                                 "FusedLocationProviderClient.requestLocationUpdates"],
            "contact_monitor": ["ContentResolver.query(contacts://)"],
            "clipboard_monitor": ["ClipboardManager.getPrimaryClip",
                                  "ClipboardManager.setPrimaryClip"],
            "camera_monitor": ["CameraManager.openCamera", "Camera.open",
                               "MediaRecorder.setVideoSource"],
            "microphone_monitor": ["AudioRecord.startRecording", "AudioRecord.read",
                                   "MediaRecorder.setAudioSource"],
            "accessibility_monitor": ["AccessibilityService.onAccessibilityEvent",
                                      "AccessibilityNodeInfo.findAccessibilityNodeInfosByText"],
            "overlay_monitor": ["WindowManagerImpl.addView", "LayoutInflater.inflate"],
        },
    }
