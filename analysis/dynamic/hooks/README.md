# Live API Hook Monitoring

Monitors 30 Win32 APIs and 24 Android Java APIs inside the sandbox and
correlates them into named behaviors.

## The design premise

Individual API calls are close to worthless as evidence:

- `VirtualAlloc` fires thousands of times in every benign process
- `CryptEncrypt` is how a password manager works
- `GetProcAddress` is ordinary dynamic linking

What separates malware from software is **ordering**:

```
VirtualAlloc(RWX) → NtWriteVirtualMemory(other process) → CreateRemoteThread
    = process injection, and essentially nothing else

ReadFile → CryptEncrypt → WriteFile, repeated across user documents
    = ransomware, not a backup tool
```

So individual calls score near zero and the chains carry the weight. A monitor
that alerts on `VirtualAlloc` is worse than no monitor — it trains
investigators to ignore it.

## Monitored surface

| Category | APIs |
|----------|------|
| Filesystem | CreateFile, ReadFile, WriteFile, DeleteFile |
| Registry | RegCreateKey, RegSetValue |
| Network | InternetConnect, WinHttpSendRequest |
| Process | CreateProcess |
| Execution | ShellExecute |
| Memory | VirtualAlloc, VirtualProtect |
| Injection | NtWriteVirtualMemory, CreateRemoteThread |
| Dynamic resolution | LoadLibrary, GetProcAddress |
| Crypto | CryptEncrypt, CryptDecrypt |
| Device | DeviceIoControl |

`-A`/`-W`/`Ex` variants normalize to one identity, so `CreateFileW`,
`VirtualAllocEx` and `WriteProcessMemory` resolve to `CreateFile`,
`VirtualAlloc` and `NtWriteVirtualMemory` respectively.

## Detected behaviors

| Chain | Sequence | Severity |
|-------|----------|----------|
| Process injection | VirtualAlloc(RWX) → NtWriteVirtualMemory → CreateRemoteThread | critical |
| Process hollowing | CreateProcess(SUSPENDED) → NtWriteVirtualMemory → CreateRemoteThread | critical |
| Runtime unpacking | VirtualAlloc → VirtualProtect(→exec) | high |
| Payload decryption | CryptDecrypt → VirtualProtect(→exec) | high |
| Ransomware cycle | ReadFile → CryptEncrypt → WriteFile | critical |
| Drop and persist | WriteFile → RegCreateKey → RegSetValue(autostart) | critical |
| Data exfiltration | ReadFile → InternetConnect → WinHttpSendRequest | critical |
| Downloader | WinHttpSendRequest → WriteFile → ShellExecute | critical |
| Dynamic resolution | LoadLibrary → GetProcAddress | medium |
| Driver communication | CreateFile(\\.\device) → DeviceIoControl | high |

Chains carry conditions beyond ordering. `NtWriteVirtualMemory` only counts as
injection when it targets a **foreign** process — self-writes are how packers
unpack, and flagging those would bury the real signal.

## Android surface

The base Android agent reports its filesystem, network, execution, crypto and
dynamic-loading hooks under the **Windows** names — `java.io.File.delete`
arrives as `DeleteFile`, `URL.openConnection` as `InternetConnect`. That is
deliberate: a rule like "read then send" is written once and matches on both
platforms, and the network half of every Android chain below is shared with
the Windows rules.

What has no Windows analogue gets its own catalog entry, because the sensitive
resource is the phone itself:

| Category | Events |
|----------|--------|
| Permissions | RequestPermissions, CheckPermission |
| SMS | SendSMS, SendMultipartSMS, ReadSMS |
| Location | RequestLocationUpdates, GetLastKnownLocation, FusedLocationUpdates |
| Contacts | ReadContacts, ContactsContractAccess |
| Clipboard | ClipboardRead, ClipboardWrite, ClipboardCheck |
| Camera | CameraOpen, CameraStartPreview, MediaRecorderVideoSource |
| Microphone | AudioRecordStart, AudioRecordRead, MediaRecorderAudioSource |
| Media | MediaRecorderStart |
| Accessibility | AccessibilityEvent, AccessibilityFindByText |
| Overlay | OverlayWindowAdded, LayoutInflate |

### Detected Android behaviors

| Chain | Sequence | Severity |
|-------|----------|----------|
| OTP interception | ReadSMS → SendSMS | critical |
| SMS exfiltration | ReadSMS → InternetConnect | critical |
| Contact-list smishing | ReadContacts → SendSMS | critical |
| Contact exfiltration | ReadContacts → InternetConnect | high |
| Location tracking | RequestLocationUpdates → InternetConnect | high |
| Cached-position reporting | GetLastKnownLocation → InternetConnect | high |
| Crypto clipper | ClipboardRead(address-shaped) → ClipboardWrite | critical |
| Clipboard hijack | ClipboardRead → ClipboardWrite | high |
| Clipboard exfiltration | ClipboardRead → InternetConnect | high |
| Audio surveillance | AudioRecordStart → InternetConnect | critical |
| Covert recording | MediaRecorderAudioSource(mic/call) → MediaRecorderStart | high |
| Camera surveillance | CameraOpen → InternetConnect | critical |
| Video recording | MediaRecorderVideoSource(camera) → MediaRecorderStart | high |
| Credential theft | AccessibilityEvent → AccessibilityFindByText("OTP") | critical |
| Screen exfiltration | AccessibilityEvent(text) → InternetConnect | high |
| Banking overlay | AccessibilityEvent(window change) → OverlayWindowAdded(overlay) | critical |
| Overlay credential theft | OverlayWindowAdded → LayoutInflate → InternetConnect | critical |
| Runtime DEX load | LoadLibrary(dex) → InternetConnect | high |

The conditions do the same work they do on Windows. `addView` is how every app
draws its own UI, so `OverlayWindowAdded` only counts when the window type can
cover *another* app (2038, 2003). `MediaRecorderAudioSource` only counts when
the source is the microphone or the call, not `VOICE_RECOGNITION`, which is
dictation the user asked for. Without those checks these rules fire on every
app on the device.

### Android volume findings

Some Android behavior is invisible per-call and unambiguous in aggregate:

| Finding | Threshold |
|---------|-----------|
| Mass text messaging | 10 sends |
| Continuous location tracking | 20 position requests |
| Sustained microphone recording | 50 buffer reads |
| Clipboard monitoring | 30 polls |
| Keystroke capture across apps | 50 text-change events |
| Tapjacking overlay | 1 invisible window |
| Call recording | 1 session |
| Sensitive-permission escalation | 5 distinct permissions |

Tapjacking and call recording have no threshold on purpose. A transparent,
untouchable window over the screen and a recorder pointed at the call audio
have no benign explanation — one is the finding.

## Usage

```python
from hooks import StageHookMonitor, generate_frida_agent

# Install in the guest
agent_js = generate_frida_agent()

# Host side, wired to the 8-stage pipeline
monitor = StageHookMonitor(analysis_id)

monitor.enter_stage("long_execution")
chains = monitor.ingest_batch(calls_from_guest)
rollup = monitor.exit_stage("long_execution")

monitor.stage_findings("long_execution")   # report-ready findings
monitor.activation_analysis()              # which stage woke the sample
```

## Joint output with the stage pipeline

Hook data and stage data are individually useful and jointly much stronger:

```python
monitor.activation_analysis()
# {
#   'first_api_call_stage': 'boot',
#   'first_critical_behavior_stage': 'reboot',
#   'reconnaissance_gap': True,
#   'silent_stages': ['idle']
# }
```

"Injection detected" is a finding. "Injection detected only after reboot,
having been absent through boot, idle, interaction and network stages" is an
evidence narrative — it establishes the payload was deliberately gated, which
speaks to intent rather than just capability. The `reconnaissance_gap` flag
marks samples that called APIs early but only acted maliciously later.

## Guest-side safety

The generated Frida agent gets three things right that naive hooking does not:

**Reentrancy guards.** The hook body calls into the CRT, which can call a
hooked API. Without a per-thread depth guard this recurses until the guest
stack dies — the most common way homegrown harnesses crash the VM.

**Sensitive data never leaves the guest.** Buffers are hashed in-guest (FNV-1a
plus a zero-byte-ratio entropy proxy); only the digest and length are
transmitted. Credential parameters are replaced with `[REDACTED]` before
serialization. An isolated lab is not a reason to pipe a victim's documents
into the evidence store.

**Batching and in-guest rate limiting.** `GetProcAddress` fires thousands of
times a second. One message per call saturates the transport and slows the
guest enough to be detectable by timing checks.

## Two decisions worth knowing

**Counting is separate from emission.** Every chain match increments the
counter; only the first within a rule's window is emitted as a distinct
finding. Conflating them was a bug — ransomware encrypts thousands of files in
seconds, so window dedup swallowed all but the first cycle and the
mass-encryption threshold could never be reached.

**Broader rules supersede narrower ones.** A single injection matches both the
full `alloc→write→thread` chain and the `write→thread` subset. Emitting both
describes one event twice and inflates apparent severity, so the narrower rule
stays silent when a fuller one matched the same call — but still fires on its
own when no allocation preceded it.

## Testing

```bash
pytest dynamic-sandbox/hooks/ -v
```

183 tests. The negative cases matter as much as the detections — benign
activity, self-writes, non-suspended process creation, ordinary registry
writes, normal file IOCTLs, an app drawing its own windows, a maps app polling
location and a messaging app reading SMS must all stay silent.

## Files

| File | Contents |
|------|----------|
| `api_catalog.py` | The 54 APIs with capture rules, risk, MITRE mapping |
| `hook_engine.py` | Chain correlation, volume findings, risk scoring |
| `hook_installer.py` | Frida agent generation (Windows + Android), CAPE config |
| `stage_integration.py` | Stage attribution, findings, mock call source |
| `test_hooks.py` | Windows test suite |
| `test_phase5_6_hooks.py` | Agent-generation tests for the extended monitors |
| `test_phase6_android_pipeline.py` | Android host-side pipeline test suite |
