# E-Rakshak Real Dynamic Sandbox Host

Decoupled, isolated microservice for detonating Linux ELF binaries natively (x86_64) and cross-architecture (ARM, MIPS, RISC-V) via QEMU user emulation with strace interception.

## Isolation Architecture
- **Single-Job Runner Lock**: Only one sample detonates at any time to prevent cross-contamination and resource contention.
- **Throwaway Container / VM Snapshot Revert**: After every run, all temporary state and filesystem artifacts are purged, reverting to a clean baseline.
- **Non-Root Execution**: Samples execute under a dedicated non-privileged user (sandbox-runner) with restricted capabilities (seccomp, prctl(PR_SET_NO_NEW_PRIVS)).
- **Network Isolation & INetSim Bridge**:
  - The guest runner is connected exclusively to an isolated host-only virtual bridge.
  - All DNS, HTTP, HTTPS, and TCP/UDP egress is redirected to an INetSim fake-service container.
  - Direct public internet egress is strictly blocked by iptables rules.
- **Canary Egress Verification**: The sandbox verifies isolation at startup and before detonation by checking that external canary probes fail.

## Artifact Contract
The sandbox host is strictly an execution and artifact-collection service. It **never parses** telemetry. It produces and serves:
1. strace.log: Full system-call trace (strace -f -tt -s 512 -yy or qemu-<arch> -strace).
2. capture.pcap: Raw network packet capture from the isolated bridge.
3. s_diff.json: Host/guest filesystem diff (created/modified/deleted files).
4. stdout.log / stderr.log: Process console outputs.
5. meta.json: Execution metadata (exit code, duration, architecture, sample hash).
6. manifest.json: Cryptographic SHA-256 hashes for all generated artifact files for HMAC chain-verification binding.
