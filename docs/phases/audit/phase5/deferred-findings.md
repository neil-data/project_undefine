# Phase 5 — Deferred Findings (Phase 6 Items)

The following items are outside the scope of Phase 5 (B4/B5) and are intentionally deferred to Phase 6 or production operations:

1. **Live Multi-Node Hypervisor Orchestration**:
   - Automated provisioning and life-cycle destruction of hardware-accelerated guest VMs (KVM/QEMU) across a distributed worker pool.
   - Deferral Rationale: Phase 4 hardened the host runner, security boundaries, and HMAC manifest integrity for isolated execution. Multi-node orchestration requires external clustering infrastructure.

2. **Continuous External Threat Feed Sync Daemons**:
   - Background daemon service to continuously pull, index, and ingest bulk feeds from Abuse.ch, AlienVault OTX, or MISP into local databases.
   - Deferral Rationale: B4 established robust real-time lookups with negative caching and multi-vendor verdict parsing. Bulk ingestion belongs in dedicated background ingestion jobs.

3. **Live VM In-Guest Memory Dumping & VMI**:
   - Virtual Machine Introspection (VMI) for live guest kernel memory carving during execution.
   - Deferral Rationale: Dynamic sandbox runner correctly captures processes, dropped files, persistence artifacts, and network traffic via standard guest monitoring hooks.
