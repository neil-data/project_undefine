# E-Rakshak Sandbox Infrastructure

The `sandbox/` directory contains host orchestration agents, hypervisor runners, and external dynamic sandbox adapters for isolated malware detonation.

---

## Directory Structure

```
sandbox/
├── host/                    # QEMU/KVM hypervisor runner and API service
│   ├── app/
│   │   ├── main.py          # FastAPI execution endpoint and worker orchestration
│   │   ├── runner.py        # VM lifecycle, snapshot revert, artifact collection
│   │   ├── canary.py        # Guest agent heartbeat and hypervisor health checks
│   │   └── config.py        # Sandbox host settings and path configuration
│   ├── tests/               # Integration tests for sandbox host runner and canaries
│   ├── Dockerfile           # Containerized sandbox host deployment definition
│   ├── provision.sh         # Bare-metal KVM/libvirt VM provisioning script
│   └── requirements.txt     # Python dependencies for the sandbox service
└── adapters/
    └── mobsf/               # Mobile Security Framework (MobSF) adapter for Android APKs
        ├── part1_connectivity.py   # MobSF REST API health and auth checks
        ├── part2_upload.py         # APK upload and static triage triggering
        ├── part3_dynamic_run.py    # Dynamic execution in Android emulator
        ├── part4_report_adapter.py # Normalization of MobSF JSON to E-Rakshak schema
        ├── part5_pipeline.py       # End-to-end APK analysis pipeline
        └── test_mobsf_dynamic.py   # Unit and integration tests for MobSF integration
```

---

## Architecture & Workflow

1. **Host Runner (`sandbox/host/`)**:
   - Manages local or remote hypervisors (QEMU/KVM with libvirt).
   - Reverts VM to a clean gold snapshot before each detonation run.
   - Drops sample into isolated guest environment, invokes execution under monitoring hooks, and gathers PCAP network captures, file modifications, and process execution trees.
   - Periodically validates guest liveness and integrity via canary checks (`canary.py`).

2. **Mobile Sandbox Adapter (`sandbox/adapters/mobsf/`)**:
   - Connects to an external MobSF instance running an Android emulator.
   - Uploads APKs, triggers runtime execution, captures network and API calls, and translates the raw MobSF output into standardized E-Rakshak report structures.

---

## Provisioning

To set up a local KVM host environment on Linux:
```bash
cd sandbox/host
chmod +x provision.sh
./provision.sh
```
Or run the containerized runner:
```bash
docker build -t erakshak-sandbox-host -f sandbox/host/Dockerfile .
```
