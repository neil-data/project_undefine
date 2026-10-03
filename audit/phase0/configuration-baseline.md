# Configuration & Cloud Dependencies Baseline (Phase 0)

This audit documents all configuration files, environment variables, deployment specifications, and cloud/GCP dependencies in the repository.

---

## 1. Targeted GCP / Cloud Dependency Audit

Using targeted regex patterns (`GCP_`, `google\.cloud`, `googleapiclient`, `gcloud`, `GOOGLE_APPLICATION_CREDENTIALS`):

| Type | Match Location | Content / Context | Active Dependency? |
|---|---|---|---|
| **Environment Variable** | `.env.example:58` | `GCP_PROJECT_ID=` | **No** (Optional legacy setting in example template) |
| **Environment Variable** | `.env.example:59` | `GCP_VM_INSTANCE_NAME=` | **No** (Optional legacy setting in example template) |
| **Shell Script** | `infra/setup_gcp_vm.sh:17-18` | `PROJECT_ID="${GCP_PROJECT_ID:-ps4-malware-suite}"`<br>`INSTANCE_NAME="${GCP_VM_INSTANCE_NAME:-ps4-detonation-sandbox}"` | **No** (Legacy manual VM setup script for CAPE) |
| **Shell Command** | `infra/setup_gcp_vm.sh:32-57` | `gcloud config set project ...`<br>`gcloud compute instances create ...` | **No** (CLI script for GCP VM provisioning, not part of runtime pipeline) |
| **Shell Comment** | `infra/install_kvm_cape.sh:5,23` | Comments referring to `setup_gcp_vm.sh` | **No** |
| **Python Code Imports** | Whole Repository | `0 matches` for `google.cloud`, `googleapiclient`, `GOOGLE_APPLICATION_CREDENTIALS` | **None** |
| **CI / CD Workflows** | `.github/` | `0 matches` for GCP credentials or actions | **None** |
| **Deployment Config** | `render.yaml` | `0 matches` for GCP | **None** |

**Conclusion**: The core malware analysis pipeline, backend services, agents, static analysis, sandbox host, and frontend have **ZERO runtime dependencies on Google Cloud Platform**. The only GCP references in the repository are legacy helper shell scripts in `infra/` for provisioning an external CAPE sandbox VM.

---

## 2. Configuration Files & Environment Variables

### `.env.example` (Root)
Key variables declared:
- `BACKEND_PORT=8000`
- `GROQ_API_KEY=` (for narrative generation)
- `GROQ_MODEL=openai/gpt-oss-120b`
- `GEOIP_DB_PATH=` (MaxMind GeoLite2-City.mmdb)
- `GEOIP_ASN_DB_PATH=` (MaxMind GeoLite2-ASN.mmdb)
- `MALWAREBAZAAR_API_KEY=` (Abuse.ch MalwareBazaar threat feed)
- `THREATFOX_API_KEY=` (ThreatFox threat feed)
- `SANDBOX_API_URL=` (URL of decoupled sandbox host)
- `SANDBOX_API_TOKEN=` (Bearer token for sandbox API)
- `CHAIN_VERIFICATION_SECRET=` (HMAC secret for chain of custody)

### `render.yaml`
Declares deployment services for Render:
- `backend`: Python web service running `uvicorn backend.app.main:app`
- `frontend`: Node/static web service running Vite build

### `frontend/`
- `.env`: Declares `VITE_API_BASE_URL`
- `.env.local`: Local frontend developer environment overrides
