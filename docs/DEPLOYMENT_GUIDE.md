# E-Rakshak Production Deployment Guide — Render & Vercel

This guide provides step-by-step instructions for deploying the **E-Rakshak Unified Forensic & Threat Analysis Suite** from the `final` / `deploy` branch to **Render** (backend services, database, Redis, Elasticsearch, MobSF) and **Vercel** (frontend dashboard).

---

## 1. System Architecture

```text
                               +-----------------------------+
                               |     Client Browser / User   |
                               +--------------+--------------+
                                              |
                                              | HTTPS
                                              v
                              +-------------------------------+
                              |    Vercel (Frontend React)    |
                              |  project-undefine.vercel.app  |
                              +---------------+---------------+
                                              |
                                              | HTTPS API (VITE_API_BASE)
                                              v
+------------------------------------------------------------------------------------------+
| Render Cloud Environment (render.yaml Blueprint)                                         |
|                                                                                          |
|  +------------------------------------------------------------------------------------+  |
|  | E-Rakshak Backend (Web Service - Docker)                                           |  |
|  | Health Check: /api/health                                                          |  |
|  +--------+------------------+---------------------+-------------------+--------------+  |
|           |                  |                     |                   |                 |
|           v                  v                     v                   v                 |
|  +----------------+  +---------------+  +--------------------+  +---------------+        |
|  | PostgreSQL DB  |  |  Redis Cache  |  |   Elasticsearch    |  |     MobSF     |        |
|  | (Managed DB)   |  | (Private Svc) |  |   (Private Svc)    |  | (Private Svc) |        |
|  |  ps4_malware   |  |   Port 6379   |  |     Port 9200      |  |   Port 8000   |        |
|  +----------------+  +---------------+  +--------------------+  +---------------+        |
+------------------------------------------------------------------------------------------+
            |                                           |
            v                                           v
+-----------------------+                   +-----------------------+
| Hybrid Analysis API   |                   | MalwareBazaar / Groq  |
| (External Dynamic/    |                   | (Threat Intelligence  |
|  Threat Intelligence) |                   |  & Grounded AI)       |
+-----------------------+                   +-----------------------+
```

---

## 2. Prerequisites

1. **GitHub Repository:** `https://github.com/neil-data/project_undefine.git`
   - Production branch: `final` or `deploy`
2. **Render Account:** [https://render.com](https://render.com)
3. **Vercel Account:** [https://vercel.com](https://vercel.com)
4. **Third-Party API Keys (Stored only in Render Environment Secrets):**
   - **Hybrid Analysis API Key:** Free / Enterprise key from [hybrid-analysis.com](https://www.hybrid-analysis.com/)
   - **MalwareBazaar API Key:** Auth key from [bazaar.abuse.ch](https://bazaar.abuse.ch/)
   - **Groq API Key:** Free / Pro key from [groq.com](https://groq.com/) for grounded narrative generation

---

## 3. Render Deployment (Backend Infrastructure)

Render uses the single source of truth blueprint located at `render.yaml`.

### Step 3.1: Connect GitHub Repository to Render
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** in the top navigation bar and select **Blueprint**.
3. Connect your GitHub account and choose repository: **`neil-data/project_undefine`**.
4. In the **Branch** field, select **`deploy`** (or **`final`**).
5. Render will automatically detect and parse `render.yaml`.

### Step 3.2: 100% Free Tier Blueprint Resources
The free blueprint creates:
1. **`e-rakshak-db`**: Managed PostgreSQL 16 database (`ps4_malware`) on Render's **Free Plan** ($0.00 / month, no credit card required).
2. **`e-rakshak-backend`**: Web service built using `apps/backend/Dockerfile` on Render's **Free Plan** ($0.00 / month, 750 free hours/month).
3. **Storage & Microservices**: Uses container storage (`/tmp/ingestion_samples`) avoiding paid disk fees. Redis, Elasticsearch, and MobSF are made optional via environment variables with the backend's built-in graceful fallbacks.

### Step 3.3: Configure Production Secrets in Render Dashboard
Under **Environment Variables** for **`e-rakshak-backend`**, provide values for the `sync: false` keys:

| Secret Key | Description | Recommended Setting |
|---|---|---|
| `HYBRID_ANALYSIS_API_KEY` | API key for external dynamic intelligence | Enter HA key |
| `MALWARE_BAZAAR_API_KEY` | API key for known hash lookups | Enter MB key |
| `GROQ_API_KEY` | API key for narrative generation | Enter Groq key |
| `MOBSF_API_KEY` | API secret key from MobSF container | Generated on MobSF startup |
| `ALLOW_EXTERNAL_SUBMISSION` | Prevents uploading raw files to public HA | `false` |
| `MOBSF_DYNAMIC` | Keeps Android dynamic gated since emulator is offline | `false` |

> [!NOTE]
> The database schema (`storage/postgres/schema.sql`) and ORM tables are automatically applied by the backend during startup (`db.py` -> `init_db()`). No manual SQL migration step is required.

### Step 3.4: Obtain Backend Production URL
Once deployment finishes:
- Copy the public URL of **`e-rakshak-backend`**, e.g.:
  `https://e-rakshak-backend.onrender.com`
- Verify health:
  `curl https://e-rakshak-backend.onrender.com/api/health`
  Expected JSON:
  ```json
  {
    "status": "ok",
    "sandbox_online": true,
    "version": "0.1.0-alpha",
    "database_online": true
  }
  ```

---

## 4. Vercel Deployment (Frontend Dashboard)

The frontend is a Vite + React + TailwindCSS application located in `apps/frontend`.

### Step 4.1: Import Project in Vercel
1. Log in to [Vercel Dashboard](https://vercel.com).
2. Click **Add New...** -> **Project**.
3. Select **`neil-data/project_undefine`**.
4. Set **Production Branch** to **`deploy`** (or **`final`**).

### Step 4.2: Build & Output Settings
Configure the project settings:
- **Framework Preset:** `Vite`
- **Root Directory:** `apps/frontend` (or root `.` as root `vercel.json` routes to `apps/frontend`)
- **Build Command:** `npm run build`
- **Output Directory:** `dist`

### Step 4.3: Environment Variables
Add the following Environment Variable in Vercel (**Settings -> Environment Variables**):

| Variable Name | Value | Purpose |
|---|---|---|
| `VITE_API_BASE` | `https://e-rakshak-backend.onrender.com/api` | Connects frontend to Render backend |
| `VITE_SUPABASE_URL` | `https://qpqigxjvxvdqohnzbenj.supabase.co` | Public Supabase endpoint (if used) |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | `sb_publishable_jZVFY-5...TAT` | Public client token (non-secret) |

> [!CAUTION]
> Never expose backend secrets (`JWT_SECRET_KEY`, database passwords, or provider API keys) in Vercel environment variables. Vite only bundles `VITE_*` variables into client-side JavaScript.

### Step 4.4: Deploy & Verify
1. Click **Deploy**.
2. Vercel installs dependencies, compiles TypeScript, runs Vite build, and deploys.
3. Access your production domain: `https://project-undefine.vercel.app`.

---

## 5. Cross-Origin Resource Sharing (CORS) Configuration

To allow the Vercel frontend to communicate with the Render backend:
1. In the **Render Dashboard**, open **`e-rakshak-backend`** -> **Environment**.
2. Verify `CORS_ORIGINS` contains your Vercel production domain:
   ```env
   CORS_ORIGINS=https://project-undefine.vercel.app,http://localhost:3000,http://localhost:5173
   ```
3. If using custom domains (e.g. `https://erakshak.gov.in`), append them separated by commas.

---

## 6. Post-Deployment Verification Checklist

| # | Test | Command / Method | Expected Result |
|---|---|---|---|
| 1 | Backend Health Check | `curl https://e-rakshak-backend.onrender.com/api/health` | HTTP 200, `database_online: true` |
| 2 | Frontend Delivery | Open `https://project-undefine.vercel.app` | Dark mode dashboard loads with Surat Police branding |
| 3 | Threat Intel Lookup | Call `/api/threat-intel/bazaar/lookup/<sha256>` | Returns MalwareBazaar intelligence record |
| 4 | File Analysis | Upload sample via Dashboard UI | Static parsing + HA Intel + deterministic fallback if AI fails |
| 5 | PDF Generation | Download analysis report from case view | Clean multi-page PDF generated via ReportLab |

---

## 7. Known Operational Limitations & Safety Invariants

1. **Android Emulator Dynamic Execution:**
   - Standard cloud container environments (Render/Docker) do not support nested hardware virtualization (KVM).
   - MobSF Android dynamic analysis is safely gated (`MOBSF_DYNAMIC=false`). Static APK analysis (manifest, permissions, certificates) operates normally without faking dynamic findings.
2. **Hybrid Analysis External Submissions:**
   - Raw binary upload to public Hybrid Analysis sandboxes is disabled (`ALLOW_EXTERNAL_SUBMISSION=false`) to guarantee sample privacy.
   - Known hash lookups run normally; external verdicts are strictly categorized as `INTEL` without fabricating dynamic behavioral evidence.
3. **Mach-O Platform:**
   - Static analysis is fully supported; dynamic sandbox execution is cleanly bypassed with an explicit static-only status.
