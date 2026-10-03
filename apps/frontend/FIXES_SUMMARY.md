# Frontend Bug Fixes — Summary

## Files changed
- `src/lib/api.ts` — added `fetchCurrentUser()` calling `GET /auth/me`, and `CurrentUser` interface
- `src/components/DashboardPage.tsx` — wired real user into sidebar, guarded upload response fields, wired real logout
- `src/components/dashboard/AiReportsTab.tsx` — replaced fake export with real jsPDF-generated download
- `src/components/HeroSection.tsx` — fixed GSAP navbar animation scope bug
- `src/components/ErrorBoundary.tsx` — NEW: catches render errors, shows recoverable screen instead of blank crash
- `src/main.tsx` — wraps <App /> in the new ErrorBoundary
- `package.json` — added `jspdf` dependency

## 1. Demo user -> real user
`fetchCurrentUser()` calls `${API_BASE}/auth/me` with the auth header and returns a `CurrentUser` object.
The sidebar now shows `full_name || username || email` and derives initials from it, falling back to
"Loading operator..." while the request is in flight.

IMPORTANT: check the actual JSON shape your `/auth/me` endpoint returns and adjust the `CurrentUser`
interface / field names in `DashboardPage.tsx` sidebar block if they don't match
(currently expects: id, email, username, full_name, agency, role, badge_number — all optional).

## 2. Report download -> real PDF
`handleExport()` in AiReportsTab.tsx now builds an actual multi-section PDF with jsPDF (executive summary,
cryptographic hash block, MITRE technique appendix, clearance section) and triggers a real browser
download via `doc.save(...)`. No more alert()/fake timeout.

Run `npm install` in your project (jspdf was added to package.json) before building.

## 3. GSAP navbar animation
The Navbar (`#navbar-container`) is rendered as a sibling of HeroSection, not inside it — so animating it
from within HeroSection's `gsap.context(fn, containerRef)` never matched the selector (scoped search only
looks inside containerRef). Moved that one tween outside the context, animated directly, and added
`navbarTween.kill()` to cleanup.

## 4. Dashboard crash
Two changes:
- New `ErrorBoundary` component wraps the whole app in `main.tsx`. Any future uncaught render error now
  shows a recoverable "Try Again / Reload" screen instead of a blank white page.
- `handleRealUpload` in DashboardPage.tsx was calling `.length` / `.map` directly on
  `result.mitre_techniques` / `result.capability_tags` from the upload API response with no null check.
  If the backend ever returns a response missing those fields (partial analysis, error state, etc.) this
  threw and — with no error boundary — blanked the entire site. Now defaults to `[]` and other fields
  have safe fallbacks too.
