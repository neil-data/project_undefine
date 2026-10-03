/**
 * Supabase browser client.
 *
 * Import as:
 *   import { createClient } from '@/src/utils/supabase/client'
 *
 * Note the `src` segment. The `@` alias maps to the frontend root (see
 * `resolve.alias` in vite.config.ts), not to `src/`, so `@/utils/supabase/client`
 * does not resolve — despite being the path the setup instructions suggested.
 *
 * Only a browser client exists here. The `server.ts` and `middleware.ts` from
 * Supabase's setup guide are Next.js-only: they import `next/headers` and
 * `next/server`, which do not exist in a Vite app.
 */

import { createBrowserClient } from "@supabase/ssr";

// Vite only exposes variables prefixed with VITE_ through import.meta.env.
// NEXT_PUBLIC_* names are inert here regardless of what .env.local contains,
// so there is deliberately no fallback to them.
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  // Without this, a missing variable surfaces as an opaque failure from inside
  // the Supabase SDK on first use, well away from the actual cause.
  throw new Error(
    "Supabase is not configured. Set VITE_SUPABASE_URL and " +
      "VITE_SUPABASE_PUBLISHABLE_KEY in frontend/.env.local, then restart the " +
      "dev server — Vite only reads env files at startup.",
  );
}

export const createClient = () => createBrowserClient(supabaseUrl, supabaseKey);
