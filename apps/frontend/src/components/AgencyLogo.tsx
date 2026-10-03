import * as React from "react";

// Drop the real agency logo at frontend/public/logo.jpeg
// and it appears automatically here, in the hero section, and in the exported
// PDF report — no code change needed anywhere that uses this component.
export const AGENCY_LOGO_PATH = "/logo.jpeg";

export function AgencyLogo({ className }: { className?: string }) {
  const [failed, setFailed] = React.useState(false);
  if (failed) return null;
  return (
    <img
      src={AGENCY_LOGO_PATH}
      alt="Gujarat Police"
      className={className}
      onError={() => setFailed(true)}
    />
  );
}

// For jsPDF's doc.addImage(), which needs a data URL rather than a plain <img> src.
export async function loadAgencyLogoDataUrl(): Promise<string | null> {
  try {
    const res = await fetch(AGENCY_LOGO_PATH);
    if (!res.ok) return null;
    const blob = await res.blob();
    return await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  } catch {
    return null;
  }
}
