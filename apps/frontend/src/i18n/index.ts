import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./en.json";
import gu from "./gu.json";

const STORAGE_KEY = "sentinel_language";

// Scope note: this covers the app's core chrome (nav, login, dashboard
// sidebar/topbar/settings) — the landing page's marketing copy
// (LandingSections.tsx) and the deeper dashboard tab bodies are not yet
// translated and fall back to English regardless of the selected language.
i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    gu: { translation: gu },
  },
  lng: localStorage.getItem(STORAGE_KEY) || "en",
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

export function setLanguage(lang: "en" | "gu") {
  i18n.changeLanguage(lang);
  localStorage.setItem(STORAGE_KEY, lang);
}

export function getLanguage(): "en" | "gu" {
  return (i18n.language as "en" | "gu") || "en";
}

export default i18n;
