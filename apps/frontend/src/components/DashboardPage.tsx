import * as React from "react";
import { 
  Shield, 
  UploadCloud, 
  Cpu, 
  Terminal, 
  Workflow, 
  Layers, 
  FileText, 
  Briefcase, 
  LogOut, 
  Search, 
  Filter, 
  FileCode, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  X, 
  Database,
  Info,
  Clock,
  Sliders,
  ChevronDown,
  Lock,
  ExternalLink,
  ChevronRight,
  FileCheck,
  Globe
} from "lucide-react";

import { AgencyLogo } from "./AgencyLogo";
import { useTranslation } from "react-i18next";
import { ThreatCase } from "./dashboard/types";
import { OverviewTab } from "./dashboard/OverviewTab";
import { StaticAnalysisTab } from "./dashboard/StaticAnalysisTab";
import { DynamicSandboxTab } from "./dashboard/DynamicSandboxTab";
import { MitreMappingTab } from "./dashboard/MitreMappingTab";
import { AiReportsTab } from "./dashboard/AiReportsTab";
import { InvestigationDashboardTab } from "./dashboard/InvestigationDashboardTab";
import { NetworkIntelligenceTab } from "./dashboard/NetworkIntelligenceTab";
import { setLanguage, getLanguage } from "../i18n";

interface DashboardPageProps {
  onLogout: () => void;
}

import { fetchCases, fetchCaseDetail, uploadSample, fetchAnalysisStatus, fetchHealth, fetchCurrentUser, logout as apiLogout, CaseSummary, CaseDetail, CurrentUser } from "../lib/api";

export function DashboardPage({ onLogout }: DashboardPageProps) {
  const { t } = useTranslation();
  const [language, setLanguageState] = React.useState<"en" | "gu">(getLanguage());
  const toggleLanguage = () => {
    const next = language === "en" ? "gu" : "en";
    setLanguage(next);
    setLanguageState(next);
  };
  const [activeTab, setActiveTab] = React.useState<
    "overview" | "upload" | "static" | "dynamic" | "behavior" | "mitre" | "reports" | "investigation" | "cases" | "network"
  >("upload");

  const [cases, setCases] = React.useState<ThreatCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = React.useState<string>("");
  const [activeCaseDetail, setActiveCaseDetail] = React.useState<CaseDetail | null>(null);
  const [isLoadingCases, setIsLoadingCases] = React.useState<boolean>(true);
  const [sandboxOnline, setSandboxOnline] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>("");

  // Upload state
  const [uploadProgress, setUploadProgress] = React.useState(0);
  const [isUploading, setIsUploading] = React.useState(false);
  const [uploadStep, setUploadStep] = React.useState("");
  const [zipPassword, setZipPassword] = React.useState("");
  const [currentTime, setCurrentTime] = React.useState("");
  const [expandedBehaviorIdx, setExpandedBehaviorIdx] = React.useState<number | null>(0);
  const [casesSearchQuery, setCasesSearchQuery] = React.useState("");
  const [currentUser, setCurrentUser] = React.useState<CurrentUser | null>(null);
  const [isLoadingCurrentUser, setIsLoadingCurrentUser] = React.useState<boolean>(true);
  const [currentUserError, setCurrentUserError] = React.useState<string>("");

  // Fetch real cases from backend API
  const loadCases = React.useCallback(async () => {
    setIsLoadingCases(true);
    setErrorMessage("");
    try {
      const data = await fetchCases();
      const mappedCases: ThreatCase[] = data.map((c: CaseSummary) => ({
        id: c.sample_id,
        name: c.original_filename
          ? `${c.original_filename} (${c.sample_id.toLowerCase().substring(0, 12)}…)`
          : `${c.sample_id.toLowerCase()}.${c.file_type}`,
        type: c.file_type.toUpperCase() as any,
        size: "Dynamic",
        hash: c.sample_id,
        riskScore: c.risk_score,
        status: c.status.toUpperCase() as any,
        date: c.submitted_at.replace("T", " ").substring(0, 19),
        agency: "Cyber Crime Unit Node",
        mitreCount: 0,
        yaraMatches: [],
      }));
      setCases(mappedCases);
      if (mappedCases.length > 0 && !selectedCaseId) {
        setSelectedCaseId(mappedCases[0].id);
      }
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to load cases");
    } finally {
      setIsLoadingCases(false);
    }
  }, [selectedCaseId]);

  React.useEffect(() => {
    loadCases();
    fetchHealth().then(h => setSandboxOnline(h.sandbox_online)).catch(() => setSandboxOnline(false));
    setIsLoadingCurrentUser(true);
    setCurrentUserError("");
    fetchCurrentUser()
      .then((user) => setCurrentUser(user))
      .catch((err: any) => {
        setCurrentUser(null);
        setCurrentUserError(err?.message || "Failed to fetch current user");
      })
      .finally(() => setIsLoadingCurrentUser(false));
  }, []);

  // Fetch detail for selected case
  React.useEffect(() => {
    if (!selectedCaseId) return;
    fetchCaseDetail(selectedCaseId)
      .then(detail => setActiveCaseDetail(detail))
      .catch(err => console.error("Failed to load case detail:", err));
  }, [selectedCaseId]);

  // Derive activeCase with detailed API data if available
  const baseActiveCase = cases.find(c => c.id === selectedCaseId) || cases[0] || {
    id: "ER-0000",
    name: "no_sample_selected",
    type: "APK",
    size: "0 B",
    hash: "0000000000000000000000000000000000000000000000000000000000000000",
    riskScore: 0,
    status: "CLEARED",
    date: new Date().toISOString(),
    agency: "Central Agency",
    mitreCount: 0,
    yaraMatches: [],
  };

  const detailMitreTechniques = activeCaseDetail?.mitre_techniques ?? [];
  const detailCapabilityTags = activeCaseDetail?.capability_tags ?? [];

  const isDetailMatch = Boolean(
    activeCaseDetail && (
      activeCaseDetail.sample_id === baseActiveCase.id ||
      activeCaseDetail.sha256 === baseActiveCase.id ||
      activeCaseDetail.sample_id === baseActiveCase.hash ||
      activeCaseDetail.sha256 === baseActiveCase.hash ||
      !baseActiveCase.id
    )
  );

  const activeCase: ThreatCase = (activeCaseDetail && isDetailMatch)
    ? {
        ...baseActiveCase,
        riskScore: activeCaseDetail.risk_score,
        status: activeCaseDetail.status.toUpperCase() as any,
        mitreCount: detailMitreTechniques.length,
        yaraMatches: detailCapabilityTags.map(c => (c.capability ?? "unknown").toUpperCase().replace(/\s+/g, "_")),
        narrativeSummary: activeCaseDetail.narrative_summary,
        mitreTechniques: detailMitreTechniques,
        capabilityTags: detailCapabilityTags,
        sha256: activeCaseDetail.sha256,
        md5: activeCaseDetail.md5,
        sha1: activeCaseDetail.sha1,
        yaraMatchDetails: activeCaseDetail.yara_matches,
        packing: activeCaseDetail.packing,
        explainedStrings: activeCaseDetail.explained_strings,
        geoIocs: activeCaseDetail.geo_iocs,
        sandboxResult: activeCaseDetail.dynamic_analysis ?? null,
        behaviorAnalysis: activeCaseDetail.behavior_analysis ?? null,
        // Part 2: Network Intelligence, Threat Assessment, AI Analysis
        networkIndicators: activeCaseDetail.network_indicators ?? null,
        threatAssessment: activeCaseDetail.threat_assessment ?? null,
        aiAnalysis: activeCaseDetail.ai_analysis ?? null,
        iocIntelligence: activeCaseDetail.ioc_intelligence ?? [],
        evidenceCorrelation: activeCaseDetail.evidence_correlation ?? [],
        evidenceTimeline: activeCaseDetail.evidence_timeline ?? [],
        riskExplanation: activeCaseDetail.risk_explanation ?? null,
        malwareBazaar: activeCaseDetail.malware_bazaar ?? null,
      }
    : baseActiveCase;


  // Live real-time IST digital clock inside Top bar
  React.useEffect(() => {
    const updateClock = () => {
      const d = new Date();
      const timeStr = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Asia/Kolkata",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }).format(d);
      setCurrentTime(`${timeStr} IST`);
    };
    updateClock();
    const t = setInterval(updateClock, 1000);
    return () => clearInterval(t);
  }, []);

  // Real file upload pipeline
  const handleRealUpload = async (file: File, customPassword?: string) => {
    setIsUploading(true);
    setUploadProgress(10);
    setUploadStep(`Uploading ${file.name} to security gateway...`);

    const stageToProgress: Record<string, number> = {
      UPLOADED: 15,
      VALIDATING: 30,
      HASHING: 40,
      STATIC_ANALYSIS: 60,
      DYNAMIC_ANALYSIS: 85,
      COMPLETED: 100,
    };

    const effectivePassword = customPassword ?? (zipPassword.trim() || undefined);

    try {
      const start = await uploadSample(file, effectivePassword);
      const analysisId = start.analysis_id;

      // Poll the backend for the real pipeline state (never a fake timer).
      let status = start.status;
      let stage = start.stage ?? "";
      let analysisError = "";
      setUploadProgress(stageToProgress[status] ?? 15);
      setUploadStep(stage || "Analysis started...");
      while (status !== "COMPLETED" && status !== "FAILED") {
        await new Promise(resolve => setTimeout(resolve, 1200));
        try {
          const poll = await fetchAnalysisStatus(analysisId);
          status = poll.status;
          stage = poll.stage ?? stage;
          analysisError = poll.error ?? analysisError;
        } catch (e) {
          // transient poll failure — keep waiting rather than aborting
          continue;
        }
        setUploadProgress(stageToProgress[status] ?? 15);
        setUploadStep(stage);
        if (status === "COMPLETED" || status === "FAILED") break;
      }

      if (status === "FAILED") {
        setIsUploading(false);
        alert(`Analysis failed: ${analysisError || stage || "Unknown error during analysis"}`);
        return;
      }

      setUploadProgress(100);
      setUploadStep("Analysis complete! Dossier generated.");

      // Fetch the full evidence-grade dossier (static + dynamic state).
      const result = await fetchCaseDetail(analysisId);

      const newCase: ThreatCase = {
        id: analysisId,
        name: result.original_filename ?? file.name,
        type: (result.file_type ?? "unknown").toUpperCase() as any,
        size: `${((result.file_size_bytes ?? file.size) / (1024 * 1024)).toFixed(1)} MB`,
        hash: result.sha256 ?? analysisId,
        riskScore: result.risk_score ?? 0,
        status: (result.status ?? "analyzing").toUpperCase() as any,
        date: result.submitted_at ? result.submitted_at.replace("T", " ").substring(0, 19) : new Date().toISOString().substring(0, 19),
        agency: "Cyber Cell Ingestion Node",
        mitreCount: (result.mitre_techniques ?? []).length,
        yaraMatches: (result.capability_tags ?? []).map(c => (c.capability ?? "unknown").toUpperCase().replace(/\s+/g, "_")),
        narrativeSummary: result.narrative_summary,
        mitreTechniques: result.mitre_techniques ?? [],
        capabilityTags: result.capability_tags ?? [],
        sha256: result.sha256,
        md5: result.md5,
        sha1: result.sha1,
        yaraMatchDetails: result.yara_matches,
        packing: result.packing,
        explainedStrings: result.explained_strings,
        geoIocs: result.geo_iocs,
        sandboxResult: result.dynamic_analysis ?? null,
        behaviorAnalysis: result.behavior_analysis ?? null,
        networkIndicators: result.network_indicators ?? null,
        threatAssessment: result.threat_assessment ?? null,
        aiAnalysis: result.ai_analysis ?? null,
        iocIntelligence: result.ioc_intelligence ?? [],
        evidenceCorrelation: result.evidence_correlation ?? [],
        evidenceTimeline: result.evidence_timeline ?? [],
        riskExplanation: result.risk_explanation ?? null,
      };

      setCases(prev => [newCase, ...prev]);
      setSelectedCaseId(newCase.id);
      setActiveCaseDetail(result);
      setTimeout(() => {
        setIsUploading(false);
        setActiveTab("overview");
      }, 500);
    } catch (err: any) {
      setIsUploading(false);
      const msg = err.message || "Unknown error during analysis";
      if (msg.toLowerCase().includes("password") || msg.toLowerCase().includes("decrypted")) {
        const userPass = window.prompt("This ZIP archive is password-protected. Please enter the password to extract:");
        if (userPass) {
          setZipPassword(userPass);
          handleRealUpload(file, userPass);
          return;
        }
      }
      alert(`Upload failed: ${msg}`);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    handleRealUpload(file);
  };

  // Behavioral log derived from real analysis data (MITRE techniques + capabilities)
  const rawTechniques: any[] = activeCase.mitreTechniques ?? [];
  const rawCapabilities: any[] = activeCase.capabilityTags ?? [];

  const formatISTTime = (date: Date) => {
    return new Intl.DateTimeFormat("en-GB", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(date);
  };

  const behaviorLog: { time: string; event: string; severity: string; desc: string; details: string }[] = [
    ...rawTechniques.map((t: any, i: number) => {
      const ts = new Date(Date.now() - (rawTechniques.length - i) * 2000);
      const conf = typeof t.confidence === "number" ? t.confidence : 0.5;
      return {
        time: formatISTTime(ts),
        event: `${t.technique_id} — ${t.technique_name}`,
        severity: conf >= 0.8 ? "CRITICAL" : conf >= 0.6 ? "HIGH" : "MEDIUM",
        desc: `MITRE technique detected: ${t.technique_name}`,
        details: `Technique: ${t.technique_id} | Confidence: ${(conf * 100).toFixed(0)}%`,
      };
    }),
    ...rawCapabilities.map((c: any, i: number) => {
      const ts = new Date(Date.now() - (rawCapabilities.length - i) * 1500);
      const conf = typeof c.confidence === "number" ? c.confidence : 0.5;
      const evidenceList: string[] = Array.isArray(c.evidence) ? c.evidence : [];
      return {
        time: formatISTTime(ts),
        event: `Capability: ${c.capability}`,
        severity: conf >= 0.8 ? "HIGH" : "MEDIUM",
        desc: evidenceList.length > 0 ? evidenceList[0] : `Capability indicator detected: ${c.capability}`,
        details: `Confidence: ${(conf * 100).toFixed(0)}%${evidenceList.length > 1 ? ` | Evidence: ${evidenceList.join("; ")}` : ""}`,
      };
    }),
  ];

  return (
    <div className="h-screen max-h-screen bg-[#090909] text-foreground flex font-sans overflow-hidden select-none">
      
      {/* Loading analysis overlay during ingestion */}
      {isUploading && (
        <div className="fixed inset-0 bg-[#090909]/95 z-[150] flex flex-col items-center justify-center border-t border-[#16ff4d]/20">
          <div className="text-center space-y-6 max-w-md w-full px-6">
            <div className="w-16 h-16 rounded-full border-4 border-[#16ff4d]/10 border-t-[#16ff4d] animate-spin mx-auto" />
            <div className="space-y-2">
              <span className="text-xs uppercase tracking-[0.25em] font-mono text-[#16ff4d] font-bold block animate-pulse">
                INGESTING EVIDENCE PAYLOAD
              </span>
              <p className="text-[#A0A0A0] text-xs font-mono">{uploadStep}</p>
            </div>
            
            {/* Elegant high-precision progress bar */}
            <div className="space-y-1">
              <div className="w-full bg-[#111111] border border-[#222222] h-2 rounded overflow-hidden">
                <div 
                  className="bg-[#16ff4d] h-full transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
              <div className="flex justify-between text-[9px] font-mono text-[#6F6F6F]">
                <span>ENCLAVE LOCK PROTOCOL</span>
                <span>{uploadProgress}%</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ================= SIDEBAR (FIXED TO VIEWPORT, NO DOWNWARD EXPANSION) ================= */}
      <aside className="w-64 h-screen max-h-screen sticky top-0 bg-[#111111] border-r border-[#222222] shrink-0 flex flex-col justify-between relative z-20 overflow-hidden">
        <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
          {/* Logo */}
          <div className="px-6 py-5 border-b border-[#222222] flex items-center gap-2.5 shrink-0">
            <AgencyLogo className="w-8 h-8 object-contain" />
            <span className="text-sm font-bold uppercase tracking-wider text-white">
              {t("dashboard.brand")} <span className="text-[#16ff4d] font-mono text-[10px]">SOC</span>
            </span>
          </div>

          {/* Nav links */}
          <nav className="p-4 space-y-1 overflow-y-auto flex-1 min-h-0">
            <span className="text-[9px] uppercase tracking-widest text-[#6F6F6F] px-3 font-mono block mb-2 font-bold">
              {t("dashboard.modules")}
            </span>
            {[
              { id: "overview", label: t("dashboard.nav.overview"), icon: Cpu },
              { id: "upload", label: t("dashboard.nav.upload"), icon: UploadCloud },
              { id: "static", label: t("dashboard.nav.static"), icon: FileCode },
              { id: "dynamic", label: t("dashboard.nav.dynamic"), icon: Terminal },
              { id: "behavior", label: t("dashboard.nav.behavior"), icon: Workflow },
              { id: "mitre", label: t("dashboard.nav.mitre"), icon: Layers },
              { id: "reports", label: t("dashboard.nav.reports"), icon: FileText },
              { id: "network", label: "Network Intel", icon: Globe },
              { id: "investigation", label: "Investigation", icon: Activity },
              { id: "cases", label: t("dashboard.nav.cases"), icon: Briefcase },
            ].map((tab) => {
              const TabIcon = tab.icon;
              const isCurrent = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded text-xs transition-all font-semibold uppercase tracking-wider text-left border focus:outline-none ${
                    isCurrent
                      ? "bg-[#16ff4d]/10 border-[#16ff4d]/20 text-[#16ff4d] shadow-sm"
                      : "text-[#A0A0A0] border-transparent hover:bg-[#171717] hover:text-white"
                  }`}
                >
                  <TabIcon className="w-4 h-4 shrink-0" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>
        </div>


        {/* Refined enterprise operator profile widget */}
        <div className="p-4 border-t border-[#222222] space-y-3.5 shrink-0 bg-[#111111]">
          <div className="bg-[#171717] p-3 rounded-lg border border-[#222222] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded bg-[#16ff4d]/10 border border-[#16ff4d]/30 flex items-center justify-center text-[#16ff4d] font-mono text-xs font-bold">
                {(() => {
                  const label = currentUser?.full_name || currentUser?.email || "";
                  const initials = label
                    .split(/[\s@._]+/)
                    .filter(Boolean)
                    .slice(0, 2)
                    .map(s => s[0]?.toUpperCase())
                    .join("");
                  return initials || "??";
                })()}
              </div>
              <div className="text-left font-sans">
                <span className="text-[10px] font-bold text-white block uppercase tracking-wide">
                  {isLoadingCurrentUser
                    ? t("dashboard.loadingOperator")
                    : currentUserError
                      ? t("dashboard.operatorUnavailable")
                      : currentUser?.full_name || currentUser?.email || t("dashboard.unknownOperator")}
                </span>
                <span className="text-[8px] text-[#A0A0A0] block">
                  {isLoadingCurrentUser
                    ? t("dashboard.fetchingIdentity")
                    : currentUserError
                      ? t("dashboard.authError")
                      : currentUser?.department || (currentUser?.officer_id ? `OFFICER #${currentUser.officer_id}` : t("dashboard.roleUnknown"))}
                </span>
              </div>
            </div>
            
            {/* Pulse online indicator */}
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#16ff4d] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#16ff4d]"></span>
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[8px] font-mono text-[#6F6F6F] uppercase border-t border-[#222222]/40 pt-2 text-center">
            <div className="bg-[#090909] py-1 rounded">
              {currentUser?.officer_id ? `#${currentUser.officer_id}` : t("dashboard.sessionActive")}
            </div>
            <div className={`bg-[#090909] py-1 rounded ${currentUserError ? "text-[#ff4040]" : "text-[#16ff4d]"}`}>
              {currentUserError ? t("dashboard.authError") : t("dashboard.verified")}
            </div>
          </div>

          <button
            onClick={toggleLanguage}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs uppercase tracking-wider text-[#A0A0A0] hover:text-white hover:bg-[#171717] border border-transparent hover:border-[#222222] rounded transition-all font-mono"
          >
            <span>{language === "en" ? "ગુજરાતી" : "English"}</span>
          </button>

          <button
            onClick={() => { apiLogout(); onLogout(); }}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs uppercase tracking-wider text-red-400 hover:text-red-300 hover:bg-red-950/20 border border-transparent hover:border-red-500/20 rounded transition-all font-mono"
          >
            <LogOut className="w-4 h-4 shrink-0" />
            <span>{t("dashboard.logout")}</span>
          </button>
        </div>
      </aside>

      {/* ================= MAIN CONTENT AREA ================= */}
      <main className="flex-1 h-screen max-h-screen bg-[#090909] flex flex-col overflow-hidden relative z-0">

        
        {/* High-density informative Top bar */}
        <header className="h-16 border-b border-[#222222] px-6 flex items-center justify-between bg-[#111111]/80 backdrop-blur-md">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs font-mono tracking-wider text-[#A0A0A0]">
              <Database className="w-3.5 h-3.5" /> ACTIVE TARGET:
            </div>
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="bg-[#171717] border border-[#222222] rounded text-xs font-mono py-1.5 px-3 text-[#16ff4d] focus:outline-none focus:border-[#16ff4d] max-w-xs uppercase font-bold"
            >
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.id} // {c.name}
                </option>
              ))}
            </select>
          </div>

          {/* Info cluster block */}
          <div className="hidden lg:flex items-center gap-4 text-[10px] font-mono text-[#A0A0A0]">
            <div className="flex items-center gap-1.5 bg-[#171717] px-3 py-1.5 rounded border border-[#222222]">
              <Clock className="w-3.5 h-3.5 text-[#16ff4d]" />
              <span className="text-white font-bold">{currentTime || "00:00:00 IST"}</span>
            </div>
          </div>
        </header>

        {/* Scrollable interior canvas */}
        <div className="flex-1 overflow-y-auto p-6">
          
          {/* ================= TAB 1: OVERVIEW SUMMARY ================= */}
          {activeTab === "overview" && (
            <OverviewTab activeCase={activeCase} onNavigate={(tab) => setActiveTab(tab as any)} />
          )}

          {/* ================= TAB 2: INGEST ARTIFACT ================= */}
          {activeTab === "upload" && (
            <div className="space-y-6 max-w-3xl mx-auto">
              <div className="border-b border-[#222222]/80 pb-4">
                <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
                  Forensic Ingestion Gateway
                </h3>
                <p className="text-[11px] text-[#A0A0A0] font-light">
                  Ingest binary suspects securely inside localized air-gapped Sandboxes. Accepted formats: APK, PE/EXE/DLL, ELF, Mach-O, or a ZIP containing one supported sample.
                </p>
              </div>

              {/* Drag and Drop Zone */}
              <input
                type="file"
                id="file-upload-input"
                className="hidden"
                accept=".apk,.exe,.dll,.elf,.macho,.dylib,.zip,application/zip"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  handleRealUpload(file);
                  e.target.value = "";
                }}
              />
              <div 
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                onClick={() => document.getElementById("file-upload-input")?.click()}
                className="border-2 border-dashed border-[#222222] hover:border-[#16ff4d]/40 rounded-lg p-12 text-center bg-[#111111] hover:bg-[#171717] transition-all duration-200 cursor-pointer group"
              >
                <div className="flex flex-col items-center space-y-4">
                  <div className="w-12 h-12 rounded bg-[#171717] border border-[#222222] flex items-center justify-center text-[#A0A0A0] group-hover:text-[#16ff4d] transition-colors">
                    <UploadCloud className="w-6 h-6" />
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs font-bold text-white uppercase tracking-wider">Drag & drop suspect binary here</p>
                    <p className="text-[10px] text-[#6F6F6F]">or click directory finder to upload APK, PE, ELF, Mach-O, or ZIP</p>
                  </div>
                </div>
              </div>

              {/* Optional ZIP Password Input */}
              <div className="flex items-center gap-3 bg-[#111111] px-4 py-3 rounded-lg border border-[#222222]">
                <Lock className="w-4 h-4 text-[#16ff4d] shrink-0" />
                <div className="flex-1">
                  <label className="block text-[9px] uppercase font-mono text-[#6F6F6F] font-bold tracking-wider">
                    ZIP Password (Optional — auto-detects standard passwords: infected, malware, password, virus...)
                  </label>
                  <input
                    type="text"
                    value={zipPassword}
                    onChange={(e) => setZipPassword(e.target.value)}
                    placeholder="Enter custom ZIP password if known..."
                    className="w-full bg-transparent text-xs text-white placeholder-[#555555] font-mono outline-none pt-0.5"
                  />
                </div>
              </div>

              {/* Sample detonators row */}
              <div className="space-y-3.5">
                <span className="text-[10px] font-mono text-[#6F6F6F] uppercase tracking-widest block font-bold">
                  FAST detonator shortcuts
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <button 
                    onClick={() => document.getElementById("file-upload-input")?.click()}
                    className="flex items-center justify-between p-4 bg-[#111111] border border-[#222222] rounded-lg text-left hover:border-[#ff4040]/30 transition-all font-mono"
                  >
                    <div>
                      <span className="text-xs text-white font-bold block">SELECT SUSPECT APK FILE</span>
                      <span className="text-[9px] text-[#ff4040] font-bold">REAL-TIME INGESTION GATEWAY</span>
                    </div>
                    <ChevronRight className="w-4 h-4 text-[#A0A0A0]" />
                  </button>

                  <button 
                    onClick={() => document.getElementById("file-upload-input")?.click()}
                    className="flex items-center justify-between p-4 bg-[#111111] border border-[#222222] rounded-lg text-left hover:border-[#ff4040]/30 transition-all font-mono"
                  >
                    <div>
                      <span className="text-xs text-white font-bold block">SELECT SUSPECT PE / EXE / ELF FILE</span>
                      <span className="text-[9px] text-[#ff4040] font-bold">REAL-TIME INGESTION GATEWAY</span>
                    </div>
                    <ChevronRight className="w-4 h-4 text-[#A0A0A0]" />
                  </button>
                </div>
              </div>

            </div>
          )}

          {/* ================= TAB 3: STATIC CODE ANALYST ================= */}
          {activeTab === "static" && (
            <StaticAnalysisTab activeCase={activeCase} />
          )}

          {/* ================= TAB 4: DETONATION SANDBOX ================= */}
          {activeTab === "dynamic" && (
            <DynamicSandboxTab
              activeCase={activeCase}
              onNavigate={(tab) => setActiveTab(tab as any)}
              onReload={async () => {
                if (selectedCaseId) {
                  try {
                    const detail = await fetchCaseDetail(selectedCaseId);
                    setActiveCaseDetail(detail);
                  } catch (e) {
                    console.error("Failed to refresh case detail:", e);
                  }
                }
                await loadCases();
              }}
            />
          )}


          {/* ================= TAB 5: BEHAVIOR TIMELINE ================= */}
          {activeTab === "behavior" && (
            <div className="space-y-6 max-w-4xl">
              
              <div className="border-b border-[#222222]/80 pb-4">
                <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
                  Sequential Behavioral Chronological Log
                </h3>
                <p className="text-[11px] text-[#A0A0A0] font-light">
                  Process hollowing, system hooks, registry writes, and socket allocations chronologically stacked on detonate timeline. Click events to view forensic evidence details.
                </p>
              </div>

              {/* Timeline list */}
              {behaviorLog.length === 0 ? (
                <div className="text-center py-16 text-[#6F6F6F] font-mono text-xs">
                  <Clock className="w-12 h-12 mx-auto mb-4 opacity-20" />
                  <p className="text-sm font-bold text-white mb-1">No Behavioral Events</p>
                  <p>Upload and analyze a binary to populate the behavior timeline.</p>
                </div>
              ) : (
              <div className="relative border-l-2 border-[#222222] ml-4 pl-8 space-y-6">
                {behaviorLog.map((log, idx) => {
                  const isExpanded = expandedBehaviorIdx === idx;
                  return (
                    <div key={idx} className="relative group">
                      
                      {/* Connection node */}
                      <span className={`absolute -left-[41px] top-1.5 w-6 h-6 rounded-full border-4 border-[#090909] flex items-center justify-center ${
                        log.severity === "CRITICAL" ? "bg-[#ff4040]" :
                        log.severity === "HIGH" ? "bg-[#f4b400]" :
                        "bg-[#16ff4d]"
                      }`} />

                      {/* Event container card */}
                      <div 
                        onClick={() => setExpandedBehaviorIdx(isExpanded ? null : idx)}
                        className={`bg-[#111111] border border-[#222222] hover:border-[#16ff4d]/20 p-5 rounded-lg transition-all cursor-pointer shadow-md ${
                          isExpanded ? "ring-1 ring-[#16ff4d]/20" : ""
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-4 font-mono">
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-[#16ff4d] font-bold">{log.time}</span>
                            <h4 className="text-xs font-bold text-white font-sans">{log.event}</h4>
                          </div>
                          <span className={`text-[8px] font-bold px-2 py-0.5 rounded border ${
                            log.severity === "CRITICAL" ? "bg-red-950/40 text-[#ff4040] border-red-500/20" :
                            log.severity === "HIGH" ? "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20" :
                            "bg-green-950/40 text-[#16ff4d] border-green-500/20"
                          }`}>
                            {log.severity}
                          </span>
                        </div>

                        <p className="text-[#A0A0A0] text-xs font-sans font-light mt-2 max-w-2xl">
                          {log.desc}
                        </p>

                        {/* Collapsible Details */}
                        {isExpanded && (
                          <div className="mt-4 pt-3 border-t border-[#222222]/60 font-mono text-[10px] text-[#ff4040] space-y-1 bg-[#090909] p-3 rounded">
                            <span className="text-[#6F6F6F] block font-bold uppercase tracking-wider">FORENSIC SIGNAL TRACE DETAILS:</span>
                            <p>{log.details}</p>
                          </div>
                        )}
                      </div>

                    </div>
                  );
                })}
              </div>
              )}

            </div>
          )}

          {/* ================= TAB 6: MITRE MAPPING ================= */}
          {activeTab === "mitre" && (
            <MitreMappingTab activeCase={activeCase} />
          )}

          {/* ================= TAB 7: AI REPORT DOSSIER ================= */}
          {activeTab === "reports" && (
            <AiReportsTab activeCase={activeCase} examiner={currentUser} />
          )}

          {/* ================= TAB 8: INVESTIGATION DASHBOARD ================= */}
          {activeTab === "investigation" && (
            <InvestigationDashboardTab activeCase={activeCase} examiner={currentUser} />
          )}

          {/* ================= TAB 8b: NETWORK INTELLIGENCE TAB ================= */}
          {activeTab === "network" && (
            <NetworkIntelligenceTab activeCase={activeCase} />
          )}

          {/* ================= TAB 9: DATABASE REGISTRY ================= */}
          {activeTab === "cases" && (
            <div className="space-y-6">
              
              <div className="border-b border-[#222222]/80 pb-4">
                <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
                  Active Forensic Case registry Database
                </h3>
                <p className="text-[11px] text-[#A0A0A0] font-light">
                  Search, filter, and review completed and quarantined forensic cases compiled inside local laboratories.
                </p>
              </div>

              {/* Filter controls */}
              <div className="flex flex-col sm:flex-row gap-4 justify-between items-center bg-[#111111] border border-[#222222] p-4 rounded-lg">
                <div className="relative flex-1 w-full max-w-md">
                  <Search className="w-4 h-4 text-[#6F6F6F] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={casesSearchQuery}
                    onChange={(e) => setCasesSearchQuery(e.target.value)}
                    placeholder="Search suspect artifact, SHA-256 summary..."
                    className="w-full bg-[#090909] border border-[#222222] rounded-lg pl-10 pr-4 py-2 text-xs text-white focus:outline-none focus:border-[#16ff4d] placeholder:text-[#6F6F6F] font-mono"
                  />
                </div>
                <div className="flex items-center gap-2 text-[#A0A0A0] text-xs font-mono">
                  <span>TOTAL CASES: {cases.length}</span>
                </div>
              </div>

              {/* Case table registry list */}
              <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden shadow-md">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="bg-[#171717] text-[#6F6F6F] border-b border-[#222222] text-[9px] uppercase tracking-wider">
                      <th className="p-4">CASE FILE ID</th>
                      <th className="p-4">SUSPECT ARTIFACT</th>
                      <th className="p-4">MALWARE TYPE</th>
                      <th className="p-4">SHA-256 SUMMARY</th>
                      <th className="p-4">RISK SEVERITY</th>
                      <th className="p-4">INTELLIGENCE STATUS</th>
                      <th className="p-4">DISPATCH DATE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#222222]/60 text-[#A0A0A0]">
                    {cases.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="p-8 text-center text-[#6F6F6F]">
                          <div className="flex flex-col items-center justify-center space-y-2">
                            <span className="text-sm font-sans text-[#A0A0A0]">No forensic cases recorded for this account.</span>
                            <span className="text-xs">Your workspace is clean. Ingest an artifact to begin forensic analysis.</span>
                            <button
                              onClick={() => setActiveTab("upload")}
                              className="mt-2 px-3 py-1.5 bg-[#16ff4d]/10 hover:bg-[#16ff4d]/20 border border-[#16ff4d]/40 text-[#16ff4d] rounded text-xs uppercase tracking-wider font-bold transition-all cursor-pointer"
                            >
                              Ingest Artifact
                            </button>
                          </div>
                        </td>
                      </tr>
                    ) : (
                      cases
                        .filter(c => c.name.toLowerCase().includes(casesSearchQuery.toLowerCase()) || c.hash.includes(casesSearchQuery))
                        .map((c) => (
                        <tr 
                          key={c.id} 
                          onClick={() => setSelectedCaseId(c.id)}
                          className={`hover:bg-[#171717] cursor-pointer transition-colors ${
                            selectedCaseId === c.id ? "bg-[#16ff4d]/5" : ""
                          }`}
                        >
                          <td className="p-4 text-[#16ff4d] font-bold">{c.id}</td>
                          <td className="p-4 text-white font-sans font-bold">{c.name}</td>
                          <td className="p-4">
                            <span className="bg-[#171717] border border-[#222222] px-2 py-0.5 rounded text-[10px] text-white">
                              {c.type}
                            </span>
                          </td>
                          <td className="p-4">{c.hash.substring(0, 12)}...</td>
                          <td className="p-4">
                            <span className={`font-bold ${c.riskScore > 75 ? "text-[#ff4040]" : c.riskScore > 40 ? "text-[#f4b400]" : "text-[#16ff4d]"}`}>
                              {c.riskScore}%
                            </span>
                          </td>
                          <td className="p-4">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-bold border uppercase tracking-wider ${
                              c.status === "QUARANTINED" ? "bg-red-950/40 text-[#ff4040] border-red-500/20" :
                              c.status === "ACTIVE_TRACE" ? "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20" :
                              "bg-green-950/40 text-[#16ff4d] border-green-500/20"
                            }`}>
                              {c.status}
                            </span>
                          </td>
                          <td className="p-4 text-[#6F6F6F]">{c.date}</td>
                        </tr>
                      )))}
                  </tbody>
                </table>
              </div>

            </div>
          )}

        </div>
      </main>

    </div>
  );
}
