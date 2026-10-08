const API_BASE = ((import.meta as any).env?.VITE_API_BASE as string) || "http://localhost:8000/api";

export interface CaseSummary {
  sample_id: string;
  platform: string;
  file_type: string;
  risk_score: number;
  status: string;
  submitted_at: string;
  original_filename?: string | null;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  confidence: number;
}

export interface CapabilityTag {
  capability: string;
  confidence: number;
  evidence: string[];
}

export interface YaraMatchDetail {
  rule_name: string;
  category: string;
  severity: string;
  description: string;
}

export interface PackingInfo {
  is_packed: boolean;
  packer_name: string | null;
  confidence: number;
  evidence: string[];
  unpack_attempted: boolean;
  unpack_succeeded: boolean;
  unpack_method: string | null;
  unpack_error: string | null;
  unpacked_sha256: string | null;
}

export interface ExplainedStringDetail {
  value: string;
  type: string;
  category: string;
  explanation: string;
  severity: string;
}

export interface GeoIocDetail {
  ip: string;
  status?: "resolved" | "unavailable" | "not_attempted" | string;
  country: string | null;
  country_iso: string | null;
  city: string | null;
  region: string | null;
  postal_code: string | null;
  timezone: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracy_radius: number | null;
  asn: number | null;
  asn_org: string | null;
  isp: string | null;
  is_hosting: boolean | null;
  is_proxy: boolean | null;
  threat_level: string | null;
  disclaimer: string | null;
}

export interface NetworkIndicators {
  ips: string[];
  domains: string[];
  urls: string[];
  dns_queries: string[];
  connections: Array<{
    ip: string;
    port: number | null;
    protocol: string;
    flagged_c2: boolean;
  }>;
}

export interface ThreatAssessment {
  risk_score: number;
  threat_level: string;  // LOW | MEDIUM | HIGH | CRITICAL
  verdict: string;       // CLEAN | SUSPICIOUS | MALICIOUS
  confidence: number;    // 0-100
  key_findings: string[];
}

export interface AiAnalysisOutput {
  executive_summary: string;
  malware_behavior: string | null;
  evidence_correlation: string | null;
  threat_classification: string | null;
  network_interpretation: string | null;
  geoip_interpretation: string | null;
  mitre_techniques_explained: string[];
  confidence: number;
  reasoning: string | null;
  recommendations: string[];
  ai_available: boolean;
  fallback_used: boolean;
}

export interface CaseDetail {
  sample_id: string;
  platform: string;
  file_type: string;
  risk_score: number;
  status: string;
  mitre_techniques: MitreTechnique[];
  capability_tags: CapabilityTag[];
  narrative_summary: string;
  submitted_at: string;
  file_size_bytes?: number | null;
  sha256?: string | null;
  md5?: string | null;
  sha1?: string | null;
  yara_matches: YaraMatchDetail[];
  packing: PackingInfo | null;
  explained_strings: ExplainedStringDetail[];
  geo_iocs: GeoIocDetail[];
  original_filename?: string | null;
  mime_type?: string | null;
  analysis_status?: string | null;
  dynamic_analysis?: DynamicAnalysis | null;
  behavior_analysis?: BehaviorAnalysis | null;
  // Part 2: Network Intelligence, Threat Assessment, AI Analysis
  network_indicators?: NetworkIndicators | null;
  threat_assessment?: ThreatAssessment | null;
  ai_analysis?: AiAnalysisOutput | null;
  ioc_intelligence?: Record<string, unknown>[];
  evidence_correlation?: Record<string, unknown>[];
  evidence_timeline?: Record<string, unknown>[];
  risk_explanation?: {
    score: number;
    contributions: Array<{ label: string; points: number }>;
    method: string;
  } | null;
  malware_bazaar?: Record<string, any> | null;
}


export interface DynamicAnalysis {
  available: boolean;
  status: string;
  message?: string;
  task_id?: string | null;
  sandbox_url?: string | null;
}

export interface BehaviorFinding {
  behavior: string;
  category: string;
  confidence: "HIGH" | "MEDIUM" | "LOW" | string;
  assessment: string;
  evidence: string[];
  reason: string;
  source: "Static Inference" | "Dynamic Analysis" | string;
  runtime_verified: boolean;
  evidence_state: "STATIC" | "OBSERVED" | string;
  rationale: string;
  corroborated_by_static?: boolean;
  corroborated_by_runtime?: boolean;
}

export interface BehaviorAnalysis {
  status: string;
  mode: "RUNTIME VERIFIED" | "MIXED EVIDENCE" | "BEHAVIORAL SIMULATION" | "STATIC ASSESSMENT" | "INSUFFICIENT EVIDENCE" | string;
  dynamic_status: string;
  fallback_reason?: string | null;
  message: string;
  findings: BehaviorFinding[];
  observed_findings: BehaviorFinding[];
  static_findings: BehaviorFinding[];
  evidence_categories: string[];
}

export interface AnalysisStartResponse {
  analysis_id: string;
  sample_id: string;
  original_filename: string;
  file_type: string;
  mime_type: string;
  sha256: string;
  file_size_bytes: number;
  status: string;
  stage?: string | null;
  message?: string | null;
}

export interface AnalysisStatus {
  analysis_id: string;
  status: string;
  stage?: string | null;
  dynamic_status?: string | null;
  error?: string | null;
  file_type?: string | null;
  updated_at?: string | null;
}

export interface HealthResponse {
  status: string;
  sandbox_online: boolean;
  version: string;
}

export interface CurrentUser {
  email: string;
  full_name: string;
  department: string;
  officer_id: string;
}

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem("sentinel_access_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function login(email: string, password: string): Promise<string> {
  const formData = new URLSearchParams();
  formData.append("username", email);
  formData.append("password", password);

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString(),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || "Authentication failed. Invalid agency credentials.");
  }

  const data = await res.json();
  localStorage.setItem("sentinel_access_token", data.access_token);
  return data.access_token;
}

export async function register(
  email: string,
  password: string,
  fullName: string,
  department?: string
): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, full_name: fullName, department }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || "Registration failed. Unable to create agency account.");
  }

  const data = await res.json();
  localStorage.setItem("sentinel_access_token", data.access_token);
  return data.access_token;
}

export function logout(): void {
  localStorage.removeItem("sentinel_access_token");
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem("sentinel_access_token");
}

export async function fetchCurrentUser(): Promise<CurrentUser> {
  const res = await fetch(`${API_BASE}/auth/me`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error("Failed to fetch current user");
  }
  return res.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Health check failed");
  return res.json();
}

export async function fetchCases(): Promise<CaseSummary[]> {
  const res = await fetch(`${API_BASE}/cases`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error("Failed to fetch cases");
  }
  return res.json();
}

export async function searchCases(query: string): Promise<CaseSummary[]> {
  const res = await fetch(`${API_BASE}/cases/search?q=${encodeURIComponent(query)}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error("Case search failed");
  }
  return res.json();
}

export async function fetchCaseDetail(sampleId: string): Promise<CaseDetail> {
  const res = await fetch(`${API_BASE}/cases/${sampleId}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error(`Failed to fetch case detail for ${sampleId}`);
  }
  return res.json();
}

export async function uploadSample(file: File, password?: string): Promise<AnalysisStartResponse> {
  const formData = new FormData();
  formData.append("file", file);
  if (password) {
    formData.append("password", password);
  }

  const res = await fetch(`${API_BASE}/cases/upload`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Sample analysis failed.");
  }

  return res.json();
}

export async function fetchAnalysisStatus(analysisId: string): Promise<AnalysisStatus> {
  const res = await fetch(`${API_BASE}/cases/${analysisId}/status`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 404) {
      throw new Error("Analysis not found");
    }
    throw new Error("Failed to fetch analysis status");
  }
  return res.json();
}

export async function lookupMalwareBazaar(hashValue: string): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE}/threat-intel/bazaar/lookup/${encodeURIComponent(hashValue)}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to lookup hash ${hashValue} in MalwareBazaar`);
  }
  return res.json();
}

export async function fetchRecentMalwareBazaar(limit = 25): Promise<Record<string, any>> {
  const res = await fetch(`${API_BASE}/threat-intel/bazaar/recent?limit=${limit}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    throw new Error("Failed to fetch recent MalwareBazaar samples");
  }
  return res.json();
}
