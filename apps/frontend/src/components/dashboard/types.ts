import { YaraMatchDetail, PackingInfo, ExplainedStringDetail, GeoIocDetail, NetworkIndicators, ThreatAssessment, AiAnalysisOutput, BehaviorAnalysis } from "../../lib/api";

export interface ThreatCase {
  id: string;
  name: string;
  type: "APK" | "PE" | "SYS" | "ELF" | "MACH_O";
  size: string;
  hash: string;
  riskScore: number;
  status: "ACTIVE_TRACE" | "QUARANTINED" | "CLEARED" | "ANALYZING";
  date: string;
  agency: string;
  mitreCount: number;
  yaraMatches: string[];
  narrativeSummary?: string;
  mitreTechniques?: any[];
  capabilityTags?: any[];
  sandboxResult?: any;
  behaviorAnalysis?: BehaviorAnalysis | null;
  sha256?: string | null;
  md5?: string | null;
  sha1?: string | null;
  yaraMatchDetails?: YaraMatchDetail[];
  packing?: PackingInfo | null;
  explainedStrings?: ExplainedStringDetail[];
  geoIocs?: GeoIocDetail[];
  // Part 2: Network Intelligence, Threat Assessment, AI Analysis
  networkIndicators?: NetworkIndicators | null;
  threatAssessment?: ThreatAssessment | null;
  aiAnalysis?: AiAnalysisOutput | null;
  iocIntelligence?: Record<string, unknown>[];
  evidenceCorrelation?: Record<string, unknown>[];
  evidenceTimeline?: Record<string, unknown>[];
  riskExplanation?: {
    score: number;
    contributions: Array<{ label: string; points: number }>;
    method: string;
  } | null;
  malwareBazaar?: Record<string, any> | null;
}
