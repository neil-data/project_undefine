import * as React from "react";
import { 
  Clock, 
  Shield, 
  FileText, 
  Download, 
  CheckCircle, 
  AlertTriangle,
  Activity,
  Globe,
  Lock,
  ChevronRight,
  ChevronDown,
  Info,
} from "lucide-react";
import { ThreatCase } from "./types";
import { CurrentUser } from "../../lib/api";
import { AgencyLogo, loadAgencyLogoDataUrl } from "../AgencyLogo";
import { jsPDF } from "jspdf";

interface InvestigationDashboardTabProps {
  activeCase: ThreatCase;
  examiner: CurrentUser | null;
}

// Investigation output types from Phase 10
interface TimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  severity: "info" | "warning" | "critical";
  evidence: string[];
}

interface MalwareExplanation {
  summary: string;
  technical_details: string;
  capabilities_identified: string[];
  confidence_level?: number;
}

interface VictimImpact {
  data_accessed: string[];
  privacy_risks: string[];
  financial_risks: string[];
  device_integrity: string[];
  overall_impact: "low" | "medium" | "high" | "critical";
  explanation: string;
}

interface ExfiltrationAnalysis {
  data_types: string[];
  destinations: string[];
  timing_patterns: string;
  encryption_status: string;
  estimated_volume: string;
  risk_assessment: string;
}

interface Recommendation {
  priority: "immediate" | "high" | "medium" | "low" | "review";
  category: "containment" | "evidence" | "investigation" | "victim";
  action: string;
  rationale: string;
}

interface InvestigationSummary {
  executive_summary: string;
  key_findings: string[];
  timeline_summary: string;
  risk_assessment: string;
  next_steps: string[];
  generated_at: string;
}

interface ChainVerification {
  status: string;
  is_valid: boolean;
  verified_links: number;
  total_links: number;
  tampered_links: string[];
  missing_links: string[];
  errors: string[];
  verified_at: string;
}

interface InvestigationOutput {
  timeline_events: TimelineEvent[];
  malware_explanation: MalwareExplanation | null;
  victim_impact: VictimImpact | null;
  exfiltration_analysis: ExfiltrationAnalysis | null;
  network_evidence: Array<{ indicator: string; source: string; runtime_verified: boolean }>;
  behavior_findings: Array<{ behavior: string; category: string; confidence: string; evidence: string[]; source: string; runtime_verified: boolean }>;
  recommendations: Recommendation[];
  investigation_summary: InvestigationSummary | null;
  chain_verification: ChainVerification | null;
}

export function InvestigationDashboardTab({ activeCase, examiner }: InvestigationDashboardTabProps) {
  const [investigationData, setInvestigationData] = React.useState<InvestigationOutput | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [expandedSections, setExpandedSections] = React.useState<Set<string>>(new Set(["timeline", "summary"]));
  const [agencyLogoDataUrl, setAgencyLogoDataUrl] = React.useState<string | null>(null);

  React.useEffect(() => {
    loadAgencyLogoDataUrl().then(setAgencyLogoDataUrl);
    fetchInvestigationData();
  }, [activeCase.id]);

  const fetchInvestigationData = async () => {
    setLoading(true);
    setError(null);
    try {
      setInvestigationData(createEvidenceBoundInvestigationData(activeCase));
    } catch (err) {
      setError("Failed to load investigation data");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  };

  const exportReport = async () => {
    if (!investigationData) return;

    const pdf = new jsPDF();
    let yPosition = 20;

    // Add agency logo if available
    if (agencyLogoDataUrl) {
      try {
        pdf.addImage(agencyLogoDataUrl, "PNG", 15, yPosition, 30, 30);
        yPosition += 35;
      } catch (e) {
        console.error("Failed to add logo to PDF", e);
      }
    }

    // Title
    pdf.setFontSize(20);
    pdf.setTextColor(0, 0, 0);
    pdf.text("Investigation Report", 15, yPosition);
    yPosition += 15;

    // Case info
    pdf.setFontSize(12);
    pdf.text(`Case ID: ${activeCase.id}`, 15, yPosition);
    yPosition += 8;
    pdf.text(`Sample: ${activeCase.name}`, 15, yPosition);
    yPosition += 8;
    pdf.text(`Risk Score: ${activeCase.riskScore}/100`, 15, yPosition);
    yPosition += 8;
    pdf.text(`Date: ${new Date().toLocaleDateString()}`, 15, yPosition);
    yPosition += 15;

    // Chain verification status
    if (investigationData.chain_verification) {
      const cv = investigationData.chain_verification;
      pdf.setFontSize(14);
      pdf.setTextColor(cv.is_valid ? 0 : 128, cv.is_valid ? 128 : 0, 0);
      pdf.text(`Chain Verification: ${cv.status.toUpperCase()}`, 15, yPosition);
      yPosition += 10;
      pdf.setFontSize(10);
      pdf.setTextColor(0, 0, 0);
      pdf.text(`Verified Links: ${cv.verified_links}/${cv.total_links}`, 15, yPosition);
      yPosition += 15;
    }

    // Executive summary
    if (investigationData.investigation_summary) {
      pdf.setFontSize(14);
      pdf.setTextColor(0, 0, 128);
      pdf.text("Executive Summary", 15, yPosition);
      yPosition += 10;
      pdf.setFontSize(10);
      pdf.setTextColor(0, 0, 0);
      const summaryLines = pdf.splitTextToSize(investigationData.investigation_summary.executive_summary, 180);
      pdf.text(summaryLines, 15, yPosition);
      yPosition += summaryLines.length * 5 + 10;
    }

    // Key findings
    if (investigationData.investigation_summary?.key_findings) {
      pdf.setFontSize(14);
      pdf.setTextColor(0, 0, 128);
      pdf.text("Key Findings", 15, yPosition);
      yPosition += 10;
      pdf.setFontSize(10);
      pdf.setTextColor(0, 0, 0);
      investigationData.investigation_summary.key_findings.forEach(finding => {
        const lines = pdf.splitTextToSize(`• ${finding}`, 180);
        pdf.text(lines, 15, yPosition);
        yPosition += lines.length * 5 + 3;
      });
      yPosition += 7;
    }

    // Timeline
    if (investigationData.timeline_events && investigationData.timeline_events.length > 0) {
      pdf.setFontSize(14);
      pdf.setTextColor(0, 0, 128);
      pdf.text("Timeline", 15, yPosition);
      yPosition += 10;
      pdf.setFontSize(10);
      pdf.setTextColor(0, 0, 0);
      investigationData.timeline_events.slice(0, 10).forEach(event => {
        const lines = pdf.splitTextToSize(
          `[${event.timestamp}] [${event.severity.toUpperCase()}] ${event.description}`,
          180
        );
        pdf.text(lines, 15, yPosition);
        yPosition += lines.length * 5 + 3;
      });
      yPosition += 7;
    }

    // Recommendations
    if (investigationData.recommendations && investigationData.recommendations.length > 0) {
      pdf.setFontSize(14);
      pdf.setTextColor(0, 0, 128);
      pdf.text("Recommendations", 15, yPosition);
      yPosition += 10;
      pdf.setFontSize(10);
      pdf.setTextColor(0, 0, 0);
      investigationData.recommendations.forEach(rec => {
        pdf.setTextColor(rec.priority === "immediate" ? 200 : 0, 0, 0);
        const lines = pdf.splitTextToSize(
          `[${rec.priority.toUpperCase()}] ${rec.action}`,
          180
        );
        pdf.text(lines, 15, yPosition);
        yPosition += lines.length * 5 + 3;
        pdf.setTextColor(0, 0, 0);
        pdf.setFontSize(8);
        const rationaleLines = pdf.splitTextToSize(`Rationale: ${rec.rationale}`, 175);
        pdf.text(rationaleLines, 20, yPosition);
        yPosition += rationaleLines.length * 4 + 5;
        pdf.setFontSize(10);
      });
    }

    // Footer
    pdf.setFontSize(8);
    pdf.setTextColor(128, 128, 128);
    pdf.text(
      `Generated by SentinelScan Investigation Engine | Examiner: ${examiner?.full_name || examiner?.email || "Unknown"}`,
      15,
      280
    );

    pdf.save(`investigation_report_${activeCase.id}.pdf`);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#16ff4d]"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-950/40 border border-red-500/20 rounded-lg p-4">
        <div className="flex items-center">
          <AlertTriangle className="h-5 w-5 text-[#ff4040] mr-2" />
          <span className="text-[#ff4040]">{error}</span>
        </div>
      </div>
    );
  }

  if (!investigationData) {
    return (
      <div className="bg-[#111111] border border-[#222222] rounded-lg p-8 text-center">
        <Info className="h-12 w-12 text-[#6F6F6F] mx-auto mb-4" />
        <p className="text-[#6F6F6F]">No investigation data available for this case.</p>
      </div>
    );
  }

  const severityColors = {
    info: "bg-cyan-950/40 text-[#00c2ff] border-cyan-500/20",
    warning: "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20",
    critical: "bg-red-950/40 text-[#ff4040] border-red-500/20",
  };

  const priorityColors = {
    immediate: "bg-red-950/40 text-[#ff4040] border-red-500/20",
    high: "bg-orange-950/40 text-[#f4b400] border-orange-500/20",
    medium: "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20",
    low: "bg-green-950/40 text-[#16ff4d] border-green-500/20",
    review: "bg-[#222222] text-[#A0A0A0] border-[#333333]",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Investigation Dashboard</h2>
          <p className="text-sm text-[#6F6F6F]">Case: {activeCase.name} | ID: {activeCase.id}</p>
        </div>
        <button
          onClick={exportReport}
          className="flex items-center px-4 py-2 bg-[#16ff4d] text-[#090909] font-bold rounded-lg hover:bg-[#16ff4d]/90 transition-colors"
        >
          <Download className="h-4 w-4 mr-2" />
          Export Report
        </button>
      </div>

      {/* Chain Verification Status */}
      {investigationData.chain_verification && (
        <div className={`rounded-lg p-4 border ${
          investigationData.chain_verification.is_valid
            ? "bg-green-950/40 border-green-500/20"
            : "bg-red-950/40 border-red-500/20"
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              {investigationData.chain_verification.is_valid ? (
                <CheckCircle className="h-5 w-5 text-[#16ff4d] mr-2" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-[#ff4040] mr-2" />
              )}
              <div>
                <p className="font-semibold text-white">
                  Chain Verification: {investigationData.chain_verification.status.toUpperCase()}
                </p>
                <p className="text-sm text-[#6F6F6F]">
                  Verified Links: {investigationData.chain_verification.verified_links}/
                  {investigationData.chain_verification.total_links}
                </p>
              </div>
            </div>
            <Lock className="h-5 w-5 text-[#6F6F6F]" />
          </div>
        </div>
      )}

      {/* Investigation Summary */}
      {investigationData.investigation_summary && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("summary")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <FileText className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">Investigation Summary</span>
            </div>
            {expandedSections.has("summary") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("summary") && (
            <div className="p-6 space-y-4">
              <div>
                <h4 className="font-semibold text-white mb-2">Executive Summary</h4>
                <p className="text-[#A0A0A0]">{investigationData.investigation_summary.executive_summary}</p>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-2">Key Findings</h4>
                <ul className="list-disc list-inside space-y-1">
                  {investigationData.investigation_summary.key_findings.map((finding, idx) => (
                    <li key={idx} className="text-[#A0A0A0]">{finding}</li>
                  ))}
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-2">Risk Assessment</h4>
                <p className="text-[#A0A0A0]">{investigationData.investigation_summary.risk_assessment}</p>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-2">Next Steps</h4>
                <ul className="list-disc list-inside space-y-1">
                  {investigationData.investigation_summary.next_steps.map((step, idx) => (
                    <li key={idx} className="text-[#A0A0A0]">{step}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Timeline */}
      {investigationData.timeline_events && investigationData.timeline_events.length > 0 && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("timeline")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <Clock className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">Timeline</span>
              <span className="ml-2 text-sm text-[#6F6F6F]">
                ({investigationData.timeline_events.length} events)
              </span>
            </div>
            {expandedSections.has("timeline") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("timeline") && (
            <div className="p-6">
              <div className="space-y-3">
                {investigationData.timeline_events.map((event, idx) => (
                  <div key={idx} className="flex items-start space-x-3 p-3 bg-[#0d0d0d] border border-[#222222]/50 rounded-lg">
                    <div className={`px-2 py-1 rounded text-xs font-medium border ${severityColors[event.severity]}`}>
                      {event.severity.toUpperCase()}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-white">{event.description}</p>
                      <p className="text-xs text-[#6F6F6F] mt-1">{event.event_type} · {event.timestamp}</p>
                      {event.evidence.length > 0 && (
                        <div className="mt-2">
                          {event.evidence.map((ev, evIdx) => (
                            <span key={evIdx} className="inline-block text-xs bg-[#222222] text-[#A0A0A0] px-2 py-1 rounded mr-1">
                              {ev}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* IOC (Indicators of Compromise) */}
      {investigationData.network_evidence.length > 0 && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("ioc")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <Shield className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">Indicators & Provenance</span>
            </div>
            {expandedSections.has("ioc") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("ioc") && (
            <div className="p-6 space-y-4">
              {investigationData.network_evidence.length > 0 && (
                <div>
                  <h4 className="font-semibold text-white mb-2">Network and File Indicators</h4>
                  <div className="space-y-2">
                    {investigationData.network_evidence.map((item, idx) => (
                      <div key={`${item.indicator}-${idx}`} className="flex items-center justify-between gap-3 p-2 bg-[#0d0d0d] border border-[#222222] rounded">
                        <span className="flex items-center min-w-0"><Globe className="h-4 w-4 text-[#00c2ff] mr-2 shrink-0" /><span className="text-sm text-[#A0A0A0] break-all">{item.indicator}</span></span>
                        <span className="text-[9px] font-mono text-[#777] shrink-0">{item.runtime_verified ? "RUNTIME VERIFIED" : item.source}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* MITRE Techniques */}
      {activeCase.mitreTechniques && activeCase.mitreTechniques.length > 0 && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("mitre")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <Shield className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">MITRE ATT&CK Techniques</span>
              <span className="ml-2 text-sm text-[#6F6F6F]">
                ({activeCase.mitreTechniques.length} techniques)
              </span>
            </div>
            {expandedSections.has("mitre") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("mitre") && (
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {activeCase.mitreTechniques.map((technique: any, idx: number) => (
                  <div key={idx} className="p-3 bg-purple-950/40 border border-purple-500/20 rounded">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-white">{technique.technique_id}</span>
                      <span className="text-xs text-[#a78bfa]">
                        {(technique.confidence * 100).toFixed(0)}% confidence
                      </span>
                    </div>
                    <p className="text-sm text-[#A0A0A0] mt-1">{technique.technique_name}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Evidence */}
      {investigationData.malware_explanation && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("evidence")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <Activity className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">Evidence Analysis</span>
            </div>
            {expandedSections.has("evidence") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("evidence") && (
            <div className="p-6 space-y-4">
              <div>
                <h4 className="font-semibold text-white mb-2">Malware Summary</h4>
                <p className="text-[#A0A0A0]">{investigationData.malware_explanation.summary}</p>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-2">Technical Details</h4>
                <p className="text-[#A0A0A0]">{investigationData.malware_explanation.technical_details}</p>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-2">Evidence-Backed Behavior Findings</h4>
                <div className="flex flex-wrap gap-2">
                  {investigationData.malware_explanation.capabilities_identified.map((cap, idx) => (
                    <span key={idx} className="px-3 py-1 bg-cyan-950/40 text-[#00c2ff] rounded-full text-sm">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
              {investigationData.behavior_findings.map((finding, idx) => (
                <div key={`${finding.category}-${idx}`} className="bg-[#090909] border border-[#222222] rounded p-3">
                  <div className="flex justify-between gap-3 text-xs">
                    <span className="text-white font-semibold">{finding.behavior}</span>
                    <span className="text-amber-300 font-mono">{finding.runtime_verified ? "RUNTIME VERIFIED" : finding.confidence}</span>
                  </div>
                  <p className="text-[10px] text-[#777] mt-1">{finding.source.replaceAll("_", " ")} · Runtime verified: {finding.runtime_verified ? "Yes" : "No"}</p>
                  <ul className="list-disc pl-4 mt-2 text-[10px] text-[#A0A0A0] space-y-1">{finding.evidence.map((item, evidenceIndex) => <li key={evidenceIndex} className="break-all">{item}</li>)}</ul>
                </div>
              ))}
              {investigationData.malware_explanation.confidence_level !== undefined && <div>
                <h4 className="font-semibold text-white mb-2">Confidence Level</h4>
                <div className="flex items-center">
                  <div className="flex-1 bg-[#222222] rounded-full h-2 mr-3">
                    <div
                      className="bg-[#16ff4d] h-2 rounded-full"
                      style={{ width: `${investigationData.malware_explanation.confidence_level * 100}%` }}
                    />
                  </div>
                  <span className="text-sm text-[#A0A0A0]">
                    {(investigationData.malware_explanation.confidence_level * 100).toFixed(0)}%
                  </span>
                </div>
              </div>}
            </div>
          )}
        </div>
      )}

      {/* Recommendations */}
      {investigationData.recommendations && investigationData.recommendations.length > 0 && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("recommendations")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <CheckCircle className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">Recommendations</span>
              <span className="ml-2 text-sm text-[#6F6F6F]">
                ({investigationData.recommendations.length} actions)
              </span>
            </div>
            {expandedSections.has("recommendations") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("recommendations") && (
            <div className="p-6">
              <div className="space-y-3">
                {investigationData.recommendations.map((rec, idx) => (
                  <div key={idx} className="p-4 border border-[#222222] rounded-lg">
                    <div className="flex items-start justify-between mb-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium border ${priorityColors[rec.priority]}`}>
                        {rec.priority.toUpperCase()}
                      </span>
                      <span className="text-xs text-[#6F6F6F] capitalize">{rec.category}</span>
                    </div>
                    <p className="text-sm font-medium text-white mb-1">{rec.action}</p>
                    <p className="text-xs text-[#6F6F6F]">{rec.rationale}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function createEvidenceBoundInvestigationData(activeCase: ThreatCase): InvestigationOutput {
  const behaviorFindings = activeCase.behaviorAnalysis?.findings ?? [];
  const timeline = (activeCase.evidenceTimeline ?? []).map((item: any) => {
    const severity = String(item.severity ?? "INFO").toLowerCase();
    return {
      timestamp: item.timestamp_display ?? item.timestamp ?? "not recorded",
      event_type: String(item.source ?? "Pipeline"),
      description: String(item.event ?? item.indicator ?? "Evidence stage recorded"),
      severity: severity === "critical" ? "critical" as const : severity === "high" || severity === "warning" ? "warning" as const : "info" as const,
      evidence: item.indicator ? [String(item.indicator)] : [],
    };
  });
  const networkEvidence = (activeCase.iocIntelligence ?? [])
    .filter((item: any) => ["IP", "DOMAIN", "URL", "HASH"].includes(String(item.type ?? "").toUpperCase()))
    .filter((item: any) => item.indicator)
    .map((item: any) => ({
      indicator: String(item.indicator),
      source: String(item.source ?? item.source_type ?? "Static Analysis"),
      runtime_verified: String(item.evidence_state ?? "").toUpperCase() === "OBSERVED" || String(item.source_type ?? "").toUpperCase() === "DYNAMIC",
    }));
  const intel = (activeCase.aiAnalysis?.recommendations ?? []).map((action) => ({
    priority: "review" as const,
    category: "investigation" as const,
    action,
    rationale: "Review this recommendation against the linked case evidence before action.",
  }));
  const behaviorSummary = activeCase.behaviorAnalysis?.message ?? "No evidence-backed behavior profile is available for this case.";
  const evidenceFindings = behaviorFindings.map((finding) =>
    `${finding.behavior} — ${finding.confidence} (${finding.source.replaceAll("_", " ")}); evidence: ${finding.evidence.join("; ")}`
  );
  const score = activeCase.threatAssessment?.risk_score ?? activeCase.riskScore;
  const verdict = activeCase.threatAssessment?.verdict ?? activeCase.status.replaceAll("_", " ");

  return {
    timeline_events: timeline,
    malware_explanation: {
      summary: `${activeCase.behaviorAnalysis?.mode ?? "INSUFFICIENT EVIDENCE"}: ${behaviorSummary}`,
      technical_details: behaviorFindings.map((finding) => `${finding.behavior}: ${finding.rationale || finding.reason}`).join("\n") || "Insufficient evidence to infer specific behavior.",
      capabilities_identified: behaviorFindings.map((finding) => `${finding.behavior} (${finding.confidence})`),
    },
    // No victim impact or exfiltration claim is populated without a dedicated
    // observation source in the case record.
    victim_impact: null,
    exfiltration_analysis: null,
    network_evidence: networkEvidence,
    behavior_findings: behaviorFindings,
    recommendations: intel,
    investigation_summary: {
      executive_summary: `Behavior profile: ${activeCase.behaviorAnalysis?.mode ?? "INSUFFICIENT EVIDENCE"}. ${behaviorSummary}`,
      key_findings: evidenceFindings.length ? evidenceFindings : ["Insufficient evidence to infer specific behavior."],
      timeline_summary: `${timeline.length} recorded pipeline evidence event(s).`,
      risk_assessment: `Recorded analysis score ${score}/100; verdict ${verdict}. This is a sample risk assessment, not confirmed victim impact.`,
      next_steps: intel.map((item) => item.action),
      generated_at: "",
    },
    // Chain-of-custody verification is shown only when an authoritative
    // verification result is supplied by the backend.
    chain_verification: null,
  };
}
