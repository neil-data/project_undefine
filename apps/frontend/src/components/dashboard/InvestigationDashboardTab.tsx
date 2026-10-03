import * as React from "react";
import { 
  Clock, 
  Shield, 
  Network, 
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
  ExternalLink
} from "lucide-react";
import { ThreatCase } from "./types";
import { CurrentUser } from "../../lib/api";
import { AgencyLogo, loadAgencyLogoDataUrl } from "../AgencyLogo";
import { jsPDF } from "jspdf";
import { NetworkGraph } from "./NetworkGraph";

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
  confidence_level: number;
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
  priority: "immediate" | "high" | "medium" | "low";
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
      // In a real implementation, this would fetch from the backend API
      // For now, we'll create mock data based on the activeCase
      const mockData: InvestigationOutput = createMockInvestigationData(activeCase);
      setInvestigationData(mockData);
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
          `[${event.severity.toUpperCase()}] ${event.description}`,
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
                      <p className="text-xs text-[#6F6F6F] mt-1">{event.event_type}</p>
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
      {(investigationData.exfiltration_analysis?.destinations.length > 0 ||
        investigationData.victim_impact?.data_accessed.length > 0) && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("ioc")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <Shield className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">Indicators of Compromise</span>
            </div>
            {expandedSections.has("ioc") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("ioc") && (
            <div className="p-6 space-y-4">
              {investigationData.exfiltration_analysis?.destinations && (
                <div>
                  <h4 className="font-semibold text-white mb-2">Exfiltration Destinations</h4>
                  <div className="space-y-2">
                    {investigationData.exfiltration_analysis.destinations.map((dest, idx) => (
                      <div key={idx} className="flex items-center p-2 bg-red-950/40 border border-red-500/20 rounded">
                        <Globe className="h-4 w-4 text-[#ff4040] mr-2" />
                        <span className="text-sm text-[#A0A0A0]">{dest}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {investigationData.victim_impact?.data_accessed && (
                <div>
                  <h4 className="font-semibold text-white mb-2">Data Accessed</h4>
                  <div className="space-y-2">
                    {investigationData.victim_impact.data_accessed.map((data, idx) => (
                      <div key={idx} className="flex items-center p-2 bg-yellow-950/40 border border-yellow-500/20 rounded">
                        <FileText className="h-4 w-4 text-[#f4b400] mr-2" />
                        <span className="text-sm text-[#A0A0A0]">{data}</span>
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

      {/* Network Graph */}
      {investigationData.exfiltration_analysis && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
          <button
            onClick={() => toggleSection("network")}
            className="w-full px-6 py-4 flex items-center justify-between bg-[#171717] hover:bg-[#1d1d1d] transition-colors"
          >
            <div className="flex items-center">
              <Network className="h-5 w-5 text-[#16ff4d] mr-3" />
              <span className="font-semibold text-white">Network Graph</span>
            </div>
            {expandedSections.has("network") ? (
              <ChevronDown className="h-5 w-5 text-[#6F6F6F]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[#6F6F6F]" />
            )}
          </button>
          {expandedSections.has("network") && (
            <div className="p-6">
              <NetworkGraph
                exfiltrationAnalysis={investigationData.exfiltration_analysis}
                victimImpact={investigationData.victim_impact}
                malwareInfo={{
                  name: activeCase.name,
                  type: activeCase.type,
                }}
              />
              <div className="mt-4 grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold text-white mb-2">Risk Assessment</h4>
                  <div className={`inline-block px-3 py-1 rounded text-sm font-medium border ${
                    investigationData.exfiltration_analysis.risk_assessment === "Critical"
                      ? "bg-red-950/40 text-[#ff4040] border-red-500/20"
                      : investigationData.exfiltration_analysis.risk_assessment === "High"
                      ? "bg-orange-950/40 text-[#f4b400] border-orange-500/20"
                      : "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20"
                  }`}>
                    {investigationData.exfiltration_analysis.risk_assessment}
                  </div>
                </div>
                <div>
                  <h4 className="font-semibold text-white mb-2">Encryption Status</h4>
                  <p className="text-sm text-[#A0A0A0]">{investigationData.exfiltration_analysis.encryption_status}</p>
                </div>
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
                <h4 className="font-semibold text-white mb-2">Capabilities Identified</h4>
                <div className="flex flex-wrap gap-2">
                  {investigationData.malware_explanation.capabilities_identified.map((cap, idx) => (
                    <span key={idx} className="px-3 py-1 bg-cyan-950/40 text-[#00c2ff] rounded-full text-sm">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
              <div>
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
              </div>
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

// Helper function to create mock investigation data
function createMockInvestigationData(activeCase: ThreatCase): InvestigationOutput {
  return {
    timeline_events: [
      {
        timestamp: new Date().toISOString(),
        event_type: "static",
        description: `File submitted for analysis: ${activeCase.name}`,
        severity: "info",
        evidence: ["SHA256 hash computed", "File type identified"]
      },
      {
        timestamp: new Date().toISOString(),
        event_type: "static",
        description: "YARA rule matched: android_spyware",
        severity: "warning",
        evidence: ["Known Android spyware signature"]
      },
      {
        timestamp: new Date().toISOString(),
        event_type: "network",
        description: "Network connection to 192.168.1.100:443",
        severity: "critical",
        evidence: ["Flagged as C2 server"]
      },
      {
        timestamp: new Date().toISOString(),
        event_type: "file",
        description: "File written: /data/data/malware/cache.dat",
        severity: "warning",
        evidence: ["File system modification detected"]
      }
    ],
    malware_explanation: {
      summary: `This ${activeCase.type} sample exhibits multiple malicious capabilities including data theft and system compromise.`,
      technical_details: `Static analysis identified ${activeCase.yaraMatches.length} YARA rule matches. Dynamic analysis captured network connections to suspicious endpoints. MITRE ATT&CK techniques mapped to known malware behaviors.`,
      capabilities_identified: activeCase.capabilityTags?.map((c: any) => c.capability) || [],
      confidence_level: 0.85
    },
    victim_impact: {
      data_accessed: ["SMS messages", "Contact list", "GPS location"],
      privacy_risks: ["Personal data exposure", "Location tracking"],
      financial_risks: ["Banking credentials theft", "Unauthorized transactions"],
      device_integrity: ["System compromise", "Persistence mechanisms"],
      overall_impact: "high",
      explanation: "The malware poses a high risk to the victim through data theft and system compromise."
    },
    exfiltration_analysis: {
      data_types: ["SMS messages", "Contact information", "Location data"],
      destinations: ["192.168.1.100:443", "c2-server.evil-domain.com"],
      timing_patterns: "Periodic every 60 seconds",
      encryption_status: "Likely encrypted",
      estimated_volume: "Medium",
      risk_assessment: "High"
    },
    recommendations: [
      {
        priority: "immediate",
        category: "containment",
        action: "Isolate the affected device from the network",
        rationale: "High-risk malware detected with potential for data exfiltration"
      },
      {
        priority: "high",
        category: "victim",
        action: "Advise victim to change all passwords from a clean device",
        rationale: "Credential theft capability detected"
      },
      {
        priority: "high",
        category: "investigation",
        action: "Review victim's SMS logs for unauthorized messages",
        rationale: "SMS theft capability detected"
      }
    ],
    investigation_summary: {
      executive_summary: `This investigation analyzed a ${activeCase.type} sample (ID: ${activeCase.id}). The sample exhibits multiple malicious capabilities. Victim impact is assessed as high. Overall risk score: ${activeCase.riskScore}/100.`,
      key_findings: [
        `Malware capabilities: ${activeCase.capabilityTags?.map((c: any) => c.capability).join(", ") || "none"}`,
        "Data accessed: SMS messages, Contact list, GPS location",
        "Exfiltration destinations: 192.168.1.100:443, c2-server.evil-domain.com",
        "Critical events detected: 2"
      ],
      timeline_summary: "Analysis captured 4 events across static, network, and file categories",
      risk_assessment: "High - urgent investigation recommended",
      next_steps: [
        "Isolate affected device from network",
        "Advise victim to change passwords from clean device",
        "Review SMS logs for unauthorized messages",
        "Investigate exfiltration destinations"
      ],
      generated_at: new Date().toISOString()
    },
    chain_verification: {
      status: "valid",
      is_valid: true,
      verified_links: 7,
      total_links: 7,
      tampered_links: [],
      missing_links: [],
      errors: [],
      verified_at: new Date().toISOString()
    }
  };
}
