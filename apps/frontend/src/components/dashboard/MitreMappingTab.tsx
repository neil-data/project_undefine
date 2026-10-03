import * as React from "react";
import { Shield, ChevronDown, ChevronUp, ExternalLink, AlertTriangle, Layers } from "lucide-react";
import { ThreatCase } from "./types";

interface MitreMappingTabProps {
  activeCase: ThreatCase;
}

export function MitreMappingTab({ activeCase }: MitreMappingTabProps) {
  const [expandedTechnique, setExpandedTechnique] = React.useState<string | null>(null);

  const mitreTechniques: any[] = activeCase.mitreTechniques ?? [];

  const hasTechniques = mitreTechniques.length > 0;

  const getSeverityColor = (confidence: number) => {
    if (confidence >= 0.8) return "#ff4040";
    if (confidence >= 0.6) return "#f4b400";
    return "#16ff4d";
  };

  const getSeverityLabel = (confidence: number) => {
    if (confidence >= 0.8) return "CRITICAL";
    if (confidence >= 0.6) return "HIGH";
    return "MEDIUM";
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex justify-between items-center border-b border-[#222222]/80 pb-4">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
            MITRE ATT&CK Enterprise Matrix Alignment
          </h3>
          <p className="text-[11px] text-[#A0A0A0] font-light font-sans">
            {hasTechniques
              ? `${mitreTechniques.length} technique${mitreTechniques.length !== 1 ? "s" : ""} detected for case ${activeCase.id}.`
              : "No MITRE techniques detected. Submit a sample for analysis to populate this view."}
          </p>
        </div>
        <div className="flex items-center gap-1.5 bg-[#ff4040]/10 border border-[#ff4040]/20 text-[#ff4040] font-mono text-[10px] px-3 py-1 rounded">
          <Shield className="w-3.5 h-3.5" /> {hasTechniques ? `${mitreTechniques.length} TECHNIQUES` : "NO DATA"}
        </div>
      </div>

      {/* Empty state */}
      {!hasTechniques && (
        <div className="text-center py-16 text-[#6F6F6F] font-mono text-xs">
          <Layers className="w-12 h-12 mx-auto mb-4 opacity-20" />
          <p className="text-sm font-bold text-white mb-1">No MITRE Techniques Mapped</p>
          <p>Upload and analyze a binary file to populate the MITRE ATT&CK matrix.</p>
        </div>
      )}

      {/* Flat technique list — no tactic grouping since backend doesn't provide tactic field */}
      {hasTechniques && (
        <div className="space-y-3">
          {mitreTechniques.map((tech: any) => {
            const confidence = typeof tech.confidence === "number" ? tech.confidence : 0.5;
            const color = getSeverityColor(confidence);
            const severityLabel = getSeverityLabel(confidence);
            const isExpanded = expandedTechnique === tech.technique_id;
            return (
              <div
                key={tech.technique_id}
                className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden transition-all duration-200"
              >
                {/* Technique row */}
                <button
                  onClick={() => setExpandedTechnique(isExpanded ? null : tech.technique_id)}
                  className="w-full flex items-center justify-between px-5 py-4 hover:bg-[#171717] transition-all text-left focus:outline-none"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                    <span className="text-sm font-mono font-bold" style={{ color }}>
                      {tech.technique_id}
                    </span>
                    <span className="text-xs font-bold text-white font-sans">
                      {tech.technique_name}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`text-[8px] font-mono font-bold px-2 py-0.5 rounded border ${
                      confidence >= 0.8 ? "bg-red-950/40 text-[#ff4040] border-red-500/20" :
                      confidence >= 0.6 ? "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20" :
                      "bg-green-950/40 text-[#16ff4d] border-green-500/20"
                    }`}>
                      {severityLabel} — {(confidence * 100).toFixed(0)}%
                    </span>
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-[#A0A0A0]" /> : <ChevronDown className="w-4 h-4 text-[#A0A0A0]" />}
                  </div>
                </button>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-1 border-t border-[#222222]/60 bg-[#090909]/60">
                    <div className="py-4 space-y-4">
                      <div className="grid grid-cols-2 gap-4 font-mono text-[11px]">
                        <div className="bg-[#111111]/80 border border-[#222222] p-4 rounded-lg space-y-2">
                          <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                            TECHNIQUE ID
                          </span>
                          <p className="text-[#16ff4d] font-bold">{tech.technique_id}</p>
                        </div>
                        <div className="bg-[#111111]/80 border border-[#222222] p-4 rounded-lg space-y-2">
                          <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                            CONFIDENCE SCORE
                          </span>
                          <p style={{ color }} className="font-bold">{(confidence * 100).toFixed(0)}%</p>
                        </div>
                      </div>
                      <a
                        href={`https://attack.mitre.org/techniques/${tech.technique_id.replace(".", "/")}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[#00c2ff] hover:underline flex items-center gap-1 font-mono text-[10px]"
                      >
                        VIEW ON MITRE ATT&CK <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

    </div>
  );
}
