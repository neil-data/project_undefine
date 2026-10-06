import * as React from "react";
import { Copy, Check, Search, FileCode, Shield, Server, Info, Hash, Database, ExternalLink } from "lucide-react";
import { ThreatCase } from "./types";

interface StaticAnalysisTabProps {
  activeCase: ThreatCase;
}

export function StaticAnalysisTab({ activeCase }: StaticAnalysisTabProps) {
  const [copied, setCopied] = React.useState(false);
  const [searchQuery, setSearchQuery] = React.useState("");
  const [activeSubTab, setActiveSubTab] = React.useState<"permissions" | "entropy" | "metadata" | "strings">("metadata");

  // ---- Real data from the case ----
  const mitreTechniques: any[] = activeCase.mitreTechniques ?? [];
  const capabilityTags: any[] = activeCase.capabilityTags ?? [];
  const yaraMatches: string[] = activeCase.yaraMatches ?? [];
  const riskScore: number = activeCase.riskScore;

  // Derive permissions / IAT from capability tags where possible
  const detectedCapabilities = capabilityTags.map(ct => ({
    name: ct.capability ?? ct,
    confidence: typeof ct.confidence === "number" ? ct.confidence : 0.5,
    evidence: Array.isArray(ct.evidence) ? ct.evidence.join("; ") : (ct.evidence ?? ""),
  }));

  const handleCopy = () => {
    const text = `CASE ID: ${activeCase.id}\nFILE: ${activeCase.name}\nRISK SCORE: ${riskScore}\nYARA MATCHES: ${yaraMatches.join(", ")}\nCAPABILITIES: ${detectedCapabilities.map(c => c.name).join(", ")}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const riskColor = riskScore >= 60 ? "#ff4040" : riskScore >= 25 ? "#f4b400" : "#16ff4d";

  return (
    <div className="space-y-6">
      
      {/* Tab select bar */}
      <div className="flex border-b border-[#222222]/80 gap-6 flex-wrap">
        {[
          { id: "metadata", label: "Cryptographic Metadata", icon: Hash },
          { id: "strings", label: "Extracted Strings / IOCs", icon: Search },
          { id: "permissions", label: activeCase.type === "APK" ? "Permissions / Capabilities" : "Capabilities / IAT Signals", icon: Shield },
          { id: "entropy", label: "Rule Engine Output", icon: Server },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`pb-2.5 text-xs font-semibold uppercase tracking-wider flex items-center gap-2 border-b-2 transition-all ${
                activeSubTab === tab.id
                  ? "border-[#16ff4d] text-white"
                  : "border-transparent text-[#A0A0A0] hover:text-white"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Cryptographic Metadata tab */}
      {activeSubTab === "metadata" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4 shadow-md font-mono text-xs">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
              Cryptographic Metadata & Evidence Hash Ledger
            </h3>
            <button
              onClick={handleCopy}
              className="bg-[#171717] hover:bg-[#222222] border border-[#222222] text-[10px] font-mono font-bold uppercase tracking-wide px-3 py-1.5 rounded text-white flex items-center gap-1.5 transition-all"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#16ff4d]" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? "Copied" : "Copy Report"}
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#090909] border border-[#222222] p-4 rounded-lg space-y-2">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                HASH REGISTER TRACE
              </span>
              <div className="space-y-1.5 font-mono text-[10px] text-[#A0A0A0]">
                <p className="truncate"><span className="text-white font-bold">CASE ID:</span> {activeCase.id}</p>
                <p className="truncate"><span className="text-white font-bold">FILE:</span> {activeCase.name}</p>
                <p><span className="text-white font-bold">TYPE:</span> {activeCase.type}</p>
                <p><span className="text-white font-bold">SIZE:</span> {activeCase.size}</p>
                <p className="break-all"><span className="text-white font-bold">SHA-256:</span> <span className="text-[#16ff4d]">{activeCase.sha256 || activeCase.hash}</span></p>
                {activeCase.md5 && <p className="break-all"><span className="text-white font-bold">MD5:</span> <span className="text-[#00c2ff]">{activeCase.md5}</span></p>}
                {activeCase.sha1 && <p className="break-all"><span className="text-white font-bold">SHA-1:</span> <span className="text-[#00c2ff]">{activeCase.sha1}</span></p>}
                <p><span className="text-white font-bold">SUBMITTED:</span> {activeCase.date}</p>
              </div>
            </div>
            <div className="bg-[#090909] border border-[#222222] p-4 rounded-lg space-y-2">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                THREAT ASSESSMENT
              </span>
              <div className="space-y-1.5 font-mono text-[10px] text-[#A0A0A0]">
                <p>
                  <span className="text-white font-bold">RISK SCORE:</span>{" "}
                  <span style={{ color: riskColor }} className="font-bold text-sm">{riskScore}/100</span>
                </p>
                <p>
                  <span className="text-white font-bold">VERDICT:</span>{" "}
                  <span style={{ color: riskColor }} className="font-bold">
                    {activeCase.status.replace("_", " ")}
                  </span>
                </p>
                <p><span className="text-white font-bold">MITRE TECHNIQUES:</span> {activeCase.mitreCount} aligned</p>
                <p><span className="text-white font-bold">YARA RULES TRIGGERED:</span> {yaraMatches.length}</p>
                <p><span className="text-white font-bold">PLATFORM:</span> {activeCase.type === "APK" ? "Android" : activeCase.type === "ELF" ? "Linux" : "Windows"}</p>
              </div>
            </div>
          </div>

          {/* YARA Matches */}
          {yaraMatches.length > 0 && (
            <div className="bg-[#090909] border border-[#222222] rounded-lg p-4 space-y-2">
              <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                RULE ENGINE MATCHES
              </span>
              <div className="flex flex-wrap gap-2">
                {yaraMatches.map((match, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 bg-red-950/30 border border-red-500/20 text-[#ff4040] font-mono text-[9px] rounded font-bold uppercase tracking-wide"
                  >
                    {match}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* MalwareBazaar Threat Intelligence (abuse.ch) */}
          {activeCase.malwareBazaar?.found ? (
            <div className="bg-[#090909] border border-red-500/30 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4 text-[#ff4040]" />
                  <span className="text-[11px] text-[#ff4040] font-bold uppercase tracking-wider font-sans">
                    MalwareBazaar Global Threat Feed Hit
                  </span>
                  <span className="px-2 py-0.5 bg-red-950/40 border border-red-500/30 text-[#ff4040] text-[9px] rounded font-bold uppercase">
                    CONFIRMED MALWARE
                  </span>
                </div>
                {activeCase.malwareBazaar.bazaar_url && (
                  <a
                    href={activeCase.malwareBazaar.bazaar_url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] text-[#00c2ff] hover:underline flex items-center gap-1 font-mono"
                  >
                    View on abuse.ch <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[10px] font-mono text-[#A0A0A0]">
                <div className="space-y-1">
                  <p><span className="text-white font-bold">SIGNATURE / FAMILY:</span> <span className="text-[#ff4040] font-bold text-xs">{activeCase.malwareBazaar.signature || "Known Malicious"}</span></p>
                  {activeCase.malwareBazaar.delivery_method && (
                    <p><span className="text-white font-bold">DELIVERY:</span> {activeCase.malwareBazaar.delivery_method}</p>
                  )}
                  {activeCase.malwareBazaar.first_seen && (
                    <p><span className="text-white font-bold">FIRST SEEN:</span> {activeCase.malwareBazaar.first_seen}</p>
                  )}
                  {activeCase.malwareBazaar.reporter && (
                    <p><span className="text-white font-bold">REPORTER:</span> @{activeCase.malwareBazaar.reporter}</p>
                  )}
                </div>
                <div className="space-y-1">
                  {activeCase.malwareBazaar.imphash && (
                    <p className="truncate"><span className="text-white font-bold">IMPHASH:</span> {activeCase.malwareBazaar.imphash}</p>
                  )}
                  {activeCase.malwareBazaar.origin_country && (
                    <p><span className="text-white font-bold">ORIGIN:</span> {activeCase.malwareBazaar.origin_country}</p>
                  )}
                  {activeCase.malwareBazaar.vendor_verdicts && activeCase.malwareBazaar.vendor_verdicts.length > 0 && (
                    <div className="mt-1">
                      <span className="text-white font-bold block">VENDOR DETECTIONS:</span>
                      <div className="space-y-0.5 mt-0.5 max-h-16 overflow-y-auto">
                        {activeCase.malwareBazaar.vendor_verdicts.slice(0, 4).map((v: string, idx: number) => (
                          <p key={idx} className="text-red-400/90 truncate">• {v}</p>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {activeCase.malwareBazaar.tags && activeCase.malwareBazaar.tags.length > 0 && (
                <div className="pt-2 border-t border-[#222222] flex flex-wrap gap-1.5 items-center">
                  <span className="text-[9px] text-[#6F6F6F] font-bold uppercase mr-1">TAGS:</span>
                  {activeCase.malwareBazaar.tags.map((t: string, i: number) => (
                    <span key={i} className="px-1.5 py-0.5 bg-[#171717] border border-[#333] text-[#A0A0A0] text-[9px] rounded font-mono">
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-[#090909] border border-[#222222] rounded-lg p-3 flex items-center justify-between text-[10px] font-mono text-[#6F6F6F]">
              <div className="flex items-center gap-2">
                <Database className="w-3.5 h-3.5 text-[#6F6F6F]" />
                <span>MalwareBazaar Intelligence (abuse.ch): Repository queried for sample hash.</span>
              </div>
              <span className="px-2 py-0.5 bg-[#171717] border border-[#222222] text-[#A0A0A0] rounded text-[9px]">
                {activeCase.sha256 || activeCase.hash ? "NOT IN BAZAAR FEED" : "AWAITING HASH"}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Extracted Strings / IOCs tab */}
      {activeSubTab === "strings" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4 shadow-md">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
            Extracted Strings & Network IOCs
          </h3>
          {mitreTechniques.length === 0 && capabilityTags.length === 0 ? (
            <div className="text-center py-12 text-[#6F6F6F] font-mono text-xs">
              <FileCode className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p>No string / IOC data available for this case.</p>
              <p className="text-[10px] mt-1">Upload a binary file to see real extracted strings and network indicators.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Capability tags as IOC signals */}
              {detectedCapabilities.length > 0 && (
                <div className="bg-[#090909] border border-[#222222] rounded-lg p-4 space-y-3">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                    BEHAVIORAL CAPABILITY SIGNALS
                  </span>
                  <div className="space-y-2">
                    {detectedCapabilities.map((cap, i) => (
                      <div key={i} className="flex items-start justify-between gap-4 font-mono text-[11px]">
                        <span className="text-[#00c2ff] font-bold">{cap.name}</span>
                        <span className={`shrink-0 px-2 py-0.5 rounded text-[8px] font-bold border uppercase ${
                          cap.confidence >= 0.8 ? "bg-red-950/30 text-[#ff4040] border-red-500/20" :
                          cap.confidence >= 0.5 ? "bg-yellow-950/30 text-[#f4b400] border-yellow-500/20" :
                          "bg-[#171717] text-[#6F6F6F] border-[#222222]"
                        }`}>
                          {cap.confidence >= 0.8 ? "HIGH" : cap.confidence >= 0.5 ? "MEDIUM" : "LOW"} confidence
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* MITRE as signals */}
              {mitreTechniques.length > 0 && (
                <div className="bg-[#090909] border border-[#222222] rounded-lg p-4 space-y-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                    MITRE ATT&CK TECHNIQUE EVIDENCE
                  </span>
                  {mitreTechniques.map((t: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 font-mono text-[10px]">
                      <span className="text-[#16ff4d] font-bold w-20 shrink-0">{t.technique_id}</span>
                      <span className="text-[#A0A0A0]">{t.technique_name}</span>
                      <span className="text-[#6F6F6F] text-[9px] ml-auto">
                        [{typeof t.confidence === "number" ? `${(t.confidence * 100).toFixed(0)}%` : "N/A"}]
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Geo-IP Observables */}
              {(activeCase.geoIocs ?? []).length > 0 && (
                <div className="bg-[#090909] border border-[#222222] rounded-lg p-4 space-y-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">
                    GEOLOCATION ATTRIBUTION (GEO-IP)
                  </span>
                  <div className="space-y-2">
                    {(activeCase.geoIocs ?? []).map((g, i) => (
                      <div key={i} className="font-mono text-[10px] border-b border-[#222222]/40 pb-2 last:border-b-0 last:pb-0">
                        <div className="text-[9px] text-[#A0A0A0]">GeoIP: {g.status === "resolved" ? "Resolved" : g.status === "not_attempted" ? "Not attempted" : "Unavailable"}</div>
                        <div className="flex justify-between items-center text-[11px] text-[#00c2ff] font-bold">
                          <span>{g.ip}</span>
                          <span className="text-[#A0A0A0] font-sans font-normal">
                            {[g.city, g.region, g.country].filter(Boolean).join(", ") || "Location unavailable"}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 text-[9px] text-[#6F6F6F] mt-1">
                          {g.isp && <div><span className="text-[#555]">ISP:</span> {g.isp}</div>}
                          {g.asn && <div><span className="text-[#555]">ASN:</span> AS{g.asn}</div>}
                        </div>
                      </div>
                    ))}
                  </div>
                  <p className="text-[8px] text-[#6F6F6F] font-mono italic mt-2">
                    ⚠ {(activeCase.geoIocs ?? [])[0]?.disclaimer ?? "Geo-IP is an approximate geographic estimate and not an exact physical location."}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Permissions / Capabilities tab */}
      {activeSubTab === "permissions" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4 shadow-md">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
            {activeCase.type === "APK" ? "Android Permission & Security Policy Audit" : "Detected Capability & Behavioral Indicators"}
          </h3>
          {detectedCapabilities.length === 0 ? (
            <div className="text-center py-12 text-[#6F6F6F] font-mono text-xs">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p>No capability data detected for this case.</p>
              <p className="text-[10px] mt-1">Upload and analyze a binary to see real permission and capability details.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-[10px]">
              {detectedCapabilities.map((cap, i) => (
                <div key={i} className="p-3.5 bg-[#090909] border border-[#222222] rounded-lg space-y-1.5">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-[#00c2ff] text-[11px]">{cap.name}</span>
                    <span className={`px-2 py-0.5 rounded font-mono text-[8px] border ${
                      cap.confidence >= 0.8 ? "bg-red-950/40 text-[#ff4040] border-red-500/20" :
                      cap.confidence >= 0.5 ? "bg-yellow-950/40 text-[#f4b400] border-yellow-500/20" :
                      "bg-[#171717] text-[#6F6F6F] border-[#222222]"
                    }`}>
                      {cap.confidence >= 0.8 ? "HIGH" : cap.confidence >= 0.5 ? "MEDIUM" : "LOW"}
                    </span>
                  </div>
                  {cap.evidence && (
                    <p className="text-[#A0A0A0] font-sans leading-relaxed text-[11px]">{cap.evidence}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Rule Engine Output tab */}
      {activeSubTab === "entropy" && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
            Rule Engine & YARA Detection Results
          </h3>
          {yaraMatches.length === 0 ? (
            <div className="text-center py-12 text-[#6F6F6F] font-mono text-xs">
              <Server className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p>No rule engine output available for this case.</p>
              <p className="text-[10px] mt-1">Upload and analyze a binary to see real rule matches and detection results.</p>
            </div>
          ) : (
            <div className="space-y-3 font-mono text-[11px] pt-2">
              {yaraMatches.map((match, i) => (
                <div key={i} className="p-4 bg-[#090909] border border-[#222222] rounded-lg flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="font-bold text-white text-xs">{match}</span>
                    <span className="text-[9px] font-mono text-[#6F6F6F] block uppercase tracking-wider">
                      YARA SIGNATURE RULE MATCH
                    </span>
                  </div>
                  <span className="px-2.5 py-1 bg-red-950/30 border border-red-500/20 text-[#ff4040] font-mono text-[9px] rounded font-bold uppercase tracking-wide">
                    MATCH TRIGGERED
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

    </div>
  );
}
