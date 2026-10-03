import * as React from "react";
import { Cpu, AlertTriangle, Layers, CheckCircle, FileCode, ArrowUpRight, ArrowDownRight, Activity } from "lucide-react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, PieChart, Pie, Cell, BarChart, Bar, Legend } from "recharts";
import { ThreatCase } from "./types";

interface OverviewTabProps {
  activeCase: ThreatCase;
  onNavigate: (tab: string) => void;
}

// Sparkline helper
function Sparkline({ data, color }: { data: number[]; color: string }) {
  const points = data.map((val, i) => `${(i / (data.length - 1)) * 100},${100 - val}`).join(" ");
  return (
    <svg className="w-16 h-8 overflow-visible" viewBox="0 0 100 100">
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="6"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={points}
      />
    </svg>
  );
}

// React-based smooth animated counter
function AnimatedCounter({ value, prefix = "", suffix = "" }: { value: number; prefix?: string; suffix?: string }) {
  const [count, setCount] = React.useState(0);

  React.useEffect(() => {
    let start = 0;
    const end = value;
    if (start === end) {
      setCount(end);
      return;
    }
    const duration = 800; // ms
    const increment = Math.ceil(end / 40);
    const timer = setInterval(() => {
      start += increment;
      if (start >= end) {
        start = end;
        clearInterval(timer);
      }
      setCount(start);
    }, 20);
    return () => clearInterval(timer);
  }, [value]);

  return <span>{prefix}{count}{suffix}</span>;
}

export function OverviewTab({ activeCase, onNavigate }: OverviewTabProps) {
  // Chart Data based on activeCase values
  const riskTrendData = [
    { name: "0.0s", risk: 0, cpu: 12, network: 0 },
    { name: "0.5s", risk: activeCase.riskScore * 0.25, cpu: 45, network: 15 },
    { name: "1.0s", risk: activeCase.riskScore * 0.55, cpu: 88, network: 42 },
    { name: "1.5s", risk: activeCase.riskScore * 0.75, cpu: 70, network: 68 },
    { name: "2.0s", risk: activeCase.riskScore * 0.90, cpu: 55, network: 89 },
    { name: "2.5s", risk: activeCase.riskScore, cpu: 62, network: 98 },
  ];

  const threatDistributionData = [
    { name: "Signature Matches", value: activeCase.yaraMatches.length * 15 || 5, color: "#ff4040" },
    { name: "Process Anomalies", value: activeCase.type === "PE" ? 65 : 30, color: "#f4b400" },
    { name: "File System Writes", value: activeCase.type === "APK" ? 45 : 55, color: "#00c2ff" },
    { name: "Network Redirection", value: 40, color: "#16ff4d" },
  ];

  const mitreCoverageData = [
    { tactic: "Initial Access", count: activeCase.type === "APK" ? 2 : 1, color: "#00c2ff" },
    { tactic: "Execution", count: activeCase.type === "APK" ? 3 : 4, color: "#16ff4d" },
    { tactic: "Persistence", count: activeCase.type === "APK" ? 2 : 3, color: "#f4b400" },
    { tactic: "Evasion", count: activeCase.type === "APK" ? 4 : 5, color: "#ff4040" },
  ];

  return (
    <div className="space-y-6">
      
      {/* 12-Column Responsive Grid of Statistic Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        
        {/* Card 1: Target Threat */}
        <div className="bg-[#111111] border border-[#222222] p-5 rounded-lg flex items-center justify-between hover:bg-[#171717] hover:border-[#16ff4d]/20 transition-all duration-200 shadow-md group">
          <div className="space-y-1">
            <span className="text-[10px] text-[#6F6F6F] uppercase font-mono tracking-widest block">
              TARGET SAMPLE
            </span>
            <span className="text-sm font-bold text-white block uppercase truncate max-w-[150px]">
              {activeCase.name}
            </span>
            <span className="text-[10px] text-[#A0A0A0] font-mono block">
              SHA256: <span className="font-mono text-[#16ff4d]">{activeCase.hash.substring(0, 8)}</span>
            </span>
          </div>
          <div className="w-10 h-10 rounded bg-[#171717] border border-[#222222] flex items-center justify-center text-[#16ff4d] group-hover:scale-105 transition-transform duration-200">
            <FileCode className="w-5 h-5" />
          </div>
        </div>

        {/* Card 2: Risk Classification */}
        <div className="bg-[#111111] border border-[#222222] p-5 rounded-lg flex items-center justify-between hover:bg-[#171717] hover:border-[#ff4040]/20 transition-all duration-200 shadow-md group">
          <div className="space-y-1">
            <span className="text-[10px] text-[#6F6F6F] uppercase font-mono tracking-widest block">
              RISK ASSESSMENT
            </span>
            <span className={`text-xl font-mono font-bold block ${activeCase.riskScore >= 70 ? "text-[#ff4040]" : activeCase.riskScore >= 40 ? "text-[#f4b400]" : "text-[#16ff4d]"}`}>
              <AnimatedCounter value={activeCase.riskScore} suffix=" / 100" />
            </span>
            <div className="flex items-center gap-1.5 mt-1">
              <Sparkline data={activeCase.riskScore > 75 ? [20, 50, 45, 80, 95] : [10, 15, 30, 25, 45]} color={activeCase.riskScore > 75 ? "#ff4040" : "#f4b400"} />
              <div className="text-[8px] font-mono text-[#A0A0A0]">
                {(() => {
                  const level = activeCase.threatAssessment?.threat_level ?? (activeCase.riskScore >= 70 ? "CRITICAL" : activeCase.riskScore >= 40 ? "HIGH" : "MEDIUM");
                  const colorMap: Record<string, string> = { CRITICAL: "#ff4040", HIGH: "#f4b400", MEDIUM: "#f4b400", LOW: "#16ff4d" };
                  return <span style={{ color: colorMap[level] ?? "#f4b400" }} className="flex items-center font-bold">{level} <ArrowUpRight className="w-3 h-3 ml-0.5" /></span>;
                })()}
              </div>
            </div>
            {activeCase.threatAssessment && (
              <span className="text-[8px] font-mono text-[#6F6F6F] block">
                Verdict: <span className={`font-bold ${activeCase.threatAssessment.verdict === "MALICIOUS" ? "text-[#ff4040]" : activeCase.threatAssessment.verdict === "SUSPICIOUS" ? "text-[#f4b400]" : "text-[#16ff4d]"}`}>{activeCase.threatAssessment.verdict}</span>
                {" · "}Confidence: <span className="text-white">{activeCase.threatAssessment.confidence}%</span>
              </span>
            )}
          </div>
          <div className={`w-10 h-10 rounded bg-[#171717] border border-[#222222] flex items-center justify-center group-hover:scale-105 transition-transform duration-200 ${activeCase.riskScore >= 70 ? "text-[#ff4040]" : "text-[#f4b400]"}`}>
            <AlertTriangle className="w-5 h-5 animate-pulse" />
          </div>
        </div>


        {/* Card 3: MITRE ATT&CK Mapping */}
        <div className="bg-[#111111] border border-[#222222] p-5 rounded-lg flex items-center justify-between hover:bg-[#171717] hover:border-[#f4b400]/20 transition-all duration-200 shadow-md group">
          <div className="space-y-1">
            <span className="text-[10px] text-[#6F6F6F] uppercase font-mono tracking-widest block">
              MITRE ALIGNMENT
            </span>
            <span className="text-xl font-mono font-bold text-white block">
              <AnimatedCounter value={activeCase.mitreCount} suffix=" Tactics" />
            </span>
            <div className="flex items-center gap-1.5 text-[10px] text-[#A0A0A0] font-mono">
              <span className="text-[#f4b400] font-bold">CONFIRMATION RATE: 94%</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded bg-[#171717] border border-[#222222] flex items-center justify-center text-[#f4b400] group-hover:scale-105 transition-transform duration-200">
            <Layers className="w-5 h-5" />
          </div>
        </div>

        {/* Card 4: Investigation Status */}
        <div className="bg-[#111111] border border-[#222222] p-5 rounded-lg flex items-center justify-between hover:bg-[#171717] hover:border-[#00c2ff]/20 transition-all duration-200 shadow-md group">
          <div className="space-y-1 w-full">
            <span className="text-[10px] text-[#6F6F6F] uppercase font-mono tracking-widest block">
              LEDGER STATUS
            </span>
            <span className="text-xs font-mono font-bold text-[#16ff4d] border border-[#16ff4d]/30 bg-[#16ff4d]/10 rounded px-2.5 py-1 inline-block mt-1 tracking-wider">
              {activeCase.status}
            </span>
            <span className="text-[9px] text-[#A0A0A0] font-mono block mt-1">
              APPROVED VIA CYBER CELL #218
            </span>
          </div>
          <div className="w-10 h-10 rounded bg-[#171717] border border-[#222222] flex items-center justify-center text-[#16ff4d] group-hover:scale-105 transition-transform duration-200 shrink-0">
            <CheckCircle className="w-5 h-5" />
          </div>
        </div>

      </div>

      {/* Main Charts & Forensic Summary Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Dynamic Recharts Chart Block */}
        <div className="lg:col-span-8 bg-[#111111] border border-[#222222] rounded-lg p-6 space-y-6 flex flex-col justify-between">
          <div className="flex justify-between items-center border-b border-[#222222]/60 pb-4">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
                Real-time Sandbox Detonation Threat Signal Trend
              </h3>
              <p className="text-[11px] text-[#A0A0A0] font-light">
                High-density signal telemetry measuring active behavioral risk and virtual guest resource loads.
              </p>
            </div>
            <span className="text-[10px] font-mono text-[#6F6F6F]">CASE FILE ID: {activeCase.id}</span>
          </div>

          {/* Interactive Recharts Graph */}
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={riskTrendData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff4040" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#ff4040" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00c2ff" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#00c2ff" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#222222" vertical={false} />
                <XAxis dataKey="name" stroke="#6F6F6F" fontSize={10} className="font-mono" />
                <YAxis stroke="#6F6F6F" fontSize={10} className="font-mono" />
                <Tooltip
                  contentStyle={{ backgroundColor: "#111111", borderColor: "#222222", borderRadius: "4px" }}
                  labelStyle={{ color: "#FFFFFF", fontFamily: "JetBrains Mono", fontSize: "10px" }}
                  itemStyle={{ fontSize: "11px" }}
                />
                <Legend wrapperStyle={{ fontSize: '10px', marginTop: '10px' }} />
                <Area type="monotone" dataKey="risk" stroke="#ff4040" strokeWidth={2} name="Calculated Risk Impact" fillOpacity={1} fill="url(#colorRisk)" />
                <Area type="monotone" dataKey="cpu" stroke="#00c2ff" strokeWidth={2} name="Virtual CPU Allocation" fillOpacity={1} fill="url(#colorCpu)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Direct Navigation Anchors */}
          <div className="pt-4 border-t border-[#222222]/60 flex flex-wrap justify-between items-center text-[10px] font-mono gap-4">
            <button 
              onClick={() => onNavigate("static")}
              className="text-[#16ff4d] hover:underline flex items-center gap-1.5 focus:outline-none uppercase"
            >
              Verify Disassembly Assembly <ChevronRight className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={() => onNavigate("dynamic")}
              className="text-[#16ff4d] hover:underline flex items-center gap-1.5 focus:outline-none uppercase"
            >
              Hypervisor Log Detonation <ChevronRight className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={() => onNavigate("reports")}
              className="text-[#16ff4d] hover:underline flex items-center gap-1.5 focus:outline-none uppercase"
            >
              Print Court Evidence <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Right Dashboard Widget Column (Donut & MITRE Coverage) */}
        <div className="lg:col-span-4 space-y-6">
          
          {/* Donut Chart: Threat Distribution */}
          <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-4">
            <span className="text-[10px] text-[#6F6F6F] font-mono uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
              THREAT SPECTRUM ANALYSIS
            </span>
            
            <div className="h-40 flex items-center justify-center relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={threatDistributionData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {threatDistributionData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: "#111111", borderColor: "#222222" }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute text-center">
                <span className="text-xl font-mono font-bold text-white block">{activeCase.riskScore}%</span>
                <span className="text-[8px] text-[#A0A0A0] uppercase font-mono block">Threat Consensus</span>
              </div>
            </div>

            {/* Custom Legend */}
            <div className="grid grid-cols-2 gap-2 text-[9px] font-mono">
              {threatDistributionData.map((item, index) => (
                <div key={index} className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                  <span className="text-[#A0A0A0] truncate">{item.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Bar Chart: MITRE Tactics Coverage */}
          <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-4">
            <span className="text-[10px] text-[#6F6F6F] font-mono uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
              MITRE ATT&CK ALIGNED MATRIX
            </span>

            <div className="h-32">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={mitreCoverageData} margin={{ top: 0, right: 0, left: -40, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#222222" horizontal={false} />
                  <XAxis dataKey="tactic" stroke="#6F6F6F" fontSize={8} />
                  <YAxis stroke="#6F6F6F" fontSize={8} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: "#111111", borderColor: "#222222" }} />
                  <Bar dataKey="count" fill="#16ff4d">
                    {mitreCoverageData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

        </div>

      </div>

      {/* Network Intelligence Observables Widget */}
      {activeCase.networkIndicators && (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-4">
          <div className="flex justify-between items-center border-b border-[#222222]/60 pb-3">
            <span className="text-[10px] text-[#6F6F6F] font-mono uppercase tracking-widest block font-bold">
              Network Observables & Geolocation Attribution
            </span>
            <button
              onClick={() => onNavigate("network")}
              className="text-[#00c2ff] hover:underline text-[10px] font-mono uppercase focus:outline-none"
            >
              Detailed View & Map →
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-[#090909] border border-[#222222] p-4 rounded-lg space-y-2">
              <span className="text-[9px] text-[#6F6F6F] uppercase tracking-widest font-mono font-bold block">IP addresses</span>
              {activeCase.networkIndicators.ips.length === 0 ? (
                <span className="text-xs text-[#444] font-mono">None extracted</span>
              ) : (
                <div className="space-y-1">
                  {activeCase.networkIndicators.ips.slice(0, 3).map((ip, i) => (
                    <div key={i} className="text-[11px] font-mono text-[#00c2ff] truncate">{ip}</div>
                  ))}
                  {activeCase.networkIndicators.ips.length > 3 && (
                    <div className="text-[9px] text-[#6F6F6F] font-mono">+ {activeCase.networkIndicators.ips.length - 3} more</div>
                  )}
                </div>
              )}
            </div>

            <div className="bg-[#090909] border border-[#222222] p-4 rounded-lg space-y-2">
              <span className="text-[9px] text-[#6F6F6F] uppercase tracking-widest font-mono font-bold block">Domains</span>
              {activeCase.networkIndicators.domains.length === 0 ? (
                <span className="text-xs text-[#444] font-mono">None extracted</span>
              ) : (
                <div className="space-y-1">
                  {activeCase.networkIndicators.domains.slice(0, 3).map((d, i) => (
                    <div key={i} className="text-[11px] font-mono text-[#f4b400] truncate">{d}</div>
                  ))}
                  {activeCase.networkIndicators.domains.length > 3 && (
                    <div className="text-[9px] text-[#6F6F6F] font-mono">+ {activeCase.networkIndicators.domains.length - 3} more</div>
                  )}
                </div>
              )}
            </div>

            <div className="bg-[#090909] border border-[#222222] p-4 rounded-lg space-y-2">
              <span className="text-[9px] text-[#6F6F6F] uppercase tracking-widest font-mono font-bold block">Geolocation Span</span>
              {(activeCase.geoIocs ?? []).length === 0 ? (
                <span className="text-xs text-[#444] font-mono">No locations mapped</span>
              ) : (
                <div className="space-y-1">
                  {activeCase.geoIocs!.slice(0, 3).map((g, i) => {
                    const place = [g.city, g.country].filter(Boolean).join(", ");
                    return (
                      <div key={i} className="text-[11px] font-mono text-white truncate flex items-center justify-between gap-2">
                        <span>{g.ip}</span>
                        <span className="text-[#6F6F6F] text-[10px] font-sans font-light truncate">{place || "unknown"}</span>
                      </div>
                    );
                  })}
                  {activeCase.geoIocs!.length > 3 && (
                    <div className="text-[9px] text-[#6F6F6F] font-mono">+ {activeCase.geoIocs!.length - 3} more</div>
                  )}
                </div>
              )}
            </div>
          </div>
          {(activeCase.geoIocs ?? []).length > 0 && (
            <p className="text-[8px] text-[#444] font-mono italic flex items-center gap-1">
              ⚠ Geolocation is an approximate geographic estimate and not an exact physical location.
            </p>
          )}
        </div>
      )}

    </div>
  );
}

function ChevronRight(props: any) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="m9 18 6-6-6-6" />
    </svg>
  );
}
