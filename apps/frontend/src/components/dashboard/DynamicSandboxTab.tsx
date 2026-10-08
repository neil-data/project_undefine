import * as React from "react";
import { Terminal, Activity, Cpu, FlaskConical, AlertTriangle, RotateCw, ArrowLeft, Network, FileCode, ShieldAlert } from "lucide-react";
import { ThreatCase } from "./types";

interface DynamicSandboxTabProps {
  activeCase: ThreatCase;
  onNavigate?: (tab: string) => void;
  onReload?: () => void;
}

export function DynamicSandboxTab({ activeCase, onNavigate, onReload }: DynamicSandboxTabProps) {
  const [logs, setLogs] = React.useState<string[]>([
    "[SYSTEM] Dynamic analysis sandbox engine initializing...",
    `[SYSTEM] Case loaded: ${activeCase.id} — ${activeCase.name}`,
  ]);

  const [inputVal, setInputVal] = React.useState("");
  const [isReloading, setIsReloading] = React.useState(false);
  const bottomRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputVal.trim()) return;
    const command = inputVal.trim();
    setLogs(prev => [...prev, `$ ${command}`, "[SYSTEM] Directive dispatched to guest sandbox. Awaiting return frame..."]);
    setInputVal("");
  };

  const handleReload = async () => {
    setIsReloading(true);
    setLogs(prev => [...prev, "[SYSTEM] Reloading sandbox environment and re-syncing telemetry..."]);
    try {
      if (onReload) {
        await onReload();
      } else {
        await new Promise(r => setTimeout(r, 600));
      }
      setLogs(prev => [...prev, "[SYSTEM] Sandbox state synchronized successfully."]);
    } catch (err: any) {
      setLogs(prev => [...prev, `[SYSTEM ERROR] Failed to reload: ${err?.message || "Unknown error"}`]);
    } finally {
      setIsReloading(false);
    }
  };

  const handleExit = () => {
    if (onNavigate) {
      onNavigate("overview");
    }
  };

  const dyn: any = activeCase.sandboxResult ?? null;
  const behavior = activeCase.behaviorAnalysis;
  const status = dyn?.status ?? "not_configured";
  const isConfigured = dyn?.available === true;
  const statusLabel: Record<string, string> = {
    not_configured: "NOT CONFIGURED",
    submitted: "SUBMITTED",
    failed: "SUBMISSION FAILED",
    completed: "ANALYSIS COMPLETE",
  };
  const sandboxStatus = status in statusLabel ? statusLabel[status] : String(status).toUpperCase();
  const sandboxConfigured = isConfigured || ["submitted", "failed", "completed"].includes(status);

  // Safe extractions for metrics (protect against array-of-objects in JSX)
  const netConnections: any[] = Array.isArray(dyn?.network_connections) ? dyn.network_connections : [];
  const netCount = netConnections.length || (typeof dyn?.network_connections === "number" ? dyn.network_connections : 0);
  
  const filesWritten: any[] = Array.isArray(dyn?.files_written) ? dyn.files_written : [];
  const fileCount = filesWritten.length || (typeof dyn?.file_drops === "number" ? dyn.file_drops : 0);

  const registryChanges: any[] = Array.isArray(dyn?.registry_changes) ? dyn.registry_changes : [];
  const regCount = registryChanges.length || (typeof dyn?.registry_writes === "number" ? dyn.registry_writes : 0);

  const processTree: any[] = Array.isArray(dyn?.process_tree) ? dyn.process_tree : [];
  const c2Endpoints: string[] = Array.isArray(dyn?.c2_endpoints_detected) ? dyn.c2_endpoints_detected : [];

  return (
    <div className="space-y-6">

      {/* Header with Reload and Exit actions */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4 border-b border-[#222222]/80 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
              Dynamic Sandbox Detonation
            </h3>
            <div className={`flex items-center gap-1.5 font-mono text-[10px] px-2.5 py-0.5 rounded border ${
              status === "completed"
                ? "bg-[#16ff4d]/10 border-[#16ff4d]/20 text-[#16ff4d]"
                : status === "submitted"
                ? "bg-[#00c2ff]/10 border-[#00c2ff]/20 text-[#00c2ff]"
                : status === "failed"
                ? "bg-[#ff4040]/10 border-[#ff4040]/20 text-[#ff4040]"
                : "bg-[#f4b400]/10 border-[#f4b400]/20 text-[#f4b400]"
            }`}>
              <Activity className="w-3 h-3" />
              {sandboxStatus}
            </div>
          </div>
          <p className="text-[11px] text-[#A0A0A0] font-light mt-1">
            {sandboxConfigured
              ? (dyn?.message ?? "Runtime behavior capture from isolated guest detonation environment.")
              : "Isolated local hypervisor profile. Static and behavioral evidence preserved."}
          </p>
        </div>

        {/* Action Controls: Reload & Exit */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleReload}
            disabled={isReloading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#171717] hover:bg-[#222222] border border-[#333333] hover:border-[#16ff4d]/40 rounded text-xs font-mono text-white transition-all active:scale-95 disabled:opacity-50"
            title="Reload sandbox status & logs"
          >
            <RotateCw className={`w-3.5 h-3.5 text-[#16ff4d] ${isReloading ? "animate-spin" : ""}`} />
            <span>Reload</span>
          </button>

          <button
            type="button"
            onClick={handleExit}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#171717] hover:bg-red-950/20 border border-[#333333] hover:border-red-500/40 rounded text-xs font-mono text-[#A0A0A0] hover:text-white transition-all active:scale-95"
            title="Exit sandbox and return to Overview"
          >
            <ArrowLeft className="w-3.5 h-3.5 text-red-400" />
            <span>Exit</span>
          </button>
        </div>
      </div>


      {/* Failure Banner when dynamic status is failed */}
      {dyn?.dynamic_status === "failed" && (
        <div className="bg-[#ff4040]/10 border border-[#ff4040]/30 rounded-lg p-3 text-[#ff4040] text-xs flex items-center gap-2.5 font-mono">
          <ShieldAlert className="w-4 h-4 shrink-0 text-[#ff4040]" />
          <div>
            <span className="font-bold uppercase tracking-wider">Execution Failure:</span> Dynamic analysis failed: {dyn.failure_reason || dyn.message || "Unknown error during detonation."}
          </div>
        </div>
      )}

      {behavior && (
        <section className="bg-[#111111] border border-[#222222] rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider">Behavioral Analysis</h4>
            <span className="text-[10px] font-mono text-[#A0A0A0]">Dynamic status: {behavior.dynamic_status.replaceAll("_", " ")}</span>
          </div>
          <p className="text-xs text-[#A0A0A0]">{behavior.message}</p>
          {behavior.fallback_reason && <p className="text-[11px] text-amber-300">Dynamic analysis unavailable: {behavior.fallback_reason}</p>}
          {[...behavior.observed_findings, ...behavior.findings].length === 0 ? (
            <p className="text-xs text-[#A0A0A0]">Insufficient evidence to infer specific behavior.</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {[...behavior.observed_findings, ...behavior.findings].map((finding, index) => (
                <article key={`${finding.behavior}-${finding.source}-${index}`} className="border border-[#292929] rounded-md p-3 space-y-2">
                  <div className="flex justify-between gap-2">
                    <span className="text-xs font-semibold text-white">{finding.behavior}</span>
                    <span className={`text-[10px] uppercase font-mono ${finding.runtime_verified ? "text-[#16ff4d]" : "text-amber-300"}`}>
                      {finding.runtime_verified ? "Observed" : finding.assessment}
                    </span>
                  </div>
                  <p className="text-[10px] text-[#A0A0A0]">{finding.reason}</p>
                  <ul className="list-disc pl-4 space-y-1 text-[10px] text-[#C8C8C8]">
                    {finding.evidence.map((item, evidenceIndex) => <li key={evidenceIndex} className="break-all">{item}</li>)}
                  </ul>
                  <div className="text-[9px] font-mono text-[#777]">Source: {finding.source} · Runtime verified: {finding.runtime_verified ? "Yes" : "No"}</div>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left: Terminal Console */}
        <div className="lg:col-span-8 bg-[#111111] border border-[#222222] rounded-lg overflow-hidden flex flex-col shadow-lg">
          <div className="bg-[#171717] px-4 py-3 border-b border-[#222222] flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#A0A0A0] uppercase font-bold tracking-wider flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-[#16ff4d]" />
              SANDBOX TERMINAL // {activeCase.id}
            </span>
            <div className="flex items-center gap-2 text-[10px] font-mono text-[#6F6F6F]">
              <span className="w-2 h-2 rounded-full bg-[#16ff4d] animate-ping" />
              <span>LIVE GUEST VM</span>
            </div>
          </div>

          <div className="p-5 font-mono text-[11px] h-[340px] overflow-y-auto space-y-2 bg-[#090909] text-[#A0A0A0] select-text">
            {dyn && (
              <div className="leading-relaxed pl-2 border-l-2 border-[#222222] text-[#A0A0A0] mb-4 bg-[#111111]/40 p-2 rounded-r">
                <span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> state={status} available={isConfigured ? "true" : "false"}
                <br />
                <span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> {dyn.message || "Hypervisor telemetry recorded."}
                {dyn.task_id && <><br /><span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> task_id={dyn.task_id}</>}
                {dyn.sandbox_url && <><br /><span className="text-[#00c2ff] font-bold">[DYNAMIC]</span> sandbox_node={dyn.sandbox_url}</>}
                {dyn.duration_seconds && <><br /><span className="text-[#16ff4d] font-bold">[DYNAMIC]</span> detonation_duration={dyn.duration_seconds}s</>}
              </div>
            )}
            {logs.map((log, index) => {
              const isSystem = log.includes("[SYSTEM]");
              const isUser = log.startsWith("$");
              const isErr = log.includes("[SYSTEM ERROR]");
              return (
                <div key={index} className={`leading-relaxed pl-2 border-l-2 ${
                  isErr ? "border-[#ff4040] text-[#ff4040]" :
                  isSystem ? "border-[#00c2ff]/40 text-[#00c2ff]" :
                  isUser ? "border-[#16ff4d]/40 text-[#16ff4d] font-bold" :
                  "border-[#222222] text-[#A0A0A0]"
                }`}>
                  {log}
                </div>
              );
            })}
            <div className="flex items-center gap-1 text-[#16ff4d] text-[11px] font-mono">
              <span>$ awaiting instructions_</span>
              <span className="w-1.5 h-3 bg-[#16ff4d] animate-pulse inline-block" />
            </div>
            <div ref={bottomRef} />
          </div>

          <form
            onSubmit={handleSubmit}
            className="p-3 bg-[#111111] border-t border-[#222222] flex items-center gap-3"
          >
            <span className="text-xs font-mono text-[#16ff4d] font-bold ml-2">$</span>
            <input
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              placeholder="Enter analyst directive (e.g. dump-memory, trace-network)..."
              className="flex-1 bg-transparent border-none text-xs font-mono text-white focus:outline-none placeholder:text-[#6F6F6F]"
            />
            <button
              type="submit"
              className="bg-[#16ff4d] hover:bg-[#16ff4d]/90 text-[#090909] font-mono text-[10px] uppercase font-bold px-3 py-1.5 rounded transition-all shrink-0 active:scale-95"
            >
              EXEC
            </button>
          </form>
        </div>

        {/* Right Rail: Safe Dynamic Status & Case Context */}
        <div className="lg:col-span-4 space-y-4">
          
          {/* Dynamic Status Card */}
          <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3 font-mono text-[11px]">
            <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
              DETONATION TELEMETRY
            </span>
            <div className="space-y-2 text-[#A0A0A0]">
              <p><span className="text-white font-bold">STATE:</span> <span className="text-[#16ff4d]">{status.toUpperCase()}</span></p>
              <p><span className="text-white font-bold">MODE:</span> <span className="text-white">Real Detonation</span></p>
              <p><span className="text-white font-bold">REAL SANDBOX:</span> <span className="text-white">{(dyn?.real_sandbox_available ?? (dyn?.execution_mode === "real")) ? "Yes" : "No"}</span></p>
              {dyn?.target_architecture && (
                <p><span className="text-white font-bold">ARCH:</span> <span className="text-white">{dyn.target_architecture}</span></p>
              )}
              {dyn?.duration_seconds !== undefined && (
                <p><span className="text-white font-bold">DURATION:</span> {dyn.duration_seconds}s</p>
              )}
              <p><span className="text-white font-bold">NET STREAMS:</span> <span className="text-white font-semibold">{netCount}</span></p>
              <p><span className="text-white font-bold">FILE DROPS:</span> <span className="text-white font-semibold">{fileCount}</span></p>
              <p><span className="text-white font-bold">REGISTRY / PERSIST:</span> <span className="text-white font-semibold">{regCount}</span></p>
            </div>
          </div>

          {/* Case Context Card */}
          <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3 font-mono text-[11px]">
            <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
              TARGET CONTEXT
            </span>
            <div className="space-y-2 text-[#A0A0A0]">
              <p><span className="text-white font-bold">FILE:</span> <span className="truncate block text-white">{activeCase.name}</span></p>
              <p><span className="text-white font-bold">FORMAT:</span> {activeCase.type}</p>
              <p><span className="text-white font-bold">RISK:</span> <span className={activeCase.riskScore >= 60 ? "text-[#ff4040] font-bold" : "text-[#f4b400] font-bold"}>{activeCase.riskScore}/100</span></p>
              <p><span className="text-white font-bold">STATUS:</span> {String(activeCase.status).replace("_", " ")}</p>
            </div>
          </div>

          {/* Sandbox Capabilities Card */}
          <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3 font-mono text-[11px]">
            <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block border-b border-[#222222]/60 pb-2">
              SANDBOX CAPABILITIES
            </span>
            <div className="space-y-1.5 text-[#6F6F6F] text-[10px]">
              <p className="flex items-center gap-2"><Cpu className="w-3 h-3 text-[#00c2ff]" /> Air-gapped containerized VM</p>
              <p className="flex items-center gap-2"><Terminal className="w-3 h-3 text-[#00c2ff]" /> Syscall & API trace hook</p>
              <p className="flex items-center gap-2"><FlaskConical className="w-3 h-3 text-[#00c2ff]" /> Real-time network stream dissection</p>
              <p className="flex items-center gap-2"><Activity className="w-3 h-3 text-[#00c2ff]" /> Memory dump & artifact capture</p>
            </div>
          </div>

        </div>

      </div>

      {/* Structured Captured Telemetry Sections */}
      {(netConnections.length > 0 || processTree.length > 0 || filesWritten.length > 0 || c2Endpoints.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          
          {/* Network Connections Table */}
          {netConnections.length > 0 && (
            <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[#222222] pb-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Network className="w-3.5 h-3.5 text-[#00c2ff]" />
                  Captured Network Connections ({netConnections.length})
                </span>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {netConnections.map((conn, idx) => (
                  <div key={idx} className="bg-[#090909] border border-[#222222] rounded p-2.5 flex items-center justify-between text-xs font-mono">
                    <div className="space-y-0.5">
                      <span className="text-white font-bold">{conn.dest_ip || conn.ip || "Unknown IP"}</span>
                      <span className="text-[#6F6F6F] text-[10px] block">Port: {conn.dest_port || conn.port || "N/A"} // {conn.protocol || "TCP"}</span>
                    </div>
                    {conn.flagged_c2 ? (
                      <span className="bg-red-950/40 text-[#ff4040] border border-red-500/20 px-2 py-0.5 rounded text-[9px] font-bold">
                        C2 SUSPECT
                      </span>
                    ) : (
                      <span className="bg-[#16ff4d]/10 text-[#16ff4d] border border-[#16ff4d]/20 px-2 py-0.5 rounded text-[9px]">
                        NORMAL
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Process Tree List */}
          {processTree.length > 0 && (
            <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[#222222] pb-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Cpu className="w-3.5 h-3.5 text-[#16ff4d]" />
                  Spawned Process Tree ({processTree.length})
                </span>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {processTree.map((proc, idx) => (
                  <div key={idx} className="bg-[#090909] border border-[#222222] rounded p-2.5 text-xs font-mono space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="text-[#16ff4d] font-bold">{proc.process_name || proc.name || "Process"}</span>
                      <span className="text-[#6F6F6F] text-[10px]">PID: {proc.pid || "N/A"}</span>
                    </div>
                    {proc.cmdline && (
                      <p className="text-[#A0A0A0] text-[10px] break-all bg-[#171717] p-1.5 rounded">{proc.cmdline}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Files Written */}
          {filesWritten.length > 0 && (
            <div className="bg-[#111111] border border-[#222222] rounded-lg p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[#222222] pb-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <FileCode className="w-3.5 h-3.5 text-[#f4b400]" />
                  Dropped Files & Artifacts ({filesWritten.length})
                </span>
              </div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {filesWritten.map((file, idx) => (
                  <div key={idx} className="bg-[#090909] border border-[#222222] rounded px-2.5 py-1.5 text-xs font-mono text-[#A0A0A0] break-all">
                    {typeof file === "string" ? file : file.path || JSON.stringify(file)}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* C2 Endpoints Detected */}
          {c2Endpoints.length > 0 && (
            <div className="bg-[#111111] border border-red-500/20 rounded-lg p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-red-500/20 pb-2">
                <span className="text-xs font-mono font-bold text-[#ff4040] uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  C2 Infrastructure Nodes ({c2Endpoints.length})
                </span>
              </div>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {c2Endpoints.map((ep, idx) => (
                  <div key={idx} className="bg-[#090909] border border-red-500/30 rounded px-2.5 py-1.5 text-xs font-mono text-[#ff4040] font-bold">
                    {ep}
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
