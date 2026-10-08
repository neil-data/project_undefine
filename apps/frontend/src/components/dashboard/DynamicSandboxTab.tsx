import * as React from "react";
import { Terminal, Activity, Cpu, AlertTriangle, RotateCw, ArrowLeft, Network, FileCode, ShieldAlert } from "lucide-react";
import { ThreatCase } from "./types";

interface DynamicSandboxTabProps {
  activeCase: ThreatCase;
  onNavigate?: (tab: string) => void;
  onReload?: () => void;
}

export function DynamicSandboxTab({ activeCase, onNavigate, onReload }: DynamicSandboxTabProps) {
  const [isReloading, setIsReloading] = React.useState(false);

  const handleReload = async () => {
    setIsReloading(true);
    try {
      if (onReload) {
        await onReload();
      }
    } catch (err: any) {
      console.error("Failed to reload analysis evidence:", err);
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
  const runtimeEventCount = netCount + fileCount + regCount + processTree.length +
    (Array.isArray(dyn?.dns_queries) ? dyn.dns_queries.length : 0) +
    (Array.isArray(dyn?.api_calls) ? dyn.api_calls.length : 0) +
    (Array.isArray(dyn?.commands) ? dyn.commands.length : 0) +
    (Array.isArray(dyn?.http_requests) ? dyn.http_requests.length : 0) +
    (Array.isArray(dyn?.services) ? dyn.services.length : 0) +
    (Array.isArray(dyn?.ipc_events) ? dyn.ipc_events.length : 0);

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
              ? (dyn?.message ?? "Dynamic analysis returned a result. Runtime events are listed only when present.")
              : "Runtime events appear only when returned by dynamic analysis; static findings retain separate provenance."}
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
              <span className="text-[10px] font-mono text-[#A0A0A0]">{behavior.mode}</span>
          </div>
          <p className="text-xs text-[#A0A0A0]">{behavior.message}</p>
          {behavior.fallback_reason && <p className="text-[11px] text-amber-300">Dynamic analysis unavailable: {behavior.fallback_reason}</p>}
          {behavior.findings.length === 0 ? (
            <p className="text-xs text-[#A0A0A0]">Insufficient evidence to infer specific behavior.</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {behavior.findings.map((finding, index) => (
                <article key={`${finding.behavior}-${finding.source}-${index}`} className="border border-[#292929] rounded-md p-3 space-y-2">
                  <div className="flex justify-between gap-2">
                    <span className="text-xs font-semibold text-white">{finding.behavior}</span>
                    <span className={`text-[10px] uppercase font-mono ${finding.runtime_verified ? "text-[#16ff4d]" : "text-amber-300"}`}>
                      {finding.runtime_verified ? "RUNTIME VERIFIED" : `${finding.confidence} · ${finding.source.replaceAll("_", " ")}`}
                    </span>
                  </div>
                  <p className="text-[10px] text-[#A0A0A0]">{finding.rationale || finding.reason}</p>
                  <ul className="list-disc pl-4 space-y-1 text-[10px] text-[#C8C8C8]">
                    {finding.evidence.map((item, evidenceIndex) => <li key={evidenceIndex} className="break-all">{item}</li>)}
                  </ul>
                  <div className="text-[9px] font-mono text-[#777]">Category: {finding.category.replaceAll("_", " ")} · Runtime verified: {finding.runtime_verified ? "Yes" : "No"}</div>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left: Captured runtime evidence */}
        <div className="lg:col-span-8 bg-[#111111] border border-[#222222] rounded-lg overflow-hidden flex flex-col shadow-lg">
          <div className="bg-[#171717] px-4 py-3 border-b border-[#222222] flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#A0A0A0] uppercase font-bold tracking-wider flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-[#16ff4d]" />
              RUNTIME EVIDENCE // {activeCase.id}
            </span>
            <div className="flex items-center gap-2 text-[10px] font-mono text-[#6F6F6F]">
              {runtimeEventCount > 0 ? "OBSERVED TELEMETRY" : "NO RUNTIME EVENTS"}
            </div>
          </div>

          <div className="p-5 font-mono text-[11px] min-h-[190px] overflow-y-auto space-y-2 bg-[#090909] text-[#A0A0A0] select-text">
            {dyn && (
              <div className="leading-relaxed pl-2 border-l-2 border-[#222222] text-[#A0A0A0] mb-4 bg-[#111111]/40 p-2 rounded-r">
                <span className="text-[#00c2ff] font-bold">DYNAMIC STATUS</span> {status}
                {dyn.message && <><br /><span className="text-[#00c2ff] font-bold">RESULT</span> {dyn.message}</>}
                {dyn.task_id && <><br /><span className="text-[#00c2ff] font-bold">TASK ID</span> {dyn.task_id}</>}
                {dyn.duration_seconds != null && <><br /><span className="text-[#00c2ff] font-bold">ANALYSIS DURATION</span> {dyn.duration_seconds}s</>}
              </div>
            )}
            {runtimeEventCount === 0 && (
              <p className="text-xs leading-relaxed">No runtime events were returned. Review the evidence-backed behavioral assessment above; it is not a record of execution.</p>
            )}
          </div>
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
              <p><span className="text-white font-bold">PROFILE:</span> <span className="text-white">{behavior?.mode ?? "Insufficient evidence"}</span></p>
              <p><span className="text-white font-bold">RUNTIME TELEMETRY:</span> <span className="text-white">{runtimeEventCount > 0 ? "Observed" : "None returned"}</span></p>
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
