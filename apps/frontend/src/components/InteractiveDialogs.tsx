import * as React from "react";
import { Button } from "./ui/button";
import { X, Calendar, Shield, Clock, Database, ChevronRight, Zap, CheckCircle, Info, Lock } from "lucide-react";

interface InteractiveDialogsProps {
  activeModal: "book-call" | "get-quote" | "our-work" | null;
  onClose: () => void;
}

export function InteractiveDialogs({ activeModal, onClose }: InteractiveDialogsProps) {
  // Modal 1: Launch Console (Book Call Form State)
  const [selectedService, setSelectedService] = React.useState("apk");
  const [selectedDay, setSelectedDay] = React.useState("Monday, July 20");
  const [selectedTime, setSelectedTime] = React.useState("10:00 AM");
  const [contactName, setContactName] = React.useState("");
  const [contactEmail, setContactEmail] = React.useState("");
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [isSubmitted, setIsSubmitted] = React.useState(false);

  // Modal 2: Explore Pipeline Estimator State
  const [ingestionVolume, setIngestionVolume] = React.useState<number>(15000); // files/day
  const [analysisNodes, setAnalysisNodes] = React.useState<number>(12);
  const [sandboxDepth, setSandboxDepth] = React.useState<number>(60); // seconds
  const [slaTier, setSlaTier] = React.useState<"standard" | "sentinel">("sentinel");

  // Reset states when modal changes
  React.useEffect(() => {
    if (activeModal) {
      setIsSubmitted(false);
      setIsSubmitting(false);
    }
  }, [activeModal]);

  if (!activeModal) return null;

  // Calculate infrastructure quote pricing in real time
  const baseCost = 1500;
  const volCost = Math.round(ingestionVolume * 0.12);
  const nodeCost = analysisNodes * 350;
  const depthCost = sandboxDepth * 15;
  const monthlySaaS = Math.round((analysisNodes * 45 + (ingestionVolume / 1000) * 12) * (slaTier === "sentinel" ? 1.5 : 1.0));
  const estimatedDeploymentTotal = baseCost + volCost + nodeCost + depthCost;

  const handleBookCallSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setTimeout(() => {
      setIsSubmitting(false);
      setIsSubmitted(true);
    }, 1800);
  };

  return (
    <div className="fixed inset-0 z-100 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in font-sora">
      
      {/* Outer Dialog Box */}
      <div className="relative w-full max-w-2xl bg-hero-bg border border-border/80 rounded-xl overflow-hidden shadow-[0_0_50px_rgba(0,191,255,0.15)] transition-all flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-border bg-background/50">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-primary animate-ping" />
            <span className="text-xs uppercase tracking-widest text-muted-foreground font-semibold">
              {activeModal === "book-call" && "Secure Console Broker"}
              {activeModal === "get-quote" && "Algorithmic Pipeline Estimator"}
              {activeModal === "our-work" && "Active Deployment Registry"}
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-secondary/50 text-muted-foreground hover:text-foreground hover:bg-secondary transition-all cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-6 overflow-y-auto flex-1">
          
          {/* ================= MODAL: LAUNCH CONSOLE / BOOK CALL ================= */}
          {activeModal === "book-call" && (
            <div>
              {!isSubmitted ? (
                <form onSubmit={handleBookCallSubmit} className="space-y-6">
                  <div>
                    <h3 className="text-xl font-bold text-foreground mb-1 uppercase tracking-tight">
                      Provision Sandbox Cluster
                    </h3>
                    <p className="text-sm text-muted-foreground font-light">
                      Register your investigation team for a dedicated, air-gapped threat simulation environment.
                    </p>
                  </div>

                  {/* Core Service selection */}
                  <div className="space-y-2">
                    <label className="text-xs font-semibold uppercase tracking-widest text-muted-foreground block">
                      Target Threat Environment
                    </label>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      {[
                        { id: "apk", name: "Android APK", desc: "Dynamic APK Behavioral trace" },
                        { id: "windows", name: "Windows PE", desc: "Dynamic sandbox execution" },
                        { id: "mitre", name: "MITRE ATT&CK", desc: "Automated mapping vectors" },
                      ].map((service) => (
                        <div
                          key={service.id}
                          onClick={() => setSelectedService(service.id)}
                          className={`p-3 rounded-lg border cursor-pointer select-none transition-all ${
                            selectedService === service.id
                              ? "bg-primary/5 border-primary text-foreground shadow-[0_0_15px_rgba(0,191,255,0.1)]"
                              : "bg-secondary/20 border-border hover:bg-secondary/40 text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          <p className="text-xs font-semibold uppercase tracking-wide">{service.name}</p>
                          <p className="text-[10px] opacity-70 mt-0.5">{service.desc}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Input details */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className="text-xs font-semibold uppercase tracking-widest text-muted-foreground block">
                        Investigating Officer
                      </label>
                      <input
                        type="text"
                        required
                        value={contactName}
                        onChange={(e) => setContactName(e.target.value)}
                        placeholder="e.g. Inspector Vance"
                        className="w-full bg-secondary/30 border border-border rounded-lg p-3 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary transition-all placeholder:text-muted-foreground/30"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs font-semibold uppercase tracking-widest text-muted-foreground block">
                        Official Agency Email
                      </label>
                      <input
                        type="email"
                        required
                        value={contactEmail}
                        onChange={(e) => setContactEmail(e.target.value)}
                        placeholder="e.g. vance@cybercell.gov"
                        className="w-full bg-secondary/30 border border-border rounded-lg p-3 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary transition-all placeholder:text-muted-foreground/30"
                      />
                    </div>
                  </div>

                  {/* Date & Time selection */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                    <div className="space-y-2">
                      <label className="text-xs font-semibold uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
                        <Calendar className="w-3.5 h-3.5 text-primary" /> Allocation Date
                      </label>
                      <select
                        value={selectedDay}
                        onChange={(e) => setSelectedDay(e.target.value)}
                        className="w-full bg-secondary/30 border border-border rounded-lg p-3 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary transition-all"
                      >
                        <option value="Monday, July 20" className="bg-hero-bg">Mon, July 20 (Available)</option>
                        <option value="Tuesday, July 21" className="bg-hero-bg">Tue, July 21 (Available)</option>
                        <option value="Wednesday, July 22" className="bg-hero-bg">Wed, July 22 (Available)</option>
                        <option value="Thursday, July 23" className="bg-hero-bg">Thu, July 23 (Available)</option>
                      </select>
                    </div>

                    <div className="space-y-2">
                      <label className="text-xs font-semibold uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-primary" /> Time Window
                      </label>
                      <select
                        value={selectedTime}
                        onChange={(e) => setSelectedTime(e.target.value)}
                        className="w-full bg-secondary/30 border border-border rounded-lg p-3 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary transition-all"
                      >
                        <option value="09:00 AM" className="bg-hero-bg">09:00 AM IST</option>
                        <option value="10:00 AM" className="bg-hero-bg">10:00 AM IST (Recommended)</option>
                        <option value="01:30 PM" className="bg-hero-bg">01:30 PM IST</option>
                        <option value="03:00 PM" className="bg-hero-bg">03:00 PM IST</option>
                      </select>
                    </div>
                  </div>

                  {/* Submission actions */}
                  <div className="pt-4 border-t border-border flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
                      <Shield className="w-3.5 h-3.5 text-primary" /> Air-gapped pipeline verified
                    </div>
                    <Button
                      variant="default"
                      size="lg"
                      disabled={isSubmitting}
                      className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold px-6 py-2 rounded-lg text-xs uppercase tracking-wider"
                    >
                      {isSubmitting ? "Allocating Sandbox..." : "Provision Secure Console Node"}
                    </Button>
                  </div>
                </form>
              ) : (
                <div className="py-8 text-center space-y-4 animate-fade-in">
                  <div className="w-16 h-16 bg-primary/10 border border-primary/30 rounded-full flex items-center justify-center mx-auto text-primary">
                    <CheckCircle className="w-8 h-8" />
                  </div>
                  <div className="space-y-2">
                    <h4 className="text-lg font-bold text-foreground uppercase tracking-wider">
                      Sandbox Cluster Allocated
                    </h4>
                    <p className="text-sm text-muted-foreground font-light max-w-md mx-auto">
                      Cryptographic handshake completed. Your dedicated threat analysis console is scheduled for:
                    </p>
                    <div className="bg-secondary/40 border border-border rounded-lg p-4 max-w-sm mx-auto font-mono text-xs space-y-1.5 text-left mt-3">
                      <p><span className="text-muted-foreground">AGENCY:</span> E-RAKSHAK Secure Node 8</p>
                      <p><span className="text-muted-foreground">OFFICER:</span> {contactName} ({contactEmail})</p>
                      <p><span className="text-muted-foreground">DATETIME:</span> {selectedDay} at {selectedTime}</p>
                      <p><span className="text-muted-foreground">TARGET PLATFORM:</span> {selectedService.toUpperCase()}</p>
                    </div>
                  </div>
                  <div className="pt-4">
                    <Button variant="secondary" onClick={onClose} className="rounded-lg text-xs uppercase tracking-widest">
                      Enter Console Gateway
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ================= MODAL: EXPLORE PIPELINE (GET QUOTE) ================= */}
          {activeModal === "get-quote" && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xl font-bold text-foreground mb-1 uppercase tracking-tight">
                  Pipeline Ingestion Estimator
                </h3>
                <p className="text-sm text-muted-foreground font-light">
                  Scale your daily ingest pipeline metrics to approximate required cloud processing footprints.
                </p>
              </div>

              {/* Slider 1: Daily Ingestion */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                  <span>Daily Ingestion Stream</span>
                  <span className="text-primary font-mono">{ingestionVolume.toLocaleString()} executables / day</span>
                </div>
                <input
                  type="range"
                  min="1000"
                  max="100000"
                  step="1000"
                  value={ingestionVolume}
                  onChange={(e) => setIngestionVolume(Number(e.target.value))}
                  className="w-full accent-primary bg-secondary/40 rounded-lg appearance-none h-1.5 cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-muted-foreground/60 font-mono">
                  <span>1,000 files/day (Regional Team)</span>
                  <span>100,000 files/day (Federal Grid)</span>
                </div>
              </div>

              {/* Slider 2: AI Agent Nodes */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                  <span>AI Agent Analysis Nodes</span>
                  <span className="text-primary font-mono">{analysisNodes} active agents</span>
                </div>
                <input
                  type="range"
                  min="2"
                  max="64"
                  step="2"
                  value={analysisNodes}
                  onChange={(e) => setAnalysisNodes(Number(e.target.value))}
                  className="w-full accent-primary bg-secondary/40 rounded-lg appearance-none h-1.5 cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-muted-foreground/60 font-mono">
                  <span>2 agents</span>
                  <span>64 agents</span>
                </div>
              </div>

              {/* Slider 3: Sandbox Depth */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                  <span>Sandbox Dynamics Duration</span>
                  <span className="text-primary font-mono">{sandboxDepth} seconds / file</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="180"
                  step="5"
                  value={sandboxDepth}
                  onChange={(e) => setSandboxDepth(Number(e.target.value))}
                  className="w-full accent-primary bg-secondary/40 rounded-lg appearance-none h-1.5 cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-muted-foreground/60 font-mono">
                  <span>10 seconds (Quick Check)</span>
                  <span>180 seconds (Deep Triage)</span>
                </div>
              </div>

              {/* SLA selection */}
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-widest text-muted-foreground block">
                  Processing Deployment Tier
                </label>
                <div className="grid grid-cols-2 gap-4">
                  <div
                    onClick={() => setSlaTier("standard")}
                    className={`p-3 rounded-lg border cursor-pointer select-none transition-all ${
                      slaTier === "standard"
                        ? "bg-primary/5 border-primary text-foreground"
                        : "bg-secondary/20 border-border text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    <p className="text-xs font-bold uppercase tracking-wide flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5" /> Standalone VM
                    </p>
                    <p className="text-[10px] opacity-70 mt-1">
                      Standard dynamic simulation, localized reporting queue, standard MITRE vectors.
                    </p>
                  </div>

                  <div
                    onClick={() => setSlaTier("sentinel")}
                    className={`p-3 rounded-lg border cursor-pointer select-none transition-all ${
                      slaTier === "sentinel"
                        ? "bg-primary/5 border-primary text-foreground shadow-[0_0_15px_rgba(0,191,255,0.1)]"
                        : "bg-secondary/20 border-border text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    <p className="text-xs font-bold uppercase tracking-wide flex items-center gap-1.5 text-primary">
                      <Zap className="w-3.5 h-3.5 text-primary" /> FedRAMP Air-gapped
                    </p>
                    <p className="text-[10px] opacity-70 mt-1">
                      24/7 dedicated isolated hypervisors, fully encrypted AI pipeline, immediate agency alert dispatch.
                    </p>
                  </div>
                </div>
              </div>

              {/* Estimates Result Panel */}
              <div className="bg-secondary/20 border border-border rounded-xl p-5 space-y-4">
                <div className="flex justify-between items-end border-b border-border/60 pb-3">
                  <div>
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest block">
                      One-Time Infrastructure Setup
                    </span>
                    <span className="text-sm font-semibold text-muted-foreground">Sandbox & Pipeline Provisioning</span>
                  </div>
                  <span className="text-2xl font-bold font-mono text-foreground">
                    ${estimatedDeploymentTotal.toLocaleString()}
                  </span>
                </div>

                <div className="flex justify-between items-end">
                  <div>
                    <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest block">
                      Monthly Compute Resources
                    </span>
                    <span className="text-sm font-semibold text-muted-foreground">Continuous AI Ingestion</span>
                  </div>
                  <span className="text-2xl font-bold font-mono text-primary">
                    ${monthlySaaS.toLocaleString()}<span className="text-xs font-sans text-muted-foreground font-normal">/mo</span>
                  </span>
                </div>

                <div className="text-[10px] text-muted-foreground/60 flex items-start gap-1.5 font-sans leading-relaxed pt-1">
                  <Info className="w-3.5 h-3.5 text-primary shrink-0" />
                  <span>These estimates represent computational resource costs allocated for secure government and enterprise clouds deploying air-gapped E-Rakshak appliances.</span>
                </div>
              </div>

              {/* Action */}
              <div className="flex justify-end gap-3 pt-2">
                <Button variant="secondary" onClick={onClose} className="rounded-lg text-xs uppercase tracking-widest">
                  Cancel
                </Button>
                <Button
                  variant="default"
                  onClick={() => {
                    setSelectedService("apk");
                    alert(`Pipeline saved: $${estimatedDeploymentTotal.toLocaleString()} deployment, $${monthlySaaS.toLocaleString()}/mo compute. Redirecting to custom configuration portal.`);
                    setIsSubmitted(false);
                  }}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-lg text-xs uppercase tracking-wider px-6"
                >
                  Save & Request Integration Spec
                </Button>
              </div>
            </div>
          )}

          {/* ================= MODAL: DEPLOYMENT REGISTRY (OUR WORK) ================= */}
          {activeModal === "our-work" && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xl font-bold text-foreground mb-1 uppercase tracking-tight">
                  Active Forensic Investigations
                </h3>
                <p className="text-sm text-muted-foreground font-light">
                  Live telemetry stats and active behavioral tracing engines across secure terminals.
                </p>
              </div>

              <div className="space-y-4">
                {[
                  {
                    id: "sys-01",
                    facility: "Android APK Behavioral Tracer",
                    type: "Dynamic APK Instrumentation",
                    nodes: "142 API calls monitored, 3 malware flags",
                    status: "TRACING DETECTED THREATS",
                    date: "July 2026",
                  },
                  {
                    id: "sys-02",
                    facility: "Windows PE Sandboxing Engine",
                    type: "Isolated Hypervisor Block",
                    nodes: "18 registry hooks monitored, zero trust active",
                    status: "SIMULATION IN PROGRESS",
                    date: "July 2026",
                  },
                  {
                    id: "sys-03",
                    facility: "MITRE ATT&CK Automated Matrix",
                    type: "AI Behavior-to-Vector Mapping",
                    nodes: "T1059 Command Execution, T1027 Obfuscation",
                    status: "MATRIX ALIGNED",
                    date: "July 2026",
                  },
                ].map((subsystem) => (
                  <div
                    key={subsystem.id}
                    className="group border border-border bg-secondary/10 hover:bg-secondary/20 rounded-xl p-4 transition-all duration-300 relative overflow-hidden"
                  >
                    {/* Glowing status bar */}
                    <div className="absolute top-0 bottom-0 left-0 w-1 bg-primary/80" />

                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                      <div className="space-y-1 pl-2">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-primary font-bold tracking-widest uppercase">
                            {subsystem.id}
                          </span>
                          <span className="text-[10px] text-muted-foreground">• {subsystem.date}</span>
                        </div>
                        <h4 className="text-base font-bold text-foreground">{subsystem.facility}</h4>
                        <p className="text-xs text-muted-foreground font-light">
                          <span className="text-foreground/70 font-semibold">{subsystem.type}</span> — {subsystem.nodes}
                        </p>
                      </div>

                      <div className="sm:text-right shrink-0">
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-primary/10 border border-primary/20 text-[10px] font-bold font-mono text-primary">
                          <Lock className="w-3 h-3 text-primary animate-pulse" /> {subsystem.status}
                        </span>
                        <div className="mt-2 text-xs text-muted-foreground/80 hover:text-foreground cursor-pointer flex items-center sm:justify-end gap-0.5 group">
                          View Analysis report
                          <ChevronRight className="w-3.5 h-3.5 transform group-hover:translate-x-0.5 transition-transform" />
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="bg-secondary/40 border border-border rounded-lg p-4 text-xs text-muted-foreground font-light flex items-start gap-2 leading-relaxed">
                <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                <span>Under federal cybersecurity frameworks and NDAs, file telemetry digests and decompiled source codes are heavily redacted in public logs. Authenticated investigators should log in via authorized CAC certificates.</span>
              </div>

              <div className="flex justify-end pt-2">
                <Button variant="default" onClick={onClose} className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold rounded-lg text-xs uppercase tracking-widest px-6">
                  Acknowledge & Close
                </Button>
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
}
