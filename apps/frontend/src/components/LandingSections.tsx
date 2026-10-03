import * as React from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { 
  Shield, 
  Activity, 
  Cpu, 
  Layers, 
  Terminal, 
  ArrowRight, 
  Lock, 
  UploadCloud, 
  Globe, 
  Search, 
  FileText, 
  CheckCircle, 
  Server, 
  Workflow, 
  Settings, 
  Github, 
  BookOpen, 
  Mail, 
  ExternalLink,
  ChevronRight,
  Database,
  Eye,
  AlertTriangle,
  Zap,
  Radio,
  FileCode,
  Compass,
  Cpu as AIChip
} from "lucide-react";

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

interface LandingSectionsProps {
  onLaunchConsoleClick: () => void;
  onExplorePipelineClick: () => void;
}

export function LandingSections({ onLaunchConsoleClick, onExplorePipelineClick }: LandingSectionsProps) {
  const rootRef = React.useRef<HTMLDivElement>(null);
  
  // Pipeline Active Step scroll state
  const [activePipelineStep, setActivePipelineStep] = React.useState(0);
  
  // Detonation Simulation State
  const [sandboxLog, setSandboxLog] = React.useState<string[]>([
    "[SYSTEM] Detonation environment initialized. Isolated Win10 VM active.",
    "[SYSTEM] Ready to receive payload..."
  ]);
  const [sandboxProgress, setSandboxProgress] = React.useState(0);
  const [isSandboxRunning, setIsSandboxRunning] = React.useState(false);
  const [malwareScore, setMalwareScore] = React.useState(0);

  // Run the sandbox simulation
  const startSandboxSim = () => {
    if (isSandboxRunning) return;
    setIsSandboxRunning(true);
    setSandboxProgress(0);
    setMalwareScore(0);
    setSandboxLog(["[SYSTEM] Detonation environment initialized. Isolated Win10 VM active."]);

    const logs = [
      { t: 800, msg: "[PROCESS] Executing suspicious sample. EXE process spawned (PID: 4892)", score: 25 },
      { t: 1500, msg: "[REGISTRY] Attempted write: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Spyware", score: 55 },
      { t: 2200, msg: "[FILE] Dropped executable: C:\\Users\\Admin\\AppData\\Local\\Temp\\dropper.dll", score: 70 },
      { t: 3000, msg: "[NETWORK] Outbound connection to malicious C2 IP: 185.220.101.5 on port 4444", score: 95 },
      { t: 3800, msg: "[MITRE] Mapping confirmed: T1071 (Application Layer Protocol) & T1547 (Boot Execution)", score: 98 },
      { t: 4500, msg: "[REPORT] Analysis complete. AI behavioral digest generated. High threat detected.", score: 98 }
    ];

    logs.forEach((item, index) => {
      setTimeout(() => {
        // Animate progress update
        gsap.to({ val: sandboxProgress }, {
          val: ((index + 1) / logs.length) * 100,
          duration: 0.4,
          onUpdate: function() {
            setSandboxProgress(Math.floor(this.targets()[0].val));
          }
        });

        // Count up threat score
        gsap.to({ val: index === 0 ? 0 : logs[index - 1].score }, {
          val: item.score,
          duration: 0.6,
          onUpdate: function() {
            setMalwareScore(Math.floor(this.targets()[0].val));
          }
        });

        setSandboxLog(prev => [...prev, item.msg]);
        if (index === logs.length - 1) {
          setIsSandboxRunning(false);
        }
      }, item.t);
    });
  };

  React.useEffect(() => {
    // Declared outside gsap.context() so the cleanup below can explicitly
    // revert it too — gsap.context() reverting its own tweens/ScrollTriggers
    // doesn't reliably guarantee a nested matchMedia instance's
    // conditionally-added (desktop-only) animations are also killed on
    // unmount/breakpoint change without this being explicit.
    let mm: gsap.MatchMedia | undefined;

    const ctx = gsap.context(() => {
      // 1. Overview Section: Reveal title and description with buttery transitions (Only once for scroll performance)
      gsap.fromTo(
        ".threat-title-anim",
        { opacity: 0, y: 30 },
        {
          opacity: 1,
          y: 0,
          duration: 1.0,
          ease: "power3.out",
          scrollTrigger: {
            trigger: ".threat-title-anim",
            start: "top 90%",
            once: true,
          }
        }
      );

      // Consolidated Threat Landscape Stats counting animation (ONE ScrollTrigger instead of 3, runs once)
      const statsObj = { 
        threat: 0, 
        decompilation: 60, 
        mitre: 0 
      };

      gsap.to(statsObj, {
        threat: 99.4,
        decompilation: 15,
        mitre: 240,
        duration: 1.8,
        ease: "power3.out",
        scrollTrigger: {
          trigger: ".threat-stat-container",
          start: "top 90%",
          once: true,
        },
        onUpdate: () => {
          const tEl = document.getElementById("stat-threat-index");
          const dEl = document.getElementById("stat-decompilation");
          const mEl = document.getElementById("stat-mitre-targets");
          if (tEl) tEl.textContent = statsObj.threat.toFixed(1) + "%";
          if (dEl) dEl.textContent = "< " + Math.floor(statsObj.decompilation) + "s";
          if (mEl) mEl.textContent = Math.floor(statsObj.mitre) + "+";
        }
      });

      // Stagger stats card entry (Runs once)
      gsap.fromTo(
        ".threat-stat-card",
        { opacity: 0, scale: 0.97, y: 15 },
        {
          opacity: 1,
          scale: 1,
          y: 0,
          duration: 0.7,
          stagger: 0.1,
          ease: "power2.out",
          scrollTrigger: {
            trigger: ".threat-stat-container",
            start: "top 90%",
            once: true,
          }
        }
      );

      // Use GSAP MatchMedia for clean responsive multi-device handling
      mm = gsap.matchMedia();

      // Desktop Pinning / Scroll scrubbing (Widths >= 1024px)
      mm.add("(min-width: 1024px)", () => {
        // 2. PINNED Pipeline Tracing Section
        gsap.timeline({
          scrollTrigger: {
            trigger: "#pipeline-scroll-trigger",
            start: "top top",
            end: "+=2200", // smooth scrolling duration
            scrub: 1.0,    // smooth scrubbing lag catchup
            pin: true,     // Pin the entire section on desktop only
            anticipatePin: 1,
            onUpdate: (self) => {
              // Throttle React state update to avoid redundant infinite renders
              const step = Math.min(5, Math.floor(self.progress * 5.99));
              setActivePipelineStep((prev) => (prev !== step ? step : prev));
            }
          }
        });

        // 5. PINNED Architecture Horizontal Data Flow Scroll-Trigger
        const archTimeline = gsap.timeline({
          force3D: true,
          scrollTrigger: {
            trigger: "#architecture-scroll-trigger",
            start: "top top",
            end: "+=1800", // desktop-only pin duration
            scrub: 1.0,    // ultra butter-smooth scrolling catchup
            pin: true,
            anticipatePin: 1,
            // Function-based tween values below are resolved once at
            // creation, not per scrub frame — invalidateOnRefresh makes
            // GSAP recompute them (correctly) on resize/refresh instead of
            // silently keeping a stale scroll distance from initial mount.
            invalidateOnRefresh: true,
          }
        });

        // Slide horizontal track to represent pipeline traversal
        archTimeline.to(".architecture-horizontal-track", {
          x: () => {
            const track = document.querySelector(".architecture-horizontal-track");
            const viewport = document.querySelector(".architecture-container-viewport");
            if (track && viewport) {
              return -(track.scrollWidth - viewport.clientWidth + 30);
            }
            return 0;
          },
          ease: "none"
        });

        // Sequentially highlight & scale cards slightly along with horizontal track progression
        const archNodes = gsap.utils.toArray(".arch-node-card");
        archNodes.forEach((node: any, idx: number) => {
          archTimeline.to(node, {
            scale: 1.03,
            duration: 0.45,
            ease: "power2.inOut"
          }, (idx / archNodes.length) * 1.5);
        });
      });

      // 3. Features staggered grid reveal (runs once)
      gsap.fromTo(
        ".feature-luxury-card",
        { opacity: 0, y: 35, scale: 0.98 },
        {
          opacity: 1,
          y: 0,
          scale: 1,
          duration: 0.8,
          stagger: 0.1,
          ease: "power3.out",
          scrollTrigger: {
            trigger: ".features-section-container",
            start: "top 80%",
            once: true,
          }
        }
      );

      // 4. Technology Cards Staggered Entry (runs once)
      gsap.fromTo(
        ".tech-stack-card",
        { opacity: 0, y: 25 },
        {
          opacity: 1,
          y: 0,
          duration: 0.8,
          stagger: 0.12,
          ease: "power3.out",
          scrollTrigger: {
            trigger: ".tech-section-container",
            start: "top 80%",
            once: true,
          }
        }
      );

      // Technology grid sub-items cascading scale (runs once)
      gsap.fromTo(
        ".tech-pill-anim",
        { scale: 0.92, opacity: 0 },
        {
          scale: 1,
          opacity: 1,
          duration: 0.5,
          stagger: 0.03,
          ease: "back.out(1.2)",
          scrollTrigger: {
            trigger: ".tech-section-container",
            start: "top 75%",
            once: true,
          }
        }
      );

      // Signal flow dash offset animation — gated to the architecture
      // section's visibility so it isn't running (and repainting) forever
      // from mount, including while scrolled far away from it.
      gsap.to(".node-signal-pulse", {
        strokeDashoffset: -40,
        duration: 1.5,
        repeat: -1,
        ease: "none",
        scrollTrigger: {
          trigger: "#architecture-scroll-trigger",
          start: "top bottom",
          end: "bottom top",
          toggleActions: "play pause resume pause",
        },
      });

      // 6. Editorial About Reveals (runs once)
      gsap.fromTo(
        ".about-reveal-line",
        { opacity: 0, y: 25 },
        {
          opacity: 1,
          y: 0,
          duration: 0.8,
          stagger: 0.15,
          ease: "power3.out",
          scrollTrigger: {
            trigger: ".about-section-container",
            start: "top 80%",
            once: true,
          }
        }
      );

      // Consolidated About counters (ONE ScrollTrigger, runs once)
      const aboutStatsObj = {
        tactics: 0,
        techniques: 0,
        precision: 0
      };

      gsap.to(aboutStatsObj, {
        tactics: 14,
        techniques: 180,
        precision: 99.2,
        duration: 2.2,
        ease: "power3.out",
        scrollTrigger: {
          trigger: ".about-section-container",
          start: "top 80%",
          once: true,
        },
        onUpdate: () => {
          const tacEl = document.getElementById("about-stat-tactics");
          const tecEl = document.getElementById("about-stat-techniques");
          const preEl = document.getElementById("about-stat-precision");
          if (tacEl) tacEl.textContent = Math.floor(aboutStatsObj.tactics) + "+";
          if (tecEl) tecEl.textContent = Math.floor(aboutStatsObj.techniques) + "+";
          if (preEl) preEl.textContent = aboutStatsObj.precision.toFixed(1) + "%";
        }
      });

      // 7. Floating particles for CTA background — gated to the CTA
      // section's visibility, same reasoning as the signal-pulse animation
      // above: an unbounded repeat: -1 tween with no ScrollTrigger keeps
      // running (and repainting 15 particles) for the entire session even
      // when the section is nowhere near the viewport.
      gsap.to(".cta-particle", {
        y: () => -(Math.random() * 100 + 50),
        x: () => (Math.random() * 30 - 15),
        opacity: () => Math.random() * 0.5 + 0.2,
        duration: () => Math.random() * 3 + 3,
        repeat: -1,
        ease: "power1.inOut",
        stagger: {
          each: 0.1,
          from: "random"
        },
        scrollTrigger: {
          trigger: "#cta-particles-section",
          start: "top bottom",
          end: "bottom top",
          toggleActions: "play pause resume pause",
        },
      });

      // Large typography reveal in CTA (runs once)
      gsap.fromTo(
        ".cta-title-anim",
        { opacity: 0, scale: 0.98, y: 20 },
        {
          opacity: 1,
          scale: 1,
          y: 0,
          duration: 1.0,
          ease: "power4.out",
          scrollTrigger: {
            trigger: ".cta-title-anim",
            start: "top 85%",
            once: true,
          }
        }
      );

      // 8. Footer Link & Icon Staggered Reveals (runs once)
      gsap.fromTo(
        ".footer-anim-stagger",
        { opacity: 0, y: 15 },
        {
          opacity: 1,
          y: 0,
          duration: 0.7,
          stagger: 0.08,
          ease: "power2.out",
          scrollTrigger: {
            trigger: "footer",
            start: "top 95%",
            once: true,
          }
        }
      );

    }, rootRef);

    return () => {
      ctx.revert();
      mm?.revert();
    };
  }, []);

  const pipelineSteps = [
    {
      title: "1. Upload Sample & Hash Ledger",
      desc: "Submit any Android APK or Windows executable. The pipeline triggers cryptographic hashing (SHA-256/MD5) to ledger check historic threat signatures.",
      detail: "Supports custom MIME types, multi-dex Android architectures, and native x86/x64 PE formats with total data air-gapping.",
      tech: "FASTAPI • SHA256 LEDGER"
    },
    {
      title: "2. Static Decompilation & YARA Check",
      desc: "Decompile DEX source code, manifest layouts, and Win32 import address tables. Match structural logic strings against localized YARA rulesets.",
      detail: "Automated entropy checks analyze section headers to highlight packers, crypters, and hidden binary payloads immediately.",
      tech: "YARA • DEX2JAR • PEFILE"
    },
    {
      title: "3. Dynamic Sandbox Detonation",
      desc: "Deport suspect binaries into highly monitored, ephemeral virtualization bubbles. Detonate Windows PE in isolated KVMs, and APKs in secure emulator runtimes.",
      detail: "Deep system-call hooking intercepting processes, dynamic registry mutations, network requests, and virtual driver interactions.",
      tech: "KVM • EPHEMERAL VM • EMULATOR"
    },
    {
      title: "4. AI Behavioral Intelligence Tracking",
      desc: "Cross-correlate raw, low-level event logs. Analyze process fork trees, process injection attempts (DLL hollowing), and shadow network queries.",
      detail: "E-Rakshak's behavioral model synthesizes scattered system calls into an easily understood chronological event timeline.",
      tech: "PYTHON ENGINE • NLP CLUSTERING"
    },
    {
      title: "5. MITRE ATT&CK Matrix Mapping",
      desc: "Align discovered behavior directly with the globally recognized MITRE ATT&CK enterprise and mobile adversarial frames.",
      detail: "Enables cyber investigators to immediately locate the exact exploitation categories, including privilege escalation, evasion, and C2 channels.",
      tech: "MITRE API • AUTO-VECTOR ALIGNMENT"
    },
    {
      title: "6. Court-Ready AI Forensic Dossier",
      desc: "AI engines parse the final behavioral traces, translating dense hexadecimal and syscall records into clear natural language reports.",
      detail: "Synthesizes indicators, malicious score charts, MITRE mappings, and remediation recommendations for judicial compliance.",
      tech: "GEMINI 2.5 PRO • FORENSICS CONVERTER"
    }
  ];

  const architectureNodes = [
    { name: "BROWSER CLIENT", desc: "Interactive Investigator Web UI Dashboard", icon: Globe },
    { name: "FRONTEND PORTAL", desc: "React-Vite air-gapped web client", icon: Layers },
    { name: "API GATEWAY", desc: "FastAPI cryptographically signed secure routes", icon: Server },
    { name: "ANALYSIS ENGINE", desc: "Static decompilers & PE signature dissecting", icon: Activity },
    { name: "SANDBOX VM", desc: "Isolated virtualization detonation environment", icon: Terminal },
    { name: "AI COGNITIVE AGENT", desc: "Deep behavioral intent semantic analysis", icon: AIChip },
    { name: "MITRE TECHNIQUES", desc: "Attack posture vector matrices alignment", icon: Shield },
    { name: "THREAT LEDGER DB", desc: "Forensic SHA-256 historical ledger index", icon: Database },
    { name: "FORENSIC REPORT", desc: "Court-ready natural language dossiers", icon: FileText }
  ];

  return (
    <div ref={rootRef} className="bg-background text-foreground overflow-x-hidden font-sora">
      
      {/* ================= SECTION 2: THE THREAT LANDSCAPE ================= */}
      <section className="relative min-h-screen py-24 px-6 sm:px-12 lg:px-16 flex flex-col justify-center border-b border-border/40 bg-secondary/20">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_60%_at_bottom_right,rgba(34,197,94,0.03),transparent)]" />
        <div className="max-w-6xl mx-auto w-full relative z-10 grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          <div>
            <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block mb-4">
              [ 01 // OVERVIEW ]
            </span>
            <h2 className="text-[clamp(2rem,5vw,3.75rem)] font-bold tracking-tight leading-none mb-6 text-white threat-title-anim">
              MALWARE IS <br />
              EVOLVING IN SILENCE.
            </h2>
            <p className="text-muted-foreground font-light leading-relaxed max-w-lg mb-8 text-sm md:text-base threat-title-anim">
              Traditional signature detection fails against modern polymorphic binaries and obfuscated APK payloads. Investigators deserve unified behavioral reasoning that exposes malicious intent instantly.
            </p>
            <div className="flex gap-4 threat-title-anim">
              <button 
                onClick={onLaunchConsoleClick}
                className="bg-primary text-primary-foreground text-xs uppercase tracking-widest px-6 py-3.5 rounded-sm hover:shadow-[0_0_20px_rgba(34,197,94,0.3)] transition-all font-bold cursor-pointer"
              >
                Launch Live Analysis
              </button>
            </div>
          </div>

          <div className="threat-stat-container grid grid-cols-2 gap-4">
            <div className="threat-stat-card bg-muted p-6 rounded-lg border border-border/80 will-change-transform will-change-opacity">
              <span className="text-[10px] text-muted-foreground uppercase font-mono block mb-1">
                MALWARE THREAT INDEX
              </span>
              <span id="stat-threat-index" className="text-3xl sm:text-4xl font-mono font-bold text-red-500 block">
                0%
              </span>
              <p className="text-[10px] text-muted-foreground mt-2 font-light">
                Average detection velocity for obfuscated 2026 polymorphic threats.
              </p>
            </div>

            <div className="threat-stat-card bg-muted p-6 rounded-lg border border-border/80 will-change-transform will-change-opacity">
              <span className="text-[10px] text-muted-foreground uppercase font-mono block mb-1">
                ANALYSIS DECOMPILATION
              </span>
              <span id="stat-decompilation" className="text-3xl sm:text-4xl font-mono font-bold text-primary block">
                &lt; 60s
              </span>
              <p className="text-[10px] text-muted-foreground mt-2 font-light">
                Static parsing and VM detonation sandbox sequence completion.
              </p>
            </div>

            <div className="threat-stat-card bg-muted p-6 rounded-lg border border-border/80 will-change-transform will-change-opacity">
              <span className="text-[10px] text-muted-foreground uppercase font-mono block mb-1">
                MITRE MAPPING TARGETS
              </span>
              <span id="stat-mitre-targets" className="text-3xl sm:text-4xl font-mono font-bold text-white block">
                0+
              </span>
              <p className="text-[10px] text-muted-foreground mt-2 font-light">
                Pre-defined active adversarial techniques automatically linked.
              </p>
            </div>

            <div className="threat-stat-card bg-muted p-6 rounded-lg border border-border/80 will-change-transform will-change-opacity">
              <span className="text-[10px] text-muted-foreground uppercase font-mono block mb-1">
                INVESTIGATION REFORMS
              </span>
              <span className="text-3xl sm:text-4xl font-mono font-bold text-primary block">
                SEC-OPS
              </span>
              <p className="text-[10px] text-muted-foreground mt-2 font-light">
                Built specifically for federal cyber cells & secure private-cloud sandbox deployments.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ================= SECTION 3: PIPELINE HEADER ================= */}
      <section id="pipeline" className="min-h-[60vh] flex items-center justify-center bg-background px-6 border-b border-border/40 relative">
        <div className="absolute inset-0 bg-[linear-gradient(to_bottom,transparent,rgba(34,197,94,0.01)_50%,transparent)] pointer-events-none" />
        <div className="text-center max-w-4xl">
          <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block mb-4">
            [ 02 // PIPELINE PROCESS ]
          </span>
          <h2 className="text-[clamp(2.5rem,6.5vw,5rem)] font-bold tracking-tighter leading-none text-white uppercase mb-4">
            One Upload.<br />
            Complete Investigation.
          </h2>
          <p className="text-muted-foreground text-sm max-w-md mx-auto font-light leading-relaxed">
            Witness the unified cyberintelligence automation. From submission to final evidence-ready court reports in seconds.
          </p>
          <div className="mt-8 flex justify-center">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-primary/10 border border-primary/20 text-primary text-xs font-mono rounded-full uppercase tracking-wider animate-pulse">
              Scroll down to detonate pipeline
            </span>
          </div>
        </div>
      </section>

      {/* ================= SECTION 4: INTERACTIVE PIPELINE TRACING ================= */}
      <section id="pipeline-scroll-trigger" className="relative bg-background border-b border-border/40 py-24 px-6 sm:px-12 lg:px-16 min-h-screen flex items-center">
        <div className="max-w-6xl mx-auto w-full">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            
            {/* Sticky Indicator Left Panel */}
            <div className="lg:col-span-5 space-y-6">
              <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block">
                [ LIVE COMPILATION CHAIN ]
              </span>
              <h3 className="text-3xl font-bold tracking-tight text-white uppercase leading-none">
                The Sandbox Execution Chain
              </h3>
              <p className="text-muted-foreground text-xs font-light leading-relaxed">
                As the threat telemetry digests, E-Rakshak cascades through automated sandboxing, decompiling vectors, cataloging indicators of compromise (IoC), and compiling report briefs.
              </p>

              {/* Progress Stepper indicators with glowing vertical progress bar */}
              <div className="flex gap-5 pt-4">
                <div className="relative w-[3px] flex flex-col items-center">
                  <div className="absolute top-0 bottom-0 w-[3px] bg-border/40 rounded-full" />
                  <div 
                    className="absolute top-0 w-[3px] bg-primary rounded-full transition-all duration-300 shadow-[0_0_15px_rgba(34,197,94,0.6)]" 
                    style={{ height: `${(activePipelineStep / 5) * 100}%` }}
                  />
                </div>
                
                <div className="space-y-4 font-mono text-[11px] flex-1">
                  {[
                    "Ingestion & Pre-Check",
                    "Static Disassembly & YARA",
                    "Isolated Detonation Loop",
                    "Behavior Tracking Array",
                    "MITRE Vector Auto-Mapping",
                    "AI Investigation Dossier"
                  ].map((stepName, idx) => (
                    <div 
                      key={idx} 
                      className={`flex items-center gap-3 transition-all duration-300 ${
                        activePipelineStep === idx ? "text-primary translate-x-2 font-bold" : "text-muted-foreground/40"
                      }`}
                    >
                      <span className="font-bold">0{idx + 1}.</span>
                      <span className="uppercase tracking-widest">{stepName}</span>
                      {activePipelineStep === idx && <div className="w-1.5 h-1.5 rounded-full bg-primary animate-ping" />}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Scrolling Steps Content Right Panel (Cinematic absolute layered stack on desktop, clean vertical layout on mobile) */}
            <div className="lg:col-span-7 relative h-auto lg:h-[420px] w-full flex flex-col lg:block gap-6">
              {pipelineSteps.map((step, idx) => (
                <div 
                  key={idx}
                  className={`pipeline-step-card lg:absolute inset-x-0 p-6 sm:p-8 rounded-lg border flex flex-col justify-between transition-all duration-500 bg-muted/60 border-border/80 will-change-transform will-change-opacity lg:pointer-events-none lg:opacity-0 lg:scale-95 lg:translate-y-8
                    ${activePipelineStep === idx ? "lg:bg-muted lg:border-primary lg:shadow-[0_0_35px_rgba(34,197,94,0.12)] lg:z-10 lg:opacity-100 lg:scale-100 lg:translate-y-0 lg:pointer-events-auto" : ""}
                    ${activePipelineStep > idx ? "lg:bg-muted/10 lg:border-border/10 lg:z-0 lg:opacity-0 lg:scale-95 lg:-translate-y-8 lg:pointer-events-none" : ""}
                  `}
                >
                  <div className="flex justify-between items-start mb-4">
                    <span className="text-[10px] font-mono text-primary bg-primary/10 border border-primary/20 px-2.5 py-0.5 rounded uppercase font-semibold">
                      {step.tech}
                    </span>
                    <span className="text-xs font-mono text-muted-foreground/40">
                      PHASE 0{idx + 1}
                    </span>
                  </div>
                  <h4 className="text-lg font-bold text-white uppercase tracking-tight mb-2">
                    {step.title}
                  </h4>
                  <p className="text-muted-foreground text-xs leading-relaxed mb-4">
                    {step.desc}
                  </p>
                  <p className="text-muted-foreground/60 text-[11px] leading-relaxed border-t border-border/40 pt-3">
                    {step.detail}
                  </p>
                </div>
              ))}
            </div>

          </div>
        </div>
      </section>

      {/* ================= SECTION 5: FEATURES DEEP DIVE ================= */}
      <section id="features" className="features-section-container py-24 px-6 sm:px-12 lg:px-16 border-b border-border/40 bg-secondary/10">
        <div className="max-w-6xl mx-auto w-full">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block mb-4">
              [ 03 // WEAPONIZED ANALYSIS ]
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white uppercase">
              Engineered for absolute accuracy.
            </h2>
            <p className="text-muted-foreground text-xs font-light leading-relaxed mt-2">
              Explore six key analytical pillars engineered to provide uncompromised telemetry for law enforcement, defense systems, and security operations.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              {
                icon: Shield,
                title: "Android APK Analysis",
                desc: "Full disassembling of DEX, AndroidManifest audits, dynamic API hook tracers, and hidden package triggers."
              },
              {
                icon: Cpu,
                title: "Windows PE Analysis",
                desc: "Deep analysis of Portable Executables, resolving import/export tables, unpacking, and entropy analysis."
              },
              {
                icon: Terminal,
                title: "Dynamic Sandbox",
                desc: "Ephemerally deployed KVM virtualization bubbles recording live system modifications with complete isolation."
              },
              {
                icon: Workflow,
                title: "Behavioral Intelligence",
                desc: "AI systems clustering system calls to construct sequential, human-readable forensic threat timelines."
              },
              {
                icon: Layers,
                title: "MITRE Mapping",
                desc: "Auto-correlates anomalous behavior logs to official ATT&CK techniques, providing systematic threat posture context."
              },
              {
                icon: FileText,
                title: "AI Forensic Reports",
                desc: "Generate legal-ready forensic dossiers that translate complex binaries into natural language evidence briefs."
              }
            ].map((feat, idx) => (
              <div 
                key={idx}
                className="feature-luxury-card bg-muted/60 hover:bg-muted p-8 rounded-lg border border-border/80 hover:border-primary/50 transition-colors duration-300 group hover:-translate-y-2 hover:shadow-[0_12px_30px_rgba(34,197,94,0.1)] relative overflow-hidden will-change-transform will-change-opacity"
              >
                <div className="w-10 h-10 rounded bg-secondary flex items-center justify-center border border-border group-hover:border-primary/20 group-hover:bg-primary/5 transition-all mb-6">
                  <feat.icon className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors" />
                </div>
                <h3 className="text-base font-bold text-white uppercase mb-3 tracking-wide">
                  {feat.title}
                </h3>
                <p className="text-muted-foreground text-xs font-light leading-relaxed">
                  {feat.desc}
                </p>
                <div className="mt-6 flex items-center gap-1 text-[10px] uppercase font-mono tracking-widest text-muted-foreground/60 group-hover:text-primary transition-colors cursor-pointer">
                  <span>Explore Subsystem</span>
                  <ChevronRight className="w-3 h-3 transform group-hover:translate-x-1 transition-transform" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ================= SECTION 6: THE DETONATION SANDBOX SIMULATION ================= */}
      <section className="py-24 px-6 sm:px-12 lg:px-16 border-b border-border/40 bg-background relative">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_50%_50%_at_top_left,rgba(34,197,94,0.02),transparent)]" />
        <div className="max-w-6xl mx-auto w-full relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          
          <div className="lg:col-span-5 space-y-6">
            <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block">
              [ 04 // LIVE SANDBOX DETONATOR ]
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white uppercase leading-none">
              Interactive sandbox<br />
              simulation.
            </h2>
            <p className="text-muted-foreground text-xs font-light leading-relaxed">
              Test drive the dynamic behavioral engine. Detonate our simulator payload and watch how E-Rakshak charts logs, tracks threat severity scores, and intercepts file interactions in real time.
            </p>
            <div className="pt-2">
              <button
                onClick={startSandboxSim}
                disabled={isSandboxRunning}
                className="bg-primary hover:bg-primary/90 text-primary-foreground text-xs uppercase tracking-widest font-bold px-6 py-3.5 rounded shadow-[0_0_20px_rgba(34,197,94,0.25)] hover:shadow-[0_0_30px_rgba(34,197,94,0.4)] disabled:opacity-40 transition-all cursor-pointer"
              >
                {isSandboxRunning ? "Detonating Payload..." : "Detonate Mock Payload"}
              </button>
            </div>
          </div>

          <div className="lg:col-span-7">
            <div className="bg-muted rounded-lg border border-border overflow-hidden">
              {/* Terminal Header */}
              <div className="bg-secondary px-4 py-3 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-primary/80" />
                  <span className="text-[10px] font-mono text-muted-foreground ml-2">sandbox-hypervisor-node_08</span>
                </div>
                <span className="text-[9px] font-mono text-primary/70 bg-primary/5 border border-primary/20 px-2 py-0.5 rounded">
                  {isSandboxRunning ? "SIMULATING ACTIVE" : "IDLE / STANDBY"}
                </span>
              </div>

              {/* Terminal Screen */}
              <div className="p-5 font-mono text-xs h-[240px] overflow-y-auto space-y-2 bg-[#050505] text-muted-foreground">
                {sandboxLog.map((log, index) => (
                  <div key={index} className="leading-relaxed border-l-2 border-primary/20 pl-2 animate-fade-in">
                    {log}
                  </div>
                ))}
              </div>

              {/* Detonation Stats and Score Panel */}
              <div className="bg-secondary/60 border-t border-border p-4 grid grid-cols-3 gap-4 text-center">
                <div>
                  <span className="text-[9px] text-muted-foreground uppercase block mb-1">
                    Threat Progress
                  </span>
                  <div className="w-full bg-border rounded-full h-1.5 mt-2">
                    <div 
                      className="bg-primary h-1.5 rounded-full transition-all duration-300"
                      style={{ width: `${sandboxProgress}%` }}
                    />
                  </div>
                </div>

                <div>
                  <span className="text-[9px] text-muted-foreground uppercase block">
                    Telemetry Score
                  </span>
                  <span className={`text-sm font-bold block mt-1 ${malwareScore > 70 ? "text-red-500" : malwareScore > 30 ? "text-yellow-500" : "text-primary"}`}>
                    {malwareScore} / 100
                  </span>
                </div>

                <div>
                  <span className="text-[9px] text-muted-foreground uppercase block">
                    File Status
                  </span>
                  <span className={`text-[10px] font-bold block mt-1 uppercase ${isSandboxRunning ? "text-yellow-500 animate-pulse" : malwareScore > 75 ? "text-red-500" : "text-primary"}`}>
                    {isSandboxRunning ? "Analyzing..." : malwareScore > 75 ? "MALICIOUS PE" : "WAITING PAYLOAD"}
                  </span>
                </div>
              </div>

            </div>
          </div>

        </div>
      </section>

      {/* ================= SECTION 7: MITRE ATT&CK REAL-TIME MATRIX ================= */}
      <section className="py-24 px-6 sm:px-12 lg:px-16 border-b border-border/40 bg-secondary/10">
        <div className="max-w-6xl mx-auto w-full">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            
            <div className="lg:col-span-7">
              <div className="bg-muted rounded-lg border border-border p-6 grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                  {
                    header: "Execution [TA0002]",
                    techniques: [
                      { id: "T1059", name: "Command Scripting", act: true },
                      { id: "T1204", name: "User Execution", act: false },
                      { id: "T1106", name: "Native API Call", act: true }
                    ]
                  },
                  {
                    header: "Defense Evasion [TA0005]",
                    techniques: [
                      { id: "T1140", name: "Deobfuscate File", act: true },
                      { id: "T1027", name: "Obfuscated Files", act: true },
                      { id: "T1036", name: "Masquerading", act: false }
                    ]
                  },
                  {
                    header: "Command & Control [TA0011]",
                    techniques: [
                      { id: "T1071", name: "App Layer Protocol", act: true },
                      { id: "T1573", name: "Encrypted Channel", act: true },
                      { id: "T1105", name: "Ingress Transfer", act: false }
                    ]
                  }
                ].map((col, idx) => (
                  <div key={idx} className="space-y-3 bg-background/50 p-4 rounded border border-border/40">
                    <span className="text-[10px] font-mono font-bold text-primary block border-b border-border/40 pb-1.5 uppercase">
                      {col.header}
                    </span>
                    <div className="space-y-2">
                      {col.techniques.map((tech) => (
                        <div 
                          key={tech.id} 
                          className={`p-2.5 rounded border text-[10px] transition-all ${
                            tech.act 
                              ? "bg-primary/5 border-primary/50 text-white shadow-[0_0_10px_rgba(34,197,94,0.05)]" 
                              : "bg-secondary/40 border-border/40 text-muted-foreground/40"
                          }`}
                        >
                          <span className="font-mono font-bold block">{tech.id}</span>
                          <span className="block font-sans truncate">{tech.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="lg:col-span-5 space-y-6">
              <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block">
                [ 05 // MITRE ATT&CK ALIGNMENT ]
              </span>
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white uppercase leading-none">
                Automated MITRE ATT&CK mapping.
              </h2>
              <p className="text-muted-foreground text-xs font-light leading-relaxed">
                Analyze and map malware behaviors directly to the global MITRE ATT&CK database. Instantly verify tactics, identify evasion modules, and understand C2 protocols used by attackers.
              </p>
              <div className="border-t border-border pt-4 flex gap-4 text-xs font-mono text-muted-foreground">
                <div>
                  <span className="text-white block font-bold">14+</span>
                  Tactics Linked
                </div>
                <div>
                  <span className="text-white block font-bold">180+</span>
                  Techniques Covered
                </div>
                <div>
                  <span className="text-white block font-bold">99.2%</span>
                  Precision Score
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* ================= SECTION 8: TECHNOLOGY STACK ================= */}
      <section id="technology" className="tech-section-container py-24 px-6 sm:px-12 lg:px-16 border-b border-border/40 bg-background">
        <div className="max-w-6xl mx-auto w-full">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block mb-4">
              [ 06 // SYSTEM STACK ]
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white uppercase">
              The Forensic Stack
            </h2>
            <p className="text-muted-foreground text-xs font-light mt-2">
              Our engineering foundation combines state-of-the-art AI systems with scalable, battle-tested cybercrime investigation tools.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {[
              {
                category: "Frontend Layer",
                items: ["React 18", "Next.js", "Tailwind CSS", "GSAP ScrollTrigger"]
              },
              {
                category: "Backend Engine",
                items: ["FastAPI", "Python 3.11", "SQLAlchemy", "JWT & Redis Cache"]
              },
              {
                category: "AI & Reasoning",
                items: ["LangGraph", "Gemini 2.5 Pro", "Behavior Clustering", "Threat Mapping"]
              },
              {
                category: "Investigation Security",
                items: ["YARA Rule Matcher", "MITRE ATT&CK Framework", "KVM Hypervisor", "DEX/PE static disassembler"]
              }
            ].map((stack, idx) => (
              <div key={idx} className="tech-stack-card bg-muted p-6 rounded-lg border border-border/80 flex flex-col justify-between">
                <div>
                  <span className="text-[10px] uppercase font-mono tracking-widest text-primary font-bold block mb-4">
                    // 0{idx + 1} {stack.category}
                  </span>
                  <div className="space-y-3">
                    {stack.items.map((item, keyIdx) => (
                      <div 
                        key={keyIdx} 
                        className="tech-pill-anim flex items-center justify-between p-3 bg-secondary/50 rounded border border-border/40 hover:border-primary/20 transition-colors"
                      >
                        <span className="text-xs font-bold text-white tracking-wide">{item}</span>
                        <CheckCircle className="w-3.5 h-3.5 text-primary" />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ================= SECTION 9: THE ANIME ARCHITECTURE DIAGRAM ================= */}
      <section id="architecture" className="py-24 px-6 sm:px-12 lg:px-16 border-b border-border/40 bg-secondary/20">
        <div className="max-w-6xl mx-auto w-full">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block mb-4">
              [ 07 // AIR-GAPPED FLOW ]
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white uppercase">
              Zero-Trust Architecture Flow
            </h2>
            <p className="text-muted-foreground text-xs font-light mt-2">
              E-Rakshak's secure pipeline runs strictly on isolated, high-throughput pipelines. See how user inputs flow into court-ready reports.
            </p>
          </div>

          {/* SVG Connection architecture diagram - Horizontal Scroll & Pinned Track */}
          <div id="architecture-scroll-trigger" className="relative w-full">
            <div className="architecture-container-viewport w-full overflow-x-auto lg:overflow-hidden relative p-6 sm:p-10 bg-muted rounded-xl border border-border scrollbar-none">
              <div className="architecture-horizontal-track flex items-center gap-8 py-10 relative">
                
                {/* Flowing animated signal dash line */}
                <svg className="absolute top-1/2 left-10 right-10 -translate-y-1/2 h-1 w-[95%] pointer-events-none z-0" xmlns="http://www.w3.org/2000/svg">
                  <line 
                    x1="0%" y1="50%" x2="100%" y2="50%" 
                    stroke="rgba(255,255,255,0.05)" 
                    strokeWidth="3" 
                  />
                  <line 
                    x1="0%" y1="50%" x2="100%" y2="50%" 
                    stroke="hsl(var(--primary))" 
                    strokeWidth="3" 
                    strokeDasharray="8, 12"
                    className="node-signal-pulse" 
                  />
                </svg>

                {architectureNodes.map((node, index) => {
                  const NodeIcon = node.icon;
                  return (
                    <div 
                      key={index} 
                      className="arch-node-card relative z-10 w-64 flex-shrink-0 bg-background border border-border/80 hover:border-primary/50 transition-colors p-5 rounded-lg text-center shadow-lg group"
                    >
                      <div className="w-12 h-12 rounded bg-secondary border border-border flex items-center justify-center mx-auto mb-3 group-hover:bg-primary/5 group-hover:border-primary/20 transition-colors">
                        <NodeIcon className="w-6 h-6 text-muted-foreground group-hover:text-primary transition-colors animate-pulse" />
                      </div>
                      <span className="text-[9px] font-mono font-bold text-primary tracking-widest block mb-1">
                        STAGE 0{index + 1}
                      </span>
                      <h4 className="text-[11px] font-mono uppercase font-bold text-white tracking-wider mb-1.5">
                        {node.name}
                      </h4>
                      <p className="text-[10px] text-muted-foreground leading-relaxed whitespace-normal font-light">
                        {node.desc}
                      </p>
                    </div>
                  );
                })}

              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ================= SECTION 10: ABOUT / SECURITY STANDARDS CONTEXT ================= */}
      <section id="about" className="about-section-container py-24 px-6 sm:px-12 lg:px-16 border-b border-border/40 bg-background">
        <div className="max-w-6xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
          
          <div className="lg:col-span-4 lg:sticky lg:top-32">
            <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block mb-4">
              [ 08 // THE MISSION ]
            </span>
            <h2 className="text-[clamp(1.75rem,4vw,3rem)] font-bold tracking-tight text-white leading-none uppercase">
              Helping cyber cells protect<br />
              the nation.
            </h2>
            <div className="h-0.5 w-16 bg-primary mt-6" />
          </div>

          <div className="lg:col-span-8 space-y-12">
            <div className="about-reveal-line space-y-4">
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground block">
                01 / THE PROBLEM STATEMENT
              </span>
              <p className="text-base sm:text-lg text-foreground font-light leading-relaxed">
                Smartphones and digital grids are under persistent attack. Traditional anti-virus scanners are blind to zero-day APK configurations, custom dynamic packers, and native Windows malware loops. Investigating officers need instant behavioral context to build evidence-ready, watertight criminal files.
              </p>
            </div>

            <div className="about-reveal-line space-y-4">
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground block">
                02 / THE SOLUTIONS ARCHITECTURE
              </span>
              <p className="text-sm text-muted-foreground font-light leading-relaxed">
                E-Rakshak unifies high-performance static parsing, sandboxed detonation loops, and AI-driven reasoning under one air-gapped web interface. Our automated MITRE ATT&CK mapping takes the guesswork out of analysis, giving cybersecurity units state-of-the-art toolsets.
              </p>
            </div>

            <div className="about-reveal-line space-y-4">
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground block">
                03 / THE REGULATORY STANDARDS
              </span>
              <p className="text-sm text-muted-foreground font-light leading-relaxed">
                Engineered under strict governmental and defense intelligence mandates, E-Rakshak is built to address active security threats faced by modern cybercells, national defense agencies, and enterprise network supervisors.
              </p>
            </div>

            {/* Enterprise Metrics Grid */}
            <div className="about-reveal-line pt-6 border-t border-border/60">
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground block mb-4">
                04 / DEPLOYMENT METRICS & CERTIFIED SECURITY
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div>
                  <span id="about-stat-tactics" className="text-white block font-bold text-base">0+</span>
                  Tactics Linked
                </div>
                <div>
                  <span id="about-stat-techniques" className="text-white block font-bold text-base">0+</span>
                  Techniques Covered
                </div>
                <div>
                  <span id="about-stat-precision" className="text-white block font-bold text-base">0%</span>
                  Precision Score
                </div>
                <div>
                  <span className="text-white block font-bold text-base">100% SECURE</span>
                  Data Air-Gapping
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* ================= SECTION 11: FINAL CALL TO ACTION ================= */}
      <section id="cta-particles-section" className="relative py-32 px-6 sm:px-12 lg:px-16 border-b border-border/40 bg-secondary/15 overflow-hidden">
        {/* Glowing radial back-plate */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_60%_at_center,rgba(34,197,94,0.04),transparent)] z-0 pointer-events-none" />
        
        {/* Floating background neural particles */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-20">
          {[...Array(15)].map((_, i) => (
            <div
              key={i}
              className="absolute w-1 h-1 bg-primary rounded-full cta-particle"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
              }}
            />
          ))}
        </div>

        <div className="max-w-4xl mx-auto text-center relative z-10 space-y-8 cta-title-anim">
          <span className="text-xs uppercase tracking-widest text-primary font-mono font-bold block">
            [ 09 // READY TO DETONATE ]
          </span>
          <h2 className="text-[clamp(2.5rem,7vw,5.5rem)] font-bold tracking-tight text-white leading-none uppercase">
            Ready to Investigate<br />
            the Next Threat?
          </h2>
          <p className="text-muted-foreground text-sm font-light max-w-lg mx-auto leading-relaxed">
            Provision your dedicated air-gapped threat sandbox, run Android or Windows executable detonations, and compile evidence-ready reports instantly.
          </p>
          <div className="flex flex-wrap gap-4 justify-center pt-4 font-bold">
            <button
              onClick={onLaunchConsoleClick}
              className="bg-primary text-primary-foreground uppercase tracking-widest px-8 py-4 text-xs font-bold rounded-sm hover:shadow-[0_0_25px_rgba(34,197,94,0.45)] hover:brightness-110 active:scale-[0.97] transition-all cursor-pointer"
            >
              Launch Secure Console
            </button>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-muted text-foreground border border-border uppercase tracking-widest px-8 py-4 text-xs font-bold rounded-sm hover:bg-muted/80 active:scale-[0.97] transition-all flex items-center gap-2 justify-center"
            >
              <Github className="w-4 h-4" /> GitHub Repository
            </a>
          </div>
        </div>
      </section>

      {/* ================= SECTION 12: FOOTER ================= */}
      <footer className="py-16 px-6 sm:px-12 lg:px-16 bg-[#030303] text-muted-foreground relative z-10">
        <div className="max-w-6xl mx-auto w-full grid grid-cols-1 md:grid-cols-12 gap-8 items-start border-b border-border/40 pb-12 mb-12">
          
          <div className="md:col-span-4 space-y-4 footer-anim-stagger">
            <span className="text-xl font-bold uppercase tracking-wider text-white font-sora">
              E-RAKSHAK<span className="text-primary">.</span>
            </span>
            <p className="text-xs font-light leading-relaxed max-w-xs">
              Unified Cross-Platform Malware Detection & Behavioral Analysis Platform.
            </p>
            <div className="flex items-center gap-1.5 text-[10px] font-mono">
              <span className="inline-block w-2 h-2 rounded-full bg-primary animate-pulse" />
              <span>ENTERPRISE ACTIVE DEFENSE</span>
            </div>
          </div>

          <div className="md:col-span-3 space-y-3 text-xs footer-anim-stagger">
            <span className="text-xs font-bold text-white uppercase block">
              Navigation
            </span>
            <div className="space-y-2 flex flex-col font-mono text-[11px]">
              <a href="#home" className="hover:text-primary transition-colors">HOME</a>
              <a href="#pipeline" className="hover:text-primary transition-colors">PIPELINE</a>
              <a href="#features" className="hover:text-primary transition-colors">FEATURES</a>
              <a href="#technology" className="hover:text-primary transition-colors">TECHNOLOGY</a>
              <a href="#architecture" className="hover:text-primary transition-colors">ARCHITECTURE</a>
              <a href="#about" className="hover:text-primary transition-colors">ABOUT</a>
            </div>
          </div>

          <div className="md:col-span-3 space-y-3 text-xs footer-anim-stagger">
            <span className="text-xs font-bold text-white uppercase block">
              Resources
            </span>
            <div className="space-y-2 flex flex-col font-mono text-[11px]">
              <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors flex items-center gap-1">
                GITHUB <ExternalLink className="w-3 h-3" />
              </a>
              <a href="#about" className="hover:text-primary transition-colors">DOCUMENTATION</a>
              <a href="#about" className="hover:text-primary transition-colors">CONTACT SECURITY</a>
              <a href="#about" className="hover:text-primary transition-colors">CRIME INCIDENT DESK</a>
            </div>
          </div>

          <div className="md:col-span-2 space-y-3 text-xs footer-anim-stagger">
            <span className="text-xs font-bold text-white uppercase block">
              Platform Standards
            </span>
            <div className="space-y-1.5 font-mono text-[10px] leading-relaxed">
              <p>• MITRE ATT&CK Mobile V5</p>
              <p>• FedRAMP High VM Compliance</p>
              <p>• Next-Gen Secure Defense</p>
              <p>• ISO 27001 Cryptology</p>
            </div>
          </div>

        </div>

        <div className="max-w-6xl mx-auto w-full flex flex-col sm:flex-row justify-between items-center text-[10px] font-mono tracking-widest uppercase opacity-60">
          <span>© {new Date().getFullYear()} E-RAKSHAK MALWARE SUITE. ALL RIGHTS RESERVED.</span>
          <span className="mt-2 sm:mt-0 text-muted-foreground/40">NATIONAL THREAT SECURITY MANDATE 2025-2026</span>
        </div>
      </footer>

    </div>
  );
}
