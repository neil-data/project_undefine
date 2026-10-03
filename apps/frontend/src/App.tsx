import * as React from "react";
import { gsap } from "gsap";
import { ScrollToPlugin } from "gsap/ScrollToPlugin";
import { Navbar } from "./components/Navbar";

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollToPlugin);
}
import { HeroSection } from "./components/HeroSection";
import { LandingSections } from "./components/LandingSections";
import { DashboardPage } from "./components/DashboardPage";
import { LoginPage } from "./components/LoginPage";
import { SignUpPage } from "./components/SignUpPage";
import { isAuthenticated } from "./lib/api";

type AppView = "landing" | "auth" | "dashboard";

export default function App() {
  // Always begin at the public landing page. A saved token may still be used
  // after the user explicitly opens the console, but it must not bypass the
  // landing and login experience on a fresh visit.
  const [view, setView] = React.useState<AppView>("landing");
  const [authMode, setAuthMode] = React.useState<"login" | "signup">("login");


  // Custom high-performance GSAP view transition controller.
  //
  // The state change that actually navigates the app (setView) lives inside
  // a GSAP tl.call(), gated behind the overlay animation reaching that point
  // in the timeline. GSAP's default ticker drives itself off
  // requestAnimationFrame — if rAF never ticks (a backgrounded/non-composited
  // tab, some automation/embedding contexts, aggressive power-saving
  // throttling), the timeline never advances and the user is stuck unable to
  // navigate at all, with no error and no visible indication why. Confirmed
  // via gsap.ticker.frame staying at 0 after invoking this in exactly that
  // situation. Fixed with a setTimeout-based safety net below: setTimeout is
  // not gated on compositing the way rAF is, so it fires regardless and
  // guarantees navigation always completes — the animation becomes a
  // best-effort enhancement instead of a hard dependency for a core feature.
  const transitionTo = (targetView: AppView, scrollAfter = false) => {
    if (targetView === "dashboard" && !isAuthenticated()) {
      targetView = "auth";
    }
    const overlay = document.getElementById("transition-overlay");
    const content = document.getElementById("transition-overlay-content");

    if (!overlay) {
      setView(targetView);
      if (scrollAfter) window.scrollTo({ top: 0 });
      return;
    }

    gsap.killTweensOf([overlay, content]);

    let navigated = false;
    const navigate = () => {
      if (navigated) return;
      navigated = true;
      setView(targetView);
      if (scrollAfter) window.scrollTo({ top: 0 });
    };

    // Safety net: force navigation after a bounded wait even if the GSAP
    // timeline below never ticks. Longer than the timeline's own ~1.2s
    // midpoint so the animation completes normally in the common case.
    const fallbackTimer = window.setTimeout(navigate, 1500);

    const tl = gsap.timeline({
      onComplete: () => window.clearTimeout(fallbackTimer),
    });

    // 1. Slide Up the overlay to cover screen, fade current view
    tl.to(overlay, {
      y: "0%",
      duration: 0.7,
      ease: "power3.inOut"
    });

    tl.to(content, {
      opacity: 1,
      scale: 1,
      duration: 0.3
    }, "-=0.2");

    // 2. Change state halfway
    tl.call(navigate);

    // 3. Slide Out overlay towards top, fade in new view
    tl.to(overlay, {
      y: "-100%",
      duration: 0.7,
      ease: "power3.inOut",
      delay: 0.2
    });

    tl.to(content, {
      opacity: 0,
      scale: 1.1,
      duration: 0.3
    }, "-=0.5");

    // 4. Reset position after animation finishes
    tl.set(overlay, { y: "100%" });
  };

  // Scroll to Pipeline Section
  const handleExplorePipeline = () => {
    const el = document.getElementById("pipeline");
    if (el) {
      gsap.to(window, {
        duration: 1.2,
        scrollTo: { y: el, autoKill: true },
        ease: "power3.inOut"
      });
    }
  };

  // Back to Landing and Scroll directly to Top
  const handleBackToLanding = () => {
    transitionTo("landing", true);
  };

  // Launch Console goes through the auth gateway first
  const handleLaunchConsole = () => {
    setAuthMode("login");
    transitionTo("auth");
  };

  return (
    <div className="bg-[#050505] min-h-screen relative font-sora selection:bg-primary selection:text-primary-foreground">
      
      {/* Cinematic Slide Transition Overlay */}
      <div 
        id="transition-overlay" 
        className="fixed inset-0 bg-[#070707] z-[100] transform translate-y-full flex flex-col items-center justify-center border-t border-primary/20"
      >
        <div id="transition-overlay-content" className="text-center opacity-0 scale-95 flex flex-col items-center">
          <div className="w-16 h-16 rounded-lg border-2 border-primary/40 border-t-primary animate-spin mb-4" />
          <span className="text-xs uppercase tracking-[0.3em] font-mono text-primary animate-pulse">
            Establishing Neural Session Handshake...
          </span>
        </div>
      </div>

      {/* 1. LANDING PAGE VIEW */}
      {view === "landing" && (
        <>
          {/* Ambient background glowing shadows */}
          <div className="fixed inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(34,197,94,0.06),rgba(0,0,0,0))] pointer-events-none z-[1]" />
          
          {/* Floating Glassmorphic Navbar */}
          <Navbar onLaunchConsoleClick={handleLaunchConsole} />

          {/* Premium Hero with Spline Integrations */}
          <HeroSection 
            onLaunchConsoleClick={handleLaunchConsole} 
            onExplorePipelineClick={handleExplorePipeline} 
          />

          {/* Extensive GSAP & Scroll-Triggered Storytelling Sections */}
          <LandingSections 
            onLaunchConsoleClick={handleLaunchConsole} 
            onExplorePipelineClick={handleExplorePipeline} 
          />
        </>
      )}

      {/* 2. AUTH GATEWAY VIEW */}
      {view === "auth" && (
        authMode === "login" ? (
          <LoginPage
            onBackToLanding={handleBackToLanding}
            onLoginSuccess={() => transitionTo("dashboard")}
            onSwitchToSignup={() => setAuthMode("signup")}
          />
        ) : (
          <SignUpPage
            onBackToLanding={handleBackToLanding}
            onSignupSuccess={() => transitionTo("dashboard")}
            onSwitchToLogin={() => setAuthMode("login")}
          />
        )
      )}

      {/* 2. DASHBOARD APPLICATION VIEW */}
      {view === "dashboard" && (
        <DashboardPage 
          onLogout={handleBackToLanding} 
        />
      )}

    </div>
  );
}
