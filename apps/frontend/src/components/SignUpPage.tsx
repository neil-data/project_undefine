import * as React from "react";
import { useTranslation } from "react-i18next";
import { Shield, Eye, EyeOff, Key, Mail, Lock, ArrowLeft, Loader2, UserPlus, Building2 } from "lucide-react";

interface SignUpPageProps {
  onBackToLanding: () => void;
  onSignupSuccess: () => void;
  onSwitchToLogin: () => void;
}

export function SignUpPage({ onBackToLanding, onSignupSuccess, onSwitchToLogin }: SignUpPageProps) {
  const { t } = useTranslation();
  const [fullName, setFullName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [department, setDepartment] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [isRegistered, setIsRegistered] = React.useState(false);
  const [errorMessage, setErrorMessage] = React.useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage("");

    if (!fullName || !email || !password) {
      setErrorMessage(t("signup.missingFields"));
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage(t("signup.passwordMismatch"));
      return;
    }

    if (password.length < 8) {
      setErrorMessage(t("signup.passwordLength"));
      return;
    }

    setIsSubmitting(true);

    try {
      const { register } = await import("../lib/api");
      await register(email, password, fullName, department || undefined);
      setIsSubmitting(false);
      setIsRegistered(true);
      setTimeout(() => {
        onSignupSuccess();
      }, 800);
    } catch (err: any) {
      setIsSubmitting(false);
      setErrorMessage(err.message || "Registration failed. Unable to create agency account.");
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-foreground flex items-center justify-center relative p-6 font-sora select-none overflow-hidden">

      {/* Background Cyber-grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#141414_1px,transparent_1px),linear-gradient(to_bottom,#141414_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-40 z-0 pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(34,197,94,0.03)_0%,transparent_70%)] pointer-events-none" />

      {/* Floating back to landing */}
      <button
        onClick={onBackToLanding}
        className="absolute top-6 left-6 flex items-center gap-2 text-xs uppercase tracking-widest font-mono text-muted-foreground hover:text-primary transition-colors focus:outline-none"
      >
        <ArrowLeft className="w-4 h-4" /> {t("signup.backToLanding")}
      </button>

      {/* Sign Up Form Wrapper */}
      <div className="w-full max-w-md bg-[#101010] border border-border rounded-xl p-8 shadow-[0_0_50px_rgba(34,197,94,0.05)] relative z-10">

        {/* Registration Success Overlay */}
        {isRegistered && (
          <div className="absolute inset-0 bg-[#101010]/95 rounded-xl z-20 flex flex-col items-center justify-center p-8 text-center animate-fade-in">
            <div className="w-16 h-16 rounded-full bg-primary/10 border border-primary flex items-center justify-center mb-6">
              <UserPlus className="w-8 h-8 text-primary animate-pulse" />
            </div>
            <h3 className="text-xl font-bold text-white uppercase tracking-tight mb-2">
              {t("signup.successTitle")}
            </h3>
            <p className="text-xs text-muted-foreground max-w-xs font-light leading-relaxed">
              {t("signup.successSubtitle")}
            </p>
            <div className="w-24 h-1 bg-border rounded-full mt-6 overflow-hidden relative">
              <div className="absolute left-0 top-0 bottom-0 bg-primary w-2/3 h-full animate-ping" />
            </div>
          </div>
        )}

        <div className="text-center space-y-3 mb-8">
          <div className="w-12 h-12 rounded bg-primary/5 border border-primary/20 flex items-center justify-center mx-auto">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div>
            <span className="text-[10px] font-mono tracking-widest uppercase text-primary font-bold">
              {t("signup.portalGateway")}
            </span>
            <h2 className="text-2xl font-bold tracking-tight text-white uppercase mt-1">
              {t("signup.title")}
            </h2>
            <p className="text-xs text-muted-foreground font-light leading-relaxed">
              {t("signup.subtitle")}
            </p>
          </div>
        </div>

        {errorMessage && (
          <div className="p-3.5 bg-red-950/40 border border-red-500/30 text-red-400 text-xs rounded mb-5 font-mono">
            {errorMessage}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">

          <div className="space-y-2">
            <label className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground block">
              {t("signup.fullNameLabel")}
            </label>
            <div className="relative">
              <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                <Key className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder={t("signup.fullNamePlaceholder")}
                className="w-full bg-[#181818] border border-border rounded-lg pl-10 pr-4 py-3 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder:text-muted-foreground/30 font-mono"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground block">
              {t("signup.emailLabel")}
            </label>
            <div className="relative">
              <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                <Mail className="w-4 h-4" />
              </div>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="investigator@cybercell.gov"
                className="w-full bg-[#181818] border border-border rounded-lg pl-10 pr-4 py-3 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder:text-muted-foreground/30 font-mono"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground block">
              {t("signup.departmentLabel")}
            </label>
            <div className="relative">
              <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                <Building2 className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                placeholder={t("signup.departmentPlaceholder")}
                className="w-full bg-[#181818] border border-border rounded-lg pl-10 pr-4 py-3 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder:text-muted-foreground/30 font-mono"
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                {t("signup.passwordLabel")}
              </label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[10px] uppercase font-mono text-muted-foreground hover:text-primary focus:outline-none"
              >
                {showPassword ? t("signup.hide") : t("signup.show")}
              </button>
            </div>
            <div className="relative">
              <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-[#181818] border border-border rounded-lg pl-10 pr-10 py-3 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder:text-muted-foreground/30 font-mono"
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                {t("signup.confirmPasswordLabel")}
              </label>
            </div>
            <div className="relative">
              <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type={showPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-[#181818] border border-border rounded-lg pl-10 pr-10 py-3 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder:text-muted-foreground/30 font-mono"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full bg-primary hover:bg-primary/95 text-primary-foreground font-bold uppercase tracking-wider py-3.5 rounded-lg text-xs hover:shadow-[0_0_20px_rgba(34,197,94,0.3)] disabled:opacity-50 transition-all flex items-center justify-center gap-2"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> {t("signup.submitting")}
              </>
            ) : (
              t("signup.submit")
            )}
          </button>

        </form>

        <div className="text-center mt-6 text-xs">
          <span className="text-muted-foreground font-mono">{t("signup.haveAccount")}</span>{" "}
          <button
            onClick={onSwitchToLogin}
            className="text-primary hover:text-primary/80 uppercase font-mono text-[11px] font-bold tracking-wider transition-colors focus:outline-none"
          >
            {t("signup.switchToLogin")}
          </button>
        </div>

        <div className="text-center text-[9px] text-muted-foreground/60 font-mono mt-6 leading-relaxed">
          {t("signup.warning")}
        </div>

      </div>
    </div>
  );
}