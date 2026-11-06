import React from 'react';
import {
  Shield,
  ArrowRight,
  AlertOctagon,
  Cpu,
  Layers,
  Activity,
  ClipboardList,
  CheckCircle2,
  Lock,
  Eye,
  SlidersHorizontal,
  FileCheck,
  Server,
  Terminal,
  Target,
  Users,
} from 'lucide-react';
import { PublicRoute } from './PublicHeader';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { SeverityIndicator } from '../common/SeverityIndicator';
import { CyberShieldHero } from './CyberShieldHero';
import { CyberServiceCards } from './CyberServiceCards';
import { CyberLockIllustration } from './CyberLockIllustration';

interface HomePageProps {
  onNavigate: (route: PublicRoute) => void;
  onEnterApp?: () => void;
  isAuthenticated: boolean;
}

export const HomePage: React.FC<HomePageProps> = ({
  onNavigate,
  onEnterApp,
  isAuthenticated,
}) => {
  return (
    <div className="space-y-16 sm:space-y-24 pb-20">
      {/* SECTION 1: CYBER HERO WITH LAYERED 2.5D SHIELD */}
      <section className="relative pt-8 sm:pt-16 pb-8 px-4 sm:px-6 max-w-7xl mx-auto flex flex-col items-center text-center space-y-8 overflow-hidden">
        {/* Subtle Ambient Radial Neon Lighting */}
        <div
          className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[450px] pointer-events-none rounded-full blur-[120px] opacity-25 dark:opacity-50 -z-10"
          style={{
            background:
              'radial-gradient(circle, rgba(168,85,247,0.5) 0%, rgba(217,70,239,0.3) 40%, rgba(6,182,212,0.15) 70%, transparent 85%)',
          }}
        />

        {/* Quiet Kicker Label */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-white/90 dark:bg-purple-950/60 border border-purple-200/90 dark:border-purple-500/40 text-xs font-mono font-medium text-purple-700 dark:text-purple-300 shadow-xs">
          <Shield className="w-3.5 h-3.5 text-purple-700 dark:text-cyan-400" />
          <span>KRYPTRION &bull; AI SECURITY OPERATIONS PLATFORM</span>
        </div>

        {/* Dual-Theme High Contrast Headline */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-slate-900 dark:text-white max-w-4xl mx-auto leading-tight font-heading">
          <span className="sr-only">See the Threat. Understand the Risk. Respond Smarter.</span>
          <span aria-hidden="true">
            <span className="text-slate-900 dark:text-white">
              See the Threat.{' '}
            </span>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-600 via-fuchsia-600 to-cyan-500 dark:from-purple-400 dark:via-fuchsia-400 dark:to-cyan-400">
              Understand the Risk. Respond Smarter.
            </span>
          </span>
        </h1>

        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-300 max-w-2xl mx-auto font-sans leading-relaxed">
          Kryptrion is an enterprise AI Security Operations platform engineered for real-time alert triage, automated threat intelligence correlation, and proactive incident response. Empower your SOC team to accelerate investigation cycles, eliminate alert fatigue, and strengthen cyber defense with zero-trust governance.
        </p>

        {/* Central Layered 2.5D Animated CyberShield */}
        <div className="pt-2 pb-4 flex justify-center w-full">
          <CyberShieldHero />
        </div>

        {/* Action Buttons: Prominent Purple Gradient CTA */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <button
            onClick={() => onNavigate('features')}
            className="w-full sm:w-auto px-7 py-3.5 rounded-xl text-sm font-semibold bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-[0_4px_16px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_24px_rgba(124,58,237,0.5)] transition-all duration-300 flex items-center justify-center gap-2 cursor-pointer font-sans"
          >
            <span>Explore the Platform</span>
            <ArrowRight className="w-4 h-4" />
          </button>

          {isAuthenticated ? (
            <button
              onClick={onEnterApp}
              className="w-full sm:w-auto px-7 py-3.5 rounded-xl text-sm font-semibold bg-white dark:bg-slate-900/90 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-100 border border-slate-300 dark:border-purple-500/40 transition flex items-center justify-center gap-2 cursor-pointer font-sans shadow-xs hover:border-purple-400 hover:text-purple-700"
            >
              <span>Enter Workspace</span>
            </button>
          ) : (
            <button
              onClick={() => onNavigate('login')}
              className="w-full sm:w-auto px-7 py-3.5 rounded-xl text-sm font-semibold bg-white dark:bg-slate-900/90 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-100 border border-slate-300 dark:border-purple-500/40 transition flex items-center justify-center gap-2 cursor-pointer font-sans shadow-xs hover:border-purple-400 hover:text-purple-700"
            >
              <span>Sign In</span>
            </button>
          )}
        </div>

        {/* Grounding and Security Notice */}
        <div className="pt-2">
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center justify-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-purple-600 dark:text-cyan-400" />
            Role-isolated workspace architecture &bull; Zero external cloud telemetry &bull; Deterministic rules
          </span>
        </div>
      </section>

      {/* SECTION 2: REPRESENTATIVE 3D PERSPECTIVE SERVICE CARDS */}
      <section className="px-4 sm:px-6 max-w-7xl mx-auto">
        <CyberServiceCards
          onExploreAction={(cardId) => {
            if (cardId === 'triage') {
              if (isAuthenticated) onEnterApp?.();
              else onNavigate('login');
            } else {
              onNavigate('features');
            }
          }}
        />
      </section>

      {/* SECTION 3: INTERACTIVE SOC DASHBOARD PREVIEW (Synthetic Demonstration) */}
      <section className="px-4 sm:px-6 max-w-7xl mx-auto">
        <div className="rounded-2xl border border-slate-200/90 dark:border-purple-500/30 bg-white dark:bg-[#080b1c]/90 shadow-[0_12px_36px_rgba(15,23,42,0.06)] dark:shadow-[0_0_50px_rgba(139,92,246,0.15)] overflow-hidden backdrop-blur-xl">
          {/* Mock Window Topbar */}
          <div className="px-4 py-3 bg-[#F8FAFD] dark:bg-[#0c102a] border-b border-slate-200/90 dark:border-purple-900/40 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.6)]" />
              <span className="w-3 h-3 rounded-full bg-amber-500 shadow-[0_0_6px_rgba(245,158,11,0.6)]" />
              <span className="w-3 h-3 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)]" />
              <span className="text-slate-800 dark:text-slate-200 ml-2 font-bold tracking-wide">
                OPERATIONAL SOC WORKSPACE &bull; ALERT TRIAGE QUEUE
              </span>
            </div>

            <div className="flex items-center gap-2">
              <ProvenanceBadge type="synthetic_demo" label="SYNTHETIC PREVIEW DATA" />
              <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono">PROTOTYPE ENGINE</span>
            </div>
          </div>

          {/* Mock Content Body */}
          <div className="p-4 sm:p-6 space-y-4 bg-slate-50/60 dark:bg-[#070918]/70">
            {/* Quick Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-white dark:bg-[#0c112e] border border-slate-200/90 dark:border-purple-900/40 rounded-xl shadow-xs">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">ACTIVE ALERTS</span>
                <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100">6 Events</span>
              </div>
              <div className="p-3 bg-rose-50/40 dark:bg-[#0c112e] border border-rose-200/90 dark:border-rose-900/50 rounded-xl shadow-xs">
                <span className="text-[10px] font-mono text-rose-700 dark:text-rose-400 uppercase block">CRITICAL QUEUE</span>
                <span className="text-xl font-bold font-mono text-rose-700 dark:text-rose-400">2 Confirmed</span>
              </div>
              <div className="p-3 bg-purple-50/40 dark:bg-[#0c112e] border border-purple-200/90 dark:border-purple-900/40 rounded-xl shadow-xs">
                <span className="text-[10px] font-mono text-purple-700 dark:text-cyan-400 uppercase block">MITRE ENTERPRISE</span>
                <span className="text-xl font-bold font-mono text-purple-700 dark:text-cyan-400">v14.1 Matrix</span>
              </div>
              <div className="p-3 bg-amber-50/40 dark:bg-[#0c112e] border border-amber-200/90 dark:border-amber-900/50 rounded-xl shadow-xs">
                <span className="text-[10px] font-mono text-amber-700 dark:text-amber-400 uppercase block">CONTAINMENT ACTIONS</span>
                <span className="text-xl font-bold font-mono text-amber-700 dark:text-amber-400">Simulated Safe</span>
              </div>
            </div>

            {/* Mock Alert Rows Preview */}
            <div className="border border-slate-200/90 dark:border-purple-900/30 rounded-xl overflow-hidden bg-white dark:bg-[#090d22] shadow-xs text-xs">
              <div className="p-3 bg-[#F8FAFD] dark:bg-[#0c112c] border-b border-slate-200/90 dark:border-purple-900/30 text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 flex items-center justify-between">
                <span>INCOMING TELEMETRY INCIDENT</span>
                <span>DETERMINISTIC EVALUATION ENGINE</span>
              </div>

              <div className="divide-y divide-slate-200/90 dark:divide-slate-800/80">
                <div className="p-3.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 hover:bg-purple-50/40 dark:hover:bg-purple-950/20 transition">
                  <div className="flex items-center gap-3 min-w-0">
                    <SeverityIndicator severity="critical" showLabel={false} size="sm" />
                    <div>
                      <div className="font-mono font-bold text-slate-900 dark:text-slate-100">
                        ALT-2026-1049 &bull; Suspicious LSASS Memory Read via Unsigned Binary
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                        Host: WORKSTATION-CORP-14 &bull; T1003.001 &bull; Procdump PROCESS_VM_READ (0x1FFFFF)
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 self-end sm:self-center">
                    <span className="px-2 py-0.5 rounded bg-rose-50 dark:bg-rose-950/80 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800 font-mono text-[10px]">
                      Rule DET-001 (94% Conf)
                    </span>
                    <span className="px-2 py-0.5 rounded bg-blue-50 dark:bg-cyan-950 text-blue-700 dark:text-cyan-300 border border-blue-200 dark:border-cyan-800 font-mono text-[10px]">
                      Quarantine Proposed
                    </span>
                  </div>
                </div>

                <div className="p-3.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 hover:bg-purple-50/40 dark:hover:bg-purple-950/20 transition">
                  <div className="flex items-center gap-3 min-w-0">
                    <SeverityIndicator severity="high" showLabel={false} size="sm" />
                    <div>
                      <div className="font-mono font-bold text-slate-900 dark:text-slate-100">
                        ALT-2026-1048 &bull; Obfuscated PowerShell Download Cradle Detected
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                        Host: FINANCE-LAPTOP-08 &bull; T1059.001 &bull; Base64 -Enc from WINWORD.EXE
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 self-end sm:self-center">
                    <span className="px-2 py-0.5 rounded bg-orange-50 dark:bg-amber-950/80 text-orange-700 dark:text-amber-300 border border-orange-200 dark:border-amber-800 font-mono text-[10px]">
                      Rule DET-002 (88% Conf)
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 font-mono text-[10px]">
                      In Triage
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="text-center pt-1">
              <button
                onClick={() => (isAuthenticated ? onEnterApp && onEnterApp() : onNavigate('login'))}
                className="text-xs font-mono text-purple-700 dark:text-cyan-400 hover:text-purple-800 dark:hover:text-cyan-300 hover:underline cursor-pointer transition-colors"
              >
                Log in to interact with the full investigation drawer and raw evidence &rarr;
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 4: PROJECT OBJECTIVE */}
      <section className="px-4 sm:px-6 max-w-5xl mx-auto space-y-4">
        <div className="text-center space-y-2">
          <span className="text-[11px] font-mono uppercase text-purple-700 dark:text-purple-400 font-bold tracking-wider">
            PROJECT OBJECTIVE
          </span>
          <h2 className="text-2xl sm:text-3xl font-bold font-heading text-slate-900 dark:text-slate-100">
            A Structured, Evidence-First Security Operations Mission
          </h2>
        </div>

        <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-[#090d22]/90 border border-slate-200/90 dark:border-purple-500/25 shadow-[0_4px_24px_rgba(15,23,42,0.04)] dark:shadow-[0_0_35px_rgba(139,92,246,0.1)] space-y-4 text-xs sm:text-sm text-slate-600 dark:text-slate-300 font-sans leading-relaxed backdrop-blur-sm">
          <p>
            Security operations centers face a common failure mode: tier-1 analysts drown in fragmented alert queues, detection engineers operate in a silo without visibility into operational coverage gaps, and IT operations teams execute containment actions without traceable justifications.
          </p>
          <p>
            Our objective is to restore transparency and coordination to this lifecycle. By uniting <strong>deterministic triage rules</strong>, authentic <strong>MITRE ATT&CK reference data</strong>, and <strong>human-in-the-loop authorization gates</strong>, our platform empowers analysts to make evidence-grounded decisions while ensuring consequential actions are strictly authorized and audited.
          </p>
        </div>
      </section>

      {/* SECTION 5: GOVERNANCE & PROVENANCE (FEATURING CYBERLOCKILLUSTRATION) */}
      <section className="px-4 sm:px-6 max-w-7xl mx-auto">
        <div className="p-6 sm:p-10 rounded-3xl bg-gradient-to-br from-purple-500/[0.04] via-indigo-500/[0.03] to-slate-100/60 dark:from-purple-950/40 dark:via-[#0c102a]/70 dark:to-[#070918]/80 border border-purple-200/90 dark:border-purple-500/30 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center shadow-[0_8px_30px_rgba(15,23,42,0.06)] dark:shadow-[0_0_40px_rgba(139,92,246,0.15)] backdrop-blur-sm">
          <div className="lg:col-span-7 space-y-4">
            <div className="inline-flex items-center gap-2 text-xs font-mono font-bold text-purple-700 dark:text-purple-400">
              <CheckCircle2 className="w-4 h-4 text-purple-700 dark:text-cyan-400" />
              <span>DETERMINISTIC GOVERNANCE & DECISION SOVEREIGNTY</span>
            </div>
            <h3 className="text-2xl sm:text-3xl font-bold font-heading text-slate-900 dark:text-white">
              Zero Black-Box Guesswork. 100% Verifiable Rationale.
            </h3>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 font-sans leading-relaxed">
              Every score produced by the platform is tied to deterministic logic. We do not use generative AI hallucinations to decide whether an endpoint is compromised. Instead, rules compute exact confidence weights based on tangible system telemetry: process ancestry, argument hashes, and access privileges.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-xs font-mono text-slate-700 dark:text-slate-300">
              <div className="flex items-center gap-2 p-2.5 rounded-lg bg-white/90 dark:bg-[#0c102c] border border-slate-200/90 dark:border-purple-900/40 shadow-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_#10b981]" />
                <span>Deterministic rule scoring</span>
              </div>
              <div className="flex items-center gap-2 p-2.5 rounded-lg bg-white/90 dark:bg-[#0c102c] border border-slate-200/90 dark:border-purple-900/40 shadow-xs">
                <span className="w-2 h-2 rounded-full bg-purple-500 shadow-[0_0_6px_#a855f7]" />
                <span>Peer-approved containment</span>
              </div>
              <div className="flex items-center gap-2 p-2.5 rounded-lg bg-white/90 dark:bg-[#0c102c] border border-slate-200/90 dark:border-purple-900/40 shadow-xs">
                <span className="w-2 h-2 rounded-full bg-cyan-500 shadow-[0_0_6px_#06b6d4]" />
                <span>MITRE ATT&CK Enterprise v14.1</span>
              </div>
              <div className="flex items-center gap-2 p-2.5 rounded-lg bg-white/90 dark:bg-[#0c102c] border border-slate-200/90 dark:border-purple-900/40 shadow-xs">
                <span className="w-2 h-2 rounded-full bg-amber-500 shadow-[0_0_6px_#f59e0b]" />
                <span>Tamper-evident audit logs</span>
              </div>
            </div>
          </div>

          <div className="lg:col-span-5 flex justify-center">
            <CyberLockIllustration className="w-full max-w-xs" />
          </div>
        </div>
      </section>

      {/* SECTION 6: EXPLAINABLE WORKFLOW (4 STEPS) */}
      <section className="px-4 sm:px-6 max-w-7xl mx-auto bg-slate-100/60 dark:bg-[#080b1c]/80 border border-slate-200/90 dark:border-purple-500/20 rounded-3xl p-6 sm:p-10 space-y-8 backdrop-blur-sm shadow-xs">
        <div className="text-center space-y-2 max-w-2xl mx-auto">
          <span className="text-[11px] font-mono uppercase text-purple-700 dark:text-purple-400 font-bold tracking-wider">
            INVESTIGATION WORKFLOW
          </span>
          <h2 className="text-2xl sm:text-3xl font-bold font-heading text-slate-900 dark:text-slate-100">
            The 4-Step Explainable Decision Pipeline
          </h2>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
            Every analytical conclusion is grounded in verifiable evidence and documented rule weights.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 bg-white dark:bg-[#0c102a] border border-slate-200/90 dark:border-purple-900/40 hover:border-purple-400 dark:hover:border-purple-500/60 rounded-2xl shadow-xs hover:shadow-[0_8px_20px_rgba(109,40,217,0.1)] space-y-2 transition-all duration-300">
            <div className="text-purple-700 dark:text-cyan-400 font-mono font-bold text-xs tracking-wider">STEP 01</div>
            <h4 className="text-sm font-bold font-heading text-slate-900 dark:text-slate-100">Telemetry Ingestion</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Sysmon Event ID 10, PowerShell ScriptBlock logs, and synthetic network flow records formatted to the CIC-IDS2017 schema are ingested with structured timestamps.
            </p>
          </div>

          <div className="p-5 bg-white dark:bg-[#0c102a] border border-slate-200/90 dark:border-purple-900/40 hover:border-purple-400 dark:hover:border-purple-500/60 rounded-2xl shadow-xs hover:shadow-[0_8px_20px_rgba(109,40,217,0.1)] space-y-2 transition-all duration-300">
            <div className="text-purple-700 dark:text-cyan-400 font-mono font-bold text-xs tracking-wider">STEP 02</div>
            <h4 className="text-sm font-bold font-heading text-slate-900 dark:text-slate-100">Deterministic Scoring</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Rules evaluate evidence for credential dumps, base64 cradles, and shadow copy deletions, outputting transparent rationale.
            </p>
          </div>

          <div className="p-5 bg-white dark:bg-[#0c102a] border border-slate-200/90 dark:border-purple-900/40 hover:border-purple-400 dark:hover:border-purple-500/60 rounded-2xl shadow-xs hover:shadow-[0_8px_20px_rgba(109,40,217,0.1)] space-y-2 transition-all duration-300">
            <div className="text-purple-700 dark:text-cyan-400 font-mono font-bold text-xs tracking-wider">STEP 03</div>
            <h4 className="text-sm font-bold font-heading text-slate-900 dark:text-slate-100">Intel Correlation</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Alerts cross-reference authentic MITRE ATT&CK techniques (T1003, T1059, T1047) to retrieve verified mitigations and detection strategies.
            </p>
          </div>

          <div className="p-5 bg-white dark:bg-[#0c102a] border border-slate-200/90 dark:border-purple-900/40 hover:border-purple-400 dark:hover:border-purple-500/60 rounded-2xl shadow-xs hover:shadow-[0_8px_20px_rgba(109,40,217,0.1)] space-y-2 transition-all duration-300">
            <div className="text-purple-700 dark:text-cyan-400 font-mono font-bold text-xs tracking-wider">STEP 04</div>
            <h4 className="text-sm font-bold font-heading text-slate-900 dark:text-slate-100">Authorized Action</h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Operators review proposal impact, submit mandatory operational rationale, and execute simulated containment safely.
            </p>
          </div>
        </div>
      </section>

      {/* SECTION 7: ROLE-SPECIFIC WORKSPACES */}
      <section className="px-4 sm:px-6 max-w-7xl mx-auto space-y-6">
        <div className="text-center space-y-2 max-w-2xl mx-auto">
          <span className="text-[11px] font-mono uppercase text-purple-700 dark:text-purple-400 font-bold tracking-wider">
            OPERATIONAL ROLES
          </span>
          <h2 className="text-2xl sm:text-3xl font-bold font-heading text-slate-900 dark:text-slate-100">
            Tailored Workspaces for Each Defender
          </h2>
          <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400">
            Three primary operational workspaces with strict data scoping and authorization boundaries.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div className="p-6 rounded-2xl bg-white dark:bg-[#090d22] border border-slate-200/90 dark:border-cyan-500/30 shadow-xs hover:border-cyan-500/70 hover:shadow-[0_8px_24px_rgba(6,182,212,0.18)] transition-all duration-300 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-bold text-purple-700 dark:text-cyan-400 uppercase">TIER 1/2</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-50 dark:bg-cyan-950 text-purple-700 dark:text-cyan-300 border border-purple-200 dark:border-cyan-800">
                ACTIVE QUEUE
              </span>
            </div>
            <h3 className="text-base font-bold font-heading text-slate-900 dark:text-slate-100">SOC Analyst</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Review and prioritize incoming alerts, examine raw telemetry evidence, correlate MITRE techniques, add investigation findings, and recommend escalation.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-white dark:bg-[#090d22] border border-slate-200/90 dark:border-blue-500/30 shadow-xs hover:border-blue-500/70 hover:shadow-[0_8px_24px_rgba(59,130,246,0.18)] transition-all duration-300 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-bold text-blue-700 dark:text-blue-400 uppercase">ENGINEERING</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
                DEFENSE AUDIT
              </span>
            </div>
            <h3 className="text-base font-bold font-heading text-slate-900 dark:text-slate-100">Security Engineer</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Explore threat tactics and techniques, assess detection coverage percentages, review mitigation mappings, and identify telemetry collection gaps.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-white dark:bg-[#090d22] border border-slate-200/90 dark:border-amber-500/30 shadow-xs hover:border-amber-500/70 hover:shadow-[0_8px_24px_rgba(245,158,11,0.18)] transition-all duration-300 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-bold text-amber-700 dark:text-amber-400 uppercase">RECOVERY</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                REMEDIATION
              </span>
            </div>
            <h3 className="text-base font-bold font-heading text-slate-900 dark:text-slate-100">IT Operations</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Review assigned remediation tasks, follow authorized containment procedures, verify offline snapshot integrity, and track operational recovery.
            </p>
          </div>
        </div>
      </section>

      {/* SECTION 8: CLOSING CTA */}
      <section className="px-4 sm:px-6 max-w-4xl mx-auto text-center space-y-4 pt-4">
        <div className="p-8 sm:p-12 rounded-3xl bg-gradient-to-b from-purple-50 via-indigo-50/40 to-white dark:from-purple-950/40 dark:to-[#090c24] border border-purple-200/90 dark:border-purple-500/30 shadow-[0_8px_30px_rgba(109,40,217,0.1)] dark:shadow-[0_0_40px_rgba(139,92,246,0.2)] space-y-5 backdrop-blur-sm">
          <h3 className="text-2xl sm:text-3xl font-bold font-heading text-slate-900 dark:text-slate-100">
            Ready to experience the operational workspace?
          </h3>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 max-w-md mx-auto">
            Test role-isolated workspaces with pre-configured synthetic security scenarios.
          </p>
          <div className="pt-2 flex justify-center">
            <button
              onClick={() => onNavigate('login')}
              className="px-8 py-3.5 rounded-xl text-sm font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 hover:from-purple-500 hover:via-purple-600 hover:to-indigo-500 text-white shadow-[0_4px_16px_rgba(124,58,237,0.35)] hover:shadow-[0_6px_22px_rgba(124,58,237,0.5)] transition cursor-pointer font-sans"
            >
              Launch Prototype Login &rarr;
            </button>
          </div>
        </div>
      </section>
    </div>
  );
};
