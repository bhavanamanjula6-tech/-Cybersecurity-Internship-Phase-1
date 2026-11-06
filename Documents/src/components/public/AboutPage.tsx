import React from 'react';
import { Shield, Target, Users, Code, Lock, CheckCircle2 } from 'lucide-react';
import { PublicRoute } from './PublicHeader';

interface AboutPageProps {
  onNavigate: (route: PublicRoute) => void;
}

export const AboutPage: React.FC<AboutPageProps> = ({ onNavigate }) => {
  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-12 space-y-12">
      {/* Title */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/90 dark:bg-purple-950/60 border border-purple-200/90 dark:border-purple-500/40 text-xs font-mono font-medium text-purple-700 dark:text-cyan-400 shadow-xs">
          <Shield className="w-3.5 h-3.5" />
          <span>PROJECT ARCHITECTURE & PURPOSE</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-slate-100 font-heading">
          Purpose, Problem Statement & Engineering Principles
        </h1>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed font-sans">
          An architectural foundation designed to restore transparency, evidence-based reasoning, and role-based data isolation to modern incident operations.
        </p>
      </div>

      {/* 1. Problem Statement */}
      <div className="p-6 sm:p-8 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_24px_rgba(15,23,42,0.04)] dark:shadow-[0_0_30px_rgba(139,92,246,0.1)] space-y-3 backdrop-blur-sm">
        <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 font-heading flex items-center gap-2">
          <Target className="w-4 h-4 text-rose-600 dark:text-rose-400" />
          The Security Operations Problem
        </h2>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 font-sans leading-relaxed">
          Modern Security Operations Centers drown in tens of thousands of fragmented telemetry signals every day. Traditional SIEMs and automated alert queues suffer from high false-positive rates, opaque heuristic scores, and disjointed handoffs between tier-1 triage analysts, detection engineers, and IT system administrators. When automated &quot;black-box&quot; systems take unilateral action, they risk taking down business-critical infrastructure; when analysts lack verifiable evidence, critical intrusions remain undetected.
        </p>
      </div>

      {/* 2. Project Objectives */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-xs font-sans">
        <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_20px_rgba(139,92,246,0.1)] space-y-2 backdrop-blur-sm hover:border-purple-400 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition">
          <h3 className="font-bold text-slate-900 dark:text-slate-100 font-heading text-sm">1. Grounded Evidence Review</h3>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            Eliminate guesswork by providing analysts with verifiable process command lines, execution lineages, event IDs, and SHA256 hashes within a single unified drawer.
          </p>
        </div>

        <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_20px_rgba(139,92,246,0.1)] space-y-2 backdrop-blur-sm hover:border-purple-400 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition">
          <h3 className="font-bold text-slate-900 dark:text-slate-100 font-heading text-sm">2. Deterministic Transparency</h3>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            Every analytical score and recommendation is derived from verifiable rules with explicit weights and cited telemetry conditions, avoiding probabilistic AI hallucination.
          </p>
        </div>

        <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_20px_rgba(139,92,246,0.1)] space-y-2 backdrop-blur-sm hover:border-purple-400 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition">
          <h3 className="font-bold text-slate-900 dark:text-slate-100 font-heading text-sm">3. Human Authorization Guard</h3>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            Consequential containment measures—such as isolating an endpoint or disabling a directory account—require explicit operator review, rationale recording, and audit logging.
          </p>
        </div>
      </div>

      {/* 3. Intended User Personas */}
      <div className="p-6 sm:p-8 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_24px_rgba(15,23,42,0.04)] dark:shadow-[0_0_30px_rgba(139,92,246,0.1)] space-y-5 backdrop-blur-sm">
        <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 font-heading flex items-center gap-2">
          <Users className="w-4 h-4 text-purple-700 dark:text-cyan-400" />
          Three Primary Operational Roles
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-sans">
          <div className="p-5 bg-[#F8FAFD] dark:bg-[#0c102a] border border-slate-200/90 dark:border-cyan-500/30 rounded-xl space-y-2">
            <span className="font-mono font-bold text-purple-700 dark:text-cyan-400 text-[11px] block">ROLE 01</span>
            <h4 className="font-bold text-slate-900 dark:text-slate-100 font-heading text-sm">SOC Analyst</h4>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
              Reviews incoming alerts, correlates raw evidence, documents investigative findings, and recommends escalation to incident response.
            </p>
          </div>

          <div className="p-5 bg-[#F8FAFD] dark:bg-[#0c102a] border border-slate-200/90 dark:border-blue-500/30 rounded-xl space-y-2">
            <span className="font-mono font-bold text-blue-700 dark:text-blue-400 text-[11px] block">ROLE 02</span>
            <h4 className="font-bold text-slate-900 dark:text-slate-100 font-heading text-sm">Security Engineer</h4>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
              Audits threat tactics, evaluates detection strategy coverage, analyzes MITRE ATT&CK mappings, and identifies telemetry coverage gaps.
            </p>
          </div>

          <div className="p-5 bg-[#F8FAFD] dark:bg-[#0c102a] border border-slate-200/90 dark:border-amber-500/30 rounded-xl space-y-2">
            <span className="font-mono font-bold text-amber-700 dark:text-amber-400 text-[11px] block">ROLE 03</span>
            <h4 className="font-bold text-slate-900 dark:text-slate-100 font-heading text-sm">IT Operations Team</h4>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
              Executes authorized containment tasks, restores affected assets, verifies snapshot integrity, and documents operational recovery.
            </p>
          </div>
        </div>
      </div>

      {/* 4. Commitment to Verifiable Integrity */}
      <div className="p-6 bg-[#F8FAFD] dark:bg-[#080b1c]/80 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-xs space-y-3 text-xs font-sans backdrop-blur-sm">
        <div className="flex items-center gap-2 text-purple-700 dark:text-cyan-400 font-bold font-heading text-sm">
          <Lock className="w-4 h-4" />
          <span>Commitment to Zero Hallucination & Transparency</span>
        </div>
        <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
          This platform is engineered without fabricated customer counts, synthetic testimonials, or artificial awards. All MITRE ATT&CK reference records represent authentic v14.1 Enterprise knowledge. Demonstration alerts and network flows are explicitly flagged as synthetic test scenarios.
        </p>
      </div>
    </div>
  );
};
