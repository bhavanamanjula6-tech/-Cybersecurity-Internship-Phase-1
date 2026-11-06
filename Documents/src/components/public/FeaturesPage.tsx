import React from 'react';
import {
  AlertOctagon,
  Layers,
  Activity,
  ClipboardList,
  FileText,
  Lock,
  Cpu,
  CheckCircle2,
  Clock,
  Sparkles,
  ShieldCheck,
} from 'lucide-react';
import { PublicRoute } from './PublicHeader';
import { ProvenanceBadge } from '../common/ProvenanceBadge';

interface FeaturesPageProps {
  onNavigate: (route: PublicRoute) => void;
}

export const FeaturesPage: React.FC<FeaturesPageProps> = ({ onNavigate }) => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-12 space-y-12">
      {/* Header */}
      <div className="text-center space-y-3 max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/90 dark:bg-purple-950/60 border border-purple-200/90 dark:border-purple-500/40 text-xs font-mono font-medium text-purple-700 dark:text-cyan-400 shadow-xs">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>CAPABILITY MATRIX & ARCHITECTURAL ROADMAP</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-slate-100 font-heading">
          Platform Capabilities & Module Architecture
        </h1>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
          We maintain rigorous distinction between implemented, verified functionality and future roadmap features.
        </p>
      </div>

      {/* IMPLEMENTED CAPABILITIES */}
      <div className="space-y-6">
        <div className="flex items-center gap-2 border-b border-slate-200/90 dark:border-purple-900/40 pb-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-cyan-400" />
          <h2 className="text-sm font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-slate-200">
            Phase 1 &bull; Implemented & Verified Capabilities
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-800">
            AVAILABLE IN PROTOTYPE
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {/* Feature 1 */}
          <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_25px_rgba(139,92,246,0.1)] space-y-3 hover:border-purple-400 dark:hover:border-purple-500/60 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="p-2.5 bg-rose-50 dark:bg-[#120f2b] rounded-xl text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-900/50">
                <AlertOctagon className="w-5 h-5" />
              </div>
              <ProvenanceBadge type="synthetic_demo" label="DEMO ALERTS" />
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
              Alert Triage & Investigation Drawer
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Real-time filterable queue with multi-criteria search, severity indicators, and deep 5-tab evidence inspection (Command lines, hashes, Sysmon logs).
            </p>
            <div className="text-[11px] font-mono text-purple-700 dark:text-cyan-400 pt-1">
              Role: Primary for SOC Analyst
            </div>
          </div>

          {/* Feature 2 */}
          <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_25px_rgba(139,92,246,0.1)] space-y-3 hover:border-purple-400 dark:hover:border-purple-500/60 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="p-2.5 bg-purple-50 dark:bg-[#140e2f] rounded-xl text-purple-700 dark:text-cyan-400 border border-purple-200 dark:border-purple-900/50">
                <Cpu className="w-5 h-5" />
              </div>
              <ProvenanceBadge type="deterministic_rule" label="EXPLAINABLE RULES" />
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
              Deterministic Triage Engine
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Transparent rule evaluation matching known credential dumping, obfuscated script execution, and ransomware precursors without LLM hallucinations.
            </p>
            <div className="text-[11px] font-mono text-purple-700 dark:text-cyan-400 pt-1">
              Engine: Rules DET-001 to DET-005
            </div>
          </div>

          {/* Feature 3 */}
          <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_25px_rgba(139,92,246,0.1)] space-y-3 hover:border-purple-400 dark:hover:border-purple-500/60 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="p-2.5 bg-blue-50 dark:bg-[#0f1435] rounded-xl text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-900/50">
                <Layers className="w-5 h-5" />
              </div>
              <ProvenanceBadge type="authentic_mitre" label="MITRE v14.1 ENTERPRISE" />
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
              MITRE ATT&CK Defense Coverage
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Curated Enterprise v14.1 tactics, techniques, and mitigations reference subset with source links and coverage percentage auditing.
            </p>
            <div className="text-[11px] font-mono text-purple-700 dark:text-cyan-400 pt-1">
              Role: Primary for Security Engineer
            </div>
          </div>

          {/* Feature 4 */}
          <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_25px_rgba(139,92,246,0.1)] space-y-3 hover:border-purple-400 dark:hover:border-purple-500/60 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="p-2.5 bg-emerald-50 dark:bg-[#0b1c2b] rounded-xl text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50">
                <Activity className="w-5 h-5" />
              </div>
              <ProvenanceBadge type="cic_ids_sample" label="CIC-IDS2017 SCHEMA" />
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
              Network Telemetry Correlation
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Full packet-rate, flow-duration, and TCP flag telemetry inspector structured to the Canadian Institute for Cybersecurity benchmark.
            </p>
            <div className="text-[11px] font-mono text-purple-700 dark:text-cyan-400 pt-1">
              Telemetry: Multi-flow analysis
            </div>
          </div>

          {/* Feature 5 */}
          <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_25px_rgba(139,92,246,0.1)] space-y-3 hover:border-purple-400 dark:hover:border-purple-500/60 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="p-2.5 bg-amber-50 dark:bg-[#1f1625] rounded-xl text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900/50">
                <ClipboardList className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800">
                RECOVERY QUEUE
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
              Incident Recovery Tasks
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Remediation task queue for system recovery, snapshot integrity validation, and credential resets with operator sign-off.
            </p>
            <div className="text-[11px] font-mono text-purple-600 dark:text-cyan-400 pt-1">
              Role: Primary for IT Operations
            </div>
          </div>

          {/* Feature 6 */}
          <div className="p-6 bg-white dark:bg-[#090d24]/90 border border-slate-200/90 dark:border-purple-900/40 rounded-2xl shadow-[0_4px_20px_rgba(15,23,42,0.04)] dark:shadow-[0_0_25px_rgba(139,92,246,0.1)] space-y-3 hover:border-purple-400 dark:hover:border-purple-500/60 hover:shadow-[0_8px_24px_rgba(109,40,217,0.12)] transition backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="p-2.5 bg-purple-50 dark:bg-[#140e2f] rounded-xl text-purple-700 dark:text-purple-400 border border-purple-200 dark:border-purple-900/50">
                <FileText className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800">
                AUDIT LEDGER
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
              Simulated Action Audit Trail
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Tamper-evident chronological ledger tracking operator callsigns, action types, targets, and mandatory justifications.
            </p>
            <div className="text-[11px] font-mono text-purple-700 dark:text-cyan-400 pt-1">
              Integrity: Chronological record
            </div>
          </div>
        </div>
      </div>

      {/* PLANNED FUTURE PHASES */}
      <div className="space-y-6 pt-6 border-t border-slate-200/90 dark:border-purple-900/40">
        <div className="flex items-center gap-2 border-b border-slate-200/90 dark:border-purple-900/40 pb-2">
          <Clock className="w-4 h-4 text-purple-700 dark:text-purple-400" />
          <h2 className="text-sm font-mono uppercase tracking-wider font-bold text-slate-900 dark:text-slate-200">
            Future Architecture Roadmap &bull; Subject to Approval
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/80 dark:text-purple-300 dark:border-purple-800">
            NOT YET IMPLEMENTED
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div className="p-6 bg-[#F8FAFD] dark:bg-[#080b1c]/60 border border-dashed border-slate-300 dark:border-purple-900/40 rounded-2xl space-y-2.5 opacity-90 backdrop-blur-sm">
            <div className="text-xs font-mono font-bold text-purple-700 dark:text-purple-400 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              PROPOSED PHASE 3: RAG AI COPILOT
            </div>
            <h4 className="text-sm font-bold text-slate-900 dark:text-slate-200 font-heading">
              Knowledge Retrieval Augmentation
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Vector embeddings over threat intelligence and incident history. Requires separate approval, vector database, and live model integration.
            </p>
          </div>

          <div className="p-6 bg-[#F8FAFD] dark:bg-[#080b1c]/60 border border-dashed border-slate-300 dark:border-purple-900/40 rounded-2xl space-y-2.5 opacity-90 backdrop-blur-sm">
            <div className="text-xs font-mono font-bold text-purple-700 dark:text-purple-400 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              PROPOSED PHASE 4: CONTROLLED AGENTS
            </div>
            <h4 className="text-sm font-bold text-slate-900 dark:text-slate-200 font-heading">
              Autonomous Investigation Agents
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Multi-step analytical agents gathering cross-platform indicators with strict authorization boundaries and sandboxed execution.
            </p>
          </div>

          <div className="p-6 bg-[#F8FAFD] dark:bg-[#080b1c]/60 border border-dashed border-slate-300 dark:border-purple-900/40 rounded-2xl space-y-2.5 opacity-90 backdrop-blur-sm">
            <div className="text-xs font-mono font-bold text-purple-700 dark:text-purple-400 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5" />
              PROPOSED PHASE 5: LIVE CONNECTORS
            </div>
            <h4 className="text-sm font-bold text-slate-900 dark:text-slate-200 font-heading">
              Production SIEM & EDR Webhooks
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 font-sans leading-relaxed">
              Production integrations with Splunk, CrowdStrike, Microsoft Defender, and live firewall API endpoints.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
