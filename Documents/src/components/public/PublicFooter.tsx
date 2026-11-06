import React from 'react';
import { Shield, Lock, Database, Cpu, CheckCircle2 } from 'lucide-react';
import { PublicRoute } from './PublicHeader';

interface PublicFooterProps {
  onNavigate: (route: PublicRoute) => void;
}

export const PublicFooter: React.FC<PublicFooterProps> = ({ onNavigate }) => {
  return (
    <footer className="bg-white/90 dark:bg-[#050713]/90 border-t border-slate-200/90 dark:border-purple-500/20 text-slate-600 dark:text-slate-400 text-xs font-sans select-none transition-colors backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-12 space-y-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand Col */}
          <div className="space-y-3 md:col-span-1">
            <div className="flex items-center gap-2 text-slate-900 dark:text-slate-100 font-heading font-bold text-sm">
              <Shield className="w-5 h-5 text-purple-700 dark:text-cyan-400" />
              <span>KRYPTRION</span>
            </div>
            <p className="text-[11px] font-semibold text-purple-700 dark:text-cyan-400">
              See the Threat. Understand the Risk. Respond Smarter.
            </p>
            <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
              Kryptrion is an enterprise AI Security Operations platform engineered for real-time alert triage, automated threat intelligence correlation, and proactive incident response. Empower your SOC team to accelerate investigation cycles, eliminate alert fatigue, and strengthen cyber defense with zero-trust governance.
            </p>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-purple-50/80 dark:bg-purple-950/60 border border-purple-200/90 dark:border-purple-800/60 text-[10px] font-mono text-purple-700 dark:text-cyan-300">
              <span>Operational Prototype v2.0</span>
            </div>
          </div>

          {/* Nav Links */}
          <div className="space-y-2">
            <h4 className="text-[11px] font-mono font-bold uppercase text-slate-900 dark:text-slate-200 tracking-wider">
              Platform Navigation
            </h4>
            <ul className="space-y-1.5 text-[11px]">
              <li>
                <button onClick={() => onNavigate('home')} className="hover:text-purple-600 dark:hover:text-cyan-300 transition cursor-pointer">
                  Platform Home
                </button>
              </li>
              <li>
                <button onClick={() => onNavigate('features')} className="hover:text-purple-600 dark:hover:text-cyan-300 transition cursor-pointer">
                  Capabilities & Features
                </button>
              </li>
              <li>
                <button onClick={() => onNavigate('about')} className="hover:text-purple-600 dark:hover:text-cyan-300 transition cursor-pointer">
                  About & Principles
                </button>
              </li>
              <li>
                <button onClick={() => onNavigate('contact')} className="hover:text-purple-600 dark:hover:text-cyan-300 transition cursor-pointer">
                  Contact & Inquiries
                </button>
              </li>
              <li>
                <button onClick={() => onNavigate('login')} className="hover:text-purple-600 dark:hover:text-cyan-300 transition cursor-pointer">
                  Secure Workspace Login
                </button>
              </li>
            </ul>
          </div>

          {/* Operational Domains */}
          <div className="space-y-2">
            <h4 className="text-[11px] font-mono font-bold uppercase text-slate-900 dark:text-slate-200 tracking-wider">
              Operational Roles
            </h4>
            <ul className="space-y-1.5 text-[11px] text-slate-500 dark:text-slate-400">
              <li>SOC Analyst &bull; Triage Queue & Drawer</li>
              <li>Security Engineer &bull; MITRE & Matrix Audit</li>
              <li>IT Operations &bull; Remediation Tasks</li>
              <li>Super Admin &bull; System Configuration</li>
            </ul>
          </div>

          {/* Architectural Guarantees */}
          <div className="space-y-2">
            <h4 className="text-[11px] font-mono font-bold uppercase text-slate-900 dark:text-slate-200 tracking-wider">
              Guarantees & Integrity
            </h4>
            <ul className="space-y-1.5 text-[11px] text-slate-500 dark:text-slate-400">
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 dark:text-cyan-400 shrink-0" />
                <span>Deterministic rule scoring</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 dark:text-cyan-400 shrink-0" />
                <span>Peer-approved containment</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 dark:text-cyan-400 shrink-0" />
                <span>Tamper-evident audit ledger</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 dark:text-cyan-400 shrink-0" />
                <span>Role-isolated views & actions</span>
              </li>
            </ul>
          </div>
        </div>

        <div className="pt-8 border-t border-slate-200/80 dark:border-purple-900/30 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-slate-500 dark:text-slate-500">
          <div>
            &copy; {new Date().getFullYear()} Kryptrion. AI Security Operations Platform.
          </div>
          <div className="flex items-center gap-4 font-mono text-[10px]">
            <span>MITRE ATT&CK v14.1</span>
            <span>&bull;</span>
            <span>CIC-IDS2017</span>
            <span>&bull;</span>
            <span>ROLE-ISOLATED RBAC</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
