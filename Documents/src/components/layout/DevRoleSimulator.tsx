import React, { useState } from 'react';
import { UserCheck, ChevronUp, ChevronDown, AlertTriangle, ShieldAlert } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { UserRole, ROLE_METADATA } from '../../types/auth';
import { isSupabaseConfigured } from '../../lib/supabaseClient';

export const DevRoleSimulator: React.FC = () => {
  const { currentUser, switchRoleDemo } = useAuth();
  const [expanded, setExpanded] = useState(false);

  // In live Supabase mode, all authorization derives from PostgreSQL user_profiles.
  // DevRoleSimulator must NEVER override or simulate a live authenticated role.
  if (isSupabaseConfigured()) return null;

  // Safeguard: Restrict role simulator to development builds or explicit evaluation flag
  const isDev = Boolean(import.meta.env?.DEV);
  const isEvalMode = typeof window !== 'undefined' && (
    localStorage.getItem('eval_simulator_enabled') === 'true' ||
    new URLSearchParams(window.location.search).get('eval_simulator') === '1'
  );

  // Guard: Never render in production unless explicitly enabled for evaluation
  if (!currentUser || (!isDev && !isEvalMode)) return null;

  return (
    <div className="fixed bottom-3 left-3 z-50 font-mono text-xs select-none">
      <div className="bg-white dark:bg-slate-900 border border-purple-300 dark:border-purple-800/80 rounded-lg shadow-2xl overflow-hidden max-w-xs">
        {/* Header Toggle */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full px-3 py-2 bg-purple-100 hover:bg-purple-200 text-purple-900 dark:bg-purple-950/70 dark:hover:bg-purple-950 dark:text-purple-300 flex items-center justify-between gap-2 cursor-pointer transition"
        >
          <div className="flex items-center gap-1.5 text-[11px] font-bold">
            <ShieldAlert className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
            <span>DEV / EVALUATION ROLE SIMULATOR</span>
          </div>
          {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
        </button>

        {/* Expanded Panel */}
        {expanded && (
          <div className="p-3 bg-slate-50 dark:bg-slate-950/95 space-y-2.5 text-[11px] text-slate-700 dark:text-slate-300 border-t border-purple-200 dark:border-purple-900/60">
            <div className="p-2 bg-purple-50 dark:bg-purple-950/40 rounded border border-purple-200 dark:border-purple-800/50 text-[10px] text-purple-800 dark:text-purple-300 space-y-1">
              <div className="flex items-center gap-1 font-bold text-amber-700 dark:text-amber-400">
                <AlertTriangle className="w-3 h-3" />
                <span>NOT A PRODUCTION SECURITY CONTROL</span>
              </div>
              <p className="text-slate-600 dark:text-slate-400 leading-normal">
                This testing panel simulates role assignments in the client prototype. Production deployment requires server-side session tokens.
              </p>
            </div>

            <div>
              <span className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-bold block mb-1">
                Simulate Operational Role:
              </span>
              <div className="space-y-1">
                {(['soc_analyst', 'security_engineer', 'it_operations', 'super_admin'] as UserRole[]).map((r) => {
                  const isCurrent = currentUser.role === r;
                  const meta = ROLE_METADATA[r];
                  return (
                    <button
                      key={r}
                      onClick={() => switchRoleDemo(r)}
                      disabled={isCurrent}
                      className={`w-full px-2 py-1.5 rounded text-left transition flex items-center justify-between cursor-pointer disabled:opacity-60 disabled:cursor-default ${
                        isCurrent
                          ? 'bg-purple-100 text-purple-900 border border-purple-400 font-bold dark:bg-purple-900/80 dark:text-purple-200 dark:border-purple-600'
                          : 'bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-800'
                      }`}
                    >
                      <span>{meta.label}</span>
                      {isCurrent && <span className="text-[9px] text-blue-700 dark:text-cyan-300 font-bold">ACTIVE</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
