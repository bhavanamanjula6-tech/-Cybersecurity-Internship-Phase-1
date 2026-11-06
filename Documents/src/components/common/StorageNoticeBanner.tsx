import React, { useState, useEffect, useCallback } from 'react';
import { Database, AlertCircle, ChevronDown, ChevronUp, RefreshCw, CheckCircle2, AlertTriangle } from 'lucide-react';

import { isSupabaseConfigured, getSupabaseConfigurationStatus } from '../../lib/supabaseClient';
import { checkDatabaseConnectivity, DatabaseConnectivityStatus } from '../../services/adminMetricsService';

export interface StorageNoticeBannerProps {
  isLive?: boolean;
  probeOverride?: () => Promise<{ success: boolean; error?: string }>;
}

export const StorageNoticeBanner: React.FC<StorageNoticeBannerProps> = ({
  isLive: propIsLive,
  probeOverride,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [isProbing, setIsProbing] = useState(false);
  const [dbStatus, setDbStatus] = useState<DatabaseConnectivityStatus>(() => {
    const configured = isSupabaseConfigured();
    return {
      isConfigured: configured,
      isConnected: propIsLive === true,
      mode: getSupabaseConfigurationStatus().mode,
      statusBadge: configured ? (propIsLive === true ? 'Connected' : 'Configured (Unverified)') : 'Local Demo',
      detail: configured
        ? (propIsLive === true ? 'PostgreSQL connection verified.' : 'Supabase credentials detected; verifying connectivity...')
        : 'Decoupled via typed repository interfaces. Not connected to a multi-user backend database.',
      checkedAt: new Date().toISOString(),
    };
  });

  const runProbe = useCallback(async () => {
    if (!isSupabaseConfigured()) {
      setDbStatus({
        isConfigured: false,
        isConnected: false,
        mode: 'development_demo',
        statusBadge: 'Local Demo',
        detail: 'Supabase credentials not configured. Local browser/in-memory adapters are active.',
        checkedAt: new Date().toISOString(),
      });
      return;
    }

    setIsProbing(true);
    try {
      const res = await checkDatabaseConnectivity(probeOverride);
      setDbStatus(res);
    } catch (err: any) {
      setDbStatus({
        isConfigured: true,
        isConnected: false,
        mode: 'live_supabase',
        statusBadge: 'Unreachable',
        detail: 'Database is configured, but connectivity probe encountered an exception.',
        errorMessage: err?.message || 'Connection check failed.',
        checkedAt: new Date().toISOString(),
      });
    } finally {
      setIsProbing(false);
    }
  }, [probeOverride]);

  useEffect(() => {
    if (propIsLive !== undefined && !probeOverride) {
      // If propIsLive was explicitly passed without a probe override, update status accordingly
      setDbStatus((prev) => ({
        ...prev,
        isConnected: propIsLive,
        statusBadge: propIsLive ? 'Connected' : (prev.isConfigured ? 'Unreachable' : 'Local Demo'),
      }));
      return;
    }
    runProbe();
  }, [propIsLive, runProbe, probeOverride]);

  // Determine current display presentation
  const isConfigured = dbStatus.isConfigured;
  const isConnected = dbStatus.isConnected;
  const isUnreachable = isConfigured && !isConnected && dbStatus.statusBadge === 'Unreachable';
  const isUnverified = isConfigured && !isConnected && !isUnreachable;

  if (isConnected) {
    return (
      <div className="bg-emerald-50/90 dark:bg-slate-900/90 border-b border-emerald-200 dark:border-emerald-900/40 px-4 py-1.5 text-xs text-emerald-900 dark:text-slate-300 transition-colors">
        <div className="flex items-center justify-between gap-3 max-w-7xl mx-auto">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-emerald-800 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-300 dark:border-emerald-800/60">
              <Database className="w-3 h-3 text-emerald-700 dark:text-emerald-400" />
              PERSISTENT STORAGE: CONNECTED / VERIFIED
            </span>
            <span className="hidden md:inline text-emerald-800/80 dark:text-slate-400 text-[11px]">
              Connected to live PostgreSQL database with Row-Level Security (RLS) enforcement.
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => runProbe()}
              disabled={isProbing}
              title="Re-verify database connectivity"
              className="text-emerald-800 hover:text-emerald-950 dark:text-emerald-400 dark:hover:text-emerald-300 flex items-center gap-1 font-mono text-[11px] cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${isProbing ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">{isProbing ? 'Verifying...' : 'Recheck'}</span>
            </button>
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-emerald-800 hover:text-emerald-950 dark:text-emerald-400 dark:hover:text-emerald-300 flex items-center gap-1 font-mono text-[11px] underline cursor-pointer"
            >
              {expanded ? 'Hide Details' : 'View Architecture Notes'}
              {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
        </div>

        {expanded && (
          <div className="mt-2 pt-2 border-t border-emerald-200 dark:border-slate-800 text-[11px] text-slate-700 dark:text-slate-400 space-y-1 max-w-7xl mx-auto bg-white dark:bg-slate-950/60 p-3 rounded border border-emerald-200 dark:border-slate-800">
            <div className="flex items-center gap-1.5 text-emerald-800 dark:text-emerald-300 font-semibold">
              <AlertCircle className="w-3.5 h-3.5" />
              Active Supabase Storage Architecture:
            </div>
            <ul className="list-disc pl-5 space-y-1 text-slate-700 dark:text-slate-300">
              <li><strong>Multi-User Persistent State:</strong> Alert triage, incident response tasks, and notes are persisted across sessions in PostgreSQL.</li>
              <li><strong>Row-Level Security Enforcement:</strong> Database-level RLS policies govern operational queue segregation, analyst note privacy, and IT Operations task scoping.</li>
              <li><strong>Append-Only Audit Trail:</strong> Operational actions and platform events are stored in WORM-immutable audit tables protected by PostgreSQL database triggers.</li>
              <li><strong>Super Admin Isolation:</strong> Platform administrators are architecturally restricted by PostgreSQL RLS from accessing operational incident records.</li>
            </ul>
          </div>
        )}
      </div>
    );
  }

  if (isUnreachable) {
    return (
      <div className="bg-rose-50/90 dark:bg-slate-900/90 border-b border-rose-200 dark:border-rose-900/40 px-4 py-1.5 text-xs text-rose-900 dark:text-slate-300 transition-colors">
        <div className="flex items-center justify-between gap-3 max-w-7xl mx-auto">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-rose-800 dark:text-rose-400 bg-rose-100 dark:bg-rose-950/60 px-1.5 py-0.5 rounded border border-rose-300 dark:border-rose-800/60">
              <AlertTriangle className="w-3 h-3 text-rose-600 dark:text-rose-400" />
              PERSISTENT STORAGE: DATABASE UNREACHABLE
            </span>
            <span className="hidden md:inline text-rose-800/80 dark:text-slate-400 text-[11px]">
              Database configured, but connectivity probe failed. Fallback fail-safe mode active.
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => runProbe()}
              disabled={isProbing}
              title="Retry database connectivity probe"
              className="px-2 py-0.5 rounded bg-rose-100 hover:bg-rose-200 dark:bg-rose-950/80 dark:hover:bg-rose-900/80 text-rose-900 dark:text-rose-300 border border-rose-300 dark:border-rose-700 flex items-center gap-1 font-mono text-[11px] cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${isProbing ? 'animate-spin' : ''}`} />
              <span>{isProbing ? 'Retrying...' : 'Retry Probe'}</span>
            </button>
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-rose-800 hover:text-rose-950 dark:text-rose-400 dark:hover:text-rose-300 flex items-center gap-1 font-mono text-[11px] underline cursor-pointer"
            >
              {expanded ? 'Hide Details' : 'View Architecture Notes'}
              {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
        </div>

        {expanded && (
          <div className="mt-2 pt-2 border-t border-rose-200 dark:border-slate-800 text-[11px] text-slate-700 dark:text-slate-400 space-y-1 max-w-7xl mx-auto bg-white dark:bg-slate-950/60 p-3 rounded border border-rose-200 dark:border-slate-800">
            <div className="flex items-center gap-1.5 text-rose-800 dark:text-rose-300 font-semibold">
              <AlertCircle className="w-3.5 h-3.5" />
              Database Unreachable Diagnostics:
            </div>
            <p className="text-slate-700 dark:text-slate-300">
              The application detected Supabase configuration parameters, but the live connection probe failed.
              {dbStatus.errorMessage && (
                <span className="block font-mono text-[10px] text-rose-700 dark:text-rose-400 mt-1">
                  Probe Error: {dbStatus.errorMessage}
                </span>
              )}
            </p>
            <ul className="list-disc pl-5 space-y-1 text-slate-700 dark:text-slate-300 pt-1">
              <li><strong>Fail-Safe Isolation:</strong> The platform will not silently corrupt state when the database is unreachable.</li>
              <li><strong>Network & Credentials:</strong> Ensure PostgreSQL project endpoint is active and firewall/CORS rules permit access.</li>
            </ul>
          </div>
        )}
      </div>
    );
  }

  if (isUnverified) {
    return (
      <div className="bg-blue-50/90 dark:bg-slate-900/90 border-b border-blue-200 dark:border-blue-900/40 px-4 py-1.5 text-xs text-blue-900 dark:text-slate-300 transition-colors">
        <div className="flex items-center justify-between gap-3 max-w-7xl mx-auto">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-blue-800 dark:text-blue-300 bg-blue-100 dark:bg-blue-950/60 px-1.5 py-0.5 rounded border border-blue-300 dark:border-blue-800/60">
              <Database className="w-3 h-3 text-blue-600 dark:text-blue-400" />
              PERSISTENT STORAGE: CONFIGURED (UNVERIFIED)
            </span>
            <span className="hidden md:inline text-blue-800/80 dark:text-slate-400 text-[11px]">
              Supabase configuration detected; verifying PostgreSQL connectivity...
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => runProbe()}
              disabled={isProbing}
              className="text-blue-800 hover:text-blue-950 dark:text-blue-400 dark:hover:text-blue-300 flex items-center gap-1 font-mono text-[11px] cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${isProbing ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">{isProbing ? 'Probing...' : 'Probe Now'}</span>
            </button>
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-blue-800 hover:text-blue-950 dark:text-blue-400 dark:hover:text-blue-300 flex items-center gap-1 font-mono text-[11px] underline cursor-pointer"
            >
              {expanded ? 'Hide Details' : 'View Architecture Notes'}
              {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
        </div>

        {expanded && (
          <div className="mt-2 pt-2 border-t border-blue-200 dark:border-slate-800 text-[11px] text-slate-700 dark:text-slate-400 space-y-1 max-w-7xl mx-auto bg-white dark:bg-slate-950/60 p-3 rounded border border-blue-200 dark:border-slate-800">
            <div className="flex items-center gap-1.5 text-blue-800 dark:text-blue-300 font-semibold">
              <AlertCircle className="w-3.5 h-3.5" />
              Unverified Storage State:
            </div>
            <p className="text-slate-700 dark:text-slate-300">
              Client credentials are configured in the environment, but a live query probe has not yet confirmed two-way connectivity to the public schema.
            </p>
          </div>
        )}
      </div>
    );
  }

  // Fallback: Local Browser Scope (unconfigured)
  return (
    <div className="bg-amber-50/90 dark:bg-slate-900/90 border-b border-amber-200 dark:border-amber-900/40 px-4 py-1.5 text-xs text-amber-900 dark:text-slate-300 transition-colors">
      <div className="flex items-center justify-between gap-3 max-w-7xl mx-auto">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="flex items-center gap-1 font-mono text-[11px] font-semibold text-amber-800 dark:text-amber-400 bg-amber-100 dark:bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-300 dark:border-amber-800/60">
            <Database className="w-3 h-3 text-amber-700 dark:text-amber-400" />
            PHASE 1 STORAGE ADAPTER: LOCAL BROWSER SCOPE
          </span>
          <span className="hidden md:inline text-amber-800/80 dark:text-slate-400 text-[11px]">
            Decoupled via typed repository interfaces. Not connected to a multi-user backend database.
          </span>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-amber-800 hover:text-amber-950 dark:text-amber-400 dark:hover:text-amber-300 flex items-center gap-1 font-mono text-[11px] underline cursor-pointer"
        >
          {expanded ? 'Hide Details' : 'View Architecture Notes'}
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>
      </div>

      {expanded && (
        <div className="mt-2 pt-2 border-t border-amber-200 dark:border-slate-800 text-[11px] text-slate-700 dark:text-slate-400 space-y-1 max-w-7xl mx-auto bg-white dark:bg-slate-950/60 p-3 rounded border border-amber-200 dark:border-slate-800">
          <div className="flex items-center gap-1.5 text-amber-800 dark:text-amber-300 font-semibold">
            <AlertCircle className="w-3.5 h-3.5" />
            Documented Architectural Limitations for Phase 1 Prototype:
          </div>
          <ul className="list-disc pl-5 space-y-1 text-slate-700 dark:text-slate-300">
            <li><strong>Single-Device Isolation:</strong> Data modified in this session is persisted solely to browser localStorage (~5MB quota) and is not shared across multi-analyst teams.</li>
            <li><strong>Zero Sensitive Secrets:</strong> No credentials, private tokens, or production telemetry are permitted in browser storage.</li>
            <li><strong>Modular Interface Boundary:</strong> All operations utilize <code className="text-blue-700 dark:text-cyan-300">IAlertRepository</code>, <code className="text-blue-700 dark:text-cyan-300">IMITRERepository</code>, and <code className="text-blue-700 dark:text-cyan-300">IAuditLogRepository</code> contracts, allowing full backend swap (PostgreSQL / Cloud SQL) without frontend refactoring.</li>
            <li><strong>Response Action Execution:</strong> All quarantine, account locks, and IP blocks are simulated with verifiable audit logging. No commands are dispatched to live production hosts.</li>
          </ul>
        </div>
      )}
    </div>
  );
};
