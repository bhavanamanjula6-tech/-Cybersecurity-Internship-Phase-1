import React from 'react';
import {
  Database,
  ShieldCheck,
  Cpu,
  Layers,
  Lock,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  Activity,
  FileText,
  Info,
} from 'lucide-react';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { DataSourceItem, DataSourceState } from '../../services/adminMetricsService';

interface DataSourceInventoryProps {
  items: DataSourceItem[];
  className?: string;
}

export const DataSourceInventory: React.FC<DataSourceInventoryProps> = ({
  items,
  className = '',
}) => {
  const renderStateBadge = (state: DataSourceState) => {
    switch (state) {
      case 'Connected':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-800">
            <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
            CONNECTED
          </span>
        );
      case 'Authentic Reference':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-800">
            <ShieldCheck className="w-3 h-3 text-blue-600 dark:text-blue-400" />
            AUTHENTIC REFERENCE
          </span>
        );
      case 'Synthetic Benchmark':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800">
            <Activity className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            SYNTHETIC BENCHMARK
          </span>
        );
      case 'Active (Append-Only)':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/80 dark:text-purple-300 dark:border-purple-800">
            <FileText className="w-3 h-3 text-purple-600 dark:text-purple-400" />
            ACTIVE (WORM LEDGER)
          </span>
        );
      case 'Configured':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-50 text-cyan-700 border border-cyan-200 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-800">
            <Cpu className="w-3 h-3 text-cyan-600 dark:text-cyan-400" />
            CONFIGURED (ADVISORY)
          </span>
        );
      case 'Standby':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            <HelpCircle className="w-3 h-3 text-slate-500 dark:text-slate-400" />
            STANDBY / LOCAL ADVISORY
          </span>
        );
      case 'Local Demo':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800">
            <Database className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            LOCAL PROTOTYPE
          </span>
        );
      case 'Unreachable':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800">
            <AlertTriangle className="w-3 h-3 text-rose-600 dark:text-rose-400" />
            UNREACHABLE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            UNKNOWN
          </span>
        );
    }
  };

  const getSourceIcon = (type: DataSourceItem['type']) => {
    switch (type) {
      case 'relational_db':
        return <Database className="w-4 h-4 text-purple-600 dark:text-purple-400" />;
      case 'threat_framework':
        return <ShieldCheck className="w-4 h-4 text-blue-600 dark:text-blue-400" />;
      case 'telemetry_benchmark':
        return <Activity className="w-4 h-4 text-amber-600 dark:text-amber-400" />;
      case 'audit_ledger':
        return <FileText className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />;
      case 'ai_copilot':
        return <Cpu className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />;
      default:
        return <Layers className="w-4 h-4 text-slate-500" />;
    }
  };

  return (
    <div className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-xs ${className}`}>
      {/* Panel Header */}
      <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-100 dark:bg-cyan-950/80 border border-cyan-300 dark:border-cyan-800 flex items-center justify-center text-cyan-700 dark:text-cyan-300">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold font-mono uppercase text-slate-900 dark:text-slate-100">
                Data Source Inventory & Provenance Catalog
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-50 text-cyan-700 border border-cyan-200 dark:bg-cyan-950 dark:text-cyan-300 dark:border-cyan-800">
                READ-ONLY CATALOG
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-sans">
              Authoritative accounting of persistence layers, intelligence taxonomies, synthetic schemas, and AI advisory engines.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
            {items.length} ACTIVE SOURCES CATALOGED
          </span>
        </div>
      </div>

      {/* Operational Isolation Reminder */}
      <div className="p-3 bg-purple-50/40 dark:bg-purple-950/20 border-b border-purple-100 dark:border-purple-900/30 flex items-start gap-2.5 text-[11px] text-purple-900 dark:text-purple-300 font-sans">
        <Lock className="w-4 h-4 text-purple-600 dark:text-purple-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong>Security Domain Invariant:</strong> This inventory catalogs data repositories, provenance metadata, and interface contracts. In compliance with RBAC Domain Separation, Super Admin consoles do NOT query or display operational intrusion alerts, analyst triage queues, or private investigation notes.
        </p>
      </div>

      {/* Data Source Cards / List */}
      <div className="divide-y divide-slate-200 dark:divide-slate-800">
        {items.map((item) => (
          <div
            key={item.id}
            className="p-4 hover:bg-slate-50/50 dark:hover:bg-slate-800/20 transition flex flex-col lg:flex-row lg:items-start justify-between gap-4"
          >
            {/* Left: Identity & Provenance */}
            <div className="space-y-2 flex-1">
              <div className="flex items-center gap-2.5 flex-wrap">
                <div className="p-1.5 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700/80">
                  {getSourceIcon(item.type)}
                </div>
                <span className="text-sm font-bold text-slate-900 dark:text-slate-100">
                  {item.name}
                </span>
                <ProvenanceBadge
                  type={item.provenanceType}
                  label={item.provenanceLabel}
                />
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                  {item.typeLabel}
                </span>
              </div>

              {/* Description & Scope Notice */}
              <div className="text-xs text-slate-600 dark:text-slate-400 font-sans space-y-1">
                <p>{item.scopeNotice}</p>
                <p className="text-[11px] text-slate-500 dark:text-slate-500 font-mono">
                  {item.stateDetail}
                </p>
              </div>

              {/* Isolation Notice */}
              <div className="flex items-center gap-1.5 text-[10px] font-mono text-purple-700 dark:text-purple-300/90 bg-purple-50/60 dark:bg-purple-950/40 px-2 py-1 rounded border border-purple-200/60 dark:border-purple-900/40 w-fit">
                <Lock className="w-3 h-3 text-purple-500 shrink-0" />
                <span>{item.isolationNotice}</span>
              </div>
            </div>

            {/* Right: State & Volume */}
            <div className="flex flex-row lg:flex-col items-center lg:items-end justify-between lg:justify-start gap-2 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-100 dark:border-slate-800">
              {renderStateBadge(item.state)}
              <span className="text-xs font-mono font-semibold text-slate-800 dark:text-slate-200">
                {item.recordCountLabel}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
