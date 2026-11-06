import React from 'react';
import { Database, ShieldCheck, Cpu } from 'lucide-react';

interface ProvenanceBadgeProps {
  type: 'authentic_mitre' | 'synthetic_demo' | 'cic_ids_sample' | 'deterministic_rule' | 'controlled_simulation';
  label?: string;
  className?: string;
}

export const ProvenanceBadge: React.FC<ProvenanceBadgeProps> = ({
  type,
  label,
  className = '',
}) => {
  if (type === 'controlled_simulation') {
    return (
      <span
        title="Notice: Controlled Simulated Windows Event Detection Pipeline event"
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wide font-bold bg-amber-100 text-amber-800 border border-amber-300 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-700 ${className}`}
      >
        <Cpu className="w-3 h-3 text-amber-600 dark:text-amber-400" />
        <span>{label || 'CONTROLLED SIMULATION'}</span>
      </span>
    );
  }

  if (type === 'authentic_mitre') {
    return (
      <span
        title="Curated MITRE ATT&CK Enterprise v14.1 reference subset"
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wide bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/70 dark:text-blue-300 dark:border-blue-800/80 ${className}`}
      >
        <ShieldCheck className="w-3 h-3 text-blue-600 dark:text-blue-400" />
        <span>{label || 'MITRE v14.1 Subset'}</span>
      </span>
    );
  }

  if (type === 'synthetic_demo') {
    return (
      <span
        title="Notice: Synthetic demonstration scenario. Not a live intrusion."
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wide bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/70 dark:text-purple-300 dark:border-purple-800/70 ${className}`}
      >
        <Database className="w-3 h-3 text-purple-600 dark:text-purple-400" />
        <span>{label || 'SYNTHETIC SCENARIO'}</span>
      </span>
    );
  }

  if (type === 'cic_ids_sample') {
    return (
      <span
        title="Synthetic network flow example following the CIC-IDS2017 schema"
        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wide bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800/70 ${className}`}
      >
        <Database className="w-3 h-3 text-amber-600 dark:text-amber-400" />
        <span>{label || 'CIC-IDS2017 Schema'}</span>
      </span>
    );
  }

  return (
    <span
      title="Phase 1 Deterministic Rule Engine (No live LLM)"
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wide bg-blue-50 text-blue-800 border border-blue-200 dark:bg-cyan-950/70 dark:text-cyan-300 dark:border-cyan-800/70 ${className}`}
    >
      <Cpu className="w-3 h-3 text-blue-600 dark:text-cyan-400" />
      <span>{label || 'Deterministic Rule'}</span>
    </span>
  );
};
