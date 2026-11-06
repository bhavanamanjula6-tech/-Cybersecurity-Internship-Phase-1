import React, { useState } from 'react';
import {
  Server,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ExternalLink,
  Search,
  Filter,
  Info,
  Lock,
  Layers,
  FileText,
  Activity,
  ArrowRight,
} from 'lucide-react';
import { EndpointRecord, ContainmentState } from '../../services/endpointInventoryService';
import { ProvenanceBadge } from '../common/ProvenanceBadge';

interface EndpointInventoryViewProps {
  endpoints: EndpointRecord[];
  onSelectTask?: (taskId: string) => void;
  onInspectAlert?: (alertId: string) => void;
  className?: string;
}

export const EndpointInventoryView: React.FC<EndpointInventoryViewProps> = ({
  endpoints,
  onSelectTask,
  onInspectAlert,
  className = '',
}) => {
  const [search, setSearch] = useState('');
  const [containmentFilter, setContainmentFilter] = useState<string>('all');

  const filteredEndpoints = endpoints.filter((ep) => {
    if (containmentFilter !== 'all' && ep.containmentStatus !== containmentFilter) {
      return false;
    }
    if (search.trim()) {
      const q = search.toLowerCase().trim();
      return (
        ep.hostname.toLowerCase().includes(q) ||
        ep.ipAddress.toLowerCase().includes(q) ||
        ep.fqdn.toLowerCase().includes(q) ||
        ep.associatedTasks.some((t) => t.taskId.toLowerCase().includes(q) || t.title.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const getContainmentBadge = (status: ContainmentState) => {
    switch (status) {
      case 'Simulated Isolated':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/80 dark:text-purple-300 dark:border-purple-800">
            <Lock className="w-3 h-3 text-purple-600 dark:text-purple-400" />
            SIMULATED ISOLATED
          </span>
        );
      case 'Quarantine Pending':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800">
            <Clock className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            QUARANTINE PENDING
          </span>
        );
      case 'Verified Recovered':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-800">
            <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
            VERIFIED RECOVERED
          </span>
        );
      case 'Active / Standard Network':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            <Activity className="w-3 h-3 text-slate-500" />
            ACTIVE / NOT ISOLATED
          </span>
        );
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Header and Scope Notice */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold font-mono uppercase text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Server className="w-5 h-5 text-amber-600 dark:text-amber-400" />
              IT Operations: Endpoint & Host Inventory
            </h2>
            <ProvenanceBadge type="synthetic_demo" label="DERIVED FROM ASSIGNED DATA" />
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Read-only asset directory aggregated strictly from assigned remediation tasks and authorized incident alert evidence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
            SCOPED ACCESS ONLY &bull; {endpoints.length} ASSETS DISCOVERED
          </span>
        </div>
      </div>

      {/* Security Domain & Non-Fabrication Invariant */}
      <div className="p-3 bg-amber-50/50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/40 rounded-xl flex items-start gap-2.5 text-xs text-amber-900 dark:text-amber-300">
        <Info className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5 font-sans">
          <p className="font-semibold text-[11px]">
            Data Provenance & Asset Scoping Boundary:
          </p>
          <p className="text-[11px] leading-relaxed text-amber-800 dark:text-amber-300/90">
            This inventory is dynamically derived from remediation tasks assigned to IT Operations and their linked alerts. Missing fields are honestly reported as "Not available" or "Not recorded in telemetry" to prevent speculative fabrication. Super Admins do not possess access to private host operational data.
          </p>
        </div>
      </div>

      {/* Search and Filter Toolbar */}
      <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col sm:flex-row gap-2.5 shadow-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search Hostname, IP address, FQDN, or task ID..."
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 rounded pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
          />
        </div>

        <select
          value={containmentFilter}
          onChange={(e) => setContainmentFilter(e.target.value)}
          className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none cursor-pointer"
          aria-label="Filter endpoints by containment status"
        >
          <option value="all">All Containment States</option>
          <option value="Simulated Isolated">Simulated Isolated</option>
          <option value="Quarantine Pending">Quarantine Pending</option>
          <option value="Verified Recovered">Verified Recovered</option>
          <option value="Active / Standard Network">Active / Standard Network</option>
        </select>
      </div>

      {/* Endpoints List */}
      {filteredEndpoints.length === 0 ? (
        <div className="p-12 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-center space-y-2 shadow-xs">
          <Server className="w-8 h-8 text-slate-400 mx-auto" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
            No Endpoints Found
          </h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            No authorized endpoints match the filter criteria. Endpoints only populate from assigned remediation tasks and authorized incident alerts.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredEndpoints.map((ep) => (
            <div
              key={ep.id}
              className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-3 hover:border-slate-300 dark:hover:border-slate-700 transition"
            >
              {/* Top Row: Identity & Status */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-slate-100 dark:border-slate-800/80 pb-2.5">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="p-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                      <Server className="w-4 h-4" />
                    </span>
                    <span className="text-sm font-bold font-mono text-slate-900 dark:text-slate-100">
                      {ep.hostname}
                    </span>
                    {getContainmentBadge(ep.containmentStatus)}
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                      {ep.id}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center gap-3 flex-wrap">
                    <span>IP: <strong className="text-blue-600 dark:text-cyan-400">{ep.ipAddress}</strong></span>
                    <span>FQDN: <strong className="text-slate-700 dark:text-slate-300">{ep.fqdn}</strong></span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-[10px] font-mono text-slate-400 block">
                    {ep.associatedTasks.length} Assigned Task{ep.associatedTasks.length === 1 ? '' : 's'} &bull; {ep.associatedAlerts.length} Scoped Alert{ep.associatedAlerts.length === 1 ? '' : 's'}
                  </span>
                </div>
              </div>

              {/* Host Metadata & Containment Rationale */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {/* Operating System & Inferred Notice */}
                <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 space-y-1">
                  <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                    Operating System & Telemetry Evidence
                  </span>
                  <div className="text-[11px] text-slate-800 dark:text-slate-200 font-mono">
                    {ep.osDetails}
                  </div>
                  <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">
                    {ep.osIsInferred
                      ? 'Note: OS is inferred from execution binaries and Sysmon/Event log telemetry (not direct CMDB agent check).'
                      : 'Telemetry data source directly reflects observed alert evidence.'}
                  </p>
                </div>

                {/* Containment State & Rationale */}
                <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 space-y-1">
                  <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                    Containment & Quarantine Rationale
                  </span>
                  <p className="text-[11px] text-slate-800 dark:text-slate-200 font-sans leading-relaxed">
                    {ep.containmentRationale}
                  </p>
                </div>
              </div>

              {/* Linked Remediation Tasks */}
              {ep.associatedTasks.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                    Linked Remediation Tasks
                  </span>
                  <div className="space-y-1">
                    {ep.associatedTasks.map((t) => (
                      <div
                        key={t.taskId}
                        className="p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                      >
                        <div className="flex items-center gap-2 truncate">
                          <span className="font-mono font-bold text-blue-700 dark:text-cyan-400 shrink-0">
                            {t.taskId}
                          </span>
                          <span className="text-[11px] text-slate-700 dark:text-slate-300 truncate">
                            {t.title}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <span
                            className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold uppercase border ${
                              t.status === 'completed'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950 dark:text-emerald-300'
                                : t.status === 'in_progress'
                                ? 'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950 dark:text-sky-300'
                                : 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950 dark:text-amber-300'
                            }`}
                          >
                            {t.status}
                          </span>
                          {onSelectTask && (
                            <button
                              type="button"
                              onClick={() => onSelectTask(t.taskId)}
                              className="text-[11px] font-mono text-blue-600 dark:text-cyan-400 hover:underline flex items-center gap-0.5 cursor-pointer"
                            >
                              <span>View Task</span>
                              <ArrowRight className="w-3 h-3" />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Linked Scoped Alerts */}
              {ep.associatedAlerts.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                    Linked Scoped Alerts
                  </span>
                  <div className="space-y-1">
                    {ep.associatedAlerts.map((a) => (
                      <div
                        key={a.alertId}
                        className="p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 flex items-center justify-between gap-2 text-xs"
                      >
                        <div className="flex items-center gap-2 truncate">
                          <span className="font-mono font-bold text-rose-700 dark:text-rose-400 shrink-0">
                            {a.alertId}
                          </span>
                          <span className="text-[11px] text-slate-700 dark:text-slate-300 truncate">
                            {a.title}
                          </span>
                        </div>

                        {onInspectAlert && (
                          <button
                            type="button"
                            onClick={() => onInspectAlert(a.alertId)}
                            className="text-[11px] font-mono text-blue-600 dark:text-cyan-400 hover:underline flex items-center gap-0.5 cursor-pointer shrink-0"
                          >
                            <span>Inspect Alert</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Provenance Footer */}
              <div className="pt-2 border-t border-slate-100 dark:border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10px] font-mono text-slate-400">
                <span>Provenance: {ep.provenance}</span>
                <span>Sources: {ep.dataSources.join(' • ')}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
