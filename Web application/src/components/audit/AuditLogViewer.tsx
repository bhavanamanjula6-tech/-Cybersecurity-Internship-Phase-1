import React, { useState } from 'react';
import { AuditLogEntry, ResponseActionType } from '../../types/audit';
import { UserProfile } from '../../types/auth';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import { FileText, ShieldCheck, Search, Filter, Database, Download, FileDown, AlertOctagon, RefreshCw } from 'lucide-react';
import { AuditExportService } from '../../services/auditExportService';
import { AuthorizationService } from '../../services/authorizationService';
import { getRepositories } from '../../repositories';

export interface AuditLogViewerProps {
  logs: AuditLogEntry[];
  initialAlertFilter?: string;
  currentUser?: UserProfile;
  isLiveDatabase?: boolean;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
}

const ACTION_LABELS: Record<string, string> = {
  isolate_host: 'Endpoint Isolation',
  unisolate_host: 'Host Reconnection',
  block_ip: 'IP Egress Block',
  unblock_ip: 'IP Unblock',
  lock_account: 'Account Lockout / Reject / Suspend',
  unlock_account: 'Account Approval / Reactivate',
  revoke_token: 'Session Token Revocation',
  platform_bootstrap: 'Platform Bootstrap',
  INITIALIZE_BOOTSTRAP_STATE: 'Bootstrap Init',
  collect_forensics: 'Forensics Package',
  remediation_verified: 'Remediation Verified',
};

function formatActionType(action: string): string {
  return ACTION_LABELS[action] || action.replace(/_/g, ' ');
}

export const AuditLogViewer: React.FC<AuditLogViewerProps> = ({
  logs,
  initialAlertFilter,
  currentUser,
  isLiveDatabase,
  isLoading = false,
  error = null,
  onRetry,
}) => {
  const [search, setSearch] = useState(initialAlertFilter || '');
  const [selectedAction, setSelectedAction] = useState<string>('all');
  const [isExporting, setIsExporting] = useState<'csv' | 'json' | null>(null);
  const [exportFeedback, setExportFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const isSuperAdmin = currentUser ? AuthorizationService.canExportAuditLogs(currentUser.role) : false;

  const handleExport = (format: 'csv' | 'json') => {
    if (!currentUser) return;
    setExportFeedback(null);
    setIsExporting(format);

    try {
      const result = AuditExportService.downloadExport(filteredLogs, currentUser, format);
      setExportFeedback({
        type: 'success',
        message: `Successfully generated and downloaded ${result.filename} (${result.rowCount} record${result.rowCount === 1 ? '' : 's'}).`,
      });
    } catch (err: any) {
      setExportFeedback({
        type: 'error',
        message: err.message || 'Export failed due to an authorization or processing error.',
      });
    } finally {
      setIsExporting(null);
    }
  };

  const filteredLogs = logs.filter((log) => {
    // Non-super-admin roles (Security Engineer, IT Operations) view operational containment records only
    if (currentUser && currentUser.role !== 'super_admin') {
      if (
        log.actionType === 'platform_bootstrap' ||
        (log.actionType as string) === 'INITIALIZE_BOOTSTRAP_STATE' ||
        log.targetResource === 'PLATFORM_SYSTEM' ||
        log.targetResource === 'SYSTEM_CORE'
      ) {
        return false;
      }
    }
    if (selectedAction !== 'all' && log.actionType !== selectedAction) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        log.id.toLowerCase().includes(q) ||
        log.targetResource.toLowerCase().includes(q) ||
        log.actorName.toLowerCase().includes(q) ||
        log.justification.toLowerCase().includes(q) ||
        (log.associatedAlertId && log.associatedAlertId.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const isLive =
    isLiveDatabase !== undefined
      ? isLiveDatabase
      : (() => {
          try {
            return getRepositories().isLive;
          } catch {
            return false;
          }
        })();

  const hasNonSimulatedLogs = logs.some((l) => !l.isSimulated);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <FileText className="w-5 h-5 text-purple-400" />
              Containment & Governance Audit Trail
            </h1>
            {isLive && hasNonSimulatedLogs ? (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wide bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/70 dark:text-emerald-300 dark:border-emerald-800/80">
                <Database className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                <span>POSTGRESQL AUDIT</span>
              </span>
            ) : !isLive && hasNonSimulatedLogs ? (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono tracking-wide bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/70 dark:text-purple-300 dark:border-purple-800/80">
                <FileText className="w-3 h-3 text-purple-600 dark:text-purple-400" />
                <span>LOCAL GOVERNANCE AUDIT</span>
              </span>
            ) : (
              <ProvenanceBadge type="synthetic_demo" label="SIMULATED AUDIT" />
            )}
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Tamper-evident, append-only record of platform governance and operational containment procedures.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {onRetry && (
            <Button
              size="sm"
              variant="secondary"
              onClick={onRetry}
              disabled={isLoading}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            >
              {isLoading ? 'Refreshing...' : 'Refresh Audit'}
            </Button>
          )}

          {/* Super Admin Accessible Export Controls */}
          {isSuperAdmin && (
            <>
              <button
                onClick={() => handleExport('csv')}
                disabled={isExporting !== null}
                aria-label="Export audit logs as CSV"
                className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-mono font-medium flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 shadow-xs"
              >
                <Download className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
                <span>{isExporting === 'csv' ? 'Exporting...' : 'Export CSV'}</span>
              </button>
              <button
                onClick={() => handleExport('json')}
                disabled={isExporting !== null}
                aria-label="Export audit logs as JSON"
                className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-mono font-medium flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 shadow-xs"
              >
                <FileDown className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
                <span>{isExporting === 'json' ? 'Exporting...' : 'Export JSON'}</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Query / Database Error Banner */}
      {error && (
        <div className="p-3 bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800 rounded-lg text-xs text-rose-800 dark:text-rose-200 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          {onRetry && (
            <Button size="xs" variant="outline" onClick={onRetry} disabled={isLoading}>
              Retry
            </Button>
          )}
        </div>
      )}

      {/* Export Status Feedback */}
      {exportFeedback && (
        <div
          role="status"
          className={`p-3 text-xs rounded-lg border flex items-center justify-between ${
            exportFeedback.type === 'success'
              ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-900/60'
              : 'bg-rose-50 text-rose-800 border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-900/60'
          }`}
        >
          <span>{exportFeedback.message}</span>
          <button
            onClick={() => setExportFeedback(null)}
            className="text-[11px] font-mono underline ml-3 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col sm:flex-row gap-2 shadow-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by ID, target resource, operator name, or justification..."
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 rounded pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
          />
        </div>

        <select
          value={selectedAction}
          onChange={(e) => setSelectedAction(e.target.value)}
          className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
          aria-label="Filter audit logs by action"
        >
          <option value="all">All Actions</option>
          <option value="isolate_host">Endpoint Isolation</option>
          <option value="block_ip">IP Egress Block</option>
          <option value="lock_account">Account Lockout / Reject</option>
          <option value="unlock_account">Account Approval / Unlock</option>
          <option value="platform_bootstrap">Platform Bootstrap</option>
          <option value="INITIALIZE_BOOTSTRAP_STATE">Bootstrap Init</option>
          <option value="collect_forensics">Forensics Package</option>
          <option value="remediation_verified">Remediation Verified</option>
        </select>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-950/80 border-b border-slate-200 dark:border-slate-800 text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 tracking-wider">
                <th className="py-2.5 px-3">Audit ID</th>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Action Type</th>
                <th className="py-2.5 px-3">Target Resource</th>
                <th className="py-2.5 px-3">Operator & Role</th>
                <th className="py-2.5 px-3">Mandatory Justification</th>
                <th className="py-2.5 px-3 text-right">Execution Mode</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800/80 font-sans">
              {isLoading && logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-xs">
                    <div className="flex flex-col items-center justify-center gap-2 text-purple-600 dark:text-purple-400">
                      <RefreshCw className="w-5 h-5 animate-spin" />
                      <span className="font-medium">Loading containment and governance audit trail...</span>
                      <span className="text-[11px] text-slate-400 font-mono">Querying operational audit records...</span>
                    </div>
                  </td>
                </tr>
              ) : error && logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-xs">
                    <div className="flex flex-col items-center justify-center gap-2 text-rose-600 dark:text-rose-400 max-w-md mx-auto">
                      <AlertOctagon className="w-5 h-5" />
                      <span className="font-medium">Failed to retrieve audit trail</span>
                      <span className="text-[11px] text-rose-700 dark:text-rose-300 font-mono">{error}</span>
                      {onRetry && (
                        <div className="mt-2">
                          <Button size="xs" variant="outline" onClick={onRetry} disabled={isLoading}>
                            Retry Audit Query
                          </Button>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 italic text-xs">
                    {logs.length === 0
                      ? 'No audit records found under active operational scope.'
                      : 'No audit records found matching your filter criteria.'}
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition">
                    <td className="py-3 px-3 font-mono font-bold text-slate-900 dark:text-slate-200">{log.id}</td>
                    <td className="py-3 px-3 font-mono text-slate-500 dark:text-slate-400 text-[11px]">
                      {new Date(log.timestamp).toUTCString().slice(5, 25)}
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <span className="px-2 py-0.5 rounded bg-purple-50 dark:bg-purple-950/80 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800 text-[10px] uppercase font-bold">
                        {formatActionType(log.actionType)}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <div className="text-blue-600 dark:text-cyan-300 font-semibold">{log.targetResource}</div>
                      {log.associatedAlertId && (
                        <div className="text-[10px] text-slate-500 dark:text-slate-400">
                          Alert: {log.associatedAlertId}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-medium text-slate-900 dark:text-slate-200">{log.actorName}</div>
                      <div className="text-[10px] font-mono text-slate-500 uppercase">{log.actorRole}</div>
                    </td>
                    <td className="py-3 px-3 text-slate-700 dark:text-slate-300 max-w-xs">{log.justification}</td>
                    <td className="py-3 px-3 text-right font-mono">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          log.isSimulated
                            ? 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700'
                            : isLive
                            ? 'bg-emerald-50 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800 font-semibold'
                            : 'bg-purple-50 dark:bg-purple-950/80 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800 font-semibold'
                        }`}
                      >
                        {log.isSimulated ? 'SIMULATED' : isLive ? 'POSTGRESQL' : 'LOCAL RECORD'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
