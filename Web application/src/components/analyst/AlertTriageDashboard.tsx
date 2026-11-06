import React, { useState, useMemo } from 'react';
import { SecurityAlert, AlertSeverity, AlertStatus } from '../../types/alert';
import { UserProfile } from '../../types/auth';
import { MitreTactic } from '../../types/mitre';
import { SeverityIndicator } from '../common/SeverityIndicator';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import { DESIGN_TOKENS } from '../../constants/designTokens';
import { AuthorizationService } from '../../services/authorizationService';
import { AlertMetricsService } from '../../services/alertMetricsService';
import { formatAttackIdDisplay } from '../../utils/mitreUtils';
import {
  Search,
  RefreshCw,
  AlertOctagon,
  ChevronRight,
  CheckSquare,
  Square,
  MinusSquare,
  CheckCircle2,
  AlertTriangle,
  X,
  Layers,
  ArrowRight,
  Clock,
  Filter,
  ArrowUpDown,
  ShieldCheck,
  ShieldAlert,
  Play,
} from 'lucide-react';
import { DetectionRecommendation } from '../../types/recommendation';
import { DetectionRecommendationsTriageView } from './DetectionRecommendationsTriageView';
import { MitreTechnique } from '../../types/mitre';
import { SimulateControlledAlertModal } from './SimulateControlledAlertModal';

interface AlertTriageDashboardProps {
  alerts: SecurityAlert[];
  tactics: MitreTactic[];
  onSelectAlert: (alert: SecurityAlert) => void;
  onRefresh: () => void;
  selectedAlertId?: string;
  onInvestigateAlert?: (alert: SecurityAlert) => void;
  currentUser?: UserProfile;
  onUpdateAlertStatus?: (alertId: string, status: AlertStatus) => Promise<void>;
  isLoading?: boolean;
  error?: string | null;
  recommendations?: DetectionRecommendation[];
  onReviewRecommendation?: (
    id: string,
    action: 'accept' | 'reject' | 'request_clarification',
    feedback?: string
  ) => Promise<void>;
  onValidateRecommendation?: (id: string, feedback?: string) => Promise<void>;
  onRefreshRecommendations?: () => void;
  onSimulateAlert?: (alert: SecurityAlert) => Promise<void>;
  techniques?: MitreTechnique[];
}

export const AlertTriageDashboard: React.FC<AlertTriageDashboardProps> = ({
  alerts,
  tactics,
  onSelectAlert,
  onRefresh,
  selectedAlertId,
  onInvestigateAlert,
  currentUser,
  onUpdateAlertStatus,
  isLoading = false,
  error = null,
  recommendations = [],
  onReviewRecommendation,
  onValidateRecommendation,
  onRefreshRecommendations,
  onSimulateAlert,
  techniques,
}) => {
  const [triageSubTab, setTriageSubTab] = useState<'alerts' | 'recommendations'>('alerts');
  const [isSimulateModalOpen, setIsSimulateModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverities, setSelectedSeverities] = useState<AlertSeverity[]>([]);
  const [selectedStatus, setSelectedStatus] = useState<AlertStatus | 'all'>('all');
  const [selectedTactic, setSelectedTactic] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'detectedAt' | 'severity' | 'confidenceScore'>('detectedAt');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Multi-alert selection state
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [isBatchProcessing, setIsBatchProcessing] = useState(false);
  const [batchFeedback, setBatchFeedback] = useState<{
    type: 'success' | 'warning' | 'error';
    message: string;
    succeeded: string[];
    failed: Array<{ id: string; error: string }>;
  } | null>(null);

  // Check if current user possesses alert:triage permission
  const canTriage = useMemo(() => {
    if (!currentUser) return false;
    return AuthorizationService.hasPermission(currentUser.role, 'alert:triage');
  }, [currentUser]);

  // Metrics computation
  const metrics = useMemo(() => {
    return {
      total: alerts.length,
      critical: alerts.filter((a) => a.severity === 'critical').length,
      high: alerts.filter((a) => a.severity === 'high').length,
      inTriage: alerts.filter((a) => a.status === 'in_triage').length,
      escalated: alerts.filter((a) => a.status === 'escalated').length,
      resolved: alerts.filter((a) => a.status === 'resolved' || a.status === 'false_positive').length,
    };
  }, [alerts]);

  // Filtered & sorted list
  const filteredAlerts = useMemo(() => {
    let result = [...alerts];

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter(
        (a) =>
          a.id.toLowerCase().includes(q) ||
          a.title.toLowerCase().includes(q) ||
          a.hostName.toLowerCase().includes(q) ||
          a.sourceIp.includes(q) ||
          (a.attack_id && a.attack_id.toLowerCase().includes(q)) ||
          (a.mitreTechniqueId && a.mitreTechniqueId.toLowerCase().includes(q))
      );
    }

    if (selectedSeverities.length > 0) {
      result = result.filter((a) => selectedSeverities.includes(a.severity));
    }

    if (selectedStatus !== 'all') {
      result = result.filter((a) => a.status === selectedStatus);
    }

    if (selectedTactic !== 'all') {
      result = result.filter((a) => a.mitreTacticId === selectedTactic);
    }

    // Sort
    result.sort((a, b) => {
      const order = sortOrder === 'asc' ? 1 : -1;
      if (sortBy === 'detectedAt') {
        return (new Date(a.detectedAt).getTime() - new Date(b.detectedAt).getTime()) * order;
      }
      if (sortBy === 'confidenceScore') {
        return (a.confidenceScore - b.confidenceScore) * order;
      }
      if (sortBy === 'severity') {
        const severityRank: Record<AlertSeverity, number> = {
          critical: 5,
          high: 4,
          medium: 3,
          low: 2,
          informational: 1,
        };
        return (severityRank[a.severity] - severityRank[b.severity]) * order;
      }
      return 0;
    });

    return result;
  }, [alerts, searchQuery, selectedSeverities, selectedStatus, selectedTactic, sortBy, sortOrder]);

  const toggleSeverity = (sev: AlertSeverity) => {
    setSelectedSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
  };

  const resetFilters = () => {
    setSearchQuery('');
    setSelectedSeverities([]);
    setSelectedStatus('all');
    setSelectedTactic('all');
    setSortBy('detectedAt');
    setSortOrder('desc');
  };

  // Selection handlers
  const handleToggleSelectAllFiltered = () => {
    const filteredIds = filteredAlerts.map((a) => a.id);
    const allSelected = filteredIds.length > 0 && filteredIds.every((id) => selectedAlertIds.includes(id));

    if (allSelected) {
      // Deselect all filtered
      setSelectedAlertIds((prev) => prev.filter((id) => !filteredIds.includes(id)));
    } else {
      // Select all filtered (union)
      setSelectedAlertIds((prev) => Array.from(new Set([...prev, ...filteredIds])));
    }
  };

  const handleToggleSelectOne = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedAlertIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleClearSelection = () => {
    setSelectedAlertIds([]);
    setBatchFeedback(null);
  };

  // Compute eligible counts for selected alerts
  const selectedAlertObjects = useMemo(() => {
    return alerts.filter((a) => selectedAlertIds.includes(a.id));
  }, [alerts, selectedAlertIds]);

  const eligibleForInTriage = useMemo(() => {
    return selectedAlertObjects.filter((a) =>
      AlertMetricsService.isStatusTransitionValid(a.status, 'in_triage')
    );
  }, [selectedAlertObjects]);

  const eligibleForEscalated = useMemo(() => {
    return selectedAlertObjects.filter((a) =>
      AlertMetricsService.isStatusTransitionValid(a.status, 'escalated')
    );
  }, [selectedAlertObjects]);

  const eligibleForResolved = useMemo(() => {
    return selectedAlertObjects.filter((a) =>
      AlertMetricsService.isStatusTransitionValid(a.status, 'resolved')
    );
  }, [selectedAlertObjects]);

  const eligibleForFalsePositive = useMemo(() => {
    return selectedAlertObjects.filter((a) =>
      AlertMetricsService.isStatusTransitionValid(a.status, 'false_positive')
    );
  }, [selectedAlertObjects]);

  // Execute bulk triage transition sequentially with per-record verification
  const handleExecuteBulkTransition = async (targetStatus: AlertStatus) => {
    if (isBatchProcessing) return;

    // 1. Re-verify authorization defensively
    if (!currentUser || !AuthorizationService.hasPermission(currentUser.role, 'alert:triage')) {
      setBatchFeedback({
        type: 'error',
        message: `Authorization Violation: Role "${currentUser?.role || 'operator'}" does not possess "alert:triage" permission.`,
        succeeded: [],
        failed: selectedAlertIds.map((id) => ({ id, error: 'Unauthorized role' })),
      });
      return;
    }

    // 2. Filter down to eligible alerts
    const eligibleAlerts = selectedAlertObjects.filter((a) =>
      AlertMetricsService.isStatusTransitionValid(a.status, targetStatus)
    );

    if (eligibleAlerts.length === 0) {
      setBatchFeedback({
        type: 'warning',
        message: `None of the selected ${selectedAlertIds.length} alerts can be transitioned to "${targetStatus}". Selected alerts are already in that state or prohibited by transition rules.`,
        succeeded: [],
        failed: [],
      });
      return;
    }

    if (!onUpdateAlertStatus) {
      setBatchFeedback({
        type: 'error',
        message: 'No update handler configured for alert status mutations.',
        succeeded: [],
        failed: eligibleAlerts.map((a) => ({ id: a.id, error: 'Missing handler' })),
      });
      return;
    }

    setIsBatchProcessing(true);
    setBatchFeedback(null);

    const succeeded: string[] = [];
    const failed: Array<{ id: string; error: string }> = [];

    // 3. Sequential update with individual error boundary
    for (const alert of eligibleAlerts) {
      try {
        await onUpdateAlertStatus(alert.id, targetStatus);
        succeeded.push(alert.id);
      } catch (err: any) {
        failed.push({
          id: alert.id,
          error: err.message || 'Update failed',
        });
      }
    }

    // 4. Reconcile selection state
    setSelectedAlertIds((prev) => prev.filter((id) => !succeeded.includes(id)));

    // 5. Construct feedback message
    if (failed.length === 0) {
      setBatchFeedback({
        type: 'success',
        message: `Successfully transitioned ${succeeded.length} alerts to "${targetStatus}": ${succeeded.join(', ')}.`,
        succeeded,
        failed: [],
      });
    } else if (succeeded.length > 0) {
      setBatchFeedback({
        type: 'warning',
        message: `Partial batch completion: ${succeeded.length} alerts updated to "${targetStatus}", ${failed.length} failed. Succeeded: ${succeeded.join(', ')}. Failed: ${failed.map((f) => `${f.id} (${f.error})`).join('; ')}.`,
        succeeded,
        failed,
      });
    } else {
      setBatchFeedback({
        type: 'error',
        message: `Bulk update failed: 0 of ${eligibleAlerts.length} alerts updated. Errors: ${failed.map((f) => `${f.id} (${f.error})`).join('; ')}.`,
        succeeded: [],
        failed,
      });
    }

    setIsBatchProcessing(false);
  };

  const allFilteredSelected =
    filteredAlerts.length > 0 &&
    filteredAlerts.every((a) => selectedAlertIds.includes(a.id));
  const someFilteredSelected =
    filteredAlerts.some((a) => selectedAlertIds.includes(a.id)) && !allFilteredSelected;

  const pendingRecommendationsCount = useMemo(() => {
    return recommendations.filter(
      (r) => r.status === 'proposed' || r.status === 'clarification_requested' || r.status === 'completed'
    ).length;
  }, [recommendations]);

  return (
    <div className="space-y-4">
      {/* Top Banner & Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <AlertOctagon className="w-5 h-5 text-blue-600 dark:text-cyan-400" />
              SOC Alert Triage Queue
            </h1>
            {alerts.length > 0 && alerts.some((a) => a.isSynthetic && !a.provenance?.includes('PostgreSQL')) && (
              <ProvenanceBadge type="synthetic_demo" label="DEMO ALERTS" />
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time security alert queue with multi-alert batch triage, deterministic evaluation, and MITRE ATT&CK correlation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {currentUser?.role === 'soc_analyst' && onSimulateAlert && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => setIsSimulateModalOpen(true)}
              className="text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-700/80 hover:bg-amber-50 dark:hover:bg-amber-950/40 font-mono text-xs flex items-center gap-1.5 cursor-pointer"
              title="Simulate controlled Windows event and persist alert to triage queue"
            >
              <Play className="w-3.5 h-3.5 text-amber-500" />
              <span>Simulate Detection Alert</span>
            </Button>
          )}

          <Button
            size="sm"
            variant="secondary"
            onClick={triageSubTab === 'recommendations' ? (onRefreshRecommendations || onRefresh) : onRefresh}
            disabled={isLoading}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
          >
            {isLoading ? 'Refreshing...' : 'Refresh Queue'}
          </Button>
        </div>
      </div>

      {/* Triage Sub-Navigation: Alert Queue vs Detection Recommendations */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-1">
        <button
          type="button"
          onClick={() => setTriageSubTab('alerts')}
          className={`px-3 py-1.5 rounded-t text-xs font-semibold flex items-center gap-2 transition cursor-pointer border-b-2 -mb-1 ${
            triageSubTab === 'alerts'
              ? 'border-blue-600 dark:border-cyan-400 text-blue-700 dark:text-cyan-300 bg-blue-50/50 dark:bg-slate-800/60'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <AlertOctagon className="w-4 h-4" />
          <span>Alert Triage Queue</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
            {alerts.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setTriageSubTab('recommendations')}
          className={`px-3 py-1.5 rounded-t text-xs font-semibold flex items-center gap-2 transition cursor-pointer border-b-2 -mb-1 ${
            triageSubTab === 'recommendations'
              ? 'border-blue-600 dark:border-cyan-400 text-blue-700 dark:text-cyan-300 bg-blue-50/50 dark:bg-slate-800/60'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4 text-amber-500" />
          <span>Detection Recommendations</span>
          {pendingRecommendationsCount > 0 ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300">
              {pendingRecommendationsCount}
            </span>
          ) : (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
              {recommendations.length}
            </span>
          )}
        </button>
      </div>

      {triageSubTab === 'recommendations' ? (
        <DetectionRecommendationsTriageView
          recommendations={recommendations}
          currentUser={currentUser}
          onReviewRecommendation={onReviewRecommendation || (async () => {})}
          onValidateRecommendation={onValidateRecommendation || (async () => {})}
          onRefresh={onRefreshRecommendations || onRefresh}
          isLoading={isLoading}
        />
      ) : (
        <>
          {/* Query / Database Error Banner */}
          {error && (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800 rounded-lg text-xs text-rose-800 dark:text-rose-200 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertOctagon className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
                <span>{error}</span>
              </div>
              <Button size="xs" variant="outline" onClick={onRefresh} disabled={isLoading}>
                Retry
              </Button>
            </div>
          )}

          {/* Filter and Search Bar */}
          <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-3 shadow-xs">
        <div className="flex flex-col lg:flex-row gap-2.5 items-stretch lg:items-center justify-between">
          {/* Search box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search alert ID, title, host, source IP, or technique (e.g. T1059, lsass, ws-14)..."
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 rounded pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
            />
          </div>

          {/* Quick Selectors */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Status Dropdown */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value as any)}
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
              aria-label="Filter by alert status"
            >
              <option value="all">Status: All Statuses</option>
              <option value="new">Status: New</option>
              <option value="in_triage">Status: In Triage</option>
              <option value="escalated">Status: Escalated</option>
              <option value="resolved">Status: Resolved</option>
              <option value="false_positive">Status: False Positive</option>
            </select>

            {/* MITRE Tactic Dropdown */}
            <select
              value={selectedTactic}
              onChange={(e) => setSelectedTactic(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
              aria-label="Filter by MITRE tactic"
            >
              <option value="all">Tactic: All Tactics</option>
              {tactics.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.id}: {t.name}
                </option>
              ))}
            </select>

            {/* Sort Dropdown */}
            <select
              value={`${sortBy}-${sortOrder}`}
              onChange={(e) => {
                const [sb, so] = e.target.value.split('-');
                setSortBy(sb as any);
                setSortOrder(so as any);
              }}
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
              aria-label="Sort order"
            >
              <option value="detectedAt-desc">Time: Newest First</option>
              <option value="detectedAt-asc">Time: Oldest First</option>
              <option value="severity-desc">Severity: High to Low</option>
              <option value="confidenceScore-desc">Scenario Confidence: High to Low</option>
            </select>

            {(searchQuery || selectedSeverities.length > 0 || selectedStatus !== 'all' || selectedTactic !== 'all') && (
              <Button size="xs" variant="ghost" onClick={resetFilters}>
                Clear
              </Button>
            )}
          </div>
        </div>

        {/* Severity Toggle Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-200 dark:border-slate-800/80 text-xs font-mono">
          <span className="text-[10px] text-slate-500 uppercase mr-1">SEVERITY FILTER:</span>
          {(['critical', 'high', 'medium', 'low', 'informational'] as AlertSeverity[]).map((sev) => {
            const isSelected = selectedSeverities.includes(sev);
            return (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={`px-2 py-0.5 rounded text-[11px] uppercase transition cursor-pointer border ${
                  isSelected
                    ? 'bg-blue-100 text-blue-900 border-blue-400 dark:bg-cyan-950 dark:text-cyan-300 dark:border-cyan-500 font-bold'
                    : 'bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            );
          })}
          <span className="text-[10px] text-slate-500 ml-auto">
            Showing <strong className="text-slate-800 dark:text-slate-200">{filteredAlerts.length}</strong> of {alerts.length}
          </span>
        </div>
      </div>

      {/* Multi-Alert Selection & Bulk Triage Toolbar */}
      {selectedAlertIds.length > 0 && (
        <div className="p-3.5 bg-slate-900 border-2 border-indigo-600/70 rounded-lg shadow-md space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="flex items-center justify-center w-6 h-6 rounded-full bg-indigo-600 text-white font-mono text-xs font-bold">
                {selectedAlertIds.length}
              </span>
              <div>
                <span className="text-xs font-bold text-slate-100">
                  {selectedAlertIds.length} Alert{selectedAlertIds.length === 1 ? '' : 's'} Selected for Batch Operations
                </span>
                <span className="text-[11px] text-slate-400 block font-mono">
                  {selectedAlertIds.join(', ')}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                size="xs"
                variant="outline"
                onClick={handleClearSelection}
                disabled={isBatchProcessing}
              >
                Clear Selection
              </Button>
            </div>
          </div>

          {/* Action buttons & Permissions gating */}
          {canTriage ? (
            <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-mono uppercase text-slate-400 mr-1 font-bold">
                TRANSITION TO:
              </span>

              <Button
                size="xs"
                variant="outline"
                disabled={isBatchProcessing || eligibleForInTriage.length === 0}
                onClick={() => handleExecuteBulkTransition('in_triage')}
                className="text-xs text-blue-300 border-blue-900 hover:bg-blue-950/60"
              >
                <Clock className="w-3 h-3 mr-1 text-blue-400" />
                In Triage ({eligibleForInTriage.length})
              </Button>

              <Button
                size="xs"
                variant="outline"
                disabled={isBatchProcessing || eligibleForEscalated.length === 0}
                onClick={() => handleExecuteBulkTransition('escalated')}
                className="text-xs text-purple-300 border-purple-900 hover:bg-purple-950/60"
              >
                <ShieldAlert className="w-3 h-3 mr-1 text-purple-400" />
                Escalate to IR ({eligibleForEscalated.length})
              </Button>

              <Button
                size="xs"
                variant="outline"
                disabled={isBatchProcessing || eligibleForResolved.length === 0}
                onClick={() => handleExecuteBulkTransition('resolved')}
                className="text-xs text-emerald-300 border-emerald-900 hover:bg-emerald-950/60"
              >
                <CheckCircle2 className="w-3 h-3 mr-1 text-emerald-400" />
                Mark Resolved ({eligibleForResolved.length})
              </Button>

              <Button
                size="xs"
                variant="outline"
                disabled={isBatchProcessing || eligibleForFalsePositive.length === 0}
                onClick={() => handleExecuteBulkTransition('false_positive')}
                className="text-xs text-slate-300 border-slate-800 hover:bg-slate-800/60"
              >
                <ShieldCheck className="w-3 h-3 mr-1 text-slate-400" />
                False Positive ({eligibleForFalsePositive.length})
              </Button>

              {isBatchProcessing && (
                <span className="text-xs font-mono text-cyan-400 flex items-center gap-1.5 ml-2">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Executing sequential triage updates...
                </span>
              )}
            </div>
          ) : (
            <div className="pt-2 border-t border-slate-800 text-[11px] text-amber-400/90 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span>
                <strong>Read-Only Scoping:</strong> Current role{' '}
                <code className="px-1 py-0.5 rounded bg-slate-950 font-mono text-slate-300">
                  {currentUser?.role || 'operator'}
                </code>{' '}
                does not possess the <code className="text-cyan-400">alert:triage</code> capability. Bulk state transitions are restricted to SOC Analysts.
              </span>
            </div>
          )}
        </div>
      )}

      {/* Batch Feedback Banner */}
      {batchFeedback && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-start justify-between gap-3 ${
            batchFeedback.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-800 text-emerald-200'
              : batchFeedback.type === 'warning'
              ? 'bg-amber-950/60 border-amber-800 text-amber-200'
              : 'bg-rose-950/60 border-rose-800 text-rose-200'
          }`}
        >
          <div className="flex items-start gap-2">
            {batchFeedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : batchFeedback.type === 'warning' ? (
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            ) : (
              <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-1">
              <p className="font-semibold">{batchFeedback.message}</p>
              {batchFeedback.failed.length > 0 && (
                <ul className="text-[11px] font-mono list-disc list-inside space-y-0.5 text-rose-300">
                  {batchFeedback.failed.map((f) => (
                    <li key={f.id}>
                      {f.id}: {f.error}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          <button
            onClick={() => setBatchFeedback(null)}
            className="text-slate-400 hover:text-slate-200 cursor-pointer p-0.5"
            aria-label="Dismiss feedback"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Alerts Table / List */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-950/80 border-b border-slate-200 dark:border-slate-800 text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 tracking-wider">
                {/* Select All Checkbox */}
                <th className="py-2.5 px-3 w-8 text-center">
                  <button
                    type="button"
                    onClick={handleToggleSelectAllFiltered}
                    className="cursor-pointer text-slate-400 hover:text-slate-200 focus:outline-none"
                    title={allFilteredSelected ? 'Deselect all filtered' : 'Select all filtered'}
                    aria-label={allFilteredSelected ? 'Deselect all filtered' : 'Select all filtered'}
                  >
                    {allFilteredSelected ? (
                      <CheckSquare className="w-4 h-4 text-cyan-400" />
                    ) : someFilteredSelected ? (
                      <MinusSquare className="w-4 h-4 text-cyan-400" />
                    ) : (
                      <Square className="w-4 h-4" />
                    )}
                  </button>
                </th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Title & Summary</th>
                <th className="py-2.5 px-3">Host & Source</th>
                <th className="py-2.5 px-3">MITRE ATT&CK (attack_id)</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-center" title="Confidence Score">Confidence</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800/80 font-sans">
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 italic text-xs">
                    <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-2 text-cyan-400" />
                    Loading operational alert queue from database...
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 italic text-xs">
                    {error ? (
                      <div className="space-y-2">
                        <p className="text-rose-500 font-medium">Failed to retrieve alerts: {error}</p>
                        <Button size="xs" variant="outline" onClick={onRefresh}>
                          Retry Query
                        </Button>
                      </div>
                    ) : alerts.length === 0 ? (
                      <div className="py-4 space-y-2.5 max-w-md mx-auto">
                        <p>The operational alert queue is currently empty. No alerts recorded in public.alerts.</p>
                        {currentUser?.role === 'soc_analyst' && onSimulateAlert && (
                          <Button
                            size="xs"
                            variant="primary"
                            onClick={() => setIsSimulateModalOpen(true)}
                            className="bg-amber-600 hover:bg-amber-700 text-white font-mono text-xs mx-auto flex items-center gap-1.5"
                          >
                            <Play className="w-3 h-3" />
                            Simulate Controlled Detection Alert
                          </Button>
                        )}
                      </div>
                    ) : (
                      'No security alerts match the selected filter criteria.'
                    )}
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isDrawerSelected = selectedAlertId === alert.id;
                  const isChecked = selectedAlertIds.includes(alert.id);
                  const statusToken = DESIGN_TOKENS.status[alert.status] || DESIGN_TOKENS.status.new;

                  return (
                    <tr
                      key={alert.id}
                      onClick={() => onSelectAlert(alert)}
                      className={`hover:bg-slate-50 dark:hover:bg-slate-800/60 transition cursor-pointer ${
                        isDrawerSelected
                          ? 'bg-blue-50/80 dark:bg-slate-800/80 ring-1 ring-inset ring-blue-500/50 dark:ring-cyan-500/50'
                          : isChecked
                          ? 'bg-indigo-950/20 dark:bg-indigo-950/30'
                          : ''
                      }`}
                    >
                      {/* Checkbox column */}
                      <td className="py-3 px-3 text-center shrink-0">
                        <button
                          type="button"
                          onClick={(e) => handleToggleSelectOne(alert.id, e)}
                          className="cursor-pointer text-slate-400 hover:text-slate-200 focus:outline-none"
                          aria-label={`Select alert ${alert.id}`}
                        >
                          {isChecked ? (
                            <CheckSquare className="w-4 h-4 text-cyan-400" />
                          ) : (
                            <Square className="w-4 h-4" />
                          )}
                        </button>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-3 shrink-0">
                        <SeverityIndicator severity={alert.severity} showLabel={false} size="sm" />
                      </td>

                      {/* Alert ID & Time */}
                      <td className="py-3 px-3 font-mono">
                        <div className="font-bold text-slate-900 dark:text-slate-200 text-xs">{alert.id}</div>
                        <div className="text-[10px] text-slate-500">
                          {new Date(alert.detectedAt).toUTCString().slice(17, 22)} UTC
                        </div>
                      </td>

                      {/* Title & Description */}
                      <td className="py-3 px-3 max-w-xs sm:max-w-md">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-900 dark:text-slate-100 truncate">{alert.title}</span>
                          {alert.provenance?.includes('Controlled Simulation') && (
                            <ProvenanceBadge type="controlled_simulation" label="SIMULATED" className="text-[9px] py-0 px-1" />
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-1">{alert.description}</div>
                      </td>

                      {/* Host & Source IP */}
                      <td className="py-3 px-3 font-mono text-[11px]">
                        <div className="text-slate-800 dark:text-slate-200 font-medium truncate">{alert.hostName}</div>
                        <div className="text-slate-500 dark:text-slate-400 text-[10px]">{alert.sourceIp}</div>
                      </td>

                      {/* MITRE ATT&CK (attack_id) */}
                      <td className="py-3 px-3 font-mono text-[11px]">
                        {alert.attack_id || alert.mitreTechniqueId ? (
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-800 text-[10px] font-bold">
                            {formatAttackIdDisplay(alert.attack_id || alert.mitreTechniqueId)}
                          </span>
                        ) : (
                          <span className="text-slate-400 dark:text-slate-600 text-[10px]">Not available</span>
                        )}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono border font-medium ${statusToken.badgeClass}`}
                        >
                          {statusToken.label}
                        </span>
                      </td>

                      {/* Confidence Score */}
                      <td className="py-3 px-3 text-center font-mono">
                        <div className="inline-flex items-center gap-1" title="Confidence Score">
                          <span className="text-xs font-bold text-slate-800 dark:text-slate-200">{alert.confidenceScore}%</span>
                        </div>
                      </td>

                      {/* Action */}
                      <td className="py-3 px-3 text-right">
                        <Button
                          size="xs"
                          variant={isDrawerSelected ? 'primary' : 'outline'}
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(alert);
                            if (onInvestigateAlert) {
                              onInvestigateAlert(alert);
                            }
                          }}
                        >
                          <span>Investigate</span>
                          <ChevronRight className="w-3 h-3" />
                        </Button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
        </>
      )}

      {/* Controlled Simulation Modal for SOC Analyst */}
      {isSimulateModalOpen && onSimulateAlert && currentUser && (
        <SimulateControlledAlertModal
          isOpen={isSimulateModalOpen}
          onClose={() => setIsSimulateModalOpen(false)}
          onSimulateAlert={onSimulateAlert}
          currentUser={currentUser}
          techniques={techniques}
          tactics={tactics}
        />
      )}
    </div>
  );
};
