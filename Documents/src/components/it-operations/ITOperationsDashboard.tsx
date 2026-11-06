import React, { useState, useMemo } from 'react';
import { IncidentTask, ResponseActionType, AuditLogEntry } from '../../types/audit';
import { SecurityAlert } from '../../types/alert';
import { UserRole, UserProfile } from '../../types/auth';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import {
  RemediationVerificationModal,
  RemediationVerificationData,
} from './RemediationVerificationModal';
import { EndpointInventoryView } from './EndpointInventoryView';
import { buildEndpointInventory } from '../../services/endpointInventoryService';
import { AuthorizationService } from '../../services/authorizationService';
import {
  ClipboardList,
  CheckCircle2,
  Clock,
  Play,
  ShieldAlert,
  Server,
  UserCheck,
  AlertTriangle,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileText,
  X,
  RefreshCw,
} from 'lucide-react';
import { getTaskReviewState, parseRemediationHistory } from '../../utils/remediationReview';

interface ITOperationsDashboardProps {
  tasks: IncidentTask[];
  alerts?: SecurityAlert[];
  auditLogs?: AuditLogEntry[];
  onUpdateTaskStatus: (taskId: string, status: IncidentTask['status'], notes?: string) => Promise<void>;
  onTriggerSimulatedAction: (actionType: ResponseActionType, target: string) => void;
  onInspectAlert?: (alertId: string) => void;
  currentRole: UserRole;
  currentUser?: UserProfile;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
}

export const ITOperationsDashboard: React.FC<ITOperationsDashboardProps> = ({
  tasks,
  alerts = [],
  auditLogs = [],
  onUpdateTaskStatus,
  onTriggerSimulatedAction,
  onInspectAlert,
  currentRole,
  currentUser,
  isLoading = false,
  error = null,
  onRetry,
}) => {
  const [activeTab, setActiveTab] = useState<'tasks' | 'endpoints'>('tasks');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [isUpdating, setIsUpdating] = useState(false);
  const [activeVerificationTask, setActiveVerificationTask] = useState<IncidentTask | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [expandedNotesTaskId, setExpandedNotesTaskId] = useState<string | null>(null);

  // Derive authorized endpoints strictly from assigned tasks and scoped alerts
  const endpoints = useMemo(() => {
    return buildEndpointInventory({
      tasks,
      scopedAlerts: alerts,
      auditLogs,
      currentUser,
    });
  }, [tasks, alerts, auditLogs, currentUser]);

  const canUpdate = AuthorizationService.hasPermission(currentRole, 'incident:update');

  const filteredTasks = tasks.filter((t) => {
    if (filterStatus === 'all') return true;
    return t.status === filterStatus;
  });

  const handleBeginRemediation = async (taskId: string) => {
    setIsUpdating(true);
    setFeedback(null);
    try {
      await onUpdateTaskStatus(taskId, 'in_progress');
      setFeedback({
        type: 'success',
        message: `Task ${taskId} status advanced to "In Progress". Remediation procedure active.`,
      });
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: `Failed to advance task ${taskId}: ${err.message || 'Operation failed'}`,
      });
    } finally {
      setIsUpdating(false);
    }
  };

  const handleOpenVerification = (task: IncidentTask) => {
    setFeedback(null);
    setActiveVerificationTask(task);
  };

  const handleConfirmVerification = async (taskId: string, data: RemediationVerificationData) => {
    setIsUpdating(true);
    try {
      await onUpdateTaskStatus(taskId, 'completed', data.serializedNotes);
      setFeedback({
        type: 'success',
        message: `Remediation for Task ${taskId} successfully confirmed and verified. Verification checklist and operator notes recorded.`,
      });
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: `Verification commitment failed for ${taskId}: ${err.message || 'Operation failed'}`,
      });
      throw err;
    } finally {
      setIsUpdating(false);
    }
  };

  const toggleExpandNotes = (taskId: string) => {
    setExpandedNotesTaskId((prev) => (prev === taskId ? null : taskId));
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <ClipboardList className="w-5 h-5 text-amber-400" />
              IT Operations: Incident Response & Recovery Tasks
            </h1>
            <ProvenanceBadge type="synthetic_demo" label="SIMULATED TASKS" />
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Operational remediation queue for authorized containment, asset recovery, and credential resets with structured verification.
          </p>
        </div>
        {onRetry && (
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={onRetry}
              disabled={isLoading}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            >
              {isLoading ? 'Refreshing...' : 'Refresh Tasks'}
            </Button>
          </div>
        )}
      </div>

      {/* Query / Database Error Banner */}
      {error && (
        <div className="p-3 bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800 rounded-lg text-xs text-rose-800 dark:text-rose-200 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          {onRetry && (
            <Button size="xs" variant="outline" onClick={onRetry} disabled={isLoading}>
              Retry
            </Button>
          )}
        </div>
      )}

      {/* Sub-Navigation Tabs: Remediation Tasks vs Endpoint Inventory */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        <button
          type="button"
          onClick={() => setActiveTab('tasks')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-2 cursor-pointer transition ${
            activeTab === 'tasks'
              ? 'bg-amber-600 text-white shadow-xs'
              : 'bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800'
          }`}
        >
          <ClipboardList className="w-3.5 h-3.5" />
          <span>Remediation Tasks</span>
          <span
            className={`px-1.5 py-0.2 rounded text-[10px] ${
              activeTab === 'tasks'
                ? 'bg-amber-700 text-white'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
            }`}
          >
            {tasks.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('endpoints')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-2 cursor-pointer transition ${
            activeTab === 'endpoints'
              ? 'bg-amber-600 text-white shadow-xs'
              : 'bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800'
          }`}
        >
          <Server className="w-3.5 h-3.5" />
          <span>Endpoint & Host Inventory</span>
          <span
            className={`px-1.5 py-0.2 rounded text-[10px] ${
              activeTab === 'endpoints'
                ? 'bg-amber-700 text-white'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
            }`}
          >
            {endpoints.length}
          </span>
        </button>
      </div>

      {activeTab === 'endpoints' ? (
        <EndpointInventoryView
          endpoints={endpoints}
          onSelectTask={(taskId) => {
            setActiveTab('tasks');
          }}
          onInspectAlert={onInspectAlert}
        />
      ) : (
        <>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 block">TOTAL TASKS</span>
          <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1 block">{tasks.length}</span>
          <span className="text-[10px] text-slate-500">Remediation actions</span>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900 border border-amber-200 dark:border-amber-950/80 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-amber-600 dark:text-amber-400 block">PENDING ACTIONS</span>
          <span className="text-xl font-bold font-mono text-amber-600 dark:text-amber-400 mt-1 block">
            {tasks.filter((t) => t.status === 'pending').length}
          </span>
          <span className="text-[10px] text-amber-700/70 dark:text-amber-300/70">Awaiting operator execution</span>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900 border border-sky-200 dark:border-sky-950/80 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-sky-600 dark:text-sky-400 block">IN PROGRESS</span>
          <span className="text-xl font-bold font-mono text-sky-600 dark:text-sky-400 mt-1 block">
            {tasks.filter((t) => t.status === 'in_progress').length}
          </span>
          <span className="text-[10px] text-sky-700/70 dark:text-sky-300/70">Under remediation</span>
        </div>

        <div className="p-3 bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-950/80 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono uppercase text-emerald-600 dark:text-emerald-400 block">RECOVERED & CLOSED</span>
          <span className="text-xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1 block">
            {tasks.filter((t) => t.status === 'completed').length}
          </span>
          <span className="text-[10px] text-emerald-700/70 dark:text-emerald-300/70">Verified recovered</span>
        </div>
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-center justify-between gap-3 ${
            feedback.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/60 border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200'
              : 'bg-rose-50 dark:bg-rose-950/60 border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
            )}
            <span>{feedback.message}</span>
          </div>
          <button
            onClick={() => setFeedback(null)}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-0.5 cursor-pointer"
            aria-label="Dismiss feedback"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex items-center justify-between shadow-xs">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-500 dark:text-slate-400">FILTER BY STATUS:</span>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1 text-xs focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
          >
            <option value="all">All ({tasks.length})</option>
            <option value="pending">Pending</option>
            <option value="in_progress">In Progress</option>
            <option value="completed">Completed</option>
          </select>
        </div>

        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          Showing <strong className="text-slate-800 dark:text-slate-200">{filteredTasks.length}</strong> of {tasks.length} tasks
        </div>
      </div>

      {/* Task Cards List */}
      <div className="space-y-3">
        {isLoading && tasks.length === 0 ? (
          <div className="p-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-center text-slate-500 text-xs shadow-xs space-y-3">
            <div className="flex items-center justify-center gap-2 text-amber-600 dark:text-amber-400 font-medium">
              <RefreshCw className="w-5 h-5 animate-spin" />
              <span>Loading incident response tasks...</span>
            </div>
            <p className="text-slate-400 dark:text-slate-500 text-[11px]">
              Querying authorized containment and recovery queue...
            </p>
          </div>
        ) : error && tasks.length === 0 ? (
          <div className="p-8 bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900/60 rounded-lg text-center text-xs shadow-xs space-y-3">
            <div className="flex items-center justify-center gap-2 text-rose-600 dark:text-rose-400 font-medium">
              <AlertTriangle className="w-5 h-5" />
              <span>Failed to retrieve incident tasks</span>
            </div>
            <p className="text-rose-700 dark:text-rose-300 font-mono text-[11px] max-w-lg mx-auto">
              {error}
            </p>
            {onRetry && (
              <div className="pt-1 flex justify-center">
                <Button
                  size="xs"
                  variant="outline"
                  onClick={onRetry}
                  disabled={isLoading}
                  className="border-rose-300 dark:border-rose-800 text-rose-700 dark:text-rose-300 hover:bg-rose-50 dark:hover:bg-rose-950"
                >
                  <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${isLoading ? 'animate-spin' : ''}`} />
                  Retry Task Query
                </Button>
              </div>
            )}
          </div>
        ) : filteredTasks.length === 0 ? (
          <div className="p-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-center text-slate-500 text-xs italic shadow-xs">
            {tasks.length === 0 ? (
              <div className="not-italic space-y-1">
                <p className="font-medium text-slate-700 dark:text-slate-300">No incident response tasks found.</p>
                <p className="text-slate-400 dark:text-slate-500">
                  You currently have zero assigned containment or recovery tasks under active operational RLS policies.
                </p>
              </div>
            ) : (
              'No incident response tasks found for the selected filter.'
            )}
          </div>
        ) : (
          filteredTasks.map((task) => {
            const isNotesExpanded = expandedNotesTaskId === task.id;
            const reviewState = getTaskReviewState(task);

            return (
              <div
                key={task.id}
                className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-3 hover:border-slate-300 dark:hover:border-slate-700 transition shadow-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/80 px-2 py-0.5 rounded border border-amber-200 dark:border-amber-800">
                      {task.id}
                    </span>
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                        task.priority === 'critical'
                          ? 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800'
                          : 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800'
                      }`}
                    >
                      Priority: {task.priority}
                    </span>
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${reviewState.badgeClass}`}
                    >
                      {reviewState.label}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    {task.associatedAlertId && (
                      <span className="text-blue-600 dark:text-cyan-400">
                        Linked Alert: <strong className="font-mono">{task.associatedAlertId}</strong>
                      </span>
                    )}
                    <div className="flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
                      Target: <strong className="text-slate-800 dark:text-slate-200">{task.targetAsset}</strong>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">{task.title}</h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">{task.description}</p>
                </div>

                {/* Rework Requested Notification Banner */}
                {reviewState.status === 'rework_requested' && reviewState.latestReworkInstructions && (
                  <div className="p-3.5 bg-orange-50 dark:bg-orange-950/50 border border-orange-300 dark:border-orange-800 rounded-lg space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-orange-900 dark:text-orange-200 flex items-center gap-1.5 font-mono text-[11px]">
                        <RefreshCw className="w-3.5 h-3.5 text-orange-600 dark:text-orange-400" />
                        REWORK REQUESTED BY {reviewState.latestReview?.reviewerName || 'SOC Analyst'}
                        {reviewState.latestReview?.timestamp && (
                          <span className="text-slate-500 font-normal">
                            ({new Date(reviewState.latestReview.timestamp).toUTCString().slice(5, 22)} UTC)
                          </span>
                        )}
                      </span>
                      <span className="text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded bg-orange-200 text-orange-900 dark:bg-orange-900 dark:text-orange-200">
                        Action Required
                      </span>
                    </div>

                    <div className="p-2.5 bg-white dark:bg-slate-950 rounded border border-orange-200 dark:border-orange-900/60 font-mono text-[11px] text-slate-800 dark:text-slate-200 whitespace-pre-wrap leading-relaxed">
                      {reviewState.latestReworkInstructions}
                    </div>

                    <div className="text-[10px] text-orange-700 dark:text-orange-400 font-mono flex items-center justify-between">
                      <span>Perform corrections on {task.targetAsset}, then click "Verify & Complete Task" to resubmit.</span>
                      <span>History: Preserved</span>
                    </div>
                  </div>
                )}

                {/* Analyst Approval Banner */}
                {reviewState.status === 'approved' && (
                  <div className="p-2.5 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 rounded-lg text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-emerald-900 dark:text-emerald-200 flex items-center gap-1.5 font-mono text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                        Remediation Approved by {reviewState.latestReview?.reviewerName || 'SOC Analyst'}
                      </span>
                      {reviewState.latestReview?.timestamp && (
                        <span className="text-[10px] font-mono text-slate-500">
                          {new Date(reviewState.latestReview.timestamp).toUTCString().slice(5, 22)} UTC
                        </span>
                      )}
                    </div>
                    {reviewState.latestReview?.notesOrInstructions && (
                      <p className="text-[11px] text-slate-700 dark:text-slate-300 font-mono pl-5">
                        {reviewState.latestReview.notesOrInstructions}
                      </p>
                    )}
                  </div>
                )}

                {/* Completed Verification Summary & Expandable Notes */}
                {task.status === 'completed' && task.completionNotes && (
                  <div className="p-3 bg-emerald-50/50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/60 rounded-lg space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-emerald-800 dark:text-emerald-300 flex items-center gap-1.5 font-mono text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Remediation Verified by {task.completedBy || 'IT Ops'}
                        {task.completedAt && (
                          <span className="text-slate-500 font-normal">
                            ({new Date(task.completedAt).toUTCString().slice(5, 22)} UTC)
                          </span>
                        )}
                      </span>
                      <button
                        type="button"
                        onClick={() => toggleExpandNotes(task.id)}
                        className="text-[11px] text-emerald-700 dark:text-emerald-400 hover:underline flex items-center gap-1 cursor-pointer font-mono"
                      >
                        {isNotesExpanded ? (
                          <>
                            <span>Hide Details</span>
                            <ChevronUp className="w-3 h-3" />
                          </>
                        ) : (
                          <>
                            <span>View Verification Evidence</span>
                            <ChevronDown className="w-3 h-3" />
                          </>
                        )}
                      </button>
                    </div>

                    {isNotesExpanded && (
                      <div className="pt-2 border-t border-emerald-200/60 dark:border-emerald-900/40">
                        <pre className="text-[11px] font-mono bg-white dark:bg-slate-950 p-2.5 rounded border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 whitespace-pre-wrap leading-relaxed">
                          {task.completionNotes}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* Task Controls & Action Execution */}
                <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    {task.suggestedActionType && (
                      <Button
                        size="xs"
                        variant="outline"
                        className="border-purple-200 text-purple-700 hover:bg-purple-50 dark:border-purple-800 dark:text-purple-300 dark:hover:bg-purple-950/60"
                        onClick={() => onTriggerSimulatedAction(task.suggestedActionType!, task.targetAsset)}
                      >
                        <ShieldAlert className="w-3 h-3 text-purple-600 dark:text-purple-400" />
                        Execute Simulated Action
                      </Button>
                    )}

                    {task.associatedAlertId && onInspectAlert && (
                      <Button
                        size="xs"
                        variant="outline"
                        className="border-blue-200 text-blue-700 hover:bg-blue-50 dark:border-blue-800 dark:text-blue-300 dark:hover:bg-blue-950/60 font-mono"
                        onClick={() => onInspectAlert(task.associatedAlertId!)}
                        title={`Inspect associated security alert ${task.associatedAlertId}`}
                      >
                        <ExternalLink className="w-3 h-3 text-blue-600 dark:text-blue-400" />
                        Inspect Associated Alert
                      </Button>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {task.status === 'pending' && canUpdate && (
                      <Button
                        size="xs"
                        variant="secondary"
                        onClick={() => handleBeginRemediation(task.id)}
                        disabled={isUpdating}
                      >
                        <Play className="w-3 h-3" />
                        Begin Remediation
                      </Button>
                    )}

                    {task.status === 'in_progress' && canUpdate && (
                      <Button
                        size="xs"
                        variant="primary"
                        onClick={() => handleOpenVerification(task)}
                        disabled={isUpdating}
                        className="bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-600 dark:hover:bg-emerald-500 text-white"
                      >
                        <CheckCircle2 className="w-3 h-3 mr-1" />
                        Verify & Complete Task
                      </Button>
                    )}

                    {task.status === 'completed' && !task.completionNotes && (
                      <span className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Completed by {task.completedBy || 'IT Ops'}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

        </>
      )}

      {/* Verification Modal */}
      {activeVerificationTask && (
        <RemediationVerificationModal
          task={activeVerificationTask}
          isOpen={Boolean(activeVerificationTask)}
          onClose={() => setActiveVerificationTask(null)}
          onConfirm={handleConfirmVerification}
          isSubmitting={isUpdating}
          associatedAlert={
            activeVerificationTask.associatedAlertId
              ? alerts.find((a) => a.id === activeVerificationTask.associatedAlertId)
              : undefined
          }
        />
      )}
    </div>
  );
};
