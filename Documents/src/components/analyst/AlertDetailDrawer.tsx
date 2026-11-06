import React, { useState, useMemo } from 'react';
import { SecurityAlert, AlertStatus } from '../../types/alert';
import { UserRole, UserProfile } from '../../types/auth';
import { ResponseActionType, IncidentTask } from '../../types/audit';
import { MitreTechnique, MitreMitigation } from '../../types/mitre';
import { DeterministicTriageRecommendation } from '../../types/triage';
import { SeverityIndicator } from '../common/SeverityIndicator';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import { DESIGN_TOKENS } from '../../constants/designTokens';
import { formatAttackIdDisplay, normalizeAttackId } from '../../utils/mitreUtils';
import { SocAnalystKnowledgeRecord } from '../../services/knowledgeService';
import { lookupSocAnalystKnowledgeForTechnique } from '../../services/relationshipService';
import { CreateTaskModal } from './CreateTaskModal';
import { RequestReworkModal } from './RequestReworkModal';
import { ApproveRemediationModal } from './ApproveRemediationModal';
import {
  getTaskReviewState,
  parseRemediationHistory,
  checkAlertClosureEligibility,
} from '../../utils/remediationReview';
import {
  X,
  Cpu,
  Terminal,
  Layers,
  FileEdit,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Lock,
  WifiOff,
  Database,
  ArrowRight,
  Activity,
  FileSearch,
  ClipboardList,
  RefreshCw,
  CheckSquare,
  History,
} from 'lucide-react';

interface AlertDetailDrawerProps {
  alert: SecurityAlert;
  onClose: () => void;
  onUpdateStatus: (alertId: string, status: AlertStatus) => Promise<void>;
  onAddNote: (alertId: string, note: string) => Promise<void>;
  mitreTechnique: MitreTechnique | null;
  mitigations: MitreMitigation[];
  triageRecommendation: DeterministicTriageRecommendation;
  currentRole: UserRole;
  onInitiateSimulatedAction: (actionType: ResponseActionType, target: string) => void;
  socKnowledge?: SocAnalystKnowledgeRecord[];
  currentUser?: UserProfile;
  tasks?: IncidentTask[];
  onCreateTask?: (taskData: Omit<IncidentTask, 'id' | 'createdAt'>) => Promise<IncidentTask>;
  onReviewTask?: (taskId: string, decision: 'approved' | 'rework_requested', notes: string) => Promise<void>;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert,
  onClose,
  onUpdateStatus,
  onAddNote,
  mitreTechnique,
  mitigations,
  triageRecommendation,
  currentRole,
  onInitiateSimulatedAction,
  socKnowledge = [],
  currentUser,
  tasks = [],
  onCreateTask,
  onReviewTask,
}) => {
  const [activeTab, setActiveTab] = useState<'triage' | 'evidence' | 'mitre' | 'notes' | 'tasks'>('triage');
  const [newNote, setNewNote] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [closureBlockedMessage, setClosureBlockedMessage] = useState<string | null>(null);
  const [isCreateTaskModalOpen, setIsCreateTaskModalOpen] = useState(false);
  const [selectedTaskForRework, setSelectedTaskForRework] = useState<IncidentTask | null>(null);
  const [selectedTaskForApproval, setSelectedTaskForApproval] = useState<IncidentTask | null>(null);

  const linkedTasks = useMemo(() => tasks.filter((t) => t.associatedAlertId === alert.id), [tasks, alert.id]);

  const attackId = alert.attack_id || normalizeAttackId(alert.mitreTechniqueId);
  const socKnowledgeDetails = useMemo(() => {
    if (!attackId || !socKnowledge || socKnowledge.length === 0) return null;
    return lookupSocAnalystKnowledgeForTechnique(attackId, socKnowledge);
  }, [attackId, socKnowledge]);

  const handleStatusChange = async (newStatus: AlertStatus) => {
    setIsUpdating(true);
    setStatusMessage(null);
    setClosureBlockedMessage(null);

    // Requirement 7: When an alert has associated remediation tasks, require all of them
    // to have explicit SOC Analyst approval before allowing the alert to become resolved.
    if (newStatus === 'resolved') {
      const eligibility = checkAlertClosureEligibility(alert.id, tasks);
      if (!eligibility.eligible) {
        setIsUpdating(false);
        setClosureBlockedMessage(eligibility.reason || 'All associated remediation tasks must be approved by a SOC Analyst before this alert can be resolved.');
        return;
      }
    }

    try {
      await onUpdateStatus(alert.id, newStatus);
      setStatusMessage(`Status updated to "${newStatus.replace('_', ' ').toUpperCase()}"`);
      setTimeout(() => setStatusMessage(null), 3500);
    } catch (e: any) {
      setStatusMessage(`Failed: ${e.message}`);
    } finally {
      setIsUpdating(false);
    }
  };

  const handleNoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setIsUpdating(true);
    try {
      await onAddNote(alert.id, newNote.trim());
      setNewNote('');
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-3xl bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-700/80 shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200">
      {/* Drawer Top Header */}
      <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-start justify-between gap-3">
        <div className="space-y-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-bold text-blue-700 dark:text-cyan-400 bg-blue-50 dark:bg-cyan-950/80 px-2 py-0.5 rounded border border-blue-200 dark:border-cyan-800">
              {alert.id}
            </span>
            <SeverityIndicator severity={alert.severity} />
            {alert.provenance?.includes('Controlled Simulation') ? (
              <ProvenanceBadge type="controlled_simulation" label="CONTROLLED SIMULATION" />
            ) : (
              <ProvenanceBadge type="synthetic_demo" label="DEMO ALERT" />
            )}
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
              {new Date(alert.detectedAt).toUTCString()}
            </span>
          </div>
          <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 truncate">{alert.title}</h2>
          <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
            <span>Host: <strong className="text-slate-800 dark:text-slate-200 font-mono">{alert.hostName}</strong></span>
            <span>Source IP: <strong className="text-slate-800 dark:text-slate-200 font-mono">{alert.sourceIp}</strong></span>
            {alert.userName && <span>User: <strong className="text-slate-800 dark:text-slate-200 font-mono">{alert.userName}</strong></span>}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {currentRole === 'soc_analyst' && onCreateTask && (
            <Button
              size="xs"
              variant="outline"
              onClick={() => setIsCreateTaskModalOpen(true)}
              className="flex items-center gap-1.5 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-700/80 hover:bg-amber-50 dark:hover:bg-amber-950/40 font-mono text-[11px]"
            >
              <ClipboardList className="w-3.5 h-3.5 text-amber-500" />
              Create Response Task
            </Button>
          )}
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer"
            aria-label="Close investigation drawer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-slate-950/40 px-4 gap-1 text-xs font-mono overflow-x-auto">
        <button
          onClick={() => setActiveTab('triage')}
          className={`flex items-center gap-1.5 px-3 py-2.5 border-b-2 font-medium transition cursor-pointer ${
            activeTab === 'triage'
              ? 'border-blue-600 dark:border-cyan-400 text-blue-700 dark:text-cyan-300 bg-white dark:bg-slate-800/40 font-semibold'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
          Deterministic Triage
        </button>
        <button
          onClick={() => setActiveTab('tasks')}
          className={`flex items-center gap-1.5 px-3 py-2.5 border-b-2 font-medium transition cursor-pointer ${
            activeTab === 'tasks'
              ? 'border-blue-600 dark:border-cyan-400 text-blue-700 dark:text-cyan-300 bg-white dark:bg-slate-800/40 font-semibold'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <ClipboardList className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
          Response Tasks ({linkedTasks.length})
        </button>
        <button
          onClick={() => setActiveTab('evidence')}
          className={`flex items-center gap-1.5 px-3 py-2.5 border-b-2 font-medium transition cursor-pointer ${
            activeTab === 'evidence'
              ? 'border-blue-600 dark:border-cyan-400 text-blue-700 dark:text-cyan-300 bg-white dark:bg-slate-800/40 font-semibold'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
          Raw Evidence & Logs
        </button>
        <button
          onClick={() => setActiveTab('mitre')}
          className={`flex items-center gap-1.5 px-3 py-2.5 border-b-2 font-medium transition cursor-pointer ${
            activeTab === 'mitre'
              ? 'border-blue-600 dark:border-cyan-400 text-blue-700 dark:text-cyan-300 bg-white dark:bg-slate-800/40 font-semibold'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
          MITRE ATT&CK ({formatAttackIdDisplay(alert.attack_id || alert.mitreTechniqueId)})
        </button>
        <button
          onClick={() => setActiveTab('notes')}
          className={`flex items-center gap-1.5 px-3 py-2.5 border-b-2 font-medium transition cursor-pointer ${
            activeTab === 'notes'
              ? 'border-blue-600 dark:border-cyan-400 text-blue-700 dark:text-cyan-300 bg-white dark:bg-slate-800/40 font-semibold'
              : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
          }`}
        >
          <FileEdit className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
          {currentRole === 'soc_analyst' ? `Notes & Triage (${alert.analystNotes.length})` : 'Triage Status'}
        </button>
      </div>

      {/* Main Drawer Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {statusMessage && (
          <div className="p-2.5 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded text-xs text-emerald-800 dark:text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            {statusMessage}
          </div>
        )}

        {/* TAB 1: DETERMINISTIC TRIAGE */}
        {activeTab === 'triage' && (
          <div className="space-y-4">
            {/* Header banner explaining rule engine */}
            <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ProvenanceBadge type="deterministic_rule" label="PHASE 1 RULE-BASED TRIAGE" />
                  <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                    Category: <span className="text-blue-700 dark:text-cyan-300">{triageRecommendation.recommendationCategory}</span>
                  </span>
                </div>
                <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400" title="Pre-configured scenario baseline confidence">
                  Scenario Confidence: <strong className="text-slate-900 dark:text-slate-100">{triageRecommendation.confidenceScore}%</strong>
                </span>
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                {triageRecommendation.summaryRationale}
              </p>
              <div className="pt-1.5 border-t border-slate-200 dark:border-slate-800/80 text-[10px] text-slate-500 dark:text-slate-400 flex flex-wrap items-center justify-between gap-1">
                <span>Triage severity is evaluated by deterministic rule weights (DET-RULE-001 to 005).</span>
                <span className="text-slate-500 dark:text-slate-400 font-mono">Scenario Confidence = preset scenario baseline</span>
              </div>
            </div>

            {/* Severity evaluation comparison */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-slate-50/70 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded">
                <span className="text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 block mb-1">INCOMING SEVERITY</span>
                <SeverityIndicator severity={alert.severity} />
              </div>
              <div className="p-3 bg-slate-50/70 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded">
                <span className="text-[10px] font-mono uppercase text-slate-500 dark:text-slate-400 block mb-1">EVALUATED RECOMMENDATION</span>
                <SeverityIndicator severity={triageRecommendation.recommendedSeverity} />
              </div>
            </div>

            {/* Matched Rules Table */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-300 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
                Deterministic Rule Evaluations ({triageRecommendation.matchedRules.length})
              </h4>
              {triageRecommendation.matchedRules.length === 0 ? (
                <p className="text-xs text-slate-500 italic p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                  No high-confidence threat rules triggered on this alert evidence.
                </p>
              ) : (
                <div className="space-y-2">
                  {triageRecommendation.matchedRules.map((r) => (
                    <div key={r.ruleId} className="p-3 bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 rounded text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-blue-700 dark:text-cyan-300 font-semibold">{r.ruleId}: {r.ruleName}</span>
                        <span className="font-mono text-[10px] px-1.5 py-0.2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded border border-slate-200 dark:border-slate-700">
                          Weight: +{r.weight}
                        </span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-300 text-[11px]">{r.description}</p>
                      <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-200 dark:border-slate-800/80">
                        Condition: <code className="text-slate-700 dark:text-slate-300">{r.matchedCondition}</code>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Supporting Evidence Citations */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-300">
                Extracted Evidence Strings
              </h4>
              <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-950 p-3 rounded border border-slate-200 dark:border-slate-800 list-disc pl-5">
                {triageRecommendation.supportingEvidence.map((ev, idx) => (
                  <li key={idx} className="font-mono text-[11px] text-slate-700 dark:text-slate-300">{ev}</li>
                ))}
              </ul>
            </div>

            {/* Suggested Response Actions (Simulation Only) */}
            <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-300 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />
                  Recommended Containment Procedures (Simulated)
                </h4>
                <span className="text-[10px] font-mono text-purple-700 dark:text-purple-400">REQUIRES HUMAN AUTHORIZATION</span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                In Phase 1, clicking an action launches a confirmation dialog and records a simulated response to the audit ledger.
              </p>

              <div className="space-y-2">
                {triageRecommendation.suggestedResponseActions.map((act, i) => (
                  <div
                    key={i}
                    className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded flex items-center justify-between gap-3"
                  >
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">{act.label}</span>
                        <span className="text-[9px] font-mono uppercase px-1 py-0.2 bg-rose-50 text-rose-700 dark:bg-rose-950 dark:text-rose-300 rounded border border-rose-200 dark:border-rose-800">
                          {act.urgency}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">{act.description}</p>
                      <div className="text-[10px] font-mono text-blue-600 dark:text-cyan-400">Target: {act.target}</div>
                    </div>

                    <Button
                      size="xs"
                      variant="outline"
                      className="shrink-0 text-blue-700 dark:text-cyan-300 hover:text-blue-900 dark:hover:text-cyan-200 border-blue-200 dark:border-cyan-800/80 hover:bg-blue-50 dark:hover:bg-cyan-950/60"
                      onClick={() => onInitiateSimulatedAction(act.actionType, act.target)}
                    >
                      Authorize Simulation
                    </Button>
                  </div>
                ))}
              </div>
            </div>

            {/* IT Operations Response Tasks Summary */}
            <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-300 flex items-center gap-1.5">
                  <ClipboardList className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                  Incident Response Tasks ({linkedTasks.length})
                </h4>
                {currentRole === 'soc_analyst' && onCreateTask && (
                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() => setIsCreateTaskModalOpen(true)}
                    className="flex items-center gap-1.5 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-700/80 hover:bg-amber-50 dark:hover:bg-amber-950/40 font-mono text-[11px]"
                  >
                    <ClipboardList className="w-3.5 h-3.5 text-amber-500" />
                    Create Response Task
                  </Button>
                )}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Remediation and recovery tasks assigned to IT Operations for this alert.
              </p>

              {linkedTasks.length === 0 ? (
                <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded text-xs text-slate-500 dark:text-slate-400 italic">
                  No incident response tasks assigned yet. Click "Create Response Task" to assign containment or recovery instructions to IT Operations.
                </div>
              ) : (
                <div className="space-y-2">
                  {linkedTasks.map((t) => (
                    <div
                      key={t.id}
                      className="p-3 bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 rounded text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-amber-700 dark:text-amber-400">{t.id}</span>
                          <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded font-bold bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                            {t.status.toUpperCase()}
                          </span>
                          <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded font-bold bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300">
                            {t.priority.toUpperCase()}
                          </span>
                        </div>
                        <span className="text-[10px] font-mono text-slate-500">
                          {new Date(t.createdAt).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="font-semibold text-slate-900 dark:text-slate-100">{t.title}</div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 line-clamp-2">{t.description}</p>
                      <div className="text-[10px] font-mono text-slate-500 flex items-center justify-between pt-1 border-t border-slate-200 dark:border-slate-800">
                        <span>Target: <strong className="text-slate-800 dark:text-slate-200">{t.targetAsset}</strong></span>
                        <span>Role: <strong className="text-amber-600 dark:text-amber-400 uppercase">{t.assignedRole}</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: RAW EVIDENCE & LOGS */}
        {activeTab === 'evidence' && (
          <div className="space-y-4">
            <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-lg border border-slate-200 dark:border-slate-800 space-y-3 font-mono text-xs">
              <div>
                <span className="text-slate-500 uppercase text-[10px] block">LOG SOURCE</span>
                <span className="text-slate-800 dark:text-slate-200">{alert.evidence.logSource}</span>
              </div>
              {alert.evidence.processName && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">PROCESS NAME</span>
                  <span className="text-emerald-600 dark:text-emerald-400">{alert.evidence.processName}</span>
                </div>
              )}
              {alert.evidence.parentProcess && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">PARENT PROCESS</span>
                  <span className="text-slate-700 dark:text-slate-300">{alert.evidence.parentProcess}</span>
                </div>
              )}
              {alert.evidence.processCommandLine && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">COMMAND LINE ARGUMENTS</span>
                  <pre className="mt-1 p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded text-amber-700 dark:text-amber-300 text-[11px] overflow-x-auto whitespace-pre-wrap break-all">
                    {alert.evidence.processCommandLine}
                  </pre>
                </div>
              )}
              {alert.evidence.fileHashSha256 && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">SHA256 HASH</span>
                  <span className="text-slate-700 dark:text-slate-300 text-[11px] break-all">{alert.evidence.fileHashSha256}</span>
                </div>
              )}
              {alert.evidence.userAccount && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">USER / SERVICE PRINCIPAL</span>
                  <span className="text-blue-600 dark:text-cyan-300">{alert.evidence.userAccount}</span>
                </div>
              )}
              {alert.evidence.rawEventLog && (
                <div>
                  <span className="text-slate-500 uppercase text-[10px] block">RAW SECURITY EVENT TELEMETRY</span>
                  <pre className="mt-1 p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded text-slate-700 dark:text-slate-300 text-[11px] overflow-x-auto whitespace-pre-wrap">
                    {alert.evidence.rawEventLog}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: MITRE ATT&CK KNOWLEDGE */}
        {activeTab === 'mitre' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <ProvenanceBadge
                type="authentic_mitre"
                label={
                  socKnowledgeDetails
                    ? 'MITRE ATT&CK v14.1 ENTERPRISE (public.soc_analyst_knowledge)'
                    : 'MITRE ATT&CK v14.1 ENTERPRISE'
                }
              />
              {mitreTechnique?.sourceUrl ? (
                <a
                  href={mitreTechnique.sourceUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-mono text-blue-600 dark:text-cyan-400 hover:underline flex items-center gap-1"
                >
                  Official Reference <ExternalLink className="w-3 h-3" />
                </a>
              ) : attackId ? (
                <a
                  href={`https://attack.mitre.org/techniques/${attackId.replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-mono text-blue-600 dark:text-cyan-400 hover:underline flex items-center gap-1"
                >
                  Official Reference <ExternalLink className="w-3 h-3" />
                </a>
              ) : null}
            </div>

            {socKnowledgeDetails || mitreTechnique ? (
              <div className="space-y-4">
                {/* Technique Header & Overview */}
                <div className="p-4 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-blue-700 dark:text-cyan-300 bg-blue-50 dark:bg-cyan-950 px-2 py-0.5 rounded border border-blue-200 dark:border-cyan-800">
                      {formatAttackIdDisplay(attackId || mitreTechnique?.id)}
                    </span>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      {socKnowledgeDetails?.techniqueName || mitreTechnique?.name}
                    </h3>
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    {socKnowledgeDetails?.techniqueDescription || mitreTechnique?.description}
                  </p>
                  <div className="pt-2 flex flex-wrap gap-2 text-[10px] font-mono text-slate-500 dark:text-slate-400">
                    {socKnowledgeDetails?.tactics.length ? (
                      <span>Tactics: <strong className="text-slate-700 dark:text-slate-300">{socKnowledgeDetails.tactics.join(', ')}</strong></span>
                    ) : null}
                    <span>Platforms: <strong className="text-slate-700 dark:text-slate-300">
                      {socKnowledgeDetails?.platforms.length
                        ? socKnowledgeDetails.platforms.join(', ')
                        : mitreTechnique?.platforms.join(', ') || 'Enterprise'}
                    </strong></span>
                  </div>
                </div>

                {/* Verified Detection Strategy */}
                <div className="p-4 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
                  <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
                    Verified MITRE Detection Strategies ({socKnowledgeDetails?.detectionStrategies.length || (mitreTechnique?.detectionGuidance ? 1 : 0)})
                  </h4>
                  {socKnowledgeDetails?.detectionStrategies.length ? (
                    <div className="space-y-1.5">
                      {socKnowledgeDetails.detectionStrategies.map((ds, idx) => (
                        <div key={idx} className="p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded text-xs flex items-center justify-between">
                          <span className="text-slate-800 dark:text-slate-200 font-medium">{ds.name}</span>
                          <span className="font-mono text-[10px] text-blue-600 dark:text-cyan-400 font-semibold">{ds.attackId}</span>
                        </div>
                      ))}
                    </div>
                  ) : mitreTechnique?.detectionGuidance ? (
                    <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">{mitreTechnique.detectionGuidance}</p>
                  ) : (
                    <p className="text-xs text-slate-500 italic">No detection strategies cataloged for this technique.</p>
                  )}
                </div>

                {/* Behavioral Analytics, Log Sources & Data Components */}
                {socKnowledgeDetails && (socKnowledgeDetails.analytics.length > 0 || socKnowledgeDetails.logSources.length > 0 || socKnowledgeDetails.dataComponents.length > 0) && (
                  <div className="p-4 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-3">
                    <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <FileSearch className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                      SOC Analyst Reference Telemetry & Analytics
                    </h4>

                    {socKnowledgeDetails.analytics.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block font-semibold">
                          Behavioral Analytics ({socKnowledgeDetails.analytics.length}):
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {socKnowledgeDetails.analytics.map((an, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-50 text-emerald-800 border border-emerald-200 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800"
                            >
                              {an.id}: {an.name}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {socKnowledgeDetails.logSources.length > 0 && (
                      <div className="space-y-1 pt-1 border-t border-slate-200 dark:border-slate-800">
                        <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block font-semibold">
                          Cataloged Log Sources ({socKnowledgeDetails.logSources.length}):
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {socKnowledgeDetails.logSources.map((ls, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-200 dark:bg-slate-900 text-slate-800 dark:text-slate-300"
                            >
                              {ls}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {socKnowledgeDetails.dataComponents.length > 0 && (
                      <div className="space-y-1 pt-1 border-t border-slate-200 dark:border-slate-800">
                        <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block font-semibold">
                          Data Components:
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {socKnowledgeDetails.dataComponents.map((dc, idx) => (
                            <span
                              key={idx}
                              className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-cyan-300 border border-blue-200 dark:border-blue-800"
                            >
                              {dc.name}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Mitigations */}
                <div className="p-4 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
                  <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-200">
                    Documented Defensive Mitigations ({mitigations.length})
                  </h4>
                  {mitigations.length === 0 ? (
                    <p className="text-xs text-slate-500 italic">No direct mitigation IDs mapped in sample baseline.</p>
                  ) : (
                    <div className="space-y-2">
                      {mitigations.map((m) => (
                        <div key={m.id} className="p-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded text-xs space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-blue-700 dark:text-cyan-400 font-semibold">{m.id}: {m.name}</span>
                            <a
                              href={m.sourceUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[10px] font-mono text-slate-500 hover:text-blue-600 dark:text-slate-400 dark:hover:text-cyan-300 flex items-center gap-1"
                            >
                              Docs <ExternalLink className="w-2.5 h-2.5" />
                            </a>
                          </div>
                          <p className="text-slate-600 dark:text-slate-300 text-[11px]">{m.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500 dark:text-slate-400 italic p-4 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                No MITRE technique mapped for this alert record.
              </p>
            )}
          </div>
        )}

        {/* TAB 4: ANALYST INVESTIGATION NOTES */}
        {activeTab === 'notes' && (
          <div className="space-y-4">
            {/* Status change bar */}
            <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-300 block">
                  Update Triage Status
                </span>
                {currentRole !== 'soc_analyst' && (
                  <span className="text-[10px] font-mono text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-200 dark:border-amber-800/60">
                    READ-ONLY (RESTRICTED TO SOC ANALYST)
                  </span>
                )}
              </div>

              {/* Incident Closure Guard Alert */}
              {closureBlockedMessage && (
                <div className="p-3 bg-rose-50 dark:bg-rose-950/80 border border-rose-300 dark:border-rose-800 rounded-lg text-xs text-rose-800 dark:text-rose-200 space-y-1">
                  <div className="flex items-center gap-2 font-semibold text-rose-700 dark:text-rose-300 font-mono text-[11px]">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>INCIDENT CLOSURE GUARD: RESOLUTION BLOCKED</span>
                  </div>
                  <p className="leading-relaxed pl-6">{closureBlockedMessage}</p>
                </div>
              )}

              <div className="flex flex-wrap gap-2">
                {(['new', 'in_triage', 'escalated', 'resolved', 'false_positive'] as AlertStatus[]).map((st) => (
                  <button
                    key={st}
                    onClick={() => handleStatusChange(st)}
                    disabled={alert.status === st || isUpdating || currentRole !== 'soc_analyst'}
                    className={`px-2.5 py-1 text-xs font-mono rounded border transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${
                      alert.status === st
                        ? 'bg-blue-100 text-blue-900 border-blue-400 dark:bg-cyan-950 dark:text-cyan-300 dark:border-cyan-700 font-bold'
                        : 'bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800'
                    }`}
                  >
                    {st.replace('_', ' ').toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* Existing notes */}
            <div className="space-y-2">
              <span className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-300 block">
                Analyst Findings Journal
              </span>
              {currentRole !== 'soc_analyst' ? (
                <p className="text-xs text-slate-500 italic p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                  Private analyst investigation notes and findings are restricted to SOC Analysts under strict role isolation.
                </p>
              ) : alert.analystNotes.length === 0 ? (
                <p className="text-xs text-slate-500 italic p-3 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                  No analyst notes recorded yet.
                </p>
              ) : (
                <div className="space-y-2">
                  {alert.analystNotes.map((note, idx) => (
                    <div key={idx} className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded text-xs text-slate-700 dark:text-slate-300 space-y-1">
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                        <span>ENTRY #{idx + 1}</span>
                        <span>CONFIDENTIAL RECORD</span>
                      </div>
                      <p className="leading-relaxed">{note}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Add note form */}
            {currentRole === 'soc_analyst' ? (
              <form onSubmit={handleNoteSubmit} className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                <label className="block text-xs font-semibold text-slate-800 dark:text-slate-200">Add New Analyst Note</label>
                <textarea
                  rows={3}
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Document your evidence review, hypothesis, or escalation recommendation..."
                  className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
                />
                <div className="flex justify-end">
                  <Button size="sm" variant="primary" type="submit" isLoading={isUpdating} disabled={!newNote.trim()}>
                    Save Note
                  </Button>
                </div>
              </form>
            ) : (
              <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded text-xs text-slate-500 dark:text-slate-400 italic">
                Note submission is restricted to SOC Analysts with active triage authorization.
              </div>
            )}
          </div>
        )}

        {/* TAB 5: INCIDENT RESPONSE TASKS */}
        {activeTab === 'tasks' && (
          <div className="space-y-4">
            <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg flex items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-mono uppercase font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                  <ClipboardList className="w-3.5 h-3.5 text-amber-500" />
                  Assigned IT Operations Remediation Tasks ({linkedTasks.length})
                </h4>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                  Tasks dispatched to IT Operations for containment, isolation, or recovery.
                </p>
              </div>
              {currentRole === 'soc_analyst' && onCreateTask && (
                <Button
                  size="xs"
                  variant="primary"
                  onClick={() => setIsCreateTaskModalOpen(true)}
                  className="flex items-center gap-1.5 shrink-0"
                >
                  <ClipboardList className="w-3.5 h-3.5" />
                  Create Response Task
                </Button>
              )}
            </div>

            {linkedTasks.length === 0 ? (
              <div className="text-center py-12 px-4 border border-dashed border-slate-200 dark:border-slate-800 rounded-lg bg-slate-50/50 dark:bg-slate-950/40 space-y-3">
                <ClipboardList className="w-8 h-8 text-slate-400 mx-auto" />
                <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  No Response Tasks Created Yet
                </div>
                <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                  SOC Analysts can dispatch actionable remediation and containment tasks directly to IT Operations.
                </p>
                {currentRole === 'soc_analyst' && onCreateTask && (
                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() => setIsCreateTaskModalOpen(true)}
                    className="text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-700/80"
                  >
                    Create First Task
                  </Button>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                {linkedTasks.map((t) => {
                  const reviewState = getTaskReviewState(t);
                  const history = reviewState.history;

                  return (
                    <div
                      key={t.id}
                      className="p-3.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-xs space-y-3"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-amber-700 dark:text-amber-400 text-xs">
                            {t.id}
                          </span>
                          <span
                            className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${reviewState.badgeClass}`}
                          >
                            {reviewState.label}
                          </span>
                          <span className="text-[9px] font-mono uppercase px-1.5 py-0.2 rounded font-bold bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                            {t.priority} priority
                          </span>
                        </div>
                        <span className="text-[10px] font-mono text-slate-500">
                          {new Date(t.createdAt).toUTCString()}
                        </span>
                      </div>

                      <div>
                        <div className="font-semibold text-slate-900 dark:text-slate-100 text-xs font-heading">
                          {t.title}
                        </div>
                        <p className="text-[11px] text-slate-600 dark:text-slate-300 whitespace-pre-wrap leading-relaxed mt-1">
                          {t.description}
                        </p>
                      </div>

                      <div className="p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 rounded font-mono text-[10px] text-slate-600 dark:text-slate-400 flex flex-wrap items-center justify-between gap-2">
                        <span>Target Asset: <strong className="text-slate-900 dark:text-slate-200">{t.targetAsset}</strong></span>
                        <span>Assigned: <strong className="text-amber-600 dark:text-amber-400 uppercase">{t.assignedRole}</strong></span>
                      </div>

                      {/* Completed Remediation Package Inspection */}
                      {(t.status === 'completed' || history.hasVerificationReport) && (
                        <div className="p-3 bg-emerald-50/50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/60 rounded-lg space-y-2.5">
                          <div className="flex flex-wrap items-center justify-between gap-1 font-mono text-[11px]">
                            <span className="font-bold text-emerald-800 dark:text-emerald-300 flex items-center gap-1.5 uppercase">
                              <ShieldAlert className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                              IT Operations Remediation Package
                            </span>
                            <div className="flex items-center gap-2">
                              {history.verificationType === 'simulation' ? (
                                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-200 dark:border-purple-800 font-bold uppercase">
                                  Simulation Verified (No Live Changes)
                                </span>
                              ) : history.verificationType === 'real' ? (
                                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 font-bold uppercase">
                                  Real Endpoint Remediation
                                </span>
                              ) : null}
                              <span className="text-slate-500 text-[10px]">
                                {t.completedAt ? new Date(t.completedAt).toUTCString() : 'Completed'}
                              </span>
                            </div>
                          </div>

                          {/* Operator Identity */}
                          <div className="text-[11px] font-mono text-slate-600 dark:text-slate-400 flex items-center gap-2">
                            <span>Certified Operator:</span>
                            <strong className="text-slate-800 dark:text-slate-200">{t.completedBy || 'IT Operations'}</strong>
                          </div>

                          {/* Work Performed */}
                          {history.workPerformed && (
                            <div className="space-y-1">
                              <span className="text-[10px] font-mono text-slate-500 uppercase block">Work Performed:</span>
                              <div className="p-2 bg-white dark:bg-slate-900 rounded border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-800 dark:text-slate-200 whitespace-pre-wrap">
                                {history.workPerformed}
                              </div>
                            </div>
                          )}

                          {/* Verification Checklist */}
                          {history.checklistItems.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-[10px] font-mono text-slate-500 uppercase block">
                                Verified Checklist ({history.checklistItems.filter((i) => i.verified).length}/{history.checklistItems.length}):
                              </span>
                              <div className="space-y-1 pl-1">
                                {history.checklistItems.map((item, idx) => (
                                  <div key={idx} className="flex items-center gap-1.5 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                                    <CheckSquare className="w-3 h-3 text-emerald-600 dark:text-emerald-400 shrink-0" />
                                    <span>{item.label}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Evidence Reference */}
                          {history.evidenceReference && (
                            <div className="space-y-1">
                              <span className="text-[10px] font-mono text-slate-500 uppercase block">Evidence / Artifact Reference:</span>
                              <div className="p-2 bg-blue-50/60 dark:bg-cyan-950/30 rounded border border-blue-200/60 dark:border-cyan-900/40 text-[11px] font-mono text-blue-700 dark:text-cyan-300 flex items-center gap-1.5">
                                <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                                <span className="break-all">{history.evidenceReference}</span>
                              </div>
                            </div>
                          )}

                          {/* Attestation */}
                          {history.operatorAttestation && (
                            <div className="pt-1.5 border-t border-emerald-200/60 dark:border-emerald-900/40 text-[10px] font-mono text-slate-500 dark:text-slate-400 italic">
                              Attestation: {history.operatorAttestation}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Review & Rework History Trail */}
                      {history.reviews.length > 0 && (
                        <div className="space-y-2 pt-1 border-t border-slate-200 dark:border-slate-800">
                          <span className="text-[10px] font-mono uppercase font-bold text-slate-500 flex items-center gap-1">
                            <History className="w-3 h-3" />
                            SOC Analyst Review History ({history.reviews.length})
                          </span>
                          <div className="space-y-1.5">
                            {history.reviews.map((rev, idx) => (
                              <div
                                key={idx}
                                className={`p-2.5 rounded border text-[11px] space-y-1 ${
                                  rev.decision === 'approved'
                                    ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200'
                                    : 'bg-orange-50 dark:bg-orange-950/40 border-orange-200 dark:border-orange-800 text-orange-900 dark:text-orange-200'
                                }`}
                              >
                                <div className="flex items-center justify-between font-mono text-[10px]">
                                  <span className="font-bold uppercase">
                                    {rev.decision === 'approved' ? '✓ Remediation Approved' : '↺ Rework Requested'}
                                  </span>
                                  <span>{new Date(rev.timestamp).toUTCString()}</span>
                                </div>
                                <div className="text-[11px]">
                                  Reviewed by: <strong>{rev.reviewerName}</strong>
                                </div>
                                <p className="font-mono bg-white dark:bg-slate-950 p-2 rounded border border-slate-200 dark:border-slate-800/80 whitespace-pre-wrap">
                                  {rev.notesOrInstructions}
                                </p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Analyst Decision Actions */}
                      {currentRole === 'soc_analyst' && onReviewTask && reviewState.canApprove && (
                        <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                          <span className="text-[11px] font-mono text-purple-700 dark:text-purple-300 font-semibold">
                            Review Decision Required:
                          </span>
                          <div className="flex items-center gap-2">
                            <Button
                              size="xs"
                              variant="outline"
                              onClick={() => setSelectedTaskForRework(t)}
                              className="text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-800 hover:bg-orange-50 dark:hover:bg-orange-950/40 font-mono text-[11px]"
                            >
                              <RefreshCw className="w-3 h-3 mr-1" />
                              Request Rework
                            </Button>
                            <Button
                              size="xs"
                              variant="primary"
                              onClick={() => setSelectedTaskForApproval(t)}
                              className="bg-emerald-600 hover:bg-emerald-700 text-white font-mono text-[11px]"
                            >
                              <CheckCircle2 className="w-3 h-3 mr-1" />
                              Approve Remediation
                            </Button>
                          </div>
                        </div>
                      )}

                      {/* Display final approval confirmation badge if already approved */}
                      {reviewState.status === 'approved' && (
                        <div className="p-2 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/80 rounded font-mono text-[11px] text-emerald-800 dark:text-emerald-300 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          <span>Remediation formally verified & approved by {reviewState.latestReview?.reviewerName || 'SOC Analyst'}. Task closed.</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Drawer Bottom Bar */}
      <div className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/90 flex items-center justify-between text-xs font-mono text-slate-600 dark:text-slate-400">
        <div>
          Current State: <strong className="text-slate-900 dark:text-slate-200 uppercase">{alert.status.replace('_', ' ')}</strong>
        </div>
        <Button size="xs" variant="ghost" onClick={onClose}>
          Close Drawer
        </Button>
      </div>

      {/* Create Task Modal */}
      {onCreateTask && (
        <CreateTaskModal
          isOpen={isCreateTaskModalOpen}
          onClose={() => setIsCreateTaskModalOpen(false)}
          alert={alert}
          currentUser={currentUser || { id: 'usr-analyst-01', name: 'Analyst', email: '', role: currentRole, callsign: 'ANALYST', title: 'SOC Analyst' }}
          onCreateTask={onCreateTask}
        />
      )}

      {/* Request Rework Modal */}
      {selectedTaskForRework && onReviewTask && (
        <RequestReworkModal
          isOpen={Boolean(selectedTaskForRework)}
          onClose={() => setSelectedTaskForRework(null)}
          task={selectedTaskForRework}
          currentUser={currentUser || { id: 'usr-analyst-01', name: 'Analyst', email: '', role: currentRole, callsign: 'ANALYST', title: 'SOC Analyst' }}
          onSubmitRework={async (taskId, instructions) => {
            await onReviewTask(taskId, 'rework_requested', instructions);
            setSelectedTaskForRework(null);
          }}
        />
      )}

      {/* Approve Remediation Modal */}
      {selectedTaskForApproval && onReviewTask && (
        <ApproveRemediationModal
          isOpen={Boolean(selectedTaskForApproval)}
          onClose={() => setSelectedTaskForApproval(null)}
          task={selectedTaskForApproval}
          currentUser={currentUser || { id: 'usr-analyst-01', name: 'Analyst', email: '', role: currentRole, callsign: 'ANALYST', title: 'SOC Analyst' }}
          onConfirmApproval={async (taskId, notes) => {
            await onReviewTask(taskId, 'approved', notes || '');
            setSelectedTaskForApproval(null);
          }}
        />
      )}
    </div>
  );
};
