import React, { useState, useMemo } from 'react';
import { SecurityAlert, AlertStatus } from '../../types/alert';
import { MitreTechnique, MitreMitigation } from '../../types/mitre';
import { ResponseActionType, IncidentTask } from '../../types/audit';
import { UserRole, UserProfile } from '../../types/auth';
import { DeterministicTriageRecommendation } from '../../types/triage';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import { formatAttackIdDisplay, normalizeAttackId } from '../../utils/mitreUtils';
import { SocAnalystKnowledgeRecord } from '../../services/knowledgeService';
import { lookupSocAnalystKnowledgeForTechnique } from '../../services/relationshipService';
import { CreateTaskModal } from './CreateTaskModal';
import {
  Search,
  AlertOctagon,
  Terminal,
  Shield,
  Layers,
  FileText,
  Clock,
  Send,
  Lock,
  Server,
  Play,
  ArrowLeft,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  History,
  BookOpen,
  FileSearch,
  ShieldAlert,
  ClipboardList,
  RefreshCw,
  CheckSquare,
} from 'lucide-react';
import { RequestReworkModal } from './RequestReworkModal';
import { ApproveRemediationModal } from './ApproveRemediationModal';
import {
  getTaskReviewState,
  parseRemediationHistory,
  checkAlertClosureEligibility,
} from '../../utils/remediationReview';

interface InvestigationWorkspaceProps {
  alerts: SecurityAlert[];
  selectedAlertId?: string;
  onSelectAlert: (alert: SecurityAlert) => void;
  onUpdateStatus: (alertId: string, status: AlertStatus) => Promise<void>;
  onAddNote: (alertId: string, note: string) => Promise<void>;
  techniques: MitreTechnique[];
  mitigations: MitreMitigation[];
  triageEvaluator: (alert: SecurityAlert) => DeterministicTriageRecommendation;
  currentRole: UserRole;
  onInitiateSimulatedAction: (actionType: ResponseActionType, target: string, alertId?: string) => void;
  onNavigateToAlertQueue: () => void;
  onNavigateToAuditTrail?: (alertId?: string) => void;
  onNavigateToPlaybooks?: (alertId?: string) => void;
  socKnowledge?: SocAnalystKnowledgeRecord[];
  tasks?: IncidentTask[];
  currentUser?: UserProfile;
  onCreateTask?: (taskData: Omit<IncidentTask, 'id' | 'createdAt'>) => Promise<IncidentTask>;
  onReviewTask?: (taskId: string, decision: 'approved' | 'rework_requested', notes: string) => Promise<void>;
}

export const InvestigationWorkspace: React.FC<InvestigationWorkspaceProps> = ({
  alerts,
  selectedAlertId,
  onSelectAlert,
  onUpdateStatus,
  onAddNote,
  techniques,
  mitigations,
  triageEvaluator,
  currentRole,
  onInitiateSimulatedAction,
  onNavigateToAlertQueue,
  onNavigateToAuditTrail,
  onNavigateToPlaybooks,
  socKnowledge = [],
  tasks = [],
  currentUser,
  onCreateTask,
  onReviewTask,
}) => {
  const [activeAlertId, setActiveAlertId] = useState<string>(
    selectedAlertId || (alerts.length > 0 ? alerts[0].id : '')
  );
  const [newNote, setNewNote] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [isCreateTaskModalOpen, setIsCreateTaskModalOpen] = useState(false);
  const [selectedTaskForRework, setSelectedTaskForRework] = useState<IncidentTask | null>(null);
  const [selectedTaskForApproval, setSelectedTaskForApproval] = useState<IncidentTask | null>(null);
  const [closureBlockedMessage, setClosureBlockedMessage] = useState<string | null>(null);

  // Active alert object
  const currentAlert = useMemo(() => {
    return alerts.find((a) => a.id === activeAlertId) || alerts[0] || null;
  }, [alerts, activeAlertId]);

  const linkedTasks = useMemo(() => {
    return (tasks || []).filter((t) => t.associatedAlertId === currentAlert?.id);
  }, [tasks, currentAlert?.id]);

  // Synchronize internal active alert state whenever external selectedAlertId updates
  React.useEffect(() => {
    if (selectedAlertId && alerts.some((a) => a.id === selectedAlertId)) {
      setActiveAlertId(selectedAlertId);
    }
  }, [selectedAlertId, alerts]);

  // Derived ATT&CK Technique ID & Knowledge
  const attackId = currentAlert?.attack_id || normalizeAttackId(currentAlert?.mitreTechniqueId);
  const socTechniqueKnowledge = useMemo(() => {
    if (!attackId || !socKnowledge || socKnowledge.length === 0) return null;
    return lookupSocAnalystKnowledgeForTechnique(attackId, socKnowledge);
  }, [attackId, socKnowledge]);

  // Derived MITRE Technique
  const currentTechnique = useMemo(() => {
    if (!currentAlert?.mitreTechniqueId) return null;
    return techniques.find((t) => t.id === currentAlert.mitreTechniqueId) || null;
  }, [currentAlert, techniques]);

  // Derived MITRE Mitigations
  const currentMitigations = useMemo(() => {
    if (!currentTechnique) return [];
    return mitigations.filter((m) => currentTechnique.mitigationIds.includes(m.id));
  }, [currentTechnique, mitigations]);

  // Derived Deterministic Recommendation
  const triageRecommendation = useMemo(() => {
    if (!currentAlert) return null;
    return triageEvaluator(currentAlert);
  }, [currentAlert, triageEvaluator]);

  const handleAlertChange = (id: string) => {
    setActiveAlertId(id);
    const target = alerts.find((a) => a.id === id);
    if (target) {
      onSelectAlert(target);
    }
  };

  const handleStatusChange = async (newStatus: AlertStatus) => {
    if (!currentAlert || isUpdatingStatus) return;
    setClosureBlockedMessage(null);

    // Requirement 7: When an alert has associated remediation tasks, require all of them
    // to have explicit SOC Analyst approval before allowing the alert to become resolved.
    if (newStatus === 'resolved') {
      const eligibility = checkAlertClosureEligibility(currentAlert.id, tasks || []);
      if (!eligibility.eligible) {
        setClosureBlockedMessage(eligibility.reason || 'All associated remediation tasks must be approved by a SOC Analyst before this alert can be resolved.');
        return;
      }
    }

    setIsUpdatingStatus(true);
    try {
      await onUpdateStatus(currentAlert.id, newStatus);
    } catch (err: any) {
      setClosureBlockedMessage(err.message || 'Failed to update alert status.');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleAddNoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentAlert || !newNote.trim() || isSubmittingNote) return;
    setIsSubmittingNote(true);
    try {
      await onAddNote(currentAlert.id, newNote.trim());
      setNewNote('');
    } finally {
      setIsSubmittingNote(false);
    }
  };

  if (!currentAlert) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-12 text-center space-y-4">
        <AlertOctagon className="w-12 h-12 text-slate-600 mx-auto" />
        <h2 className="text-lg font-semibold text-slate-200">No Investigation Selected</h2>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          The alert queue contains no items or you do not have permission to view operational alert evidence.
        </p>
        <Button variant="primary" size="sm" onClick={onNavigateToAlertQueue}>
          Return to Alert Queue
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header & Navigation Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={onNavigateToAlertQueue}
            className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            Alert Queue
          </Button>
          <div className="h-4 w-px bg-slate-800" />
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Search className="w-4 h-4 text-sky-400" />
            Investigation Workspace: <span className="font-mono text-sky-300">{currentAlert.id}</span>
          </h1>
        </div>

        {/* Action Controls & Alert Selector Dropdown */}
        <div className="flex items-center gap-2">
          {onNavigateToPlaybooks && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onNavigateToPlaybooks(currentAlert.id)}
              className="text-xs text-emerald-300 border border-emerald-800/60 hover:bg-emerald-950/40 flex items-center gap-1.5"
            >
              <BookOpen className="w-3.5 h-3.5 text-emerald-400" />
              Response Playbooks
            </Button>
          )}
          <label htmlFor="alert-select" className="text-xs text-slate-400 whitespace-nowrap">
            Switch Incident:
          </label>
          <select
            id="alert-select"
            value={currentAlert.id}
            onChange={(e) => handleAlertChange(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded px-2.5 py-1.5 focus:outline-none focus:border-sky-500 font-mono"
          >
            {alerts.map((a) => (
              <option key={a.id} value={a.id}>
                {a.id} — [{a.severity.toUpperCase()}] {a.title.slice(0, 40)}...
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <ProvenanceBadge
          type="synthetic_demo"
          label="SYNTHETIC TELEMETRY EVIDENCE"
        />
        <span className="text-xs text-slate-400">
          Evidence parameters, process trees, and hash artifacts are synthetic demonstration fixtures. All triage notes appended here are stored locally in accordance with Phase 1 protocols.
        </span>
      </div>

      {/* Main Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Columns: Evidence, MITRE, and Notes */}
        <div className="lg:col-span-2 space-y-6">
          {/* Incident Overview Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-xs font-mono text-slate-400">{currentAlert.id}</span>
                <h2 className="text-base font-bold text-slate-100">{currentAlert.title}</h2>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 text-xs font-semibold uppercase rounded ${
                    currentAlert.severity === 'critical'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : currentAlert.severity === 'high'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                  }`}
                >
                  {currentAlert.severity}
                </span>
                <span className="px-2 py-0.5 text-xs font-medium rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {currentAlert.status}
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded border border-slate-800/80">
              {currentAlert.description}
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
                <span className="text-[11px] text-slate-400 block">Host Name</span>
                <span className="font-mono text-slate-200 font-semibold">{currentAlert.hostName}</span>
              </div>
              <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
                <span className="text-[11px] text-slate-400 block">Source IP</span>
                <span className="font-mono text-slate-200 font-semibold">{currentAlert.sourceIp}</span>
              </div>
              <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
                <span className="text-[11px] text-slate-400 block">Destination IP</span>
                <span className="font-mono text-slate-200 font-semibold">
                  {currentAlert.destinationIp || 'Local / None'}
                </span>
              </div>
              <div className="p-2.5 bg-slate-950/40 rounded border border-slate-800">
                <span className="text-[11px] text-slate-400 block">Detected At</span>
                <span className="font-mono text-slate-300 text-[11px]">
                  {new Date(currentAlert.detectedAt).toLocaleTimeString()}
                </span>
              </div>
            </div>
          </div>

          {/* Forensic Process & Command Line Evidence */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Forensic Process & Command-Line Evidence
            </h3>

            <div className="space-y-3 text-xs">
              {currentAlert.evidence.processName && (
                <div>
                  <span className="text-[11px] text-slate-400 block mb-1">Process Name:</span>
                  <div className="font-mono bg-slate-950 p-2.5 rounded border border-slate-800 text-emerald-300 break-all select-all">
                    {currentAlert.evidence.processName}
                  </div>
                </div>
              )}

              {currentAlert.evidence.processCommandLine && (
                <div>
                  <span className="text-[11px] text-slate-400 block mb-1">Full Execution Command Line:</span>
                  <div className="font-mono bg-slate-950 p-2.5 rounded border border-slate-800 text-amber-300 break-all select-all">
                    {currentAlert.evidence.processCommandLine}
                  </div>
                </div>
              )}

              {currentAlert.evidence.parentProcess && (
                <div>
                  <span className="text-[11px] text-slate-400 block mb-1">Parent Process Lineage:</span>
                  <div className="font-mono bg-slate-950 p-2.5 rounded border border-slate-800 text-slate-300 break-all">
                    {currentAlert.evidence.parentProcess}
                  </div>
                </div>
              )}

              {currentAlert.evidence.rawEventLog && (
                <div>
                  <span className="text-[11px] text-slate-400 block mb-1">Raw Event Log (SIEM Telemetry):</span>
                  <pre className="font-mono text-[11px] bg-slate-950 p-3 rounded border border-slate-800 text-slate-300 overflow-x-auto whitespace-pre-wrap select-all max-h-48 overflow-y-auto">
                    {currentAlert.evidence.rawEventLog}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* MITRE ATT&CK Mapping & Mitigations */}
          {(socTechniqueKnowledge || currentTechnique) && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-blue-400" />
                  MITRE ATT&CK Correlation
                  {socTechniqueKnowledge && (
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/80 px-1.5 py-0.2 rounded border border-cyan-800">
                      public.soc_analyst_knowledge
                    </span>
                  )}
                </h3>
                <span className="font-mono text-xs text-blue-400 font-bold bg-blue-950 px-2 py-0.5 rounded border border-blue-900">
                  {formatAttackIdDisplay(attackId || currentTechnique?.id)}
                </span>
              </div>

              <div>
                <h4 className="text-sm font-semibold text-slate-100">
                  {socTechniqueKnowledge?.techniqueName || currentTechnique?.name}
                </h4>
                <p className="text-xs text-slate-400 mt-1">
                  {socTechniqueKnowledge?.techniqueDescription || currentTechnique?.description}
                </p>
                <div className="pt-2 flex flex-wrap gap-2 text-[10px] font-mono text-slate-400">
                  {socTechniqueKnowledge?.tactics.length ? (
                    <span>Tactics: <strong className="text-slate-300">{socTechniqueKnowledge.tactics.join(', ')}</strong></span>
                  ) : null}
                  <span>Platforms: <strong className="text-slate-300">
                    {socTechniqueKnowledge?.platforms.length
                      ? socTechniqueKnowledge.platforms.join(', ')
                      : currentTechnique?.platforms.join(', ') || 'Enterprise'}
                  </strong></span>
                </div>
              </div>

              {/* Verified Detection Strategy */}
              {socTechniqueKnowledge?.detectionStrategies.length ? (
                <div className="p-3 bg-slate-950/80 rounded border border-slate-800 space-y-2">
                  <span className="text-xs font-mono uppercase font-bold text-slate-300 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
                    Verified Detection Strategies ({socTechniqueKnowledge.detectionStrategies.length})
                  </span>
                  <div className="space-y-1.5">
                    {socTechniqueKnowledge.detectionStrategies.map((ds, idx) => (
                      <div key={idx} className="p-2 bg-slate-900 border border-slate-800 rounded text-xs flex items-center justify-between">
                        <span className="text-slate-200">{ds.name}</span>
                        <span className="font-mono text-[10px] text-cyan-400 font-semibold">{ds.attackId}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              {/* Behavioral Analytics & Log Sources */}
              {socTechniqueKnowledge && (socTechniqueKnowledge.analytics.length > 0 || socTechniqueKnowledge.logSources.length > 0) && (
                <div className="p-3 bg-slate-950/80 rounded border border-slate-800 space-y-2.5">
                  <span className="text-xs font-mono uppercase font-bold text-emerald-400 flex items-center gap-1.5">
                    <FileSearch className="w-3.5 h-3.5" />
                    Reference Analytics & Log Sources
                  </span>

                  {socTechniqueKnowledge.analytics.length > 0 && (
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-slate-400 uppercase block">
                        Behavioral Analytics:
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {socTechniqueKnowledge.analytics.map((an, idx) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800"
                          >
                            {an.id}: {an.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {socTechniqueKnowledge.logSources.length > 0 && (
                    <div className="space-y-1 pt-1 border-t border-slate-800/80">
                      <span className="text-[10px] font-mono text-slate-400 uppercase block">
                        Log Sources:
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {socTechniqueKnowledge.logSources.map((ls, idx) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-300 border border-slate-800"
                          >
                            {ls}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {currentMitigations.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <span className="text-xs font-medium text-slate-300 block">
                    Recommended Defensive Mitigations ({currentMitigations.length}):
                  </span>
                  <div className="space-y-2">
                    {currentMitigations.map((mit) => (
                      <div key={mit.id} className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-xs">
                        <div className="flex items-center justify-between text-slate-200 font-semibold mb-1">
                          <span>{mit.name}</span>
                          <span className="font-mono text-[11px] text-blue-400">{mit.id}</span>
                        </div>
                        <p className="text-[11px] text-slate-400">{mit.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Chronological Analyst Notes */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <FileText className="w-4 h-4 text-purple-400" />
              Chronological Analyst Investigation Notes ({currentAlert.analystNotes.length})
            </h3>

            {currentAlert.analystNotes.length === 0 ? (
              <div className="py-4 text-center text-xs text-slate-500">
                No notes attached yet. Record forensic findings below.
              </div>
            ) : (
              <div className="space-y-2.5">
                {currentAlert.analystNotes.map((noteText, idx) => (
                  <div key={idx} className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                        Analyst Observation #{idx + 1}
                      </span>
                    </div>
                    <p className="text-xs text-slate-200 whitespace-pre-wrap">{noteText}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Note Append Form */}
            {currentRole === 'soc_analyst' ? (
              <form onSubmit={handleAddNoteSubmit} className="pt-3 border-t border-slate-800 space-y-2">
                <label htmlFor="analyst-note-input" className="text-xs font-medium text-slate-300 block">
                  Add Forensic Note / Triage Finding:
                </label>
                <textarea
                  id="analyst-note-input"
                  rows={3}
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Record evidence observation, hypothesis, or containment rationale..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    variant="primary"
                    size="sm"
                    disabled={!newNote.trim() || isSubmittingNote}
                    className="text-xs flex items-center gap-1.5"
                  >
                    <Send className="w-3.5 h-3.5" />
                    {isSubmittingNote ? 'Saving Note...' : 'Append Note'}
                  </Button>
                </div>
              </form>
            ) : (
              <div className="p-3 bg-slate-950/40 rounded border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 text-slate-500" />
                Only Tier 1/2 SOC Analysts have permission to append investigation notes.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Triage Recommendation, Status Transitions, Containment Actions */}
        <div className="space-y-6">
          {/* Deterministic Triage Recommendation */}
          {triageRecommendation && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Deterministic Triage
                </h3>
                <span className="font-mono text-xs font-bold text-slate-300">
                  Confidence: {triageRecommendation.confidenceScore}%
                </span>
              </div>

              <div className="p-3 bg-slate-950/80 rounded border border-slate-800 text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Category:</span>
                  <span className="font-mono font-bold text-amber-300 uppercase">
                    {triageRecommendation.recommendationCategory}
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed">
                  {triageRecommendation.summaryRationale}
                </p>
              </div>

              {triageRecommendation.matchedRules.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[11px] font-medium text-slate-400 block">Matched Rules:</span>
                  {triageRecommendation.matchedRules.map((rule) => (
                    <div key={rule.ruleId} className="p-2 bg-slate-950/50 rounded border border-slate-800 text-[11px]">
                      <div className="font-mono font-bold text-indigo-400">{rule.ruleId}</div>
                      <div className="text-slate-300 font-medium">{rule.ruleName}</div>
                      <div className="text-slate-500 text-[10px] mt-0.5">{rule.description}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Incident Status Transitions */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
            <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Clock className="w-4 h-4 text-slate-400" />
              Triage Lifecycle Transition
            </h3>
            <p className="text-[11px] text-slate-400">
              Update status to reflect current operational workflow state:
            </p>

            {/* Incident Closure Guard Alert */}
            {closureBlockedMessage && (
              <div className="p-3 bg-rose-950/80 border border-rose-800 rounded-lg text-xs text-rose-200 space-y-1">
                <div className="flex items-center gap-2 font-semibold text-rose-300 font-mono text-[11px]">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>INCIDENT CLOSURE GUARD: RESOLUTION BLOCKED</span>
                </div>
                <p className="leading-relaxed pl-6">{closureBlockedMessage}</p>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2">
              {(['new', 'in_triage', 'escalated', 'resolved', 'false_positive'] as AlertStatus[]).map((status) => (
                <Button
                  key={status}
                  variant={currentAlert.status === status ? 'primary' : 'outline'}
                  size="sm"
                  disabled={isUpdatingStatus || currentRole !== 'soc_analyst'}
                  onClick={() => handleStatusChange(status)}
                  className="text-xs capitalize justify-center"
                >
                  {status.replace('_', ' ')}
                </Button>
              ))}
            </div>
          </div>

          {/* Containment Simulation Actions */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
            <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Play className="w-4 h-4 text-rose-400" />
              Simulated Response Actions
            </h3>
            <p className="text-[11px] text-slate-400">
              Execute approved containment simulations with mandatory operator rationale:
            </p>

            <div className="space-y-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => onInitiateSimulatedAction('isolate_host', currentAlert.hostName, currentAlert.id)}
                className="w-full text-xs justify-start text-rose-300 border-rose-900/50 hover:bg-rose-950/40"
              >
                Isolate Host: {currentAlert.hostName}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onInitiateSimulatedAction('block_ip', currentAlert.sourceIp, currentAlert.id)}
                className="w-full text-xs justify-start text-amber-300 border-amber-900/50 hover:bg-amber-950/40"
              >
                Block Source IP: {currentAlert.sourceIp}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onInitiateSimulatedAction('lock_account', 'Target User', currentAlert.id)}
                className="w-full text-xs justify-start text-yellow-300 border-yellow-900/50 hover:bg-yellow-950/40"
              >
                Lock Affected User Account
              </Button>
            </div>
          </div>

          {/* IT Operations Remediation Tasks Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <ClipboardList className="w-4 h-4 text-amber-400" />
                Response Tasks ({linkedTasks.length})
              </h3>
              {currentRole === 'soc_analyst' && onCreateTask && (
                <Button
                  size="xs"
                  variant="outline"
                  onClick={() => setIsCreateTaskModalOpen(true)}
                  className="text-amber-300 border-amber-900/60 hover:bg-amber-950/40 text-[11px] flex items-center gap-1"
                >
                  <ClipboardList className="w-3 h-3 text-amber-400" />
                  Create Task
                </Button>
              )}
            </div>
            <p className="text-[11px] text-slate-400">
              Assigned remediation tasks for IT Operations linked to {currentAlert.id}:
            </p>

            {linkedTasks.length === 0 ? (
              <p className="text-xs text-slate-500 italic p-3 bg-slate-950/50 rounded border border-slate-800">
                No remediation tasks dispatched for this alert yet.
              </p>
            ) : (
              <div className="space-y-2.5">
                {linkedTasks.map((t) => {
                  const reviewState = getTaskReviewState(t);
                  return (
                    <div key={t.id} className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg text-xs space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-amber-400">{t.id}</span>
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded font-bold border ${reviewState.badgeClass}`}>
                            {reviewState.label}
                          </span>
                          <span className="text-[9px] font-mono uppercase px-1.5 py-0.2 rounded font-bold bg-amber-950 text-amber-300">
                            {t.priority}
                          </span>
                        </div>
                      </div>
                      <div className="font-medium text-slate-200 text-xs">{t.title}</div>
                      <div className="text-[10px] font-mono text-slate-400 flex items-center justify-between">
                        <span>Target: <strong className="text-slate-300">{t.targetAsset}</strong></span>
                        <span>Role: {t.assignedRole}</span>
                      </div>

                      {/* If rework instructions exist */}
                      {reviewState.status === 'rework_requested' && reviewState.latestReworkInstructions && (
                        <div className="p-2 bg-orange-950/30 border border-orange-800/60 rounded text-[10px] text-orange-300 font-mono space-y-0.5">
                          <span className="font-bold uppercase flex items-center gap-1">
                            <RefreshCw className="w-2.5 h-2.5" />
                            Rework Instructions Sent:
                          </span>
                          <p className="line-clamp-2">{reviewState.latestReworkInstructions}</p>
                        </div>
                      )}

                      {/* If approved */}
                      {reviewState.status === 'approved' && (
                        <div className="p-2 bg-emerald-950/30 border border-emerald-800/60 rounded text-[10px] text-emerald-300 font-mono flex items-center gap-1.5">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>Remediation approved by {reviewState.latestReview?.reviewerName || 'Analyst'}</span>
                        </div>
                      )}

                      {/* Action buttons if awaiting review */}
                      {currentRole === 'soc_analyst' && onReviewTask && reviewState.canApprove && (
                        <div className="pt-2 border-t border-slate-800 flex items-center justify-between gap-1.5">
                          <span className="text-[10px] font-mono text-purple-300">Review Decision:</span>
                          <div className="flex items-center gap-1.5">
                            <Button
                              size="xs"
                              variant="outline"
                              onClick={() => setSelectedTaskForRework(t)}
                              className="text-orange-300 border-orange-800 hover:bg-orange-950 text-[10px] py-0.5 px-2 font-mono"
                            >
                              <RefreshCw className="w-2.5 h-2.5 mr-1" />
                              Rework
                            </Button>
                            <Button
                              size="xs"
                              variant="primary"
                              onClick={() => setSelectedTaskForApproval(t)}
                              className="bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] py-0.5 px-2 font-mono"
                            >
                              <CheckCircle2 className="w-2.5 h-2.5 mr-1" />
                              Approve
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Response Playbooks Deep-Link */}
          {onNavigateToPlaybooks && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5 text-emerald-400" />
                Response Playbooks
              </h3>
              <p className="text-[11px] text-slate-400">
                Execute standardized containment SOPs and mitigation workflows pre-linked to incident {currentAlert.id}.
              </p>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => onNavigateToPlaybooks(currentAlert.id)}
                className="w-full text-xs justify-center flex items-center gap-1.5 text-emerald-300 border border-emerald-900/60 hover:bg-emerald-950/40"
              >
                Launch Playbook for {currentAlert.id}
                <ExternalLink className="w-3.5 h-3.5" />
              </Button>
            </div>
          )}

          {/* Audit Trail Deep-Link */}
          {onNavigateToAuditTrail && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <History className="w-3.5 h-3.5 text-purple-400" />
                Associated Audit Records
              </h3>
              <p className="text-[11px] text-slate-400">
                View tamper-evident action logs specifically associated with {currentAlert.id}.
              </p>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => onNavigateToAuditTrail(currentAlert.id)}
                className="w-full text-xs justify-center flex items-center gap-1.5"
              >
                View Audit Records for {currentAlert.id}
                <ExternalLink className="w-3.5 h-3.5" />
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Create Task Modal */}
      {onCreateTask && currentAlert && (
        <CreateTaskModal
          isOpen={isCreateTaskModalOpen}
          onClose={() => setIsCreateTaskModalOpen(false)}
          alert={currentAlert}
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
