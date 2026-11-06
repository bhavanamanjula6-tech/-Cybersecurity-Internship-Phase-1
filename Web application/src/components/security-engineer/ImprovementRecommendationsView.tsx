import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  FileCode2,
  CheckCircle2,
  Cpu,
  ArrowRight,
  Filter,
  Layers,
  Sparkles,
  ExternalLink,
  Info,
  Send,
  Clock,
  Check,
  X,
  HelpCircle,
  ShieldCheck,
  MessageSquare,
  RefreshCw,
} from 'lucide-react';
import {
  ImprovementRecommendation,
  RecommendationPriority,
} from '../../services/securityAnalyticsService';
import {
  DetectionRecommendation,
  CreateRecommendationInput,
  RecommendationStatus,
} from '../../types/recommendation';
import { UserProfile } from '../../types/auth';
import { DetectionRuleDraft, DetectionRuleService, RuleValidationResult } from '../../services/detectionRuleService';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';

interface ImprovementRecommendationsViewProps {
  recommendations: ImprovementRecommendation[];
  onSelectTechniqueForDraft?: (techniqueId: string) => void;
  className?: string;
  currentUser?: UserProfile;
  activeRecommendations?: DetectionRecommendation[];
  onSubmitRecommendation?: (input: CreateRecommendationInput) => Promise<void>;
  onUpdateImplementation?: (
    recommendationId: string,
    status: 'in_progress' | 'completed',
    notes?: string,
    sigmaDraftReference?: string
  ) => Promise<void>;
  availableDrafts?: DetectionRuleDraft[];
  onRefreshActiveRecommendations?: () => void;
}

export const ImprovementRecommendationsView: React.FC<ImprovementRecommendationsViewProps> = ({
  recommendations,
  onSelectTechniqueForDraft,
  className = '',
  currentUser,
  activeRecommendations = [],
  onSubmitRecommendation,
  onUpdateImplementation,
  availableDrafts = [],
  onRefreshActiveRecommendations,
}) => {
  const [subTab, setSubTab] = useState<'catalog' | 'active_queue'>('catalog');
  const [priorityFilter, setPriorityFilter] = useState<string>('all');
  const [activeStatusFilter, setActiveStatusFilter] = useState<string>('all');

  // Submission Modal state
  const [isSubmitModalOpen, setIsSubmitModalOpen] = useState(false);
  const [submitFormData, setSubmitFormData] = useState<CreateRecommendationInput>({
    title: '',
    techniqueId: '',
    techniqueName: '',
    tacticId: '',
    tacticName: '',
    priority: 'high',
    detectionGap: '',
    technicalExplanation: '',
    proposedImprovement: '',
    supportingEvidence: '',
    relatedRuleDraftId: '',
  });
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitSuccessMsg, setSubmitSuccessMsg] = useState<string | null>(null);

  // Implementation Modal state
  const [implementModal, setImplementModal] = useState<{
    rec: DetectionRecommendation | null;
    targetStatus: 'in_progress' | 'completed' | null;
  }>({ rec: null, targetStatus: null });
  const [implementNotes, setImplementNotes] = useState('');
  const [selectedSigmaRef, setSelectedSigmaRef] = useState('');
  const [implementError, setImplementError] = useState<string | null>(null);
  const [isUpdatingImpl, setIsUpdatingImpl] = useState(false);
  const [sigmaValidation, setSigmaValidation] = useState<RuleValidationResult | null>(null);

  const filteredCatalogRecommendations = useMemo(() => {
    return recommendations.filter((rec) => {
      if (priorityFilter !== 'all' && rec.priority !== priorityFilter) return false;
      return true;
    });
  }, [recommendations, priorityFilter]);

  const filteredActiveRecommendations = useMemo(() => {
    return activeRecommendations.filter((rec) => {
      if (activeStatusFilter !== 'all' && rec.status !== activeStatusFilter) return false;
      return true;
    });
  }, [activeRecommendations, activeStatusFilter]);

  const criticalCount = recommendations.filter((r) => r.priority === 'critical').length;
  const highCount = recommendations.filter((r) => r.priority === 'high').length;
  const mediumCount = recommendations.filter((r) => r.priority === 'medium').length;

  const pendingActiveCount = activeRecommendations.filter(
    (r) => r.status === 'proposed' || r.status === 'clarification_requested'
  ).length;
  const acceptedForEngineeringCount = activeRecommendations.filter(
    (r) => r.status === 'accepted' || r.status === 'in_progress'
  ).length;

  const getPriorityBadge = (priority: RecommendationPriority) => {
    switch (priority) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800">
            <AlertTriangle className="w-3 h-3 text-rose-600 dark:text-rose-400" />
            CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800">
            <AlertTriangle className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-800">
            <Info className="w-3 h-3 text-blue-600 dark:text-blue-400" />
            MEDIUM
          </span>
        );
      case 'low':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            LOW
          </span>
        );
    }
  };

  const getStatusBadge = (status: RecommendationStatus) => {
    switch (status) {
      case 'proposed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-50 text-purple-700 border border-purple-200 dark:bg-purple-950/80 dark:text-purple-300 dark:border-purple-800">
            <Clock className="w-3 h-3 text-purple-600 dark:text-purple-400" />
            PENDING SOC REVIEW
          </span>
        );
      case 'accepted':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-800">
            <Check className="w-3 h-3 text-blue-600 dark:text-blue-400" />
            ACCEPTED BY SOC
          </span>
        );
      case 'in_progress':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-50 text-cyan-800 border border-cyan-200 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-800">
            <FileCode2 className="w-3 h-3 text-cyan-600 dark:text-cyan-400 animate-pulse" />
            IMPLEMENTATION IN PROGRESS
          </span>
        );
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-300 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-700">
            <CheckCircle2 className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            COMPLETED &bull; AWAITING SOC VALIDATION
          </span>
        );
      case 'validated':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-700">
            <ShieldCheck className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
            VALIDATED BY SOC
          </span>
        );
      case 'rejected':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800">
            <X className="w-3 h-3 text-rose-600 dark:text-rose-400" />
            REJECTED
          </span>
        );
      case 'clarification_requested':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800">
            <HelpCircle className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            CLARIFICATION REQUESTED
          </span>
        );
      default:
        return null;
    }
  };

  const getCategoryLabel = (cat: ImprovementRecommendation['category']) => {
    switch (cat) {
      case 'uncovered_high_impact':
        return 'High-Impact Gap';
      case 'active_incident_correlation':
        return 'Active Threat Correlation';
      case 'missing_draft_rule':
        return 'Missing Detection Draft';
      case 'rule_syntax_validation':
        return 'Rule Syntax Fix';
      default:
        return 'Defensive Coverage';
    }
  };

  // Open Submit Modal for a Catalog Recommendation
  const handleOpenSubmitModal = (rec: ImprovementRecommendation) => {
    // Check if an authored draft exists for this technique
    const matchingDraft = availableDrafts.find((d) => d.techniqueId === rec.techniqueId);

    setSubmitFormData({
      title: `${rec.techniqueName} Detection Strategy`,
      techniqueId: rec.techniqueId,
      techniqueName: rec.techniqueName,
      tacticId: rec.tacticId,
      tacticName: rec.tacticName,
      priority: rec.priority,
      detectionGap: rec.whyItMatters,
      technicalExplanation: `${rec.priorityRationale}\n\nObserved Data Sources: ${rec.dataSources.join(', ') || 'Process monitoring, Network flow'}.`,
      proposedImprovement: rec.suggestedNextAction,
      supportingEvidence: rec.dataSources.join(', '),
      relatedRuleDraftId: matchingDraft?.id || '',
    });
    setSubmitError(null);
    setIsSubmitModalOpen(true);
  };

  // Check if a catalog recommendation has already been submitted
  const isAlreadySubmitted = (techId: string, title: string) => {
    return activeRecommendations.some(
      (r) =>
        r.techniqueId.toLowerCase() === techId.toLowerCase() &&
        r.title.toLowerCase().trim() === title.toLowerCase().trim() &&
        r.status !== 'rejected'
    );
  };

  // Handle Form Submission
  const handleConfirmSubmit = async () => {
    if (!onSubmitRecommendation) return;

    if (!submitFormData.title.trim()) {
      setSubmitError('Recommendation title is required.');
      return;
    }
    if (!submitFormData.techniqueId.trim()) {
      setSubmitError('Technique ID is required.');
      return;
    }
    if (!submitFormData.detectionGap.trim()) {
      setSubmitError('Detection gap explanation is required.');
      return;
    }
    if (!submitFormData.technicalExplanation.trim()) {
      setSubmitError('Technical explanation is required.');
      return;
    }
    if (!submitFormData.proposedImprovement.trim()) {
      setSubmitError('Proposed improvement is required.');
      return;
    }

    if (isAlreadySubmitted(submitFormData.techniqueId, submitFormData.title)) {
      setSubmitError(`A detection recommendation for ${submitFormData.techniqueId} with this title already exists in the active queue.`);
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await onSubmitRecommendation(submitFormData);
      setIsSubmitModalOpen(false);
      setSubmitSuccessMsg(`Successfully submitted recommendation for ${submitFormData.techniqueId} to SOC Analyst triage queue.`);
      setSubTab('active_queue');
      setTimeout(() => setSubmitSuccessMsg(null), 5000);
    } catch (err: any) {
      setSubmitError(err.message || 'Failed to submit recommendation.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle opening implementation modal
  const handleOpenImplementModal = (
    rec: DetectionRecommendation,
    targetStatus: 'in_progress' | 'completed'
  ) => {
    setImplementModal({ rec, targetStatus });
    setImplementNotes(rec.implementationNotes || '');

    // Pre-select matching Sigma draft if available
    const matchingDraft =
      availableDrafts.find((d) => d.id === rec.sigmaDraftReference) ||
      availableDrafts.find((d) => d.techniqueId === rec.techniqueId);
    const chosenRef = rec.sigmaDraftReference || matchingDraft?.id || '';
    setSelectedSigmaRef(chosenRef);

    if (matchingDraft?.rawYaml) {
      const val = DetectionRuleService.validateSigmaRuleStructure(matchingDraft.rawYaml);
      setSigmaValidation(val);
    } else {
      setSigmaValidation(null);
    }
    setImplementError(null);
  };

  const handleSigmaDraftSelect = (draftId: string) => {
    setSelectedSigmaRef(draftId);
    const d = availableDrafts.find((draft) => draft.id === draftId);
    if (d?.rawYaml) {
      const val = DetectionRuleService.validateSigmaRuleStructure(d.rawYaml);
      setSigmaValidation(val);
    } else {
      setSigmaValidation(null);
    }
  };

  const handleConfirmImplementUpdate = async () => {
    if (!implementModal.rec || !implementModal.targetStatus || !onUpdateImplementation) return;
    const { rec, targetStatus } = implementModal;

    if (targetStatus === 'completed' && implementNotes.trim().length < 10) {
      setImplementError('Mandatory implementation notes of at least 10 characters are required to mark completed.');
      return;
    }

    setIsUpdatingImpl(true);
    setImplementError(null);

    try {
      await onUpdateImplementation(
        rec.id,
        targetStatus,
        implementNotes.trim(),
        selectedSigmaRef.trim() || undefined
      );
      setImplementModal({ rec: null, targetStatus: null });
    } catch (err: any) {
      setImplementError(err.message || 'Failed to update implementation.');
    } finally {
      setIsUpdatingImpl(false);
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Top Header & Sub-Tab Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold font-mono uppercase text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-amber-500" />
              Detection Improvement Recommendations
            </h2>
            <ProvenanceBadge type="deterministic_rule" label="ENGINEERING COLLABORATION" />
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Submit prioritized detection engineering recommendations to SOC Analyst triage, author Sigma rules, and track validation.
          </p>
        </div>

        {/* Sub-tab Navigation */}
        <div className="flex items-center rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-950 p-0.5">
          <button
            type="button"
            onClick={() => setSubTab('catalog')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${
              subTab === 'catalog'
                ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-cyan-400 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Gap Catalog</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
              {recommendations.length}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSubTab('active_queue')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${
              subTab === 'active_queue'
                ? 'bg-white dark:bg-slate-800 text-blue-700 dark:text-cyan-400 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <Send className="w-3.5 h-3.5 text-blue-500" />
            <span>Submitted to SOC</span>
            {activeRecommendations.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-blue-100 dark:bg-cyan-950 text-blue-800 dark:text-cyan-300">
                {activeRecommendations.length}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Success Notification Banner */}
      {submitSuccessMsg && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/80 border border-emerald-300 dark:border-emerald-700 rounded-lg text-xs text-emerald-800 dark:text-emerald-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>{submitSuccessMsg}</span>
          </div>
          <button type="button" onClick={() => setSubmitSuccessMsg(null)} className="text-emerald-600 hover:text-emerald-800">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* TAB A: GAP CATALOG VIEW */}
      {subTab === 'catalog' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500 font-mono">Filter by Priority:</span>
              <select
                value={priorityFilter}
                onChange={(e) => setPriorityFilter(e.target.value)}
                className="bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1 text-xs focus:outline-none cursor-pointer"
                aria-label="Filter recommendations by priority"
              >
                <option value="all">All Priorities ({recommendations.length})</option>
                <option value="critical">Critical ({criticalCount})</option>
                <option value="high">High ({highCount})</option>
                <option value="medium">Medium ({mediumCount})</option>
              </select>
            </div>

            <span className="text-xs text-slate-400 font-mono">
              Deterministic MITRE ATT&CK coverage gap evaluation
            </span>
          </div>

          {filteredCatalogRecommendations.length === 0 ? (
            <div className="p-12 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-center space-y-2 shadow-xs">
              <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                No Recommendations in Selected Priority
              </h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                All coverage areas in this filter tier are currently addressed or documented.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredCatalogRecommendations.map((rec) => {
                const alreadySubmitted = isAlreadySubmitted(
                  rec.techniqueId,
                  `${rec.techniqueName} Detection Strategy`
                );

                return (
                  <div
                    key={rec.id}
                    className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition space-y-3"
                  >
                    {/* Header Row */}
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-2.5">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          {getPriorityBadge(rec.priority)}
                          <span className="text-xs font-mono font-bold text-blue-700 dark:text-cyan-400">
                            {rec.techniqueId}
                          </span>
                          <span className="text-sm font-bold text-slate-900 dark:text-slate-100">
                            {rec.techniqueName}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                            {rec.tacticName} ({rec.tacticId})
                          </span>
                        </div>
                        <span className="text-[10px] font-mono text-slate-400 block">
                          Category: {getCategoryLabel(rec.category)} &bull; {rec.generationNotice}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
                        {onSelectTechniqueForDraft && (
                          <button
                            type="button"
                            onClick={() => onSelectTechniqueForDraft(rec.techniqueId)}
                            className="px-2.5 py-1 rounded text-xs font-mono font-semibold bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 transition flex items-center gap-1.5 shrink-0 cursor-pointer shadow-xs"
                            title={`Open Detection Workbench for ${rec.techniqueId}`}
                          >
                            <FileCode2 className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
                            <span>Workbench</span>
                          </button>
                        )}

                        <Button
                          size="xs"
                          variant={alreadySubmitted ? 'outline' : 'primary'}
                          disabled={alreadySubmitted}
                          onClick={() => handleOpenSubmitModal(rec)}
                          icon={<Send className="w-3.5 h-3.5" />}
                        >
                          {alreadySubmitted ? 'Submitted to SOC' : 'Submit to SOC Analyst'}
                        </Button>
                      </div>
                    </div>

                    {/* Rationale & Evidence */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="space-y-1 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80">
                        <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                          Why It Matters (Available Evidence)
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans text-[11px]">
                          {rec.whyItMatters}
                        </p>
                      </div>

                      <div className="space-y-1 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80">
                        <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                          Priority Rationale
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans text-[11px]">
                          {rec.priorityRationale}
                        </p>
                      </div>
                    </div>

                    {/* Next Action Box */}
                    <div className="p-2.5 rounded-lg bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 flex items-start gap-2 text-xs">
                      <ArrowRight className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                      <div className="space-y-0.5">
                        <span className="font-bold text-emerald-900 dark:text-emerald-300 font-mono text-[11px] block">
                          SUGGESTED NEXT ACTION:
                        </span>
                        <p className="text-emerald-800 dark:text-emerald-300/90 text-[11px] font-sans">
                          {rec.suggestedNextAction}
                        </p>
                      </div>
                    </div>

                    {/* Telemetry Sources */}
                    {rec.dataSources.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap text-[10px] font-mono text-slate-500">
                        <span className="font-semibold">Telemetry Sources:</span>
                        {rec.dataSources.map((ds) => (
                          <span
                            key={ds}
                            className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700"
                          >
                            {ds}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB B: SUBMITTED COLLABORATIVE QUEUE VIEW */}
      {subTab === 'active_queue' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500 font-mono">Filter by Status:</span>
              <select
                value={activeStatusFilter}
                onChange={(e) => setActiveStatusFilter(e.target.value)}
                className="bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1 text-xs focus:outline-none cursor-pointer"
                aria-label="Filter active recommendations by status"
              >
                <option value="all">All Submitted ({activeRecommendations.length})</option>
                <option value="proposed">Pending SOC Review ({activeRecommendations.filter((r) => r.status === 'proposed').length})</option>
                <option value="accepted">Accepted by SOC ({activeRecommendations.filter((r) => r.status === 'accepted').length})</option>
                <option value="in_progress">In Progress ({activeRecommendations.filter((r) => r.status === 'in_progress').length})</option>
                <option value="completed">Completed / Awaiting Validation ({activeRecommendations.filter((r) => r.status === 'completed').length})</option>
                <option value="validated">Validated ({activeRecommendations.filter((r) => r.status === 'validated').length})</option>
                <option value="rejected">Rejected ({activeRecommendations.filter((r) => r.status === 'rejected').length})</option>
                <option value="clarification_requested">Clarification Needed ({activeRecommendations.filter((r) => r.status === 'clarification_requested').length})</option>
              </select>
            </div>

            <Button
              size="xs"
              variant="secondary"
              onClick={onRefreshActiveRecommendations}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
            >
              Refresh Queue
            </Button>
          </div>

          {filteredActiveRecommendations.length === 0 ? (
            <div className="p-12 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-center space-y-2 shadow-xs">
              <CheckCircle2 className="w-8 h-8 text-blue-500 mx-auto" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                No Recommendations in this Filter
              </h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                {activeRecommendations.length === 0
                  ? 'No recommendations submitted yet. Select a recommendation from the Gap Catalog to submit it to the SOC Analyst.'
                  : 'Try selecting All Submitted in the status filter.'}
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredActiveRecommendations.map((rec) => (
                <div
                  key={rec.id}
                  className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-3"
                >
                  {/* Header Row */}
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-2.5">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        {getPriorityBadge(rec.priority)}
                        {getStatusBadge(rec.status)}
                        <span className="text-xs font-mono font-bold text-blue-700 dark:text-cyan-400">
                          {rec.techniqueId}: {rec.techniqueName}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">
                          ({rec.id})
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                        {rec.title}
                      </h3>
                      <span className="text-[10px] font-mono text-slate-400 block">
                        Submitted by: {rec.createdByName} &bull; {new Date(rec.createdAt).toLocaleString()}
                      </span>
                    </div>

                    {/* Implementation Actions for Security Engineer */}
                    <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
                      {rec.status === 'accepted' && (
                        <Button
                          size="xs"
                          variant="primary"
                          onClick={() => handleOpenImplementModal(rec, 'in_progress')}
                          icon={<FileCode2 className="w-3.5 h-3.5" />}
                        >
                          Start Implementation
                        </Button>
                      )}

                      {rec.status === 'in_progress' && (
                        <Button
                          size="xs"
                          variant="primary"
                          onClick={() => handleOpenImplementModal(rec, 'completed')}
                          icon={<CheckCircle2 className="w-3.5 h-3.5" />}
                        >
                          Mark Completed
                        </Button>
                      )}

                      {rec.status === 'clarification_requested' && (
                        <Button
                          size="xs"
                          variant="outline"
                          onClick={() => handleOpenImplementModal(rec, 'in_progress')}
                          icon={<HelpCircle className="w-3.5 h-3.5 text-amber-500" />}
                        >
                          Review Feedback & Re-Draft
                        </Button>
                      )}
                    </div>
                  </div>

                  {/* Core Content Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                        Detection Gap
                      </span>
                      <p className="text-slate-800 dark:text-slate-200 text-[11px] leading-relaxed">
                        {rec.detectionGap}
                      </p>
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] font-mono uppercase font-bold text-slate-500 block">
                        Proposed Improvement
                      </span>
                      <p className="text-slate-800 dark:text-slate-200 text-[11px] leading-relaxed">
                        {rec.proposedImprovement}
                      </p>
                    </div>
                  </div>

                  {/* Implementation Notes & Sigma Reference */}
                  {(rec.implementationNotes || rec.sigmaDraftReference) && (
                    <div className="p-3 rounded-lg bg-cyan-50/50 dark:bg-cyan-950/20 border border-cyan-200 dark:border-cyan-900/40 space-y-1.5 text-xs">
                      <span className="text-[10px] font-mono font-bold uppercase text-cyan-800 dark:text-cyan-300 block">
                        Implementation Details & Attached Artifacts
                      </span>
                      {rec.sigmaDraftReference && (
                        <div className="flex items-center gap-2 text-xs font-mono">
                          <span className="text-slate-500">Sigma Draft Ref:</span>
                          <span className="px-1.5 py-0.5 rounded bg-white dark:bg-slate-900 border border-cyan-300 dark:border-cyan-800 font-bold text-cyan-700 dark:text-cyan-300">
                            {rec.sigmaDraftReference}
                          </span>
                        </div>
                      )}
                      {rec.implementationNotes && (
                        <p className="text-slate-800 dark:text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap">
                          {rec.implementationNotes}
                        </p>
                      )}
                    </div>
                  )}

                  {/* SOC Review Feedback */}
                  {rec.socFeedback && (
                    <div className="p-3 rounded-lg bg-purple-50/50 dark:bg-purple-950/20 border border-purple-200 dark:border-purple-900/40 space-y-1 text-xs">
                      <span className="text-[10px] font-mono font-bold uppercase text-purple-800 dark:text-purple-300 flex items-center gap-1.5">
                        <MessageSquare className="w-3.5 h-3.5" />
                        SOC Analyst Feedback ({rec.reviewedByName || 'SOC Analyst'})
                      </span>
                      <p className="text-slate-800 dark:text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap">
                        {rec.socFeedback}
                      </p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SUBMISSION MODAL */}
      {isSubmitModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl max-w-xl w-full p-5 space-y-4 shadow-xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Send className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
                Submit Recommendation to SOC Analyst Triage
              </h3>
              <button
                type="button"
                onClick={() => setIsSubmitModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs space-y-3">
              {/* Title & Priority */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2 space-y-1">
                  <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                    Recommendation Title *
                  </label>
                  <input
                    type="text"
                    value={submitFormData.title}
                    onChange={(e) => setSubmitFormData({ ...submitFormData, title: e.target.value })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none"
                    placeholder="e.g. PowerShell Encoded Command Execution Strategy"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                    Priority Tier *
                  </label>
                  <select
                    value={submitFormData.priority}
                    onChange={(e) => setSubmitFormData({ ...submitFormData, priority: e.target.value as any })}
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              {/* MITRE Reference Details */}
              <div className="grid grid-cols-2 gap-3 p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 text-[11px] font-mono">
                <div>
                  <span className="text-slate-400 block text-[10px]">Technique</span>
                  <strong className="text-blue-700 dark:text-cyan-400">{submitFormData.techniqueId}</strong>: {submitFormData.techniqueName}
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">Tactic</span>
                  <strong className="text-slate-700 dark:text-slate-300">{submitFormData.tacticId}</strong>: {submitFormData.tacticName}
                </div>
              </div>

              {/* Detection Gap */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Detection Gap *
                </label>
                <textarea
                  rows={2}
                  value={submitFormData.detectionGap}
                  onChange={(e) => setSubmitFormData({ ...submitFormData, detectionGap: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none"
                  placeholder="Identify where current defenses fail to observe this attack pattern..."
                />
              </div>

              {/* Technical Explanation */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Technical Explanation *
                </label>
                <textarea
                  rows={3}
                  value={submitFormData.technicalExplanation}
                  onChange={(e) => setSubmitFormData({ ...submitFormData, technicalExplanation: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none font-sans"
                  placeholder="Explain telemetry evidence, process artifacts, or event IDs..."
                />
              </div>

              {/* Proposed Improvement */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Proposed Improvement / Rule Strategy *
                </label>
                <textarea
                  rows={3}
                  value={submitFormData.proposedImprovement}
                  onChange={(e) => setSubmitFormData({ ...submitFormData, proposedImprovement: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none font-sans"
                  placeholder="Proposed Sigma rule logic, selection criteria, or correlation thresholds..."
                />
              </div>

              {/* Supporting Evidence */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Supporting Evidence / Telemetry Sources
                </label>
                <input
                  type="text"
                  value={submitFormData.supportingEvidence || ''}
                  onChange={(e) => setSubmitFormData({ ...submitFormData, supportingEvidence: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none"
                  placeholder="e.g. Sysmon Event ID 1, Windows Security 4688, Zeek conn.log"
                />
              </div>

              {/* Related Sigma Draft Reference */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Related Sigma Rule Draft (Optional)
                </label>
                <select
                  value={submitFormData.relatedRuleDraftId || ''}
                  onChange={(e) => setSubmitFormData({ ...submitFormData, relatedRuleDraftId: e.target.value })}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none"
                >
                  <option value="">No draft attached (or author draft later)</option>
                  {availableDrafts.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.id} — {d.title} ({d.techniqueId})
                    </option>
                  ))}
                </select>
              </div>

              {submitError && (
                <div className="p-2.5 bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800 rounded text-rose-700 dark:text-rose-300 text-xs">
                  {submitError}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
              <Button size="xs" variant="ghost" onClick={() => setIsSubmitModalOpen(false)} disabled={isSubmitting}>
                Cancel
              </Button>
              <Button size="xs" variant="primary" onClick={handleConfirmSubmit} disabled={isSubmitting}>
                {isSubmitting ? 'Submitting...' : 'Submit to SOC Queue'}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* IMPLEMENTATION / PROGRESS MODAL */}
      {implementModal.rec && implementModal.targetStatus && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-blue-600 dark:text-cyan-400" />
                {implementModal.targetStatus === 'in_progress'
                  ? 'Start Implementation & Draft Detection'
                  : 'Complete Detection Implementation'}
              </h3>
              <button
                type="button"
                onClick={() => setImplementModal({ rec: null, targetStatus: null })}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs space-y-3">
              <div className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 font-mono text-[11px]">
                <strong className="text-blue-700 dark:text-cyan-400">{implementModal.rec.techniqueId}</strong>: {implementModal.rec.title}
              </div>

              {/* Attach Sigma Draft Reference */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Sigma Detection Rule Reference
                </label>
                <select
                  value={selectedSigmaRef}
                  onChange={(e) => handleSigmaDraftSelect(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none"
                >
                  <option value="">Select an authored Sigma rule draft...</option>
                  {availableDrafts.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.id} — {d.title} ({d.techniqueId})
                    </option>
                  ))}
                </select>
              </div>

              {/* Sigma Validation Feedback */}
              {sigmaValidation && (
                <div
                  className={`p-2.5 rounded text-xs border space-y-1 ${
                    sigmaValidation.isValid
                      ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-700 text-emerald-800 dark:text-emerald-200'
                      : 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-700 text-amber-800 dark:text-amber-200'
                  }`}
                >
                  <div className="flex items-center gap-1.5 font-semibold">
                    {sigmaValidation.isValid ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                    )}
                    <span>
                      Sigma Structural Syntax: {sigmaValidation.isValid ? 'VALID' : 'SYNTAX WARNINGS'}
                    </span>
                  </div>
                  {sigmaValidation.errors.length > 0 && (
                    <ul className="list-disc pl-4 text-[10px]">
                      {sigmaValidation.errors.map((e, idx) => (
                        <li key={idx}>{e}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Implementation Notes */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  {implementModal.targetStatus === 'completed'
                    ? 'Implementation Notes (Mandatory, min 10 chars) *'
                    : 'Initial Implementation Plan / Notes'}
                </label>
                <textarea
                  rows={4}
                  value={implementNotes}
                  onChange={(e) => setImplementNotes(e.target.value)}
                  placeholder="Document rule testing, logsource configuration, expected event volume, or false-positive suppression logic..."
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none font-sans"
                />
              </div>

              {implementError && (
                <div className="p-2 bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800 rounded text-rose-700 dark:text-rose-300 text-xs">
                  {implementError}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
              <Button
                size="xs"
                variant="ghost"
                onClick={() => setImplementModal({ rec: null, targetStatus: null })}
                disabled={isUpdatingImpl}
              >
                Cancel
              </Button>
              <Button
                size="xs"
                variant="primary"
                onClick={handleConfirmImplementUpdate}
                disabled={isUpdatingImpl}
              >
                {isUpdatingImpl
                  ? 'Saving...'
                  : implementModal.targetStatus === 'in_progress'
                  ? 'Confirm In Progress'
                  : 'Submit as Completed'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
