import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  FileCode2,
  CheckCircle2,
  Clock,
  Search,
  Filter,
  Check,
  X,
  HelpCircle,
  ShieldCheck,
  ArrowRight,
  ExternalLink,
  MessageSquare,
  AlertOctagon,
  RefreshCw,
  Info,
} from 'lucide-react';
import { DetectionRecommendation, RecommendationPriority, RecommendationStatus } from '../../types/recommendation';
import { UserProfile } from '../../types/auth';
import { Button } from '../common/Button';
import { ProvenanceBadge } from '../common/ProvenanceBadge';

interface DetectionRecommendationsTriageViewProps {
  recommendations: DetectionRecommendation[];
  currentUser?: UserProfile;
  onReviewRecommendation: (
    id: string,
    action: 'accept' | 'reject' | 'request_clarification',
    feedback?: string
  ) => Promise<void>;
  onValidateRecommendation: (id: string, feedback?: string) => Promise<void>;
  onRefresh: () => void;
  isLoading?: boolean;
}

export const DetectionRecommendationsTriageView: React.FC<DetectionRecommendationsTriageViewProps> = ({
  recommendations,
  currentUser,
  onReviewRecommendation,
  onValidateRecommendation,
  onRefresh,
  isLoading = false,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [priorityFilter, setPriorityFilter] = useState<string>('all');
  const [selectedRecId, setSelectedRecId] = useState<string | null>(() => {
    return recommendations.length > 0 ? recommendations[0].id : null;
  });

  // Modal / action states
  const [actionModal, setActionModal] = useState<{
    type: 'accept' | 'reject' | 'request_clarification' | 'validate' | null;
    rec: DetectionRecommendation | null;
  }>({ type: null, rec: null });
  const [feedbackText, setFeedbackText] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const filteredRecommendations = useMemo(() => {
    let list = [...recommendations];
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(
        (r) =>
          r.title.toLowerCase().includes(q) ||
          r.techniqueId.toLowerCase().includes(q) ||
          r.techniqueName.toLowerCase().includes(q) ||
          r.tacticId.toLowerCase().includes(q) ||
          r.createdByName.toLowerCase().includes(q)
      );
    }
    if (statusFilter !== 'all') {
      list = list.filter((r) => r.status === statusFilter);
    }
    if (priorityFilter !== 'all') {
      list = list.filter((r) => r.priority === priorityFilter);
    }
    return list;
  }, [recommendations, searchQuery, statusFilter, priorityFilter]);

  const selectedRec = useMemo(() => {
    if (!selectedRecId) return filteredRecommendations[0] || null;
    return recommendations.find((r) => r.id === selectedRecId) || filteredRecommendations[0] || null;
  }, [recommendations, selectedRecId, filteredRecommendations]);

  const pendingCount = recommendations.filter(
    (r) => r.status === 'proposed' || r.status === 'clarification_requested'
  ).length;
  const readyToValidateCount = recommendations.filter((r) => r.status === 'completed').length;

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
            PENDING TRIAGE
          </span>
        );
      case 'accepted':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-800">
            <Check className="w-3 h-3 text-blue-600 dark:text-blue-400" />
            ACCEPTED (QUEUED)
          </span>
        );
      case 'in_progress':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-50 text-cyan-800 border border-cyan-200 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-800">
            <FileCode2 className="w-3 h-3 text-cyan-600 dark:text-cyan-400 animate-pulse" />
            IN PROGRESS
          </span>
        );
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-300 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-700">
            <CheckCircle2 className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            AWAITING VALIDATION
          </span>
        );
      case 'validated':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-700">
            <ShieldCheck className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
            VALIDATED
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
            CLARIFICATION NEEDED
          </span>
        );
      default:
        return null;
    }
  };

  const handleOpenActionModal = (
    type: 'accept' | 'reject' | 'request_clarification' | 'validate',
    rec: DetectionRecommendation
  ) => {
    setActionModal({ type, rec });
    setFeedbackText('');
    setActionError(null);
  };

  const handleCloseActionModal = () => {
    setActionModal({ type: null, rec: null });
    setFeedbackText('');
    setActionError(null);
  };

  const handleConfirmAction = async () => {
    if (!actionModal.rec || !actionModal.type) return;
    const { type, rec } = actionModal;

    if ((type === 'reject' || type === 'request_clarification') && feedbackText.trim().length < 10) {
      setActionError(`Mandatory feedback of at least 10 characters is required to ${type.replace('_', ' ')}.`);
      return;
    }

    setIsSubmitting(true);
    setActionError(null);

    try {
      if (type === 'validate') {
        await onValidateRecommendation(rec.id, feedbackText.trim());
      } else {
        await onReviewRecommendation(rec.id, type, feedbackText.trim());
      }
      handleCloseActionModal();
    } catch (err: any) {
      setActionError(err.message || 'Operation failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Overview metrics bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono text-slate-500 uppercase block">Total Recommendations</span>
          <span className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100">{recommendations.length}</span>
        </div>
        <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono text-purple-600 dark:text-purple-400 uppercase block">Pending Triage</span>
          <span className="text-xl font-bold font-mono text-purple-700 dark:text-purple-300">{pendingCount}</span>
        </div>
        <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono text-amber-600 dark:text-amber-400 uppercase block">Ready for Validation</span>
          <span className="text-xl font-bold font-mono text-amber-700 dark:text-amber-300">{readyToValidateCount}</span>
        </div>
        <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs">
          <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 uppercase block">Validated Rules</span>
          <span className="text-xl font-bold font-mono text-emerald-700 dark:text-emerald-300">
            {recommendations.filter((r) => r.status === 'validated').length}
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-3 shadow-xs">
        <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search recommendations by title, technique (e.g. T1059.001), or author..."
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700/80 rounded pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:outline-none"
              aria-label="Filter by recommendation status"
            >
              <option value="all">All Statuses ({recommendations.length})</option>
              <option value="proposed">Pending Triage ({recommendations.filter((r) => r.status === 'proposed').length})</option>
              <option value="accepted">Accepted ({recommendations.filter((r) => r.status === 'accepted').length})</option>
              <option value="in_progress">In Progress ({recommendations.filter((r) => r.status === 'in_progress').length})</option>
              <option value="completed">Ready for Validation ({recommendations.filter((r) => r.status === 'completed').length})</option>
              <option value="validated">Validated ({recommendations.filter((r) => r.status === 'validated').length})</option>
              <option value="rejected">Rejected ({recommendations.filter((r) => r.status === 'rejected').length})</option>
              <option value="clarification_requested">Clarification Needed ({recommendations.filter((r) => r.status === 'clarification_requested').length})</option>
            </select>

            <select
              value={priorityFilter}
              onChange={(e) => setPriorityFilter(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2.5 py-1.5 text-xs focus:outline-none"
              aria-label="Filter by priority"
            >
              <option value="all">All Priorities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <Button size="xs" variant="secondary" onClick={onRefresh} disabled={isLoading} icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}>
              Refresh
            </Button>
          </div>
        </div>
      </div>

      {/* Main split-view */}
      {filteredRecommendations.length === 0 ? (
        <div className="p-12 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-center space-y-3 shadow-xs">
          <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
            No Recommendations Match Current Filter
          </h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            {recommendations.length === 0
              ? 'No detection improvement recommendations submitted yet by Security Engineers.'
              : 'Try clearing search keywords or status filters.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* List column */}
          <div className="lg:col-span-5 space-y-2 max-h-[700px] overflow-y-auto pr-1">
            {filteredRecommendations.map((rec) => {
              const isSelected = selectedRec?.id === rec.id;
              return (
                <div
                  key={rec.id}
                  onClick={() => setSelectedRecId(rec.id)}
                  className={`p-3 rounded-lg border text-xs transition cursor-pointer space-y-2 ${
                    isSelected
                      ? 'bg-blue-50/70 dark:bg-slate-800 border-blue-500 dark:border-cyan-500 ring-1 ring-blue-500 dark:ring-cyan-400 shadow-xs'
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 flex-wrap">
                    <div className="flex items-center gap-1.5">
                      {getPriorityBadge(rec.priority)}
                      {getStatusBadge(rec.status)}
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      {new Date(rec.createdAt).toLocaleDateString()}
                    </span>
                  </div>

                  <div>
                    <h4 className="font-bold text-slate-900 dark:text-slate-100 text-xs leading-snug">
                      {rec.title}
                    </h4>
                    <span className="text-[11px] font-mono text-blue-700 dark:text-cyan-400">
                      {rec.techniqueId}: {rec.techniqueName}
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-600 dark:text-slate-400 line-clamp-2">
                    {rec.detectionGap}
                  </p>

                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-100 dark:border-slate-800">
                    <span>By: {rec.createdByName}</span>
                    <span>{rec.id}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Details / Inspection Column */}
          <div className="lg:col-span-7">
            {selectedRec ? (
              <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xs space-y-4">
                {/* Header */}
                <div className="border-b border-slate-200 dark:border-slate-800 pb-3 space-y-2">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      {getPriorityBadge(selectedRec.priority)}
                      {getStatusBadge(selectedRec.status)}
                      <span className="text-xs font-mono text-slate-400">{selectedRec.id}</span>
                    </div>
                    <ProvenanceBadge type="deterministic_rule" label="SECURITY ENGINEERING" />
                  </div>

                  <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                    {selectedRec.title}
                  </h3>

                  <div className="flex items-center gap-2 text-xs font-mono text-slate-600 dark:text-slate-400 flex-wrap">
                    <span className="font-bold text-blue-700 dark:text-cyan-400">
                      {selectedRec.techniqueId}: {selectedRec.techniqueName}
                    </span>
                    <span>&bull;</span>
                    <span>Tactic: {selectedRec.tacticName} ({selectedRec.tacticId})</span>
                    <span>&bull;</span>
                    <span>Author: {selectedRec.createdByName}</span>
                  </div>
                </div>

                {/* Technical Details Grid */}
                <div className="space-y-3 text-xs">
                  {/* Detection Gap */}
                  <div className="p-3 rounded-lg bg-rose-50/50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-900/40 space-y-1">
                    <span className="text-[10px] font-mono font-bold uppercase text-rose-700 dark:text-rose-400 block">
                      Detection Gap Identified
                    </span>
                    <p className="text-slate-800 dark:text-slate-200 leading-relaxed text-[11px]">
                      {selectedRec.detectionGap}
                    </p>
                  </div>

                  {/* Technical Explanation */}
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                    <span className="text-[10px] font-mono font-bold uppercase text-slate-500 block">
                      Technical Explanation
                    </span>
                    <p className="text-slate-800 dark:text-slate-200 leading-relaxed text-[11px] whitespace-pre-wrap">
                      {selectedRec.technicalExplanation}
                    </p>
                  </div>

                  {/* Proposed Improvement */}
                  <div className="p-3 rounded-lg bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 space-y-1">
                    <span className="text-[10px] font-mono font-bold uppercase text-emerald-800 dark:text-emerald-300 block">
                      Proposed Detection Strategy / Rule Improvement
                    </span>
                    <p className="text-slate-800 dark:text-slate-200 leading-relaxed text-[11px] whitespace-pre-wrap">
                      {selectedRec.proposedImprovement}
                    </p>
                  </div>

                  {/* Supporting Evidence / Telemetry */}
                  {selectedRec.supportingEvidence && (
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                      <span className="text-[10px] font-mono font-bold uppercase text-slate-500 block">
                        Supporting Evidence & Data Sources
                      </span>
                      <p className="text-slate-700 dark:text-slate-300 font-mono text-[11px]">
                        {selectedRec.supportingEvidence}
                      </p>
                    </div>
                  )}

                  {/* Related Rule Draft Link (if present) */}
                  {selectedRec.relatedRuleDraftId && (
                    <div className="flex items-center gap-2 p-2 bg-blue-50/50 dark:bg-slate-950 border border-blue-200 dark:border-slate-800 rounded text-xs font-mono">
                      <FileCode2 className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
                      <span className="text-slate-600 dark:text-slate-400">Associated Rule Draft:</span>
                      <strong className="text-blue-700 dark:text-cyan-300">{selectedRec.relatedRuleDraftId}</strong>
                    </div>
                  )}

                  {/* Implementation Notes & Sigma Reference (if in_progress or completed) */}
                  {(selectedRec.implementationNotes || selectedRec.sigmaDraftReference) && (
                    <div className="p-3 rounded-lg bg-cyan-50/50 dark:bg-cyan-950/20 border border-cyan-200 dark:border-cyan-900/40 space-y-2">
                      <span className="text-[10px] font-mono font-bold uppercase text-cyan-800 dark:text-cyan-300 block">
                        Security Engineer Implementation Artifacts
                      </span>
                      {selectedRec.sigmaDraftReference && (
                        <div className="flex items-center gap-1.5 text-xs font-mono">
                          <span className="text-slate-500">Sigma Draft Ref:</span>
                          <span className="px-1.5 py-0.5 rounded bg-white dark:bg-slate-900 border border-cyan-300 dark:border-cyan-800 font-bold text-cyan-700 dark:text-cyan-300">
                            {selectedRec.sigmaDraftReference}
                          </span>
                        </div>
                      )}
                      {selectedRec.implementationNotes && (
                        <p className="text-slate-800 dark:text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap">
                          {selectedRec.implementationNotes}
                        </p>
                      )}
                    </div>
                  )}

                  {/* SOC Review Feedback (if reviewed/rejected/clarification/validated) */}
                  {selectedRec.socFeedback && (
                    <div className="p-3 rounded-lg bg-purple-50/50 dark:bg-purple-950/20 border border-purple-200 dark:border-purple-900/40 space-y-1">
                      <span className="text-[10px] font-mono font-bold uppercase text-purple-800 dark:text-purple-300 flex items-center gap-1">
                        <MessageSquare className="w-3 h-3" />
                        SOC Analyst Review History ({selectedRec.reviewedByName || 'SOC Analyst'})
                      </span>
                      <p className="text-slate-800 dark:text-slate-200 text-[11px] leading-relaxed whitespace-pre-wrap">
                        {selectedRec.socFeedback}
                      </p>
                    </div>
                  )}
                </div>

                {/* Action Toolbar */}
                <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
                  <div className="text-[11px] text-slate-500 font-mono">
                    Updated: {new Date(selectedRec.updatedAt).toLocaleString()}
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Actions for proposed / clarification_requested */}
                    {(selectedRec.status === 'proposed' || selectedRec.status === 'clarification_requested') && (
                      <>
                        <Button
                          size="xs"
                          variant="outline"
                          onClick={() => handleOpenActionModal('request_clarification', selectedRec)}
                          icon={<HelpCircle className="w-3.5 h-3.5 text-amber-500" />}
                        >
                          Request Clarification
                        </Button>
                        <Button
                          size="xs"
                          variant="outline"
                          onClick={() => handleOpenActionModal('reject', selectedRec)}
                          icon={<X className="w-3.5 h-3.5 text-rose-500" />}
                        >
                          Reject
                        </Button>
                        <Button
                          size="xs"
                          variant="primary"
                          onClick={() => handleOpenActionModal('accept', selectedRec)}
                          icon={<Check className="w-3.5 h-3.5" />}
                        >
                          Accept Recommendation
                        </Button>
                      </>
                    )}

                    {/* Action for completed -> validation */}
                    {selectedRec.status === 'completed' && (
                      <Button
                        size="xs"
                        variant="primary"
                        onClick={() => handleOpenActionModal('validate', selectedRec)}
                        icon={<ShieldCheck className="w-3.5 h-3.5 text-emerald-300" />}
                      >
                        Validate Detection Improvement
                      </Button>
                    )}

                    {/* Pre-completion indicator */}
                    {(selectedRec.status === 'accepted' || selectedRec.status === 'in_progress') && (
                      <span className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400 italic">
                        In progress with Security Engineering &bull; Awaiting implementation completion
                      </span>
                    )}

                    {selectedRec.status === 'validated' && (
                      <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-600 dark:text-emerald-400 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Validated for Detection Triage
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Confirmation / Feedback Modal */}
      {actionModal.type && actionModal.rec && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                {actionModal.type === 'accept' && <Check className="w-4 h-4 text-emerald-500" />}
                {actionModal.type === 'reject' && <X className="w-4 h-4 text-rose-500" />}
                {actionModal.type === 'request_clarification' && <HelpCircle className="w-4 h-4 text-amber-500" />}
                {actionModal.type === 'validate' && <ShieldCheck className="w-4 h-4 text-emerald-500" />}
                {actionModal.type === 'accept' && 'Accept Detection Recommendation'}
                {actionModal.type === 'reject' && 'Reject Detection Recommendation'}
                {actionModal.type === 'request_clarification' && 'Request Clarification from Security Engineer'}
                {actionModal.type === 'validate' && 'Validate Detection Improvement'}
              </h3>
              <button
                type="button"
                onClick={handleCloseActionModal}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs space-y-2">
              <div className="p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800 font-mono text-[11px]">
                <strong className="text-blue-700 dark:text-cyan-400">{actionModal.rec.techniqueId}</strong>: {actionModal.rec.title}
              </div>

              {actionModal.type === 'accept' && (
                <p className="text-slate-600 dark:text-slate-400">
                  Accepting this recommendation signals to the Security Engineer that this detection strategy is approved for authoring and implementation.
                </p>
              )}

              {actionModal.type === 'reject' && (
                <p className="text-rose-700 dark:text-rose-400 font-semibold">
                  Mandatory: Please provide a clear technical rationale explaining why this recommendation is rejected. (Minimum 10 characters required)
                </p>
              )}

              {actionModal.type === 'request_clarification' && (
                <p className="text-amber-800 dark:text-amber-300 font-semibold">
                  Mandatory: Specify what additional evidence, telemetry parameters, or false positive considerations the Security Engineer must clarify. (Minimum 10 characters required)
                </p>
              )}

              {actionModal.type === 'validate' && (
                <p className="text-slate-600 dark:text-slate-400">
                  Confirm that the completed Sigma detection draft reference and implementation notes meet operational fidelity standards for SOC alert triage.
                </p>
              )}

              {/* Feedback text area */}
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  {actionModal.type === 'reject' || actionModal.type === 'request_clarification'
                    ? 'Mandatory Instructions / Feedback *'
                    : 'Analyst Notes (Optional)'}
                </label>
                <textarea
                  rows={4}
                  value={feedbackText}
                  onChange={(e) => setFeedbackText(e.target.value)}
                  placeholder={
                    actionModal.type === 'reject'
                      ? 'Explain reason for rejection (e.g. out of scope, alternate telemetry stream already monitored)...'
                      : actionModal.type === 'request_clarification'
                      ? 'Describe what specific details or false-positive scenarios require clarification...'
                      : 'Enter optional validation remarks or instructions for SIEM rule ingestion...'
                  }
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2 text-xs focus:outline-none font-sans"
                />
              </div>

              {actionError && (
                <div className="p-2 bg-rose-50 dark:bg-rose-950/80 border border-rose-200 dark:border-rose-800 rounded text-rose-700 dark:text-rose-300 text-xs">
                  {actionError}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
              <Button size="xs" variant="ghost" onClick={handleCloseActionModal} disabled={isSubmitting}>
                Cancel
              </Button>
              <Button
                size="xs"
                variant={actionModal.type === 'reject' ? 'danger' : 'primary'}
                onClick={handleConfirmAction}
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Recording...' : 'Confirm Action'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
