/**
 * Approve Remediation Modal
 *
 * Provides explicit confirmation dialog for SOC Analysts to validate and sign off
 * on completed IT Operations remediation evidence.
 * Ensures the analyst inspects the full verification package before confirmation.
 */

import React, { useState } from 'react';
import { IncidentTask } from '../../types/audit';
import { UserProfile } from '../../types/auth';
import { Button } from '../common/Button';
import { CheckCircle2, X, ShieldCheck, FileText, CheckSquare, ExternalLink } from 'lucide-react';
import { parseRemediationHistory } from '../../utils/remediationReview';

interface ApproveRemediationModalProps {
  isOpen: boolean;
  onClose: () => void;
  task: IncidentTask;
  currentUser: UserProfile;
  onConfirmApproval: (taskId: string, notes?: string) => Promise<void>;
}

export const ApproveRemediationModal: React.FC<ApproveRemediationModalProps> = ({
  isOpen,
  onClose,
  task,
  currentUser,
  onConfirmApproval,
}) => {
  const [reviewNotes, setReviewNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const history = parseRemediationHistory(task.completionNotes);

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    try {
      setIsSubmitting(true);
      await onConfirmApproval(task.id, reviewNotes.trim() || undefined);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to approve remediation task.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="approve-modal-title"
    >
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-2xl max-w-xl w-full flex flex-col overflow-hidden text-slate-900 dark:text-slate-100 animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-emerald-50/60 dark:bg-emerald-950/40 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-100 dark:bg-emerald-900/60 text-emerald-700 dark:text-emerald-300">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <h2 id="approve-modal-title" className="text-sm font-bold font-heading text-slate-900 dark:text-slate-100">
                Approve IT Operations Remediation
              </h2>
              <span className="text-[11px] font-mono text-emerald-700 dark:text-emerald-400">
                Task {task.id} • Target Asset: {task.targetAsset}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isSubmitting}
            className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-1 rounded-md transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={handleConfirm} className="p-5 space-y-4 text-xs overflow-y-auto max-h-[75vh]">
          {error && (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 rounded-lg text-rose-800 dark:text-rose-300">
              {error}
            </div>
          )}

          <div className="p-3 bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-slate-500">TASK INFORMATION</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-bold uppercase">{task.status}</span>
            </div>
            <div className="font-semibold text-slate-900 dark:text-slate-100">{task.title}</div>
            <p className="text-[11px] text-slate-600 dark:text-slate-300">{task.description}</p>
          </div>

          {/* Verification Package Inspection */}
          <div className="space-y-2 border border-slate-200 dark:border-slate-800 rounded-lg p-3.5 bg-slate-50/50 dark:bg-slate-950/40">
            <div className="flex items-center justify-between">
              <h3 className="font-mono uppercase font-bold text-slate-700 dark:text-slate-300 text-[11px] flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                Remediation Evidence Package
              </h3>
              {history.verificationType === 'simulation' ? (
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-200 dark:border-purple-800 font-bold uppercase">
                  Simulation Verified
                </span>
              ) : history.verificationType === 'real' ? (
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 font-bold uppercase">
                  Real Endpoint Remediation
                </span>
              ) : null}
            </div>

            {/* Operator & Timestamp */}
            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-600 dark:text-slate-400 pt-1">
              <div>
                <span className="text-slate-400 block text-[10px]">OPERATOR</span>
                <span className="text-slate-800 dark:text-slate-200 font-bold">{task.completedBy || 'IT Operations'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">COMPLETION TIMESTAMP</span>
                <span className="text-slate-800 dark:text-slate-200">
                  {task.completedAt ? new Date(task.completedAt).toUTCString() : 'Recorded'}
                </span>
              </div>
            </div>

            {/* Work Performed */}
            {history.workPerformed && (
              <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-slate-400 block text-[10px] font-mono">WORK PERFORMED</span>
                <p className="text-slate-800 dark:text-slate-200 font-mono text-[11px] bg-white dark:bg-slate-900 p-2 rounded border border-slate-200 dark:border-slate-800">
                  {history.workPerformed}
                </p>
              </div>
            )}

            {/* Verified Checklist */}
            {history.checklistItems.length > 0 && (
              <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-1.5">
                <span className="text-slate-400 block text-[10px] font-mono">
                  VERIFIED CHECKLIST ({history.checklistItems.filter((i) => i.verified).length}/{history.checklistItems.length})
                </span>
                <div className="space-y-1">
                  {history.checklistItems.map((item, idx) => (
                    <div key={idx} className="flex items-center gap-1.5 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                      <CheckSquare className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                      <span>{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence References */}
            {history.evidenceReference && (
              <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-slate-400 block text-[10px] font-mono">EVIDENCE / ARTIFACT URL / TICKET</span>
                <div className="font-mono text-[11px] text-blue-600 dark:text-cyan-400 bg-blue-50/50 dark:bg-cyan-950/30 p-2 rounded border border-blue-200/60 dark:border-cyan-900/40 flex items-center gap-1.5">
                  <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                  <span className="break-all">{history.evidenceReference}</span>
                </div>
              </div>
            )}

            {/* Attestation */}
            {history.operatorAttestation && (
              <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 block text-[10px] font-mono">OPERATOR ATTESTATION</span>
                <p className="text-slate-600 dark:text-slate-300 text-[10px] font-mono italic">
                  {history.operatorAttestation}
                </p>
              </div>
            )}
          </div>

          {/* Optional Review Notes */}
          <div className="space-y-1.5">
            <label htmlFor="approval-notes" className="font-semibold text-slate-800 dark:text-slate-200 block">
              Analyst Approval Findings & Notes (Optional)
            </label>
            <textarea
              id="approval-notes"
              rows={2}
              value={reviewNotes}
              onChange={(e) => setReviewNotes(e.target.value)}
              placeholder="e.g., Host isolation verified via perimeter telemetry. IOC artifact confirmed inactive."
              className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:ring-1 focus:ring-emerald-500 focus:outline-none"
            />
          </div>

          {/* Reviewer Identity Notice */}
          <div className="p-2.5 bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200/80 dark:border-emerald-900/40 rounded text-[11px] text-emerald-900 dark:text-emerald-300 flex items-center justify-between font-mono">
            <span>Signing Analyst: <strong>{currentUser.name}</strong> ({currentUser.callsign || currentUser.role})</span>
            <span>WORM Audit Trail: Immutable</span>
          </div>

          {/* Buttons */}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={isSubmitting}
              className="bg-emerald-600 hover:bg-emerald-700 text-white"
            >
              <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
              {isSubmitting ? 'Confirming Approval...' : 'Confirm & Approve Remediation'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
