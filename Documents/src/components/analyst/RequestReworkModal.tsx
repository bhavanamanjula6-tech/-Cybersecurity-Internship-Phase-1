/**
 * Request Rework Modal
 *
 * Allows SOC Analysts to return a completed remediation task back to IT Operations
 * with mandatory, actionable rework instructions.
 * Enforces validation (non-empty, minimum length).
 */

import React, { useState } from 'react';
import { IncidentTask } from '../../types/audit';
import { UserProfile } from '../../types/auth';
import { Button } from '../common/Button';
import { AlertTriangle, X, RefreshCw, Server, ShieldCheck } from 'lucide-react';
import { parseRemediationHistory } from '../../utils/remediationReview';

interface RequestReworkModalProps {
  isOpen: boolean;
  onClose: () => void;
  task: IncidentTask;
  currentUser: UserProfile;
  onSubmitRework: (taskId: string, instructions: string) => Promise<void>;
}

export const RequestReworkModal: React.FC<RequestReworkModalProps> = ({
  isOpen,
  onClose,
  task,
  currentUser,
  onSubmitRework,
}) => {
  const [instructions, setInstructions] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  if (!isOpen) return null;

  const history = parseRemediationHistory(task.completionNotes);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    const trimmed = instructions.trim();
    if (trimmed.length < 10) {
      setValidationError('Mandatory rework instructions must be at least 10 characters long describing the specific remediation deficiencies or missing evidence.');
      return;
    }

    try {
      setIsSubmitting(true);
      await onSubmitRework(task.id, trimmed);
      onClose();
    } catch (err: any) {
      setValidationError(err.message || 'Failed to submit rework request.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="rework-modal-title"
    >
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-2xl max-w-xl w-full flex flex-col overflow-hidden text-slate-900 dark:text-slate-100 animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-orange-50/50 dark:bg-orange-950/40 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-orange-100 dark:bg-orange-900/60 text-orange-700 dark:text-orange-300">
              <RefreshCw className="w-5 h-5" />
            </div>
            <div>
              <h2 id="rework-modal-title" className="text-sm font-bold font-heading text-slate-900 dark:text-slate-100">
                Request Remediation Rework
              </h2>
              <span className="text-[11px] font-mono text-orange-700 dark:text-orange-400">
                Task {task.id} • Will transition status from Completed to In Progress
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

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs overflow-y-auto max-h-[75vh]">
          {validationError && (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 rounded-lg text-rose-800 dark:text-rose-300 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-600 dark:text-rose-400" />
              <span>{validationError}</span>
            </div>
          )}

          {/* Target Task Summary */}
          <div className="p-3 bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-slate-500">TASK TITLE</span>
              <span className="text-amber-600 dark:text-amber-400 font-bold uppercase">{task.priority} Priority</span>
            </div>
            <div className="font-semibold text-slate-900 dark:text-slate-100">{task.title}</div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-200 dark:border-slate-800">
              <Server className="w-3.5 h-3.5" />
              <span>Target Asset: <strong className="text-slate-800 dark:text-slate-200">{task.targetAsset}</strong></span>
              {task.completedBy && <span>• Completed by: <strong>{task.completedBy}</strong></span>}
            </div>
          </div>

          {/* Current Remediation Attestation Summary */}
          {history.operatorAttestation && (
            <div className="p-2.5 bg-slate-100/60 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded text-[11px] font-mono text-slate-600 dark:text-slate-400 flex items-start gap-2">
              <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5 text-emerald-500" />
              <div className="space-y-0.5">
                <span className="font-bold text-slate-700 dark:text-slate-300">Previous Operator Attestation:</span>
                <p className="line-clamp-2">{history.operatorAttestation}</p>
              </div>
            </div>
          )}

          {/* Instructions Input */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor="rework-instructions" className="font-semibold text-slate-800 dark:text-slate-200">
                Actionable Rework Instructions <span className="text-rose-500">*</span>
              </label>
              <span className="text-[10px] font-mono text-slate-400">
                {instructions.trim().length} chars (min 10)
              </span>
            </div>
            <p className="text-[11px] text-slate-500">
              Specify why the remediation was rejected (e.g., incomplete host isolation, missing IOC scans, invalid evidence links, unverified offline snapshot).
            </p>
            <textarea
              id="rework-instructions"
              rows={4}
              value={instructions}
              onChange={(e) => setInstructions(e.target.value)}
              placeholder="e.g., Host isolation incomplete: outbound connections on port 443 are still active. Perform complete network perimeter block and re-attach firewall evidence log."
              className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-3 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:ring-1 focus:ring-orange-500 focus:outline-none"
              required
            />
          </div>

          {/* Reviewer Identity Notice */}
          <div className="p-2.5 bg-orange-50/60 dark:bg-orange-950/20 border border-orange-200/80 dark:border-orange-900/40 rounded text-[11px] text-orange-900 dark:text-orange-300 flex items-center justify-between font-mono">
            <span>Reviewer: <strong>{currentUser.name}</strong> ({currentUser.callsign || currentUser.role})</span>
            <span>Audit: WORM Logged</span>
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
              disabled={isSubmitting || instructions.trim().length < 10}
              className="bg-orange-600 hover:bg-orange-700 text-white"
            >
              {isSubmitting ? 'Submitting Rework Request...' : 'Submit Rework Request'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
