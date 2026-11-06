import React, { useState, useEffect } from 'react';
import { IncidentTask } from '../../types/audit';
import { SecurityAlert } from '../../types/alert';
import { Button } from '../common/Button';
import {
  CheckCircle2,
  X,
  ShieldCheck,
  AlertTriangle,
  Server,
  FileText,
  Terminal,
  Info,
  CheckSquare,
  Square,
  RefreshCw,
  Cpu,
  ShieldAlert,
} from 'lucide-react';
import { parseRemediationHistory } from '../../utils/remediationReview';

export interface VerificationChecklistItem {
  id: string;
  label: string;
  description: string;
  required?: boolean;
}

export const DEFAULT_VERIFICATION_CHECKLIST: VerificationChecklistItem[] = [
  {
    id: 'target_state',
    label: 'Asset Target State & Identity Confirmed',
    description: 'Verified target asset hostname/IP and confirmed operational state prior to closing.',
  },
  {
    id: 'fix_applied',
    label: 'Remediation Procedure Executed & Tested',
    description: 'Applied technical fix (e.g. credential revocation, network rule, backup verification, or host recovery).',
  },
  {
    id: 'telemetry_clean',
    label: 'Absence of Malicious Telemetry Re-infection',
    description: 'Confirmed zero anomalous secondary execution spikes or alerts on the target asset.',
  },
  {
    id: 'operational_restoral',
    label: 'Authorized Operational Service Restoral',
    description: 'Target asset conforms to production baseline and service readiness has been validated.',
  },
];

export const SIMULATION_VERIFICATION_CHECKLIST: VerificationChecklistItem[] = [
  {
    id: 'synthetic_telemetry',
    label: 'Synthetic Telemetry & Scenario Payload Validated',
    description: 'Confirmed synthetic event indicators and simulated behavior match the controlled detection scenario.',
  },
  {
    id: 'containment_reviewed',
    label: 'Simulated Containment & Recovery Procedure Formulated',
    description: 'Reviewed and confirmed appropriate response playbook actions (e.g. host isolation or account lockout) for this scenario.',
  },
  {
    id: 'telemetry_isolated',
    label: 'Absence of Unintended Telemetry or Side Effects',
    description: 'Audited simulation logs to ensure synthetic events did not produce anomalous secondary noise or unexpected execution.',
  },
  {
    id: 'zero_prod_impact',
    label: 'Zero Production Impact Attested',
    description: 'Confirmed that zero operational endpoints or production credentials were altered or compromised.',
  },
];

export interface RemediationVerificationData {
  completionNotes: string;
  checklist: Array<{ id: string; label: string; verified: boolean }>;
  evidenceReference?: string;
  attestationConfirmed: boolean;
  serializedNotes: string;
  verificationType: 'simulation' | 'real';
}

interface RemediationVerificationModalProps {
  task: IncidentTask;
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (taskId: string, verificationData: RemediationVerificationData) => Promise<void>;
  isSubmitting?: boolean;
  associatedAlert?: SecurityAlert;
}

export const RemediationVerificationModal: React.FC<RemediationVerificationModalProps> = ({
  task,
  isOpen,
  onClose,
  onConfirm,
  isSubmitting = false,
  associatedAlert,
}) => {
  const isSyntheticScenario = Boolean(
    associatedAlert?.isSynthetic ||
    associatedAlert?.provenance?.toLowerCase().includes('simulation') ||
    associatedAlert?.provenance?.toLowerCase().includes('synthetic') ||
    task.associatedAlertId?.toUpperCase().includes('SIM') ||
    task.title.toLowerCase().includes('synthetic') ||
    task.title.toLowerCase().includes('simulated')
  );

  const [verificationMode, setVerificationMode] = useState<'simulation' | 'real'>(
    isSyntheticScenario ? 'simulation' : 'real'
  );

  const [notes, setNotes] = useState('');
  const [checkedItems, setCheckedItems] = useState<Record<string, boolean>>({});
  const [evidenceReference, setEvidenceReference] = useState('');
  const [attestationConfirmed, setAttestationConfirmed] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const activeChecklist =
    verificationMode === 'simulation' ? SIMULATION_VERIFICATION_CHECKLIST : DEFAULT_VERIFICATION_CHECKLIST;

  // Initialize checklist items when mode changes or on mount
  useEffect(() => {
    const initial: Record<string, boolean> = {};
    activeChecklist.forEach((item) => {
      initial[item.id] = true;
    });
    setCheckedItems(initial);
  }, [verificationMode]);

  // Reset mode to synthetic if task changes
  useEffect(() => {
    setVerificationMode(isSyntheticScenario ? 'simulation' : 'real');
    setNotes('');
    setEvidenceReference('');
    setAttestationConfirmed(false);
    setValidationError(null);
  }, [task.id, isSyntheticScenario]);

  const reworkHistory = parseRemediationHistory(task.completionNotes);

  if (!isOpen) return null;

  const toggleChecklistItem = (id: string) => {
    setCheckedItems((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    // Validation rules
    const trimmedNotes = notes.trim();
    if (trimmedNotes.length < 10) {
      setValidationError(
        verificationMode === 'simulation'
          ? 'Completion notes must be at least 10 characters describing the simulation review performed.'
          : 'Completion notes must be at least 10 characters describing the technical remediation performed.'
      );
      return;
    }

    const verifiedCount = Object.values(checkedItems).filter(Boolean).length;
    if (verifiedCount === 0) {
      setValidationError('You must record at least one verified checklist step.');
      return;
    }

    if (!attestationConfirmed) {
      setValidationError(
        verificationMode === 'simulation'
          ? 'You must confirm the simulation verification attestation before completing this task.'
          : 'You must confirm the technical verification attestation before completing this task.'
      );
      return;
    }

    // Build serialized notes to store in existing public.incident_tasks.completion_notes column
    const verifiedLabels = activeChecklist
      .filter((item) => checkedItems[item.id])
      .map((item) => `[X] ${item.label}`);

    const serializedSections = [
      `Work Performed:\n${trimmedNotes}`,
      `\nVerification Type: ${verificationMode === 'simulation' ? 'Controlled Simulation Verification' : 'Real Endpoint Remediation'}`,
      `\n--- VERIFIED REMEDIATION CHECKLIST (${verifiedCount}/${activeChecklist.length}) ---\n${verifiedLabels.join('\n')}`,
    ];

    if (evidenceReference.trim()) {
      serializedSections.push(`\n--- TECHNICAL EVIDENCE & REFERENCE ---\n${evidenceReference.trim()}`);
    }

    if (verificationMode === 'simulation') {
      serializedSections.push(
        `\n--- ATTESTATION ---\nOperator certified controlled simulation verification for synthetic alert "${task.associatedAlertId || 'N/A'}" on asset "${task.targetAsset}" at ${new Date().toISOString()}. No real endpoint modifications executed.`
      );
    } else {
      serializedSections.push(
        `\n--- ATTESTATION ---\nOperator certified independent technical verification on target asset "${task.targetAsset}" at ${new Date().toISOString()}`
      );
    }

    const currentSubmission = serializedSections.join('\n');
    const serializedNotes = task.completionNotes
      ? `${task.completionNotes.trim()}\n\n========================================\nREMEDIATION RESUBMISSION REPORT\n========================================\nResubmitted by: Operator certified at ${new Date().toISOString()}\n${currentSubmission}`
      : currentSubmission;

    const checklistData = activeChecklist.map((item) => ({
      id: item.id,
      label: item.label,
      verified: Boolean(checkedItems[item.id]),
    }));

    try {
      await onConfirm(task.id, {
        completionNotes: trimmedNotes,
        checklist: checklistData,
        evidenceReference: evidenceReference.trim() || undefined,
        attestationConfirmed,
        serializedNotes,
        verificationType: verificationMode,
      });
      onClose();
    } catch (err: any) {
      setValidationError(err.message || 'Failed to complete remediation verification.');
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="verification-modal-title"
    >
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] flex flex-col overflow-hidden text-slate-900 dark:text-slate-100">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div
              className={`p-2 rounded-lg border ${
                verificationMode === 'simulation'
                  ? 'bg-purple-50 dark:bg-purple-950/80 border-purple-200 dark:border-purple-800 text-purple-600 dark:text-purple-400'
                  : 'bg-emerald-50 dark:bg-emerald-950/80 border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400'
              }`}
            >
              {verificationMode === 'simulation' ? (
                <Cpu className="w-5 h-5" />
              ) : (
                <ShieldCheck className="w-5 h-5" />
              )}
            </div>
            <div>
              <h2 id="verification-modal-title" className="text-sm font-bold flex items-center gap-2">
                {verificationMode === 'simulation'
                  ? 'Controlled Simulation Verification & Task Completion'
                  : 'Remediation Verification & Task Completion'}
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800">
                  {task.id}
                </span>
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Target Asset: <strong className="font-mono text-slate-800 dark:text-slate-200">{task.targetAsset}</strong>
                {task.associatedAlertId && (
                  <span className="ml-2 text-blue-600 dark:text-cyan-400">
                    • Linked Alert: {task.associatedAlertId}
                  </span>
                )}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={isSubmitting}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer p-1 rounded focus:outline-none"
            aria-label="Close verification modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Verification Path Selector Tab Bar */}
        <div className="flex border-b border-slate-200 dark:border-slate-800 bg-slate-100/60 dark:bg-slate-950/50 px-4 gap-2 pt-2 text-xs font-mono">
          <button
            type="button"
            onClick={() => setVerificationMode('simulation')}
            className={`flex items-center gap-1.5 px-3 py-2 border-b-2 font-medium transition cursor-pointer ${
              verificationMode === 'simulation'
                ? 'border-purple-600 text-purple-700 dark:text-purple-300 bg-white dark:bg-slate-900 font-bold rounded-t'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-purple-500" />
            <span>Controlled Simulation Verification</span>
            {isSyntheticScenario && (
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 font-bold uppercase">
                Synthetic Alert
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setVerificationMode('real')}
            className={`flex items-center gap-1.5 px-3 py-2 border-b-2 font-medium transition cursor-pointer ${
              verificationMode === 'real'
                ? 'border-emerald-600 text-emerald-700 dark:text-emerald-300 bg-white dark:bg-slate-900 font-bold rounded-t'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
            <span>Real Endpoint Remediation</span>
          </button>
        </div>

        {/* Modal Body / Form */}
        <form onSubmit={handleSubmit} className="p-5 overflow-y-auto space-y-4 flex-1 text-xs">
          {/* Path Context Notice */}
          {verificationMode === 'simulation' ? (
            <div className="p-3 bg-purple-50 dark:bg-purple-950/50 border border-purple-200 dark:border-purple-800/80 rounded-lg text-purple-900 dark:text-purple-200 space-y-1">
              <div className="flex items-center gap-1.5 font-bold font-mono text-[11px] text-purple-800 dark:text-purple-300">
                <Info className="w-4 h-4 text-purple-600 dark:text-purple-400 shrink-0" />
                <span>CONTROLLED SIMULATION EXERCISE VERIFICATION</span>
              </div>
              <p className="text-[11px] text-purple-800 dark:text-purple-300 leading-relaxed">
                This task is associated with a synthetic simulation scenario. No live changes were made to physical infrastructure.
                Attest truthfully to reviewing the synthetic telemetry and containment readiness without asserting real endpoint modifications.
              </p>
            </div>
          ) : (
            <div className="p-3 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 rounded-lg space-y-1">
              <div className="flex items-center gap-1.5 font-bold font-mono text-[11px] text-emerald-700 dark:text-emerald-300">
                <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>OPERATIONAL PRODUCTION REMEDIATION</span>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                Standard technical verification for operational endpoints. Requires independent confirmation that physical/credential
                containment was executed and production baseline was validated.
              </p>
            </div>
          )}

          {/* Task Summary Banner */}
          <div className="p-3 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 rounded-lg space-y-1">
            <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block">
              TASK DESCRIPTION
            </span>
            <p className="text-xs text-slate-700 dark:text-slate-300">{task.description}</p>
          </div>

          {/* Rework Requested Notification Banner */}
          {reworkHistory.latestReworkInstructions && (
            <div className="p-3 bg-orange-50 dark:bg-orange-950/60 border border-orange-200 dark:border-orange-800 rounded-lg text-orange-900 dark:text-orange-200 space-y-1.5">
              <div className="flex items-center gap-2 font-mono font-bold text-[11px] text-orange-700 dark:text-orange-300">
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Rework Instructions from {reworkHistory.latestReview?.reviewerName || 'SOC Analyst'}:</span>
              </div>
              <p className="text-xs bg-white dark:bg-slate-900 p-2.5 rounded border border-orange-200 dark:border-orange-900/60 font-mono text-slate-800 dark:text-slate-200 whitespace-pre-wrap">
                {reworkHistory.latestReworkInstructions}
              </p>
              <span className="text-[10px] text-orange-600 dark:text-orange-400 block font-mono">
                Address the instructions above. Your previous submissions and this new verification will both be preserved.
              </span>
            </div>
          )}

          {/* Validation Error Banner */}
          {validationError && (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/70 border border-rose-200 dark:border-rose-900 rounded-lg text-rose-700 dark:text-rose-300 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-xs">Verification Incomplete</p>
                <p className="text-[11px] mt-0.5">{validationError}</p>
              </div>
            </div>
          )}

          {/* Section 1: Verification Checklist */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="font-bold text-xs uppercase font-mono tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <CheckSquare className="w-4 h-4 text-emerald-500" />
                {verificationMode === 'simulation'
                  ? 'Controlled Simulation Verification Checklist'
                  : 'Technical Verification Checklist'}
              </label>
              <span className="text-[10px] text-slate-400 font-mono">
                {Object.values(checkedItems).filter(Boolean).length} of {activeChecklist.length} attested
              </span>
            </div>

            <div className="space-y-1.5 bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-lg p-2.5">
              {activeChecklist.map((item) => {
                const isChecked = Boolean(checkedItems[item.id]);

                return (
                  <label
                    key={item.id}
                    className={`flex items-start gap-2.5 p-2 rounded cursor-pointer transition select-none ${
                      isChecked
                        ? verificationMode === 'simulation'
                          ? 'bg-purple-50/60 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-900/50'
                          : 'bg-emerald-50/60 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50'
                        : 'hover:bg-slate-100 dark:hover:bg-slate-900 border border-transparent'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => toggleChecklistItem(item.id)}
                      disabled={isSubmitting}
                      className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500 cursor-pointer"
                    />
                    <div className="flex-1">
                      <div className="font-semibold text-slate-900 dark:text-slate-200 text-xs">
                        {item.label}
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                        {item.description}
                      </div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Section 2: Completion Notes (Required) */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor="completion-notes" className="font-bold text-xs uppercase font-mono tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-blue-500" />
                {verificationMode === 'simulation'
                  ? 'Simulation Findings & Review Notes'
                  : 'Work Performed & Remediation Notes'}{' '}
                <span className="text-rose-500">*</span>
              </label>
              <span className="text-[10px] text-slate-400 font-mono">
                Min 10 characters ({notes.trim().length} entered)
              </span>
            </div>
            <textarea
              id="completion-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={isSubmitting}
              rows={3}
              placeholder={
                verificationMode === 'simulation'
                  ? 'Detail simulation review findings (e.g., reviewed synthetic ransomware IoCs, validated process telemetry, containment playbook formulated)...'
                  : 'Detail specific remediation work performed (e.g., credentials revoked on domain controller, host quarantine verified, backup snapshot hashes compared)...'
              }
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-emerald-500 dark:focus:ring-emerald-400 focus:outline-none"
              required
            />
          </div>

          {/* Section 3: Technical Evidence Reference (Optional) */}
          <div className="space-y-1.5">
            <label htmlFor="evidence-reference" className="font-bold text-xs uppercase font-mono tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-amber-500" />
              Evidence Reference / Scenario Reference <span className="text-slate-400 text-[10px] lowercase font-normal">(optional)</span>
            </label>
            <input
              id="evidence-reference"
              type="text"
              value={evidenceReference}
              onChange={(e) => setEvidenceReference(e.target.value)}
              disabled={isSubmitting}
              placeholder={
                verificationMode === 'simulation'
                  ? 'e.g. Synthetic event log reference, simulated playbook ID, or test verification artifact...'
                  : 'e.g. Script verification hash, firewall rule ID, or shell command output...'
              }
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-emerald-500 dark:focus:ring-emerald-400 focus:outline-none font-mono"
            />
          </div>

          {/* Section 4: Mandatory Operator Attestation */}
          <div
            className={`p-3 rounded-lg border ${
              verificationMode === 'simulation'
                ? 'bg-purple-50/70 dark:bg-purple-950/40 border-purple-200 dark:border-purple-900/60'
                : 'bg-amber-50/70 dark:bg-amber-950/40 border-amber-200 dark:border-amber-900/60'
            }`}
          >
            <label className="flex items-start gap-2.5 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={attestationConfirmed}
                onChange={(e) => setAttestationConfirmed(e.target.checked)}
                disabled={isSubmitting}
                className={`mt-0.5 rounded cursor-pointer ${
                  verificationMode === 'simulation'
                    ? 'text-purple-600 focus:ring-purple-500'
                    : 'text-amber-600 focus:ring-amber-500'
                }`}
              />
              <div
                className={`text-xs leading-relaxed ${
                  verificationMode === 'simulation'
                    ? 'text-purple-900 dark:text-purple-200'
                    : 'text-amber-900 dark:text-amber-200'
                }`}
              >
                {verificationMode === 'simulation' ? (
                  <>
                    <span className="font-bold">Controlled Simulation Verification Attestation: </span>
                    I confirm that I have reviewed the synthetic detection telemetry for this controlled simulation exercise and confirmed appropriate containment procedures without executing real destructive changes on production endpoints.
                  </>
                ) : (
                  <>
                    <span className="font-bold">Operator Verification Attestation: </span>
                    I confirm that this technical remediation was independently executed and verified on{' '}
                    <strong className="font-mono">{task.targetAsset}</strong> in accordance with CyberOps SOC incident response procedures.
                  </>
                )}
              </div>
            </label>
          </div>

          {/* Section 5: Persistence & Schema Disclosure Callout */}
          <div className="p-2.5 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded text-[11px] text-slate-500 dark:text-slate-400 flex items-start gap-2">
            <Info className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-700 dark:text-slate-300">Persistence Disclosure: </strong>
              Verification checklist items, evidence references, and operator notes are serialized directly into the existing{' '}
              <code className="text-cyan-600 dark:text-cyan-400 font-mono">completion_notes</code> column of{' '}
              <code className="text-slate-600 dark:text-slate-400 font-mono">public.incident_tasks</code>. No unapproved database columns are created.
            </div>
          </div>

          {/* Modal Footer */}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2.5">
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
              className={
                verificationMode === 'simulation'
                  ? 'bg-purple-600 hover:bg-purple-700 text-white'
                  : 'bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-600 dark:hover:bg-emerald-500 text-white'
              }
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin mr-1.5" />
                  Recording Verification...
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                  {verificationMode === 'simulation'
                    ? 'Confirm & Complete Simulation Review'
                    : 'Confirm & Complete Task'}
                </>
              )}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
