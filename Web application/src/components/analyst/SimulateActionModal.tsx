import React, { useState } from 'react';
import { Modal } from '../common/Modal';
import { Button } from '../common/Button';
import { ResponseActionType } from '../../types/audit';
import { UserRole } from '../../types/auth';
import { AlertTriangle, ShieldCheck, Info } from 'lucide-react';

interface SimulateActionModalProps {
  isOpen: boolean;
  onClose: () => void;
  actionType: ResponseActionType;
  target: string;
  alertId?: string;
  currentRole: UserRole;
  onConfirm: (justification: string) => Promise<void>;
}

export const SimulateActionModal: React.FC<SimulateActionModalProps> = ({
  isOpen,
  onClose,
  actionType,
  target,
  alertId,
  currentRole,
  onConfirm,
}) => {
  const [justification, setJustification] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getActionDetails = () => {
    switch (actionType) {
      case 'isolate_host':
        return {
          title: 'Simulate Endpoint Network Isolation',
          impact: 'Sever all network traffic except management tunnel. Will disrupt user productivity on target host.',
          defaultRationale: `Isolated host ${target} due to malicious activity detected in ${alertId || 'alert queue'}.`,
        };
      case 'block_ip':
        return {
          title: 'Simulate Edge Firewall IP Block',
          impact: 'Drop all ingress and egress packets matching target external IP across perimeter firewalls.',
          defaultRationale: `Blocked external IP ${target} correlated with active C2 beaconing or exploit attempt.`,
        };
      case 'lock_account':
        return {
          title: 'Simulate Directory Account Lockout',
          impact: 'Immediately disable Active Directory account and terminate active Kerberos sessions.',
          defaultRationale: `Account ${target} locked following credential dumping or unauthorized WMI invocation.`,
        };
      case 'collect_forensics':
        return {
          title: 'Request Volatile Memory & Disk Triage Package',
          impact: 'Execute read-only forensic script to capture RAM dump and MFT records.',
          defaultRationale: `Initiated forensic package collection for ${target}.`,
        };
      default:
        return {
          title: 'Simulate Containment Action',
          impact: 'Simulated operational response procedure.',
          defaultRationale: 'Action performed per approved incident playbook.',
        };
    }
  };

  const details = getActionDetails();

  const handleExecute = async () => {
    if (!justification.trim()) {
      setError('An analyst justification is required for audit compliance before simulation.');
      return;
    }
    setError(null);
    setIsSubmitting(true);
    try {
      await onConfirm(justification.trim());
      setJustification('');
      onClose();
    } catch (e: any) {
      setError(e.message || 'Execution error');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={details.title}
      subtitle={`Target: ${target}`}
      footer={
        <div className="flex items-center justify-between w-full">
          <span className="text-[11px] font-mono text-purple-400 flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            SIMULATION MODE ONLY
          </span>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={onClose} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleExecute}
              isLoading={isSubmitting}
            >
              Authorize & Record Simulated Action
            </Button>
          </div>
        </div>
      }
    >
      <div className="space-y-4">
        {/* Boundary Notice */}
        <div className="p-3 bg-purple-50 dark:bg-purple-950/40 border border-purple-200 dark:border-purple-800/60 rounded-md text-xs space-y-1">
          <div className="flex items-center gap-1.5 font-semibold text-purple-700 dark:text-purple-300">
            <Info className="w-4 h-4 text-purple-600 dark:text-purple-400" />
            Security & Simulation Boundary
          </div>
          <p className="text-slate-600 dark:text-slate-300 text-[11px]">
            In Phase 1, response actions are <strong>simulated proposals only</strong>. No packets or agent commands are transmitted to production infrastructure. The action will be written to the tamper-evident audit ledger with your analyst callsign.
          </p>
        </div>

        {/* Impact Warning */}
        <div className="p-3 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/50 rounded-md text-xs space-y-1">
          <div className="flex items-center gap-1.5 font-semibold text-amber-800 dark:text-amber-300">
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
            Production Impact Pre-Evaluation
          </div>
          <p className="text-slate-600 dark:text-slate-300 text-[11px]">{details.impact}</p>
        </div>

        {/* Justification Form */}
        <div>
          <label className="block text-xs font-semibold text-slate-800 dark:text-slate-200 mb-1">
            Operational Justification / Rationale <span className="text-rose-500">*</span>
          </label>
          <textarea
            rows={3}
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            placeholder={details.defaultRationale}
            className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded p-2.5 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
          />
          <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1">
            Mandatory: Recorded alongside timestamp and analyst role ({currentRole}) in the audit ledger.
          </p>
        </div>

        {error && (
          <div className="p-2 bg-rose-950/60 border border-rose-800 rounded text-xs text-rose-300">
            {error}
          </div>
        )}
      </div>
    </Modal>
  );
};
