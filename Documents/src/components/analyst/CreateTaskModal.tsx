import React, { useState, useEffect } from 'react';
import { Modal } from '../common/Modal';
import { Button } from '../common/Button';
import { SecurityAlert } from '../../types/alert';
import { IncidentTask } from '../../types/audit';
import { UserProfile } from '../../types/auth';
import {
  ClipboardList,
  Send,
  AlertCircle,
  CheckCircle2,
  Server,
  ShieldAlert,
  Info,
} from 'lucide-react';

interface CreateTaskModalProps {
  isOpen: boolean;
  onClose: () => void;
  alert: SecurityAlert;
  currentUser: UserProfile;
  onCreateTask: (taskData: Omit<IncidentTask, 'id' | 'createdAt'>) => Promise<IncidentTask>;
  onSuccess?: (createdTask: IncidentTask) => void;
}

export const CreateTaskModal: React.FC<CreateTaskModalProps> = ({
  isOpen,
  onClose,
  alert,
  currentUser,
  onCreateTask,
  onSuccess,
}) => {
  // Map alert severity to sensible task priority baseline
  const mapSeverityToPriority = (severity: string): IncidentTask['priority'] => {
    switch (severity) {
      case 'critical':
        return 'critical';
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
      case 'informational':
      default:
        return 'low';
    }
  };

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState<IncidentTask['priority']>('high');
  const [targetAsset, setTargetAsset] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Initialize or reset form whenever modal opens with an alert
  useEffect(() => {
    if (isOpen && alert) {
      setTitle(`Remediate: ${alert.title}`);
      setDescription('');
      setPriority(mapSeverityToPriority(alert.severity));
      setTargetAsset(alert.hostName || alert.sourceIp || '');
      setErrorMessage(null);
      setSuccessMessage(null);
      setIsSubmitting(false);
    }
  }, [isOpen, alert]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;

    // Strict client-side validation
    if (!alert || !alert.id || !alert.id.trim()) {
      setErrorMessage('A valid associated alert ID is required to create an incident response task.');
      return;
    }

    const trimmedTitle = title.trim();
    if (!trimmedTitle) {
      setErrorMessage('Task title is required.');
      return;
    }

    const trimmedDesc = description.trim();
    if (!trimmedDesc) {
      setErrorMessage('Remediation instructions and description are required.');
      return;
    }

    const trimmedAsset = targetAsset.trim();
    if (!trimmedAsset) {
      setErrorMessage('Target asset is required.');
      return;
    }

    const validPriorities: IncidentTask['priority'][] = ['critical', 'high', 'medium', 'low'];
    if (!validPriorities.includes(priority)) {
      setErrorMessage('A valid priority level must be selected.');
      return;
    }

    setErrorMessage(null);
    setSuccessMessage(null);
    setIsSubmitting(true);

    try {
      const created = await onCreateTask({
        title: trimmedTitle,
        description: trimmedDesc,
        priority,
        targetAsset: trimmedAsset,
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: alert.id,
      });

      setSuccessMessage(`Task ${created.id} successfully created and assigned to IT Operations.`);
      if (onSuccess) {
        onSuccess(created);
      }
      setTimeout(() => {
        onClose();
      }, 1200);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to create remediation task.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Create Incident Response Task"
      subtitle={`Alert Association: ${alert?.id || 'Unknown Alert'}`}
      maxWidth="lg"
      footer={
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-500 dark:text-slate-400">
            <Server className="w-3.5 h-3.5 text-amber-500" />
            <span>Assigned Target: <strong className="text-slate-800 dark:text-slate-200">IT Operations</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              form="create-task-form"
              variant="primary"
              size="sm"
              isLoading={isSubmitting}
              disabled={isSubmitting || !title.trim() || !description.trim() || !targetAsset.trim()}
              className="flex items-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              Assign to IT Operations
            </Button>
          </div>
        </div>
      }
    >
      <form id="create-task-form" onSubmit={handleSubmit} className="p-4 space-y-4 text-xs font-sans">
        {/* Error Feedback */}
        {errorMessage && (
          <div className="p-3 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 rounded-md flex items-start gap-2 text-rose-800 dark:text-rose-200">
            <AlertCircle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1 font-mono text-[11px]">{errorMessage}</div>
          </div>
        )}

        {/* Success Feedback */}
        {successMessage && (
          <div className="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 rounded-md flex items-start gap-2 text-emerald-800 dark:text-emerald-200">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            <div className="flex-1 font-mono text-[11px]">{successMessage}</div>
          </div>
        )}

        {/* Alert Context Summary */}
        <div className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg space-y-1.5 font-mono">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-500 uppercase font-bold">ASSOCIATED ALERT</span>
            <span className="px-1.5 py-0.5 rounded bg-blue-100 dark:bg-cyan-950 text-blue-800 dark:text-cyan-300 font-bold border border-blue-200 dark:border-cyan-800">
              {alert.id}
            </span>
          </div>
          <div className="text-xs text-slate-900 dark:text-slate-100 font-semibold truncate font-heading">
            {alert.title}
          </div>
          <div className="flex items-center gap-3 text-[10px] text-slate-500 dark:text-slate-400">
            <span>Host: <strong className="text-slate-800 dark:text-slate-200">{alert.hostName}</strong></span>
            <span>IP: <strong className="text-slate-800 dark:text-slate-200">{alert.sourceIp}</strong></span>
            <span>Severity: <strong className="text-slate-800 dark:text-slate-200 uppercase">{alert.severity}</strong></span>
          </div>
        </div>

        {/* Task Title */}
        <div className="space-y-1.5">
          <label htmlFor="task-title" className="block text-xs font-semibold text-slate-800 dark:text-slate-200">
            Task Title <span className="text-rose-500">*</span>
          </label>
          <input
            id="task-title"
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g. Verify Endpoint Isolation & Terminate Rogue Lineage"
            disabled={isSubmitting}
            className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md p-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
            required
          />
        </div>

        {/* Target Asset & Priority Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <label htmlFor="target-asset" className="block text-xs font-semibold text-slate-800 dark:text-slate-200">
              Target Asset <span className="text-rose-500">*</span>
            </label>
            <input
              id="target-asset"
              type="text"
              value={targetAsset}
              onChange={(e) => setTargetAsset(e.target.value)}
              placeholder="e.g. FILESERVER-01 (192.168.10.99)"
              disabled={isSubmitting}
              className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md p-2 text-xs font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
              required
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="task-priority" className="block text-xs font-semibold text-slate-800 dark:text-slate-200">
              Task Priority <span className="text-rose-500">*</span>
            </label>
            <select
              id="task-priority"
              value={priority}
              onChange={(e) => setPriority(e.target.value as IncidentTask['priority'])}
              disabled={isSubmitting}
              className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md p-2 text-xs font-mono text-slate-900 dark:text-slate-100 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none"
            >
              <option value="critical">Critical (Immediate containment required)</option>
              <option value="high">High (Priority operational containment)</option>
              <option value="medium">Medium (Standard remediation cycle)</option>
              <option value="low">Low (Routine verification / cleanup)</option>
            </select>
          </div>
        </div>

        {/* Remediation Instructions */}
        <div className="space-y-1.5">
          <label htmlFor="task-description" className="block text-xs font-semibold text-slate-800 dark:text-slate-200">
            Remediation Instructions & Scope <span className="text-rose-500">*</span>
          </label>
          <textarea
            id="task-description"
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Provide specific technical instructions for IT Operations: e.g. '1. Quarantine host from VLAN 20. 2. Verify VSS volume backup snapshot on cold storage. 3. Collect process memory dump before reboot.'"
            disabled={isSubmitting}
            className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-md p-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500 dark:focus:ring-cyan-400 focus:outline-none leading-relaxed"
            required
          />
        </div>

        {/* Pre-Configured Operational Invariants Box */}
        <div className="p-3 bg-amber-50/60 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/50 rounded-lg text-[11px] space-y-1 text-slate-600 dark:text-slate-400">
          <div className="flex items-center gap-1.5 font-bold text-amber-800 dark:text-amber-300 font-mono">
            <Info className="w-3.5 h-3.5" />
            AUTOMATIC OPERATIONAL ROUTING
          </div>
          <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono pt-0.5">
            <span>Assigned Role: <strong className="text-slate-900 dark:text-slate-200">it_operations</strong></span>
            <span>Initial Status: <strong className="text-slate-900 dark:text-slate-200">pending</strong></span>
            <span>Associated Alert: <strong className="text-slate-900 dark:text-slate-200">{alert.id}</strong></span>
          </div>
          <p className="text-[10px] text-slate-500 dark:text-slate-400 pt-1">
            IT Operations lead will receive this task in their Incident Response Tasks queue with scoped read access to the alert telemetry.
          </p>
        </div>
      </form>
    </Modal>
  );
};
