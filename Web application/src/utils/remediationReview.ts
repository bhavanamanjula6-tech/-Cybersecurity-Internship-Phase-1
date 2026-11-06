/**
 * Remediation Review & Lifecycle Utilities
 *
 * Implements structured parsing, formatting, and status derivation for the
 * SOC Analyst <-> IT Operations collaborative remediation lifecycle.
 *
 * Enforces zero database schema changes by serializing review attestations,
 * approval records, and rework instructions into immutable audit-friendly markers
 * within `incident_tasks.completion_notes`.
 */

import { IncidentTask } from '../types/audit';
import { UserProfile } from '../types/auth';

export const REVIEW_MARKERS = {
  SUBMISSION_HEADER: '--- REMEDIATION VERIFICATION REPORT ---',
  RESUBMISSION_HEADER: '========================================\nREMEDIATION RESUBMISSION REPORT\n========================================',
  APPROVAL_HEADER: '--- SOC ANALYST REVIEW: APPROVED ---',
  REWORK_HEADER: '--- SOC ANALYST REVIEW: REWORK REQUESTED ---',
} as const;

export type TaskReviewStatus =
  | 'pending'
  | 'in_progress'
  | 'rework_requested'
  | 'awaiting_review'
  | 'approved'
  | 'blocked';

export interface ParsedReviewEntry {
  decision: 'approved' | 'rework_requested';
  reviewerName: string;
  reviewerCallsign?: string;
  timestamp: string;
  notesOrInstructions: string;
  rawBlock: string;
}

export interface ParsedRemediationHistory {
  hasVerificationReport: boolean;
  verificationType: 'simulation' | 'real' | null;
  operatorAttestation: string | null;
  workPerformed: string | null;
  checklistItems: Array<{ label: string; verified: boolean }>;
  evidenceReference: string | null;
  reviews: ParsedReviewEntry[];
  latestReview: ParsedReviewEntry | null;
  latestReworkInstructions: string | null;
  resubmissionCount: number;
}

/**
 * Parses raw completion_notes into structured verification and review components.
 */
export function parseRemediationHistory(notes?: string): ParsedRemediationHistory {
  const result: ParsedRemediationHistory = {
    hasVerificationReport: false,
    verificationType: null,
    operatorAttestation: null,
    workPerformed: null,
    checklistItems: [],
    evidenceReference: null,
    reviews: [],
    latestReview: null,
    latestReworkInstructions: null,
    resubmissionCount: 0,
  };

  if (!notes || !notes.trim()) {
    return result;
  }

  // Count resubmissions
  const resubMatches = notes.match(/REMEDIATION RESUBMISSION REPORT/g);
  result.resubmissionCount = resubMatches ? resubMatches.length : 0;

  // Check if initial or resubmitted verification report exists
  result.hasVerificationReport =
    notes.includes('Work Performed:') ||
    notes.includes('VERIFIED REMEDIATION CHECKLIST') ||
    notes.includes('--- ATTESTATION ---');

  // Detect verification type (Controlled Simulation vs Real Endpoint Remediation)
  if (
    notes.includes('Verification Type: Controlled Simulation Verification') ||
    notes.toLowerCase().includes('controlled simulation verification') ||
    notes.includes('SIMULATION VERIFICATION')
  ) {
    result.verificationType = 'simulation';
  } else if (
    notes.includes('Verification Type: Real Endpoint Remediation') ||
    notes.toLowerCase().includes('real endpoint remediation') ||
    notes.includes('independent technical verification on target asset')
  ) {
    result.verificationType = 'real';
  }

  // Extract work performed (first occurrence or after latest resubmission)
  const workMatch = notes.match(/Work Performed:\s*([\s\S]*?)(?=(?:\n---|\n===|$))/);
  if (workMatch) {
    result.workPerformed = workMatch[1].trim();
  }

  // Extract checklist items
  const checklistMatch = notes.match(/--- VERIFIED REMEDIATION CHECKLIST[^\n]*---\s*([\s\S]*?)(?=(?:\n---|\n===|$))/);
  if (checklistMatch) {
    const lines = checklistMatch[1].split('\n').map((l) => l.trim()).filter(Boolean);
    result.checklistItems = lines.map((line) => {
      const isVerified = line.startsWith('[X]') || line.startsWith('[x]');
      const label = line.replace(/^\[[Xx\s]\]\s*/, '').trim();
      return { label, verified: isVerified };
    });
  }

  // Extract evidence reference
  const evidenceMatch = notes.match(/--- TECHNICAL EVIDENCE & REFERENCE ---\s*([\s\S]*?)(?=(?:\n---|\n===|$))/);
  if (evidenceMatch) {
    result.evidenceReference = evidenceMatch[1].trim();
  }

  // Extract attestation
  const attestationMatch = notes.match(/--- ATTESTATION ---\s*([\s\S]*?)(?=(?:\n---|\n===|$))/);
  if (attestationMatch) {
    result.operatorAttestation = attestationMatch[1].trim();
  }

  // Parse all review entries (both APPROVED and REWORK REQUESTED) in chronological order
  const reviewRegex = /---\s*SOC ANALYST REVIEW:\s*(APPROVED|REWORK REQUESTED)\s*---\s*\nReviewed by:\s*([^\n]+)\s+at\s+([^\n]+)\s*\nVerdict:\s*([^\n]+)\s*\n(?:Review Notes|Instructions):\s*([\s\S]*?)(?=(?:\n---|\n===|$))/g;

  let match: RegExpExecArray | null;
  while ((match = reviewRegex.exec(notes)) !== null) {
    const rawDecision = match[1].trim();
    const decision: 'approved' | 'rework_requested' = rawDecision === 'APPROVED' ? 'approved' : 'rework_requested';
    const reviewerRaw = match[2].trim();
    const timestamp = match[3].trim();
    const content = match[5].trim();

    result.reviews.push({
      decision,
      reviewerName: reviewerRaw,
      timestamp,
      notesOrInstructions: content,
      rawBlock: match[0].trim(),
    });

    if (decision === 'rework_requested') {
      result.latestReworkInstructions = content;
    }
  }

  if (result.reviews.length > 0) {
    result.latestReview = result.reviews[result.reviews.length - 1];
  }

  return result;
}

/**
 * Derives the active collaborative review state for an IncidentTask.
 * Crucial rule: Never treats `task.status === 'completed'` alone as proof of approval.
 */
export function getTaskReviewState(task: IncidentTask): {
  status: TaskReviewStatus;
  label: string;
  badgeClass: string;
  canApprove: boolean;
  canRequestRework: boolean;
  history: ParsedRemediationHistory;
  latestReview: ParsedReviewEntry | null;
  latestReworkInstructions: string | null;
} {
  const history = parseRemediationHistory(task.completionNotes);

  if (task.status === 'blocked') {
    return {
      status: 'blocked',
      label: 'Blocked',
      badgeClass: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border-rose-300 dark:border-rose-800',
      canApprove: false,
      canRequestRework: false,
      history,
      latestReview: history.latestReview,
      latestReworkInstructions: history.latestReworkInstructions,
    };
  }

  if (task.status === 'pending') {
    return {
      status: 'pending',
      label: 'Pending Operator Execution',
      badgeClass: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-800',
      canApprove: false,
      canRequestRework: false,
      history,
      latestReview: history.latestReview,
      latestReworkInstructions: history.latestReworkInstructions,
    };
  }

  if (task.status === 'in_progress') {
    // If rework was requested in history and the task is now in progress, it is awaiting IT Ops rework
    if (history.latestReview?.decision === 'rework_requested') {
      return {
        status: 'rework_requested',
        label: 'Rework In Progress (IT Ops)',
        badgeClass: 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300 border-orange-300 dark:border-orange-800',
        canApprove: false,
        canRequestRework: false,
        history,
        latestReview: history.latestReview,
        latestReworkInstructions: history.latestReworkInstructions,
      };
    }

    return {
      status: 'in_progress',
      label: 'Under Remediation',
      badgeClass: 'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300 border-sky-300 dark:border-sky-800',
      canApprove: false,
      canRequestRework: false,
      history,
      latestReview: history.latestReview,
      latestReworkInstructions: history.latestReworkInstructions,
    };
  }

  if (task.status === 'completed') {
    // Explicit SOC Analyst Approval is verified when the latest review entry is 'approved'
    if (history.latestReview?.decision === 'approved') {
      return {
        status: 'approved',
        label: 'Remediation Approved by Analyst',
        badgeClass: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800',
        canApprove: false, // Already approved; prevent duplicate review decisions
        canRequestRework: false,
        history,
        latestReview: history.latestReview,
        latestReworkInstructions: history.latestReworkInstructions,
      };
    }

    // Task is completed by IT Ops, but not yet explicitly approved by SOC Analyst
    return {
      status: 'awaiting_review',
      label: 'Awaiting SOC Analyst Review',
      badgeClass: 'bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border-purple-300 dark:border-purple-800',
      canApprove: true,
      canRequestRework: true,
      history,
      latestReview: history.latestReview,
      latestReworkInstructions: history.latestReworkInstructions,
    };
  }

  return {
    status: 'pending',
    label: task.status,
    badgeClass: 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300',
    canApprove: false,
    canRequestRework: false,
    history,
    latestReview: history.latestReview,
    latestReworkInstructions: history.latestReworkInstructions,
  };
}

/**
 * Serializes an approval block to append to `completion_notes`.
 */
export function formatApprovalNotes(
  existingNotes: string | undefined,
  analyst: UserProfile,
  reviewNotes?: string
): string {
  const timestamp = new Date().toISOString();
  const reviewerIdentity = `${analyst.name} (${analyst.callsign || analyst.role})`;
  const approvalBlock = [
    `\n\n${REVIEW_MARKERS.APPROVAL_HEADER}`,
    `Reviewed by: ${reviewerIdentity} at ${timestamp}`,
    `Verdict: APPROVED`,
    `Review Notes: ${reviewNotes?.trim() || 'Remediation verification and evidence validated by SOC Analyst. Approved.'}`,
  ].join('\n');

  return (existingNotes || '').trim() + approvalBlock;
}

/**
 * Serializes a rework request block to append to `completion_notes`.
 */
export function formatReworkNotes(
  existingNotes: string | undefined,
  analyst: UserProfile,
  instructions: string
): string {
  const timestamp = new Date().toISOString();
  const reviewerIdentity = `${analyst.name} (${analyst.callsign || analyst.role})`;
  const reworkBlock = [
    `\n\n${REVIEW_MARKERS.REWORK_HEADER}`,
    `Reviewed by: ${reviewerIdentity} at ${timestamp}`,
    `Verdict: REWORK REQUIRED`,
    `Instructions: ${instructions.trim()}`,
  ].join('\n');

  return (existingNotes || '').trim() + reworkBlock;
}

/**
 * Serializes an IT Operations resubmission report while preserving existing history.
 */
export function formatResubmissionNotes(
  existingNotes: string | undefined,
  operator: UserProfile,
  newReport: string
): string {
  const timestamp = new Date().toISOString();
  const operatorIdentity = `${operator.name} (${operator.callsign || operator.role})`;
  const resubmissionBlock = [
    `\n\n${REVIEW_MARKERS.RESUBMISSION_HEADER}`,
    `Resubmitted by: ${operatorIdentity} at ${timestamp}`,
    newReport.trim(),
  ].join('\n');

  return (existingNotes || '').trim() + resubmissionBlock;
}

/**
 * Evaluates whether an alert can be marked as 'resolved'.
 * Requirement 7: When an alert has associated remediation tasks, all of them
 * must have explicit SOC Analyst approval before allowing the alert to become resolved.
 */
export function checkAlertClosureEligibility(
  alertId: string,
  tasks: IncidentTask[]
): {
  eligible: boolean;
  linkedTasks: IncidentTask[];
  unapprovedTasks: IncidentTask[];
  reason?: string;
} {
  const linkedTasks = tasks.filter((t) => t.associatedAlertId === alertId);

  // Alerts without associated remediation tasks retain their existing resolution behavior
  if (linkedTasks.length === 0) {
    return {
      eligible: true,
      linkedTasks: [],
      unapprovedTasks: [],
    };
  }

  // Filter tasks that do not have explicit SOC Analyst approval
  const unapprovedTasks = linkedTasks.filter((t) => {
    const reviewState = getTaskReviewState(t);
    return reviewState.status !== 'approved';
  });

  if (unapprovedTasks.length === 0) {
    return {
      eligible: true,
      linkedTasks,
      unapprovedTasks: [],
    };
  }

  const taskBreakdown = unapprovedTasks
    .map((t) => {
      const state = getTaskReviewState(t);
      return `${t.id} (${state.label})`;
    })
    .join(', ');

  return {
    eligible: false,
    linkedTasks,
    unapprovedTasks,
    reason: `Cannot resolve alert: ${unapprovedTasks.length} associated remediation task(s) require explicit SOC Analyst approval before closure: ${taskBreakdown}.`,
  };
}
