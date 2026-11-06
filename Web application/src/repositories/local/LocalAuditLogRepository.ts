/**
 * Local Browser Storage Adapter for Audit Logs & Incident Tasks with Role Enforcement
 *
 * PROTOTYPE ARCHITECTURE & SECURITY NOTICE:
 * Logs generated here represent SIMULATED actions and proposed remediation workflows.
 * No actions are dispatched to production firewalls, EDR agents, or directory services.
 * Unauthorized cross-role executions throw explicit AccessDeniedError.
 */

import { IAuditLogRepository } from '../IAuditLogRepository';
import { AuditLogEntry, IncidentTask } from '../../types/audit';
import { UserProfile, AccessDeniedError } from '../../types/auth';
import { AuthorizationService } from '../../services/authorizationService';
import { formatApprovalNotes, formatReworkNotes, getTaskReviewState } from '../../utils/remediationReview';

const AUDIT_STORAGE_KEY = 'ai_soc_audit_logs_v1';
const TASKS_STORAGE_KEY = 'ai_soc_tasks_v1';

const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'AUD-SIM-001',
    timestamp: '2026-10-12T04:00:20Z',
    actorName: 'Marcus Vance',
    actorRole: 'it_operations',
    actionType: 'isolate_host',
    targetResource: 'FILESERVER-01 (192.168.10.99)',
    justification: 'VSSadmin shadow copy deletion detected. Authorized host network quarantine per Playbook IR-04.',
    status: 'SIMULATED_SUCCESS',
    associatedAlertId: 'ALT-2026-1046',
    isSimulated: true,
    systemNote: 'Simulated endpoint isolation flag set. Network interface not severed in prototype environment.',
  },
  {
    id: 'AUD-GOV-001',
    timestamp: '2026-10-12T00:00:00Z',
    actorName: 'Platform Security System',
    actorRole: 'super_admin',
    actionType: 'platform_bootstrap',
    targetResource: 'system.bootstrap.domain_c',
    justification: 'Platform baseline security configuration and initial RBAC domain segregation established.',
    status: 'SUCCESS',
    isSimulated: false,
    systemNote: 'Initial platform security baseline initialized.',
  },
];

const INITIAL_TASKS: IncidentTask[] = [
  {
    id: 'TSK-2026-001',
    title: 'Verify File Server Offline Snapshot Integrity',
    description: 'Ensure offline storage backups for FILESERVER-01 are uncorrupted following shadow copy tampering alert.',
    assignedRole: 'it_operations',
    status: 'pending',
    priority: 'critical',
    createdAt: '2026-10-12T04:02:00Z',
    targetAsset: 'FILESERVER-01',
    suggestedActionType: 'isolate_host',
    associatedAlertId: 'ALT-2026-1046',
  },
  {
    id: 'TSK-2026-002',
    title: 'Revoke and Reset Compromised Service Account Kerberos Ticket',
    description: 'Service account DOMAIN\\svc_backup observed initiating unauthorized WMI process creation on DC-01.',
    assignedRole: 'it_operations',
    status: 'in_progress',
    priority: 'high',
    createdAt: '2026-10-12T04:35:00Z',
    targetAsset: 'DOMAIN\\svc_backup',
    suggestedActionType: 'lock_account',
    associatedAlertId: 'ALT-2026-1047',
  },
  {
    id: 'TSK-2026-003',
    title: 'Configure Edge Firewall Rate Limiting for DMZ Proxy',
    description: 'Implement connection threshold per IP to mitigate Slowloris resource exhaustion attempts.',
    assignedRole: 'security_engineer',
    status: 'pending',
    priority: 'medium',
    createdAt: '2026-10-12T05:12:00Z',
    targetAsset: 'WEB-PROXY-DMZ',
    suggestedActionType: 'block_ip',
  },
];

const SEED_TASK_ALERT_MAPPINGS: Record<string, string> = {
  'TSK-2026-001': 'ALT-2026-1046',
  'TSK-2026-002': 'ALT-2026-1047',
};

export class LocalAuditLogRepository implements IAuditLogRepository {
  private memoryAudit: AuditLogEntry[] | null = null;
  private memoryTasks: IncidentTask[] | null = null;

  private getAuditData(): AuditLogEntry[] {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const stored = window.localStorage.getItem(AUDIT_STORAGE_KEY);
        if (stored) return JSON.parse(stored);
      } catch {
        // Fallback
      }
    }
    if (this.memoryAudit) return this.memoryAudit;
    this.memoryAudit = [...INITIAL_AUDIT_LOGS];
    this.saveAuditData(this.memoryAudit);
    return this.memoryAudit;
  }

  private saveAuditData(logs: AuditLogEntry[]): void {
    this.memoryAudit = logs;
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.setItem(AUDIT_STORAGE_KEY, JSON.stringify(logs));
      } catch {
        // Fallback
      }
    }
  }

  private getTasksData(): IncidentTask[] {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const stored = window.localStorage.getItem(TASKS_STORAGE_KEY);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (Array.isArray(parsed)) {
            let migratedCount = 0;
            const migrated = parsed.map((task: any) => {
              if (
                task &&
                typeof task === 'object' &&
                SEED_TASK_ALERT_MAPPINGS[task.id] &&
                !task.associatedAlertId
              ) {
                migratedCount++;
                return {
                  ...task,
                  associatedAlertId: SEED_TASK_ALERT_MAPPINGS[task.id],
                };
              }
              return task;
            });

            if (migratedCount > 0) {
              this.saveTasksData(migrated);
            }
            return migrated;
          }
        }
      } catch {
        // Fallback
      }
    }
    if (this.memoryTasks) return this.memoryTasks;
    this.memoryTasks = [...INITIAL_TASKS];
    this.saveTasksData(this.memoryTasks);
    return this.memoryTasks;
  }

  private saveTasksData(tasks: IncidentTask[]): void {
    this.memoryTasks = tasks;
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.setItem(TASKS_STORAGE_KEY, JSON.stringify(tasks));
      } catch {
        // Fallback
      }
    }
  }

  async getLogsForUser(user: UserProfile): Promise<AuditLogEntry[]> {
    if (!user || !user.role) {
      throw new AccessDeniedError('Unauthenticated access to audit logs', 'audit:read', 'unknown' as any);
    }
    AuthorizationService.assertPermission(user, 'audit:read');
    const all = this.getAuditData();
    if (user.role === 'super_admin') {
      // Super Admin receives platform governance logs; strictly isolated from operational containment & remediation
      return all.filter(
        (log) =>
          log.actorRole === 'super_admin' ||
          log.actionType === 'platform_bootstrap' ||
          log.id.startsWith('AUD-GOV')
      );
    }
    // Operational roles receive operational containment and remediation logs
    return all.filter((log) => log.actorRole !== 'super_admin' && !log.id.startsWith('AUD-GOV'));
  }

  async recordSimulatedAction(
    user: UserProfile,
    entry: Omit<AuditLogEntry, 'id' | 'timestamp' | 'isSimulated' | 'actorName' | 'actorRole'>
  ): Promise<AuditLogEntry> {
    const isRecommendationAction = entry.actionType.startsWith('recommendation_');
    const isAuthorizedRecommendationRole = user.role === 'security_engineer' || user.role === 'soc_analyst';

    // Assert authorization: IT Operations, SOC Analyst, or authorized recommendation roles
    const canAuthorize = AuthorizationService.canAuthorizeSimulatedActions(user.role);
    const canPropose = AuthorizationService.canProposeActions(user.role);

    if (!canAuthorize && !canPropose && !(isRecommendationAction && isAuthorizedRecommendationRole)) {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to execute or propose response actions.`,
        'action:authorize_simulated',
        user.role
      );
    }

    const logs = this.getAuditData();
    const newLog: AuditLogEntry = {
      ...entry,
      id: `AUD-SIM-${Date.now().toString().slice(-5)}`,
      timestamp: new Date().toISOString(),
      actorName: user.name,
      actorRole: user.role,
      isSimulated: true,
      status: entry.status || (canAuthorize ? 'SIMULATED_SUCCESS' : 'PROPOSED'),
    };
    logs.unshift(newLog);
    this.saveAuditData(logs);
    return newLog;
  }

  async getIncidentTasksForUser(user: UserProfile): Promise<IncidentTask[]> {
    if (user.role === 'super_admin') {
      return []; // Platform Administrator cannot inspect private operational incident tasks
    }
    AuthorizationService.assertPermission(user, 'incident:read');
    const tasks = this.getTasksData();
    if (user.role === 'it_operations') {
      // IT Operations sees operational remediation tasks assigned to it_operations (Option A hardening)
      return tasks.filter((t) => t.assignedRole === 'it_operations');
    }
    if (user.role === 'security_engineer') {
      // Security Engineers see detection engineering tasks
      return tasks.filter((t) => t.assignedRole === 'security_engineer');
    }
    return tasks;
  }

  async updateTaskStatus(
    user: UserProfile,
    taskId: string,
    status: IncidentTask['status'],
    notes?: string
  ): Promise<IncidentTask> {
    AuthorizationService.assertPermission(user, 'incident:update');

    const tasks = this.getTasksData();
    const idx = tasks.findIndex((t) => t.id === taskId);
    if (idx === -1) throw new Error(`Task ${taskId} not found`);

    const wasPending = tasks[idx].status === 'pending';
    const wasCompleted = tasks[idx].status === 'completed';
    const completionTimestamp = new Date().toISOString();
    const updated: IncidentTask = {
      ...tasks[idx],
      status,
      completedAt: status === 'completed' ? (tasks[idx].completedAt || completionTimestamp) : tasks[idx].completedAt,
      completedBy: status === 'completed' ? (tasks[idx].completedBy || `${user.name} (${user.callsign || user.role})`) : tasks[idx].completedBy,
      completionNotes: notes || tasks[idx].completionNotes,
    };
    tasks[idx] = updated;
    this.saveTasksData(tasks);

    // Record remediation_started audit event when starting remediation from pending
    if (status === 'in_progress' && wasPending) {
      const logs = this.getAuditData();
      const auditEntry: AuditLogEntry = {
        id: `AUD-SIM-${Date.now().toString().slice(-5)}`,
        timestamp: new Date().toISOString(),
        actorName: user.name,
        actorRole: user.role,
        actionType: 'remediation_started',
        targetResource: updated.targetAsset || `Task ${taskId}`,
        justification: `Remediation procedure initiated by operator for task ${taskId}.`,
        status: 'SIMULATED_SUCCESS',
        associatedAlertId: updated.associatedAlertId,
        isSimulated: true,
        systemNote: `Remediation started for task ${taskId} by ${user.name} (${user.role}).`,
      };
      logs.unshift(auditEntry);
      this.saveAuditData(logs);
    }

    // Record operational remediation_verified audit event upon completion (with idempotency check to avoid duplicate logs on retry)
    if (status === 'completed' && !wasCompleted) {
      const logs = this.getAuditData();
      const alreadyLogged = logs.some(
        (l) => l.actionType === 'remediation_verified' && l.systemNote.includes(`task ${taskId}`)
      );
      if (!alreadyLogged) {
        const isSimVerification = notes?.includes('Controlled Simulation') || notes?.toLowerCase().includes('simulation verification');
        const auditEntry: AuditLogEntry = {
          id: `AUD-SIM-${Date.now().toString().slice(-5)}`,
          timestamp: updated.completedAt || completionTimestamp,
          actorName: user.name,
          actorRole: user.role,
          actionType: 'remediation_verified',
          targetResource: updated.targetAsset || `Task ${taskId}`,
          justification: notes || `Remediation verified for task ${taskId}.`,
          status: 'SIMULATED_SUCCESS',
          associatedAlertId: updated.associatedAlertId,
          isSimulated: true,
          systemNote: isSimVerification
            ? `Controlled simulation verification confirmed for task ${taskId}. Synthetic telemetry reviewed with zero live endpoint changes.`
            : `Remediation verification confirmed for task ${taskId}. Operator attestation and checklist verified.`,
        };
        logs.unshift(auditEntry);
        this.saveAuditData(logs);
      }
    }

    return updated;
  }

  async reviewRemediationTask(
    user: UserProfile,
    taskId: string,
    decision: 'approved' | 'rework_requested',
    notes: string
  ): Promise<IncidentTask> {
    if (user.role !== 'soc_analyst') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to review remediation tasks. Only SOC Analysts can review and approve remediation.`,
        'incident:update',
        user.role
      );
    }

    const tasks = this.getTasksData();
    const idx = tasks.findIndex((t) => t.id === taskId);
    if (idx === -1) throw new Error(`Task ${taskId} not found`);

    const currentTask = tasks[idx];

    // Must be in completed status to be reviewed
    if (currentTask.status !== 'completed') {
      throw new Error(`Task ${taskId} is currently "${currentTask.status}". Only completed remediation tasks can be reviewed.`);
    }

    // Verify current review state: cannot review if already approved
    const reviewState = getTaskReviewState(currentTask);
    if (reviewState.status === 'approved') {
      throw new Error(`Task ${taskId} has already been approved by a SOC Analyst. Duplicate review decisions are prevented.`);
    }

    // Validate inputs
    const trimmedNotes = (notes || '').trim();
    if (decision === 'rework_requested') {
      if (trimmedNotes.length < 10) {
        throw new Error('Mandatory rework instructions must be at least 10 characters long describing the corrective action required.');
      }
    }

    const reviewTimestamp = new Date().toISOString();
    let newStatus: IncidentTask['status'];
    let updatedNotes: string;
    let actionType: 'remediation_approved' | 'remediation_rework_requested';
    let justification: string;

    if (decision === 'approved') {
      newStatus = 'completed'; // Keep task status as completed
      updatedNotes = formatApprovalNotes(currentTask.completionNotes, user, trimmedNotes);
      actionType = 'remediation_approved';
      justification = trimmedNotes || 'Remediation verification and technical evidence validated and approved by SOC Analyst.';
    } else {
      newStatus = 'in_progress'; // Change task status from completed to in_progress
      updatedNotes = formatReworkNotes(currentTask.completionNotes, user, trimmedNotes);
      actionType = 'remediation_rework_requested';
      justification = trimmedNotes;
    }

    const updatedTask: IncidentTask = {
      ...currentTask,
      status: newStatus,
      completionNotes: updatedNotes,
    };

    tasks[idx] = updatedTask;
    this.saveTasksData(tasks);

    // Record immutable operational audit event
    const logs = this.getAuditData();
    const auditEntry: AuditLogEntry = {
      id: `AUD-SIM-${Date.now().toString().slice(-5)}`,
      timestamp: reviewTimestamp,
      actorName: user.name,
      actorRole: user.role,
      actionType,
      targetResource: currentTask.targetAsset || `Task ${taskId}`,
      justification,
      status: 'SIMULATED_SUCCESS',
      associatedAlertId: currentTask.associatedAlertId,
      isSimulated: true,
      systemNote: `SOC Analyst remediation review decision (${decision.toUpperCase()}) recorded for task ${taskId}. Reviewer: ${user.name} (${user.callsign || user.role}).`,
    };
    logs.unshift(auditEntry);
    this.saveAuditData(logs);

    return updatedTask;
  }

  private static taskCounter = 0;

  private generateUniqueTaskId(existingTasks: IncidentTask[]): string {
    const existingIds = new Set(existingTasks.map((t) => t.id));

    // Determine highest sequential number among existing TSK-2026-(digits) tasks
    let maxSeq = 3; // Seed tasks occupy 001, 002, 003
    for (const t of existingTasks) {
      const match = t.id.match(/^TSK-2026-(\d+)$/);
      if (match) {
        const val = parseInt(match[1], 10);
        if (!isNaN(val) && val > maxSeq) {
          maxSeq = val;
        }
      }
    }

    let next = Math.max(maxSeq + 1, ++LocalAuditLogRepository.taskCounter);
    let candidate = `TSK-2026-${String(next).padStart(3, '0')}`;
    while (existingIds.has(candidate)) {
      next++;
      candidate = `TSK-2026-${String(next).padStart(3, '0')}`;
    }
    LocalAuditLogRepository.taskCounter = next;
    return candidate;
  }

  async createTask(user: UserProfile, task: Omit<IncidentTask, 'id' | 'createdAt'>): Promise<IncidentTask> {
    if (user.role !== 'soc_analyst') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to create incident response tasks. Only SOC Analysts can create tasks.`,
        'alert:escalate',
        user.role
      );
    }

    if (!task.title?.trim()) {
      throw new Error('Task title is required.');
    }
    if (!task.description?.trim()) {
      throw new Error('Task description and remediation instructions are required.');
    }
    if (!task.targetAsset?.trim()) {
      throw new Error('Target asset is required.');
    }
    if (!task.associatedAlertId?.trim()) {
      throw new Error('Associated alert ID is required.');
    }

    const tasks = this.getTasksData();
    const newTask: IncidentTask = {
      ...task,
      title: task.title.trim(),
      description: task.description.trim(),
      targetAsset: task.targetAsset.trim(),
      associatedAlertId: task.associatedAlertId.trim(),
      id: this.generateUniqueTaskId(tasks),
      createdAt: new Date().toISOString(),
    };
    tasks.unshift(newTask);
    this.saveTasksData(tasks);

    // Record immutable operational audit event for task creation
    const logs = this.getAuditData();
    const auditEntry: AuditLogEntry = {
      id: `AUD-SIM-${Date.now().toString().slice(-5)}`,
      timestamp: newTask.createdAt,
      actorName: user.name,
      actorRole: user.role,
      actionType: 'task_created',
      targetResource: newTask.targetAsset,
      justification: newTask.description,
      status: 'SIMULATED_SUCCESS',
      associatedAlertId: newTask.associatedAlertId,
      isSimulated: true,
      systemNote: `Incident response task ${newTask.id} ("${newTask.title}") created by ${user.name} and assigned to ${newTask.assignedRole}.`,
    };
    logs.unshift(auditEntry);
    this.saveAuditData(logs);

    return newTask;
  }

  async recordGovernanceAction(
    admin: UserProfile,
    action: {
      actionType: 'unlock_account' | 'lock_account';
      targetEmail: string;
      justification: string;
      systemNote?: string;
      expectedAuditId?: string;
    }
  ): Promise<AuditLogEntry> {
    if (admin.role !== 'super_admin') {
      throw new AccessDeniedError(
        'Access Denied: Only Platform Administrators may record governance actions.',
        'platform:admin',
        admin.role
      );
    }

    const logs = this.getAuditData();
    const newLog: AuditLogEntry = {
      id: action.expectedAuditId || `AUD-GOV-${Date.now().toString().slice(-5)}`,
      timestamp: new Date().toISOString(),
      actorName: admin.name,
      actorRole: admin.role,
      actionType: action.actionType,
      targetResource: action.targetEmail,
      justification: action.justification,
      status: 'SUCCESS',
      isSimulated: false,
      systemNote: action.systemNote || `Governance action for ${action.targetEmail}`,
    };
    logs.unshift(newLog);
    this.saveAuditData(logs);
    return newLog;
  }
}

