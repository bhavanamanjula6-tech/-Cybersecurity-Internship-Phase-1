/**
 * Audit Log Repository Interface
 * Defines role-aware, tamper-evident audit logging and remediation task management.
 */

import { AuditLogEntry, IncidentTask } from '../types/audit';
import { UserProfile } from '../types/auth';

export interface IAuditLogRepository {
  /**
   * Retrieves audit logs visible to the requesting user role.
   */
  getLogsForUser(user: UserProfile): Promise<AuditLogEntry[]>;

  /**
   * Records a simulated action. Asserts user authorization.
   */
  recordSimulatedAction(
    user: UserProfile,
    entry: Omit<AuditLogEntry, 'id' | 'timestamp' | 'isSimulated' | 'actorName' | 'actorRole'>
  ): Promise<AuditLogEntry>;

  /**
   * Retrieves incident tasks scoped to role.
   */
  getIncidentTasksForUser(user: UserProfile): Promise<IncidentTask[]>;

  /**
   * Updates task status. Asserts 'incident:update' permission.
   */
  updateTaskStatus(
    user: UserProfile,
    taskId: string,
    status: IncidentTask['status'],
    notes?: string
  ): Promise<IncidentTask>;

  /**
   * Creates a remediation task. Asserts authorization.
   */
  createTask(user: UserProfile, task: Omit<IncidentTask, 'id' | 'createdAt'>): Promise<IncidentTask>;

  /**
   * Reviews an IT Operations remediation task (Approve or Request Rework).
   * Restricted strictly to SOC Analysts.
   */
  reviewRemediationTask(
    user: UserProfile,
    taskId: string,
    decision: 'approved' | 'rework_requested',
    notes: string
  ): Promise<IncidentTask>;

  /**
   * Records and confirms a platform governance audit log.
   */
  recordGovernanceAction(
    admin: UserProfile,
    action: {
      actionType: 'unlock_account' | 'lock_account';
      targetEmail: string;
      justification: string;
      systemNote?: string;
      expectedAuditId?: string;
    }
  ): Promise<AuditLogEntry>;
}
