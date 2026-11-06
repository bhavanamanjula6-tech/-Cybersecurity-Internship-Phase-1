/**
 * Audit Log Data Contract
 * Records simulated containment & remediation actions with user role and rationale.
 */

import { UserRole } from './auth';

export type ResponseActionType =
  | 'isolate_host'
  | 'unisolate_host'
  | 'block_ip'
  | 'unblock_ip'
  | 'lock_account'
  | 'unlock_account'
  | 'revoke_token'
  | 'collect_forensics'
  | 'platform_bootstrap'
  | 'task_created'
  | 'remediation_started'
  | 'remediation_verified'
  | 'remediation_approved'
  | 'remediation_rework_requested'
  | 'alert_resolved'
  | 'recommendation_created'
  | 'recommendation_accepted'
  | 'recommendation_rejected'
  | 'recommendation_clarification_requested'
  | 'recommendation_implementation_started'
  | 'recommendation_implemented'
  | 'recommendation_validated';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actorName: string;
  actorRole: UserRole | 'system';
  actionType: ResponseActionType;
  targetResource: string;
  justification: string;
  status: 'SIMULATED_SUCCESS' | 'SIMULATED_FAILED' | 'PROPOSED' | 'SUCCESS' | 'FAILED';
  associatedAlertId?: string;
  isSimulated: boolean; // Explicit flag confirming whether execution is simulated or live
  systemNote: string;
}

export interface IncidentTask {
  id: string;
  title: string;
  description: string;
  assignedRole: UserRole;
  status: 'pending' | 'in_progress' | 'completed' | 'blocked';
  priority: 'critical' | 'high' | 'medium' | 'low';
  createdAt: string;
  targetAsset: string;
  suggestedActionType?: ResponseActionType;
  associatedAlertId?: string;
  completedAt?: string;
  completedBy?: string;
  completionNotes?: string;
}
