/**
 * Supabase PostgreSQL Adapter for Audit Logs & Incident Tasks
 *
 * Enforces:
 * 1. PostgreSQL RLS policies on public.audit_logs and public.incident_tasks.
 * 2. Immutable WORM audit logs (preventing client update or delete).
 * 3. Segregation of platform vs. operational audit logs.
 * 4. Task role isolation (IT Operations sees it_operations tasks, Security Engineers see security_engineer tasks).
 * 5. Super Admin operational isolation (Super Admins receive empty task lists and cannot inspect remediation tasks).
 */

import { IAuditLogRepository } from '../IAuditLogRepository';
import { AuditLogEntry, IncidentTask, ResponseActionType } from '../../types/audit';
import { UserProfile, UserRole, AccessDeniedError } from '../../types/auth';
import { AuthorizationService } from '../../services/authorizationService';
import { getSupabaseClient } from '../../lib/supabaseClient';
import { formatApprovalNotes, formatReworkNotes, getTaskReviewState } from '../../utils/remediationReview';

function mapRowToAuditLogEntry(row: any): AuditLogEntry {
  return {
    id: row.id,
    timestamp: row.timestamp,
    actorName: row.actor_name,
    actorRole: (row.actor_role as UserRole | 'system') || 'system',
    actionType: row.action_type as ResponseActionType,
    targetResource: row.target_resource,
    justification: row.justification || '',
    status: row.status as AuditLogEntry['status'],
    associatedAlertId: row.associated_alert_id || undefined,
    isSimulated: Boolean(row.is_simulated ?? true),
    systemNote: row.system_note || '',
  };
}

function mapRowToIncidentTask(row: any): IncidentTask {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    assignedRole: row.assigned_role as UserRole,
    status: row.status as IncidentTask['status'],
    priority: row.priority as IncidentTask['priority'],
    createdAt: row.created_at,
    targetAsset: row.target_asset,
    suggestedActionType: (row.suggested_action_type as ResponseActionType) || undefined,
    associatedAlertId: row.associated_alert_id || undefined,
    completedAt: row.completed_at || undefined,
    completedBy: row.completed_by || undefined,
    completionNotes: row.completion_notes || undefined,
  };
}

export class SupabaseAuditLogRepository implements IAuditLogRepository {
  /**
   * Retrieves audit logs visible to requesting user role.
   * Super Admins receive platform audit logs; operational roles receive operational logs.
   */
  async getLogsForUser(user: UserProfile): Promise<AuditLogEntry[]> {
    AuthorizationService.assertPermission(user, 'audit:read');

    const client = getSupabaseClient();
    let query = client.from('audit_logs').select('*').order('timestamp', { ascending: false });

    if (user.role === 'super_admin') {
      query = query.eq('audit_category', 'platform');
    } else {
      query = query.eq('audit_category', 'operational');
    }

    const { data, error } = await query;
    if (error) {
      throw new Error(`[SupabaseAuditLogRepository] Query failed: ${error.message}`);
    }

    return (data || []).map(mapRowToAuditLogEntry);
  }

  /**
   * Records a simulated response action with tamper-evident audit trail.
   */
  async recordSimulatedAction(
    user: UserProfile,
    entry: Omit<AuditLogEntry, 'id' | 'timestamp' | 'isSimulated' | 'actorName' | 'actorRole'>
  ): Promise<AuditLogEntry> {
    const isRecommendationAction = entry.actionType.startsWith('recommendation_');
    const isAuthorizedRecommendationRole = user.role === 'security_engineer' || user.role === 'soc_analyst';

    const canAuthorize = AuthorizationService.canAuthorizeSimulatedActions(user.role);
    const canPropose = AuthorizationService.canProposeActions(user.role);

    if (!canAuthorize && !canPropose && !(isRecommendationAction && isAuthorizedRecommendationRole)) {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to execute or propose response actions.`,
        'action:authorize_simulated',
        user.role
      );
    }

    const client = getSupabaseClient();
    const status = canAuthorize ? 'SIMULATED_SUCCESS' : 'PROPOSED';
    const payload = {
      audit_category: 'operational',
      actor_id: user.id.startsWith('usr-') ? null : user.id,
      actor_name: user.name,
      actor_role: user.role,
      action_type: entry.actionType,
      target_resource: entry.targetResource,
      justification: entry.justification,
      status,
      associated_alert_id: entry.associatedAlertId || null,
      is_simulated: true,
      system_note: entry.systemNote || `Simulated action for ${entry.targetResource}`,
    };

    const { data, error } = await client
      .from('audit_logs')
      .insert(payload)
      .select('*')
      .single();

    if (error) {
      throw new Error(`[SupabaseAuditLogRepository] Failed to insert audit log: ${error.message}`);
    }

    return mapRowToAuditLogEntry(data);
  }

  /**
   * Retrieves incident tasks scoped to role.
   * Super Admins receive empty list to enforce domain isolation.
   */
  async getIncidentTasksForUser(user: UserProfile): Promise<IncidentTask[]> {
    if (user.role === 'super_admin') {
      return []; // Platform Administrator cannot inspect operational tasks
    }

    AuthorizationService.assertPermission(user, 'incident:read');

    const client = getSupabaseClient();
    let query = client.from('incident_tasks').select('*').order('created_at', { ascending: false });

    if (user.role === 'it_operations') {
      query = query.eq('assigned_role', 'it_operations');
    } else if (user.role === 'security_engineer') {
      query = query.eq('assigned_role', 'security_engineer');
    }

    const { data, error } = await query;
    if (error) {
      throw new Error(`[SupabaseAuditLogRepository] Failed to fetch incident tasks: ${error.message}`);
    }

    return (data || []).map(mapRowToIncidentTask);
  }

  /**
   * Updates task status and completion metadata.
   */
  async updateTaskStatus(
    user: UserProfile,
    taskId: string,
    status: IncidentTask['status'],
    notes?: string
  ): Promise<IncidentTask> {
    AuthorizationService.assertPermission(user, 'incident:update');

    const client = getSupabaseClient();
    const updatePayload: Record<string, any> = {
      status,
      updated_at: new Date().toISOString(),
    };

    if (status === 'completed') {
      updatePayload.completed_at = new Date().toISOString();
      updatePayload.completed_by = user.id.startsWith('usr-') ? null : user.id;
    }

    if (notes) {
      updatePayload.completion_notes = notes;
    }

    const { data, error } = await client
      .from('incident_tasks')
      .update(updatePayload)
      .eq('id', taskId)
      .select('*')
      .single();

    if (error) {
      throw new Error(`[SupabaseAuditLogRepository] Failed to update task ${taskId}: ${error.message}`);
    }

    if (status === 'in_progress') {
      try {
        const { data: existingStarted } = await client
          .from('audit_logs')
          .select('id')
          .eq('action_type', 'remediation_started')
          .like('system_note', `%task ${taskId}%`)
          .limit(1);

        if (!existingStarted || existingStarted.length === 0) {
          const auditPayload = {
            audit_category: 'operational',
            actor_id: user.id.startsWith('usr-') ? null : user.id,
            actor_name: user.name,
            actor_role: user.role,
            action_type: 'remediation_started',
            target_resource: data.target_asset || `Task ${taskId}`,
            justification: `Remediation procedure initiated by operator for task ${taskId}.`,
            status: 'SIMULATED_SUCCESS',
            associated_alert_id: data.associated_alert_id || null,
            is_simulated: true,
            system_note: `Remediation started for task ${taskId} by ${user.name} (${user.role}).`,
          };
          await client.from('audit_logs').insert(auditPayload);
        }
      } catch (startErr) {
        console.warn('[SupabaseAuditLogRepository] Non-fatal: failed to record remediation_started audit log:', startErr);
      }
    }

    if (status === 'completed') {
      try {
        // Check for existing audit log for this task to avoid duplicates on retry
        const { data: existingAudits } = await client
          .from('audit_logs')
          .select('id')
          .eq('action_type', 'remediation_verified')
          .like('system_note', `%task ${taskId}%`)
          .limit(1);

        if (!existingAudits || existingAudits.length === 0) {
          const isSimVerification = notes?.includes('Controlled Simulation') || notes?.toLowerCase().includes('simulation verification');
          const auditPayload = {
            audit_category: 'operational',
            actor_id: user.id.startsWith('usr-') ? null : user.id,
            actor_name: user.name,
            actor_role: user.role,
            action_type: 'remediation_verified',
            target_resource: data.target_asset || `Task ${taskId}`,
            justification: notes || `Remediation verification completed for task ${taskId}.`,
            status: 'SIMULATED_SUCCESS',
            associated_alert_id: data.associated_alert_id || null,
            is_simulated: true,
            system_note: isSimVerification
              ? `Controlled simulation verification confirmed for task ${taskId}. Synthetic telemetry reviewed with zero live endpoint changes.`
              : `Remediation verification confirmed for task ${taskId}. Operator attestation and checklist verified.`,
          };

          const { error: auditError } = await client
            .from('audit_logs')
            .insert(auditPayload);

          if (auditError) {
            console.error('[SupabaseAuditLogRepository] Failed to record verification audit log:', auditError);
            throw new Error(`[SupabaseAuditLogRepository] Task updated but audit log recording failed: ${auditError.message}`);
          }
        }
      } catch (err: any) {
        // Preserve error to prevent false success reporting in UI
        if (err.message?.includes('[SupabaseAuditLogRepository] Task updated but audit log recording failed')) {
          throw err;
        }
        console.error('[SupabaseAuditLogRepository] Unexpected error recording verification audit log:', err);
        throw new Error(`[SupabaseAuditLogRepository] Task verification audit logging failed: ${err.message || err}`);
      }
    }

    return mapRowToIncidentTask(data);
  }

  /**
   * Reviews an IT Operations remediation task (Approve or Request Rework).
   * Restricted strictly to SOC Analysts.
   */
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

    const client = getSupabaseClient();
    const { data: currentTaskData, error: fetchErr } = await client
      .from('incident_tasks')
      .select('*')
      .eq('id', taskId)
      .single();

    if (fetchErr || !currentTaskData) {
      throw new Error(`[SupabaseAuditLogRepository] Task ${taskId} not found: ${fetchErr?.message || 'Unknown error'}`);
    }

    const currentTask = mapRowToIncidentTask(currentTaskData);

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

    const { data: updatedData, error: updateErr } = await client
      .from('incident_tasks')
      .update({
        status: newStatus,
        completion_notes: updatedNotes,
      })
      .eq('id', taskId)
      .select('*')
      .single();

    if (updateErr || !updatedData) {
      throw new Error(`[SupabaseAuditLogRepository] Failed to review task ${taskId}: ${updateErr?.message}`);
    }

    // Insert operational audit log
    const auditPayload = {
      audit_category: 'operational',
      actor_id: user.id.startsWith('usr-') ? null : user.id,
      actor_name: user.name,
      actor_role: user.role,
      action_type: actionType,
      target_resource: currentTask.targetAsset || `Task ${taskId}`,
      justification,
      status: 'SIMULATED_SUCCESS',
      associated_alert_id: currentTask.associatedAlertId || null,
      is_simulated: true,
      system_note: `SOC Analyst remediation review decision (${decision.toUpperCase()}) recorded for task ${taskId}. Reviewer: ${user.name} (${user.callsign || user.role}).`,
    };

    const { error: auditError } = await client.from('audit_logs').insert(auditPayload);
    if (auditError) {
      console.error('[SupabaseAuditLogRepository] Failed to record review audit log:', auditError);
      throw new Error(`[SupabaseAuditLogRepository] Task reviewed but audit log recording failed: ${auditError.message}`);
    }

    return mapRowToIncidentTask(updatedData);
  }

  /**
   * Creates a remediation task with a unique task sequence ID.
   */
  async createTask(
    user: UserProfile,
    task: Omit<IncidentTask, 'id' | 'createdAt'>
  ): Promise<IncidentTask> {
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

    const client = getSupabaseClient();

    // Query recent tasks to calculate next sequential candidate ID
    const { data: recentTasks } = await client
      .from('incident_tasks')
      .select('id')
      .order('created_at', { ascending: false })
      .limit(50);

    const existingIds = new Set((recentTasks || []).map((t: any) => t.id));
    let maxSeq = 3;
    for (const t of recentTasks || []) {
      const match = t.id.match(/^TSK-2026-(\d+)$/);
      if (match) {
        const val = parseInt(match[1], 10);
        if (!isNaN(val) && val > maxSeq) {
          maxSeq = val;
        }
      }
    }

    let next = maxSeq + 1;
    let candidate = `TSK-2026-${String(next).padStart(3, '0')}`;
    while (existingIds.has(candidate)) {
      next++;
      candidate = `TSK-2026-${String(next).padStart(3, '0')}`;
    }

    const dbPayload = {
      id: candidate,
      title: task.title,
      description: task.description,
      assigned_role: task.assignedRole,
      status: task.status,
      priority: task.priority,
      target_asset: task.targetAsset,
      suggested_action_type: task.suggestedActionType || null,
      associated_alert_id: task.associatedAlertId || null,
    };

    const { data, error } = await client
      .from('incident_tasks')
      .insert(dbPayload)
      .select('*')
      .single();

    if (error) {
      throw new Error(`[SupabaseAuditLogRepository] Failed to create incident task: ${error.message}`);
    }

    // Insert operational audit log for task creation
    try {
      const auditPayload = {
        audit_category: 'operational',
        actor_id: user.id.startsWith('usr-') ? null : user.id,
        actor_name: user.name,
        actor_role: user.role,
        action_type: 'task_created',
        target_resource: data.target_asset || `Task ${candidate}`,
        justification: task.description,
        status: 'SIMULATED_SUCCESS',
        associated_alert_id: data.associated_alert_id || null,
        is_simulated: true,
        system_note: `Incident response task ${candidate} created by ${user.name} and assigned to ${task.assignedRole}.`,
      };
      await client.from('audit_logs').insert(auditPayload);
    } catch (auditErr) {
      console.warn('[SupabaseAuditLogRepository] Non-fatal: failed to record task_created audit log:', auditErr);
    }

    return mapRowToIncidentTask(data);
  }

  /**
   * Platform governance audit handler for Super Admin operations.
   * Matches exact audit event produced by database trigger; does not synthesize fake records.
   */
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

    const client = getSupabaseClient();

    let query = client
      .from('audit_logs')
      .select('*')
      .eq('target_resource', action.targetEmail)
      .eq('audit_category', 'platform')
      .eq('action_type', action.actionType)
      .eq('actor_id', admin.id);

    if (action.expectedAuditId) {
      query = query.eq('id', action.expectedAuditId);
    }

    query = query.order('timestamp', { ascending: false }).limit(1);

    let { data, error } = await query.maybeSingle();

    // If not immediately found, wait 200ms and retry once to accommodate trigger commit/replication
    if (!data && !error) {
      await new Promise((resolve) => setTimeout(resolve, 200));
      const retry = await query.maybeSingle();
      data = retry.data;
      error = retry.error;
    }

    if (error) {
      throw new Error(`[SupabaseAuditLogRepository] Failed to query database governance audit record: ${error.message}`);
    }

    if (!data) {
      throw new Error(
        `Audit Verification Failed: Persistent database audit record ${action.expectedAuditId ? `(${action.expectedAuditId}) ` : ''}could not be confirmed for ${action.actionType} on ${action.targetEmail}.`
      );
    }

    return mapRowToAuditLogEntry(data);
  }
}
