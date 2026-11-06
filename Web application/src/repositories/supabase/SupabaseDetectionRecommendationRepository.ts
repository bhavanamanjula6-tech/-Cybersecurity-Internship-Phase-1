/**
 * Supabase PostgreSQL Adapter for Detection Improvement Recommendations
 * Enforces:
 * 1. PostgreSQL RLS policies on public.detection_improvement_recommendations.
 * 2. Database trigger-driven audit events in public.audit_logs (no client-side duplication).
 * 3. Super Admin and IT Operations complete operational isolation.
 * 4. Strict status transition invariants and role boundaries.
 * 5. Explicit error when migration 20261104000000_detection_improvement_recommendations.sql is missing.
 */

import { IDetectionRecommendationRepository } from '../IDetectionRecommendationRepository';
import {
  DetectionRecommendation,
  CreateRecommendationInput,
  RecommendationStatus,
  RecommendationPriority,
} from '../../types/recommendation';
import { UserProfile, AccessDeniedError } from '../../types/auth';
import { AuthorizationService } from '../../services/authorizationService';
import { getSupabaseClient } from '../../lib/supabaseClient';

const MIGRATION_REQUIRED_MESSAGE =
  '[Supabase Schema Error] Table "public.detection_improvement_recommendations" was not found in the Supabase schema cache. ' +
  'The required database migration "supabase/migrations/20261104000000_detection_improvement_recommendations.sql" ' +
  'must be applied to your connected Supabase project to enable Detection Improvement Recommendations.';

function isMissingTableError(err: any): boolean {
  return (
    err?.code === 'PGRST205' ||
    err?.code === '42P01' ||
    err?.message?.includes('schema cache') ||
    err?.message?.includes('does not exist')
  );
}

function handleDatabaseError(context: string, error: any): never {
  if (isMissingTableError(error)) {
    throw new Error(MIGRATION_REQUIRED_MESSAGE);
  }
  throw new Error(`[SupabaseDetectionRecommendationRepository] ${context} failed: ${error?.message || error}`);
}

function mapRowToRecommendation(row: any): DetectionRecommendation {
  return {
    id: row.id,
    title: row.title,
    techniqueId: row.technique_id,
    techniqueName: row.technique_name,
    tacticId: row.tactic_id,
    tacticName: row.tactic_name,
    priority: row.priority as RecommendationPriority,
    detectionGap: row.detection_gap,
    technicalExplanation: row.technical_explanation,
    proposedImprovement: row.proposed_improvement,
    supportingEvidence: row.supporting_evidence || '',
    relatedRuleDraftId: row.related_rule_draft_id || undefined,
    status: row.status as RecommendationStatus,
    createdBy: row.created_by,
    createdByRole: row.created_by_role,
    createdByName: row.created_by_name,
    reviewedBy: row.reviewed_by || undefined,
    reviewedByName: row.reviewed_by_name || undefined,
    socFeedback: row.soc_feedback || undefined,
    implementationNotes: row.implementation_notes || undefined,
    sigmaDraftReference: row.sigma_draft_reference || undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class SupabaseDetectionRecommendationRepository implements IDetectionRecommendationRepository {
  async getRecommendationsForUser(user: UserProfile): Promise<DetectionRecommendation[]> {
    if (!user || !user.role) {
      throw new AccessDeniedError('Unauthenticated access to recommendations', 'recommendation:read', 'unknown' as any);
    }

    if (user.role === 'super_admin' || user.role === 'it_operations') {
      return [];
    }

    AuthorizationService.assertPermission(user, 'recommendation:read');

    const client = getSupabaseClient();
    const { data, error } = await client
      .from('detection_improvement_recommendations')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      handleDatabaseError('Query', error);
    }

    return (data || []).map(mapRowToRecommendation);
  }

  async createRecommendation(
    user: UserProfile,
    input: CreateRecommendationInput
  ): Promise<DetectionRecommendation> {
    if (user.role !== 'security_engineer') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to create detection improvement recommendations.`,
        'recommendation:create',
        user.role
      );
    }
    AuthorizationService.assertPermission(user, 'recommendation:create');

    if (
      !input.title?.trim() ||
      !input.techniqueId?.trim() ||
      !input.detectionGap?.trim() ||
      !input.technicalExplanation?.trim() ||
      !input.proposedImprovement?.trim()
    ) {
      throw new Error('All required fields must be non-empty.');
    }

    const client = getSupabaseClient();
    const dbPayload = {
      title: input.title.trim(),
      technique_id: input.techniqueId.trim(),
      technique_name: input.techniqueName.trim(),
      tactic_id: input.tacticId?.trim() || 'TA0002',
      tactic_name: input.tacticName?.trim() || 'Enterprise ATT&CK',
      priority: input.priority || 'medium',
      detection_gap: input.detectionGap.trim(),
      technical_explanation: input.technicalExplanation.trim(),
      proposed_improvement: input.proposedImprovement.trim(),
      supporting_evidence: input.supportingEvidence?.trim() || '',
      related_rule_draft_id: input.relatedRuleDraftId?.trim() || null,
      status: 'proposed',
      created_by: user.id,
      created_by_role: 'security_engineer',
      created_by_name: user.name,
    };

    const { data, error } = await client
      .from('detection_improvement_recommendations')
      .insert(dbPayload)
      .select('*')
      .single();

    if (error) {
      handleDatabaseError('Insert', error);
    }

    if (!data) {
      throw new Error('[SupabaseDetectionRecommendationRepository] Insert returned no data.');
    }

    return mapRowToRecommendation(data);
  }

  async reviewRecommendation(
    user: UserProfile,
    recommendationId: string,
    action: 'accept' | 'reject' | 'request_clarification',
    feedback?: string
  ): Promise<DetectionRecommendation> {
    if (user.role !== 'soc_analyst') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to review detection recommendations.`,
        'recommendation:review',
        user.role
      );
    }
    AuthorizationService.assertPermission(user, 'recommendation:review');

    const trimmed = feedback?.trim() || '';
    if ((action === 'reject' || action === 'request_clarification') && trimmed.length < 10) {
      throw new Error(`Mandatory feedback of at least 10 characters is required to ${action.replace('_', ' ')}.`);
    }

    let targetStatus: RecommendationStatus = 'accepted';
    if (action === 'reject') {
      targetStatus = 'rejected';
    } else if (action === 'request_clarification') {
      targetStatus = 'clarification_requested';
    }

    const client = getSupabaseClient();
    const { data, error } = await client
      .from('detection_improvement_recommendations')
      .update({
        status: targetStatus,
        soc_feedback: trimmed || null,
        reviewed_by: user.id,
        reviewed_by_name: user.name,
      })
      .eq('id', recommendationId)
      .select('*')
      .single();

    if (error) {
      handleDatabaseError('Review', error);
    }

    if (!data) {
      throw new Error('[SupabaseDetectionRecommendationRepository] Review returned no data.');
    }

    return mapRowToRecommendation(data);
  }

  async updateImplementation(
    user: UserProfile,
    recommendationId: string,
    status: 'in_progress' | 'completed',
    notes?: string,
    sigmaDraftReference?: string
  ): Promise<DetectionRecommendation> {
    if (user.role !== 'security_engineer') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to update recommendation implementation.`,
        'recommendation:update',
        user.role
      );
    }
    AuthorizationService.assertPermission(user, 'recommendation:update');

    const trimmedNotes = notes?.trim() || '';
    if (status === 'completed' && trimmedNotes.length < 10) {
      throw new Error('Implementation notes of at least 10 characters are required to complete implementation.');
    }

    const client = getSupabaseClient();
    const updatePayload: any = {
      status,
      implementation_notes: trimmedNotes || null,
    };
    if (sigmaDraftReference?.trim()) {
      updatePayload.sigma_draft_reference = sigmaDraftReference.trim();
    }

    const { data, error } = await client
      .from('detection_improvement_recommendations')
      .update(updatePayload)
      .eq('id', recommendationId)
      .select('*')
      .single();

    if (error) {
      handleDatabaseError('Implementation update', error);
    }

    if (!data) {
      throw new Error('[SupabaseDetectionRecommendationRepository] Implementation update returned no data.');
    }

    return mapRowToRecommendation(data);
  }

  async validateRecommendation(
    user: UserProfile,
    recommendationId: string,
    validationFeedback?: string
  ): Promise<DetectionRecommendation> {
    if (user.role !== 'soc_analyst') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to validate detection improvements.`,
        'recommendation:validate',
        user.role
      );
    }
    AuthorizationService.assertPermission(user, 'recommendation:validate');

    const client = getSupabaseClient();

    // Query current status to ensure completed invariant
    const { data: current, error: queryErr } = await client
      .from('detection_improvement_recommendations')
      .select('*')
      .eq('id', recommendationId)
      .single();

    if (queryErr) {
      handleDatabaseError('Validation lookup', queryErr);
    }

    if (!current) {
      throw new Error(`Recommendation "${recommendationId}" not found.`);
    }

    if (current.status !== 'completed') {
      throw new Error(
        `Cannot validate recommendation in status "${current.status}". Detection improvement must be "completed" before validation.`
      );
    }

    const feedbackText = validationFeedback?.trim();
    const updatedFeedback = feedbackText
      ? `${current.soc_feedback ? `${current.soc_feedback}\n\n` : ''}[VALIDATION CONFIRMED by ${user.name} at ${new Date().toISOString()}]: ${feedbackText}`
      : current.soc_feedback;

    const { data: updatedData, error: updateErr } = await client
      .from('detection_improvement_recommendations')
      .update({
        status: 'validated',
        reviewed_by: user.id,
        reviewed_by_name: user.name,
        soc_feedback: updatedFeedback,
      })
      .eq('id', recommendationId)
      .select('*')
      .single();

    if (updateErr) {
      handleDatabaseError('Validation update', updateErr);
    }

    if (!updatedData) {
      throw new Error('[SupabaseDetectionRecommendationRepository] Validation update returned no data.');
    }

    return mapRowToRecommendation(updatedData);
  }
}
