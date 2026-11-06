/**
 * Local Browser Storage Adapter for Detection Improvement Recommendations
 * Enforces:
 * 1. Role-based capabilities (Security Engineer creation/implementation, SOC Analyst review/validation).
 * 2. Immutable WORM audit events in public.audit_logs via IAuditLogRepository.
 * 3. Super Admin and IT Operations complete isolation (returns empty array).
 * 4. Strict status transition invariants and mandatory feedback rules.
 * 5. Zero synthetic or fake records injected.
 */

import { IDetectionRecommendationRepository } from '../IDetectionRecommendationRepository';
import {
  DetectionRecommendation,
  CreateRecommendationInput,
  RecommendationStatus,
} from '../../types/recommendation';
import { UserProfile, AccessDeniedError } from '../../types/auth';
import { AuthorizationService } from '../../services/authorizationService';
import { IAuditLogRepository } from '../IAuditLogRepository';
import { LocalAuditLogRepository } from './LocalAuditLogRepository';

const RECOMMENDATIONS_STORAGE_KEY = 'ai_soc_detection_recommendations_v1';

export class LocalDetectionRecommendationRepository implements IDetectionRecommendationRepository {
  private memoryRecs: DetectionRecommendation[] | null = null;
  private auditRepo: IAuditLogRepository;

  constructor(auditRepo?: IAuditLogRepository) {
    this.auditRepo = auditRepo || new LocalAuditLogRepository();
  }

  private getData(): DetectionRecommendation[] {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const stored = window.localStorage.getItem(RECOMMENDATIONS_STORAGE_KEY);
        if (stored) return JSON.parse(stored);
      } catch {
        // Fallback
      }
    }
    if (this.memoryRecs) return this.memoryRecs;
    this.memoryRecs = [];
    return this.memoryRecs;
  }

  private saveData(data: DetectionRecommendation[]): void {
    this.memoryRecs = data;
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.setItem(RECOMMENDATIONS_STORAGE_KEY, JSON.stringify(data));
      } catch {
        // Fallback
      }
    }
  }

  async getRecommendationsForUser(user: UserProfile): Promise<DetectionRecommendation[]> {
    if (!user || !user.role) {
      throw new AccessDeniedError('Unauthenticated access to recommendations', 'recommendation:read', 'unknown' as any);
    }

    // Super Admin and IT Operations have zero operational recommendation access
    if (user.role === 'super_admin' || user.role === 'it_operations') {
      return [];
    }

    AuthorizationService.assertPermission(user, 'recommendation:read');
    return this.getData();
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

    // Field validation
    if (!input.title?.trim()) {
      throw new Error('Recommendation title is required.');
    }
    if (!input.techniqueId?.trim()) {
      throw new Error('MITRE technique ID is required.');
    }
    if (!input.techniqueName?.trim()) {
      throw new Error('MITRE technique name is required.');
    }
    if (!input.detectionGap?.trim()) {
      throw new Error('Detection gap explanation is required.');
    }
    if (!input.technicalExplanation?.trim()) {
      throw new Error('Technical explanation is required.');
    }
    if (!input.proposedImprovement?.trim()) {
      throw new Error('Proposed improvement is required.');
    }

    const items = this.getData();

    // Prevent duplicate active proposals for the exact same technique and title
    const isDuplicate = items.some(
      (r) =>
        r.techniqueId.toLowerCase() === input.techniqueId.toLowerCase() &&
        r.title.toLowerCase().trim() === input.title.toLowerCase().trim() &&
        r.status !== 'rejected'
    );
    if (isDuplicate) {
      throw new Error(
        `A detection recommendation for technique ${input.techniqueId} with title "${input.title}" already exists.`
      );
    }

    const now = new Date().toISOString();
    const id = `REC-${Date.now().toString().slice(-6)}`;

    const newRec: DetectionRecommendation = {
      id,
      title: input.title.trim(),
      techniqueId: input.techniqueId.trim(),
      techniqueName: input.techniqueName.trim(),
      tacticId: input.tacticId?.trim() || 'TA0002',
      tacticName: input.tacticName?.trim() || 'Enterprise ATT&CK',
      priority: input.priority || 'medium',
      detectionGap: input.detectionGap.trim(),
      technicalExplanation: input.technicalExplanation.trim(),
      proposedImprovement: input.proposedImprovement.trim(),
      supportingEvidence: input.supportingEvidence?.trim() || '',
      relatedRuleDraftId: input.relatedRuleDraftId?.trim() || undefined,
      status: 'proposed',
      createdBy: user.id,
      createdByRole: 'security_engineer',
      createdByName: user.name,
      createdAt: now,
      updatedAt: now,
    };

    items.unshift(newRec);
    this.saveData(items);

    // Record immutable audit event
    await this.auditRepo.recordSimulatedAction(user, {
      actionType: 'recommendation_created',
      targetResource: `Recommendation ${newRec.id} (${newRec.techniqueId})`,
      justification: `Detection recommendation submitted: ${newRec.title}. Gap: ${newRec.detectionGap}`,
      status: 'PROPOSED',
      systemNote: `Security Engineer ${user.name} submitted detection recommendation for technique ${newRec.techniqueId}. Priority: ${newRec.priority.toUpperCase()}.`,
    });

    return newRec;
  }

  async reviewRecommendation(
    user: UserProfile,
    recommendationId: string,
    action: 'accept' | 'reject' | 'request_clarification',
    feedback?: string
  ): Promise<DetectionRecommendation> {
    if (user.role !== 'soc_analyst') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to review detection recommendations. Only SOC Analysts can review.`,
        'recommendation:review',
        user.role
      );
    }
    AuthorizationService.assertPermission(user, 'recommendation:review');

    const items = this.getData();
    const index = items.findIndex((r) => r.id === recommendationId);
    if (index === -1) {
      throw new Error(`Detection recommendation "${recommendationId}" not found.`);
    }

    const rec = items[index];

    // Enforce status constraints
    if (rec.status !== 'proposed' && rec.status !== 'clarification_requested') {
      throw new Error(
        `Recommendation "${recommendationId}" cannot be reviewed in status "${rec.status}". Only proposed or clarification_requested records can be reviewed.`
      );
    }

    const trimmedFeedback = feedback?.trim() || '';

    // Validate mandatory feedback for reject and clarification
    if (action === 'reject') {
      if (trimmedFeedback.length < 10) {
        throw new Error('Mandatory feedback of at least 10 characters is required to reject a recommendation.');
      }
    } else if (action === 'request_clarification') {
      if (trimmedFeedback.length < 10) {
        throw new Error('Mandatory feedback of at least 10 characters is required to request clarification.');
      }
    }

    let targetStatus: RecommendationStatus = 'accepted';
    let actionType: any = 'recommendation_accepted';

    if (action === 'reject') {
      targetStatus = 'rejected';
      actionType = 'recommendation_rejected';
    } else if (action === 'request_clarification') {
      targetStatus = 'clarification_requested';
      actionType = 'recommendation_clarification_requested';
    }

    const now = new Date().toISOString();
    const updated: DetectionRecommendation = {
      ...rec,
      status: targetStatus,
      reviewedBy: user.id,
      reviewedByName: user.name,
      socFeedback: trimmedFeedback || rec.socFeedback,
      updatedAt: now,
    };

    items[index] = updated;
    this.saveData(items);

    // Record immutable audit event
    await this.auditRepo.recordSimulatedAction(user, {
      actionType,
      targetResource: `Recommendation ${rec.id} (${rec.techniqueId})`,
      justification: trimmedFeedback || `SOC Analyst reviewed recommendation: ${action.toUpperCase()}`,
      status: 'SIMULATED_SUCCESS',
      systemNote: `SOC Analyst ${user.name} reviewed recommendation ${rec.id}. Action: ${action.toUpperCase()}. Status updated to ${targetStatus}.`,
    });

    return updated;
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
        `Access Denied: Role "${user.role}" is not authorized to update recommendation implementation. Only Security Engineers can update.`,
        'recommendation:update',
        user.role
      );
    }
    AuthorizationService.assertPermission(user, 'recommendation:update');

    const items = this.getData();
    const index = items.findIndex((r) => r.id === recommendationId);
    if (index === -1) {
      throw new Error(`Detection recommendation "${recommendationId}" not found.`);
    }

    const rec = items[index];

    // Status transition rules for Security Engineer
    if (status === 'in_progress') {
      if (rec.status !== 'accepted') {
        throw new Error(
          `Cannot start implementation on recommendation in status "${rec.status}". Must be in "accepted" status.`
        );
      }
    } else if (status === 'completed') {
      if (rec.status !== 'in_progress') {
        throw new Error(
          `Cannot mark recommendation completed when status is "${rec.status}". Must be "in_progress".`
        );
      }
      const trimmedNotes = notes?.trim() || '';
      if (trimmedNotes.length < 10) {
        throw new Error('Implementation notes of at least 10 characters are required to complete implementation.');
      }
    }

    const now = new Date().toISOString();
    const updated: DetectionRecommendation = {
      ...rec,
      status,
      implementationNotes: notes?.trim() || rec.implementationNotes,
      sigmaDraftReference: sigmaDraftReference?.trim() || rec.sigmaDraftReference,
      updatedAt: now,
    };

    items[index] = updated;
    this.saveData(items);

    const actionType: any =
      status === 'in_progress'
        ? 'recommendation_implementation_started'
        : 'recommendation_implemented';

    await this.auditRepo.recordSimulatedAction(user, {
      actionType,
      targetResource: `Recommendation ${rec.id} (${rec.techniqueId})`,
      justification: notes?.trim() || `Implementation progress updated to ${status}.`,
      status: 'SIMULATED_SUCCESS',
      systemNote: `Security Engineer ${user.name} transitioned recommendation ${rec.id} to ${status}. Sigma Reference: ${sigmaDraftReference || 'None'}.`,
    });

    return updated;
  }

  async validateRecommendation(
    user: UserProfile,
    recommendationId: string,
    validationFeedback?: string
  ): Promise<DetectionRecommendation> {
    if (user.role !== 'soc_analyst') {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to validate detection improvements. Only SOC Analysts can validate.`,
        'recommendation:validate',
        user.role
      );
    }
    AuthorizationService.assertPermission(user, 'recommendation:validate');

    const items = this.getData();
    const index = items.findIndex((r) => r.id === recommendationId);
    if (index === -1) {
      throw new Error(`Detection recommendation "${recommendationId}" not found.`);
    }

    const rec = items[index];

    // INVARIANT: Cannot validate before implementation is marked completed
    if (rec.status !== 'completed') {
      throw new Error(
        `Cannot validate recommendation in status "${rec.status}". Detection improvement must be "completed" before final SOC validation.`
      );
    }

    const now = new Date().toISOString();
    const feedbackText = validationFeedback?.trim();
    const updatedFeedback = feedbackText
      ? `${rec.socFeedback ? `${rec.socFeedback}\n\n` : ''}[VALIDATION CONFIRMED by ${user.name} at ${now}]: ${feedbackText}`
      : rec.socFeedback;

    const updated: DetectionRecommendation = {
      ...rec,
      status: 'validated',
      reviewedBy: user.id,
      reviewedByName: user.name,
      socFeedback: updatedFeedback,
      updatedAt: now,
    };

    items[index] = updated;
    this.saveData(items);

    await this.auditRepo.recordSimulatedAction(user, {
      actionType: 'recommendation_validated',
      targetResource: `Recommendation ${rec.id} (${rec.techniqueId})`,
      justification: feedbackText || 'SOC Analyst validated completed detection rule and telemetry logic.',
      status: 'SIMULATED_SUCCESS',
      systemNote: `SOC Analyst ${user.name} completed final validation on recommendation ${rec.id}. Detection rule verified for triage integration.`,
    });

    return updated;
  }
}
