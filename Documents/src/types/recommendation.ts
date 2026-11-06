/**
 * CyberOps SOC — Detection Improvement Recommendation Data Contract
 * Facilitates Security Engineer ↔ SOC Analyst collaboration.
 */

export type RecommendationStatus =
  | 'proposed'
  | 'accepted'
  | 'rejected'
  | 'clarification_requested'
  | 'in_progress'
  | 'completed'
  | 'validated';

export type RecommendationPriority = 'critical' | 'high' | 'medium' | 'low';

export interface DetectionRecommendation {
  id: string; // UUID
  title: string;
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  priority: RecommendationPriority;
  detectionGap: string;
  technicalExplanation: string;
  proposedImprovement: string;
  supportingEvidence: string;
  relatedRuleDraftId?: string;
  status: RecommendationStatus;
  createdBy: string;
  createdByRole: 'security_engineer';
  createdByName: string;
  reviewedBy?: string;
  reviewedByName?: string;
  socFeedback?: string;
  implementationNotes?: string;
  sigmaDraftReference?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateRecommendationInput {
  title: string;
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  priority: RecommendationPriority;
  detectionGap: string;
  technicalExplanation: string;
  proposedImprovement: string;
  supportingEvidence?: string;
  relatedRuleDraftId?: string;
}
