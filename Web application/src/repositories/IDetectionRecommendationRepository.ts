/**
 * CyberOps SOC — Detection Improvement Recommendation Repository Interface
 *
 * Defines contracts for:
 * 1. Security Engineer recommendation creation and implementation tracking.
 * 2. SOC Analyst recommendation review, rejection, clarification, and validation.
 * 3. Role-scoped querying and access control enforcement.
 */

import { DetectionRecommendation, CreateRecommendationInput } from '../types/recommendation';
import { UserProfile } from '../types/auth';

export interface IDetectionRecommendationRepository {
  /**
   * Retrieves all detection recommendations visible to requesting user role.
   * - Security Engineer: sees all recommendations.
   * - SOC Analyst: sees all recommendations.
   * - IT Operations & Super Admin: isolated, receives empty list.
   */
  getRecommendationsForUser(user: UserProfile): Promise<DetectionRecommendation[]>;

  /**
   * Creates a new detection improvement recommendation.
   * Restricted to Security Engineers.
   */
  createRecommendation(
    user: UserProfile,
    input: CreateRecommendationInput
  ): Promise<DetectionRecommendation>;

  /**
   * Reviews a submitted recommendation (accept, reject, or request clarification).
   * Restricted to SOC Analysts.
   * Mandatory feedback is required for rejection and clarification requests.
   */
  reviewRecommendation(
    user: UserProfile,
    recommendationId: string,
    action: 'accept' | 'reject' | 'request_clarification',
    feedback?: string
  ): Promise<DetectionRecommendation>;

  /**
   * Updates implementation progress for an accepted recommendation.
   * Restricted to Security Engineers.
   * Allows marking in_progress or completed, attaching Sigma rule draft references.
   */
  updateImplementation(
    user: UserProfile,
    recommendationId: string,
    status: 'in_progress' | 'completed',
    notes?: string,
    sigmaDraftReference?: string
  ): Promise<DetectionRecommendation>;

  /**
   * Validates completed detection improvement.
   * Restricted to SOC Analysts.
   * Cannot validate before implementation is marked completed.
   */
  validateRecommendation(
    user: UserProfile,
    recommendationId: string,
    validationFeedback?: string
  ): Promise<DetectionRecommendation>;
}
