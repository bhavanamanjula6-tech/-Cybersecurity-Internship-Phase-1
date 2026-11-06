/**
 * Deterministic Triage Recommendation Types
 * Explainable, rule-based reasoning engine contracts.
 */

import { AlertSeverity } from './alert';

export interface TriageRuleMatch {
  ruleId: string;
  ruleName: string;
  matchedField: string;
  matchedCondition: string;
  weight: number; // impact on severity/confidence
  description: string;
}

export interface DeterministicTriageRecommendation {
  alertId: string;
  recommendedSeverity: AlertSeverity;
  confidenceScore: number; // 0 to 100
  recommendationCategory: 'Immediate Escalation' | 'Investigate Further' | 'Benign Activity' | 'Informational Baseline';
  summaryRationale: string;
  matchedRules: TriageRuleMatch[];
  supportingEvidence: string[];
  suggestedResponseActions: Array<{
    actionType: 'isolate_host' | 'block_ip' | 'lock_account' | 'collect_forensics' | 'revoke_token';
    label: string;
    description: string;
    urgency: 'critical' | 'high' | 'medium';
    target: string;
  }>;
  evaluatedAt: string;
  isDeterministic: true; // Explicit flag proving this is rule-based, not live LLM
}
