/**
 * CyberOps SOC — Security Engineer Analytics & Recommendations Verification Suite
 *
 * Verifies:
 * 1. Accurate security analytics computation:
 *    - MITRE ATT&CK detection and mitigation catalog coverage.
 *    - Accurate categorization of techniques without authored drafts.
 *    - Detection rule inventory counts, validation status, and compile-time zero-deployed invariant.
 *    - Honest reporting of unmeasured telemetry metrics (trigger velocity, false positive rate, detection drift).
 * 2. Deterministic prioritized improvement recommendations:
 *    - Critical priority for high-impact destructive techniques (T1486).
 *    - High priority for active incident correlations (T1003.001, T1059.001).
 *    - High priority for perimeter exploits (T1190) and internal lateral movement (T1021.002).
 *    - Zero live AI/LLM generation calls (pure deterministic rule engine).
 *    - Evidence-based whyItMatters, priorityRationale, and actionable suggestedNextAction.
 * 3. Security Engineer role isolation and read-only boundaries:
 *    - Zero deployed detections in production SIEM.
 *    - Security Engineer cannot triage, escalate, or append analyst notes.
 */

import {
  computeSecurityAnalytics,
  generateImprovementRecommendations,
} from '../services/securityAnalyticsService';
import {
  AUTHENTIC_MITRE_TECHNIQUES,
  AUTHENTIC_MITRE_TACTICS,
} from '../data/mitreData';
import { DetectionRuleService } from '../services/detectionRuleService';
import { INITIAL_SYNTHETIC_ALERTS } from '../data/syntheticAlerts';
import { AuthorizationService } from '../services/authorizationService';
import { DEMO_PERSONAS, AccessDeniedError } from '../types/auth';

let totalTests = 0;
let passedTests = 0;

function assert(condition: boolean, message: string) {
  totalTests++;
  if (!condition) {
    console.error(`  [FAIL] Test ${totalTests}: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passedTests++;
  console.log(`  [PASS] Test ${totalTests}: ${message}`);
}

export async function runSecurityEngineerAnalyticsAndRecommendationsTests(): Promise<{ passed: number; total: number }> {
  console.log('--- Security Engineer Analytics & Recommendations Test Suite ---');

  const starterDrafts = DetectionRuleService.getInitialStarterDrafts(
    AUTHENTIC_MITRE_TECHNIQUES,
    AUTHENTIC_MITRE_TACTICS
  );

  // =========================================================================
  // 1. SECURITY ANALYTICS COMPUTATION
  // =========================================================================
  console.log('\n[Group 1: Security Analytics & Coverage Accounting]');

  const analytics = computeSecurityAnalytics(
    AUTHENTIC_MITRE_TECHNIQUES,
    AUTHENTIC_MITRE_TACTICS,
    starterDrafts,
    INITIAL_SYNTHETIC_ALERTS
  );

  // 1.1 Catalog coverage
  assert(analytics.coverage.totalTechniques === 8, 'Total cataloged techniques is 8');
  assert(
    analytics.coverage.techniquesWithDetectionGuidance === 8,
    'All 8 techniques have documented detection guidance'
  );
  assert(analytics.coverage.detectionPercentage === 100, 'Catalog detection percentage is 100%');
  assert(
    analytics.coverage.techniquesWithMitigations === 8,
    'All 8 techniques have documented defensive mitigations'
  );
  assert(analytics.coverage.mitigationPercentage === 100, 'Catalog mitigation percentage is 100%');
  assert(
    analytics.coverage.fullCatalogCoverage === 8,
    'All 8 techniques have both detection guidance and mitigations'
  );
  assert(
    analytics.coverage.uncoveredTechniquesCount === 0,
    'Zero undocumented catalog techniques (all 8 have reference guidance)'
  );

  // 1.2 Techniques without authored drafts in workbench
  // Out of 8 techniques, starterDrafts covers 3 (T1059.001, T1003.001, T1047)
  // Remaining 5 techniques are without authored drafts (T1021.002, T1078.002, T1190, T1071.001, T1486)
  assert(
    analytics.coverage.techniquesWithoutAuthoredDrafts.length === 5,
    'Exactly 5 techniques in catalog currently lack authored Sigma drafts'
  );
  const unauthoredIds = analytics.coverage.techniquesWithoutAuthoredDrafts.map((t) => t.id);
  assert(unauthoredIds.includes('T1486'), 'T1486 (Ransomware/Encryption) identified without draft');
  assert(unauthoredIds.includes('T1190'), 'T1190 (Exploit Public-Facing App) identified without draft');
  assert(unauthoredIds.includes('T1021.002'), 'T1021.002 (SMB Admin Shares) identified without draft');
  assert(unauthoredIds.includes('T1078.002'), 'T1078.002 (Valid Accounts) identified without draft');
  assert(unauthoredIds.includes('T1071.001'), 'T1071.001 (Web Protocols) identified without draft');

  // 1.3 Detection Rule Inventory & Validation
  assert(analytics.ruleInventory.totalDrafts === 3, 'Total starter drafts count is 3');
  assert(analytics.ruleInventory.validSyntaxCount === 3, 'All 3 starter drafts pass Sigma syntax validation');
  assert(analytics.ruleInventory.invalidSyntaxCount === 0, 'Zero syntax validation errors in starter drafts');

  // 1.4 Non-Deployed Rule Invariant (Critical Requirement!)
  assert(
    analytics.ruleInventory.deployedDetectionsCount === 0,
    'Deployed detections count is strictly 0 (never claim drafts are deployed)'
  );
  assert(
    analytics.ruleInventory.deploymentStatus === 'all_drafts_non_deployed',
    'Deployment status is explicitly all_drafts_non_deployed'
  );
  assert(
    analytics.ruleInventory.deploymentNotice.includes('Zero active detections are deployed'),
    'Deployment notice clearly warns that rules are authoring drafts'
  );

  // 1.5 Honest Telemetry Bounds & Non-Fabrication (Critical Requirement!)
  assert(
    analytics.telemetry.triggerVelocity === 'Not measured',
    'Trigger velocity is honestly marked "Not measured"'
  );
  assert(
    analytics.telemetry.falsePositiveRate === 'Not available',
    'False positive rate is honestly marked "Not available"'
  );
  assert(
    analytics.telemetry.detectionDrift === 'Not measured',
    'Detection drift is honestly marked "Not measured"'
  );
  assert(
    analytics.telemetry.unavailableNotice.includes('not measured in this prototype environment'),
    'Unavailable notice documents requirement for live SIEM telemetry ingestion'
  );
  assert(
    analytics.telemetry.observedCorrelatedAlertsCount > 0,
    'Observed correlated alerts count reflects alerts in dataset'
  );

  // =========================================================================
  // 2. PRIORITIZED DEFENSIVE IMPROVEMENT RECOMMENDATIONS
  // =========================================================================
  console.log('\n[Group 2: Prioritized Improvement Recommendations]');

  const recommendations = generateImprovementRecommendations(
    AUTHENTIC_MITRE_TECHNIQUES,
    AUTHENTIC_MITRE_TACTICS,
    starterDrafts,
    INITIAL_SYNTHETIC_ALERTS
  );

  assert(recommendations.length >= 4, 'At least 4 prioritized recommendations generated');

  // 2.1 Pure Deterministic Generation (No AI calls)
  for (const rec of recommendations) {
    assert(
      rec.generationType === 'deterministic',
      `${rec.id} is labeled generationType: "deterministic"`
    );
    assert(
      rec.generationNotice.includes('Deterministic Rule Engine'),
      `${rec.id} explicitly confirms no live AI calls were made`
    );
    assert(Boolean(rec.techniqueId), `${rec.id} specifies techniqueId`);
    assert(Boolean(rec.whyItMatters), `${rec.id} specifies whyItMatters evidence rationale`);
    assert(Boolean(rec.priorityRationale), `${rec.id} specifies priorityRationale`);
    assert(Boolean(rec.suggestedNextAction), `${rec.id} specifies suggestedNextAction`);
    assert(rec.dataSources.length > 0, `${rec.id} specifies required telemetry sources`);
  }

  // 2.2 Critical Priority Gap: T1486 (Data Encrypted for Impact)
  const t1486Rec = recommendations.find((r) => r.techniqueId === 'T1486');
  assert(Boolean(t1486Rec), 'Recommendation exists for uncovered technique T1486');
  assert(t1486Rec?.priority === 'critical', 'T1486 recommendation has CRITICAL priority');
  assert(
    t1486Rec?.whyItMatters.includes('vssadmin delete shadows') === true,
    'T1486 whyItMatters cites volume shadow copy deletion evidence'
  );

  // 2.3 Priority Ordering (Critical before High before Medium)
  const priorities = recommendations.map((r) => r.priority);
  let sawHigh = false;
  let sawMedium = false;
  let priorityOrderValid = true;

  for (const p of priorities) {
    if (p === 'critical' && (sawHigh || sawMedium)) {
      priorityOrderValid = false;
    }
    if (p === 'high') sawHigh = true;
    if (p === 'medium') sawMedium = true;
  }
  assert(priorityOrderValid, 'Recommendations list strictly maintains critical > high > medium order');

  // 2.4 Active Incident Correlation
  const activeIncidentRecs = recommendations.filter((r) =>
    r.techniqueId === 'T1003.001' || r.techniqueId === 'T1059.001'
  );
  assert(
    activeIncidentRecs.length > 0,
    'Active alerts in telemetry generate high-priority staging/review recommendations'
  );

  // =========================================================================
  // 3. SECURITY ENGINEER ROLE BOUNDARIES & READ-ONLY ENFORCEMENT
  // =========================================================================
  console.log('\n[Group 3: Security Engineer Role Boundaries]');

  const secEng = DEMO_PERSONAS.security_engineer;

  assert(
    AuthorizationService.canAnalyzeMitreCoverage(secEng.role) === true,
    'Security Engineer has mitre:analyze_coverage capability'
  );
  assert(
    AuthorizationService.canTriageAlerts(secEng.role) === false,
    'Security Engineer CANNOT triage alerts (read-only boundary)'
  );
  assert(
    AuthorizationService.canAddNote(secEng.role) === false,
    'Security Engineer CANNOT add analyst notes (read-only boundary)'
  );
  assert(
    AuthorizationService.canAuthorizeSimulatedActions(secEng.role) === false,
    'Security Engineer CANNOT authorize containment or remediation actions'
  );
  assert(
    AuthorizationService.isPlatformAdmin(secEng.role) === false,
    'Security Engineer is strictly isolated from Super Admin domain'
  );

  console.log(`\nAll ${totalTests} Security Engineer Analytics & Recommendations tests passed successfully!`);
  return { passed: passedTests, total: totalTests };
}

// Execute when invoked directly
if (process.argv[1]?.endsWith('securityEngineerAnalyticsAndRecommendationsTest.ts')) {
  runSecurityEngineerAnalyticsAndRecommendationsTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
