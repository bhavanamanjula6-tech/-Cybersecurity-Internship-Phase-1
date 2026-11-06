/**
 * Focused Verification Tests for Phase 1: SOC Analyst Workflow Refinement
 *
 * Verifies:
 * 1. 24-hour alert intake interval boundaries, grouping, and timestamp edge cases.
 * 2. Defensible MTTA & MTTR calculations, invalid timestamps, zero duration, and contributing counts.
 * 3. Alert lifecycle transition validity rules.
 * 4. Multi-alert selection and authorized vs unauthorized bulk triage gating.
 * 5. Partial failure tracking and selection reconciliation.
 * 6. Preservation of single-alert triage and role isolation invariants.
 */

import { AlertMetricsService } from '../services/alertMetricsService';
import { AuthorizationService } from '../services/authorizationService';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { INITIAL_SYNTHETIC_ALERTS } from '../data/syntheticAlerts';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { SecurityAlert, AlertStatus } from '../types/alert';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`[ASSERTION FAILED]: ${message}`);
  }
}

let passedTests = 0;

function runTest(name: string, fn: () => void | Promise<void>): Promise<void> | void {
  try {
    const res = fn();
    if (res instanceof Promise) {
      return res
        .then(() => {
          console.log(`  [PASS] ${name}`);
          passedTests++;
        })
        .catch((err) => {
          console.error(`  [FAIL] ${name}:`, err.message);
          process.exit(1);
        });
    }
    console.log(`  [PASS] ${name}`);
    passedTests++;
  } catch (err: any) {
    console.error(`  [FAIL] ${name}:`, err.message);
    process.exit(1);
  }
}

async function main() {
  console.log('=== RUNNING SOC ANALYST WORKFLOW REFINEMENT VERIFICATION TESTS ===\n');

  const analystUser: UserProfile = DEMO_PERSONAS.soc_analyst;
  const engineerUser: UserProfile = DEMO_PERSONAS.security_engineer;
  const itOpsUser: UserProfile = DEMO_PERSONAS.it_operations;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;

  console.log('-- Group 1: 24-Hour Alert-Intake Interval Boundaries & Edge Cases --');

  runTest('Test 1: 24h intake trend generates exactly 6 4-hour intervals for synthetic fixtures', () => {
    const result = AlertMetricsService.calculate24hIntakeTrend(INITIAL_SYNTHETIC_ALERTS);
    assert(result.buckets.length === 6, `Expected 6 buckets, got ${result.buckets.length}`);
    assert(result.hasUsableData === true, 'Expected usable data in synthetic fixtures');
    assert(result.totalWithinWindow === 6, `Expected 6 alerts in window, got ${result.totalWithinWindow}`);
    assert(result.invalidTimestampCount === 0, 'Expected 0 invalid timestamps');
    assert(result.isAnchoredToTelemetry === true, 'Historical fixtures should be anchored to telemetry horizon');
  });

  runTest('Test 2: Handles completely empty alerts array safely without crashing', () => {
    const result = AlertMetricsService.calculate24hIntakeTrend([]);
    assert(result.buckets.length === 6, 'Should generate 6 empty buckets');
    assert(result.totalWithinWindow === 0, 'Total should be 0');
    assert(result.hasUsableData === false, 'hasUsableData should be false');
    assert(result.invalidTimestampCount === 0, 'Invalid count should be 0');
    for (const b of result.buckets) {
      assert(b.count === 0, 'Each bucket count must be 0');
    }
  });

  runTest('Test 3: Handles corrupted, missing, and invalid ISO timestamps gracefully', () => {
    const corruptedAlerts: SecurityAlert[] = [
      {
        ...INITIAL_SYNTHETIC_ALERTS[0],
        id: 'CORRUPT-1',
        detectedAt: 'not-a-valid-date',
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[1],
        id: 'CORRUPT-2',
        detectedAt: '',
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[2],
        id: 'VALID-1',
        detectedAt: '2026-10-12T04:00:00Z',
      },
    ];

    const result = AlertMetricsService.calculate24hIntakeTrend(corruptedAlerts);
    assert(result.invalidTimestampCount === 2, `Expected 2 invalid timestamps, got ${result.invalidTimestampCount}`);
    assert(result.totalWithinWindow === 1, `Expected 1 valid alert within window, got ${result.totalWithinWindow}`);
  });

  runTest('Test 4: Correctly buckets alerts based on exact 4-hour intervals', () => {
    const refEnd = new Date('2026-10-12T24:00:00Z').getTime(); // 2026-10-13 00:00:00Z
    const testAlerts: SecurityAlert[] = [
      {
        ...INITIAL_SYNTHETIC_ALERTS[0],
        id: 'B1',
        detectedAt: '2026-10-12T01:00:00Z', // In bucket 0 (00:00 - 04:00)
        severity: 'critical',
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[1],
        id: 'B2',
        detectedAt: '2026-10-12T05:00:00Z', // In bucket 1 (04:00 - 08:00)
        severity: 'high',
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[2],
        id: 'B3',
        detectedAt: '2026-10-12T21:00:00Z', // In bucket 5 (20:00 - 24:00)
        severity: 'medium',
      },
    ];

    const result = AlertMetricsService.calculate24hIntakeTrend(testAlerts, { referenceTime: refEnd });
    assert(result.buckets[0].count === 1, 'Bucket 0 must contain 1 alert');
    assert(result.buckets[0].criticalCount === 1, 'Bucket 0 criticalCount must be 1');
    assert(result.buckets[1].count === 1, 'Bucket 1 must contain 1 alert');
    assert(result.buckets[1].highCount === 1, 'Bucket 1 highCount must be 1');
    assert(result.buckets[5].count === 1, 'Bucket 5 must contain 1 alert');
    assert(result.buckets[5].mediumCount === 1, 'Bucket 5 mediumCount must be 1');
  });

  console.log('\n-- Group 2: Defensible MTTA & MTTR Velocity Calculations --');

  runTest('Test 5: MTTA reports "unavailable" (N/A) with 0 contributing records when timestamps are unpopulated', () => {
    const mtta = AlertMetricsService.calculateMTTA(INITIAL_SYNTHETIC_ALERTS);
    assert(mtta.status === 'unavailable', 'Expected MTTA to be unavailable');
    assert(mtta.valueMinutes === null, 'valueMinutes must be null');
    assert(mtta.formattedValue === 'N/A', 'formattedValue must be N/A');
    assert(mtta.contributingRecords === 0, 'contributingRecords must be 0');
    assert(mtta.reason.includes('acknowledged_at'), 'Reason must explain lack of acknowledged_at');
  });

  runTest('Test 6: MTTR reports "unavailable" (N/A) and refuses to fabricate simple elapsed time', () => {
    const mttr = AlertMetricsService.calculateMTTR(INITIAL_SYNTHETIC_ALERTS);
    assert(mttr.status === 'unavailable', 'Expected MTTR to be unavailable');
    assert(mttr.valueMinutes === null, 'valueMinutes must be null');
    assert(mttr.formattedValue === 'N/A', 'formattedValue must be N/A');
    assert(mttr.contributingRecords === 0, 'contributingRecords must be 0');
    assert(mttr.reason.includes('resolved_at'), 'Reason must explain lack of resolved_at');
  });

  runTest('Test 7: MTTA accurately computes mean when valid acknowledgment timestamps are provided', () => {
    const alertsWithAck: any[] = [
      {
        ...INITIAL_SYNTHETIC_ALERTS[0],
        id: 'A1',
        detectedAt: '2026-10-12T10:00:00Z',
        acknowledgedAt: '2026-10-12T10:15:00Z', // 15 mins
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[1],
        id: 'A2',
        detectedAt: '2026-10-12T11:00:00Z',
        acknowledgedAt: '2026-10-12T11:45:00Z', // 45 mins
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[2],
        id: 'A3',
        detectedAt: '2026-10-12T12:00:00Z',
        acknowledgedAt: '2026-10-12T12:00:00Z', // 0 mins (immediate triage)
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[3],
        id: 'A4',
        detectedAt: '2026-10-12T13:00:00Z',
        acknowledgedAt: '2026-10-12T12:30:00Z', // Negative interval: should be excluded
      },
    ];

    const mtta = AlertMetricsService.calculateMTTA(alertsWithAck);
    assert(mtta.status === 'computed', 'Status should be computed');
    assert(mtta.contributingRecords === 3, `Expected 3 contributing records (excluding negative), got ${mtta.contributingRecords}`);
    // Mean of (15 + 45 + 0) / 3 = 20 minutes
    assert(mtta.valueMinutes === 20, `Expected 20 minutes mean, got ${mtta.valueMinutes}`);
    assert(mtta.formattedValue === '20m', `Expected '20m', got ${mtta.formattedValue}`);
  });

  runTest('Test 8: MTTR accurately computes mean when valid resolution timestamps are provided', () => {
    const alertsWithRes: any[] = [
      {
        ...INITIAL_SYNTHETIC_ALERTS[0],
        id: 'R1',
        detectedAt: '2026-10-12T08:00:00Z',
        resolvedAt: '2026-10-12T09:30:00Z', // 90 mins (1.5h)
      },
      {
        ...INITIAL_SYNTHETIC_ALERTS[1],
        id: 'R2',
        detectedAt: '2026-10-12T10:00:00Z',
        resolvedAt: '2026-10-12T10:30:00Z', // 30 mins (0.5h)
      },
    ];

    const mttr = AlertMetricsService.calculateMTTR(alertsWithRes);
    assert(mttr.status === 'computed', 'Status should be computed');
    assert(mttr.contributingRecords === 2, `Expected 2 contributing records, got ${mttr.contributingRecords}`);
    // Mean of (90 + 30) / 2 = 60 minutes = 1h
    assert(mttr.valueMinutes === 60, `Expected 60 minutes mean, got ${mttr.valueMinutes}`);
    assert(mttr.formattedValue === '1h', `Expected '1h', got ${mttr.formattedValue}`);
  });

  console.log('\n-- Group 3: Alert Lifecycle Transition Rules --');

  runTest('Test 9: Validates allowed and prohibited lifecycle status transitions', () => {
    // Valid transitions
    assert(AlertMetricsService.isStatusTransitionValid('new', 'in_triage'), 'new -> in_triage must be valid');
    assert(AlertMetricsService.isStatusTransitionValid('new', 'escalated'), 'new -> escalated must be valid');
    assert(AlertMetricsService.isStatusTransitionValid('new', 'resolved'), 'new -> resolved must be valid');
    assert(AlertMetricsService.isStatusTransitionValid('in_triage', 'escalated'), 'in_triage -> escalated must be valid');
    assert(AlertMetricsService.isStatusTransitionValid('in_triage', 'resolved'), 'in_triage -> resolved must be valid');
    assert(AlertMetricsService.isStatusTransitionValid('resolved', 'in_triage'), 'resolved -> in_triage (reopen) must be valid');

    // Prohibited transitions
    assert(!AlertMetricsService.isStatusTransitionValid('new', 'new'), 'new -> new must be prohibited (identical)');
    assert(!AlertMetricsService.isStatusTransitionValid('in_triage', 'new'), 'in_triage -> new must be prohibited');
    assert(!AlertMetricsService.isStatusTransitionValid('escalated', 'new'), 'escalated -> new must be prohibited');
  });

  runTest('Test 10: Correctly filters eligible alerts for target status', () => {
    const sample: SecurityAlert[] = [
      { ...INITIAL_SYNTHETIC_ALERTS[0], status: 'new' },
      { ...INITIAL_SYNTHETIC_ALERTS[1], status: 'in_triage' },
      { ...INITIAL_SYNTHETIC_ALERTS[2], status: 'resolved' },
    ];

    const eligibleForInTriage = AlertMetricsService.getEligibleAlertsForTransition(sample, 'in_triage');
    // 'new' and 'resolved' (reopen) are eligible; 'in_triage' is already in triage
    assert(eligibleForInTriage.length === 2, `Expected 2 eligible alerts, got ${eligibleForInTriage.length}`);
  });

  console.log('\n-- Group 4: Authorization Gating for Bulk Triage Operations --');

  runTest('Test 11: SOC Analyst has "alert:triage" and is authorized for bulk operations', () => {
    assert(AuthorizationService.hasPermission(analystUser.role, 'alert:triage'), 'SOC Analyst must have alert:triage');
    assert(AuthorizationService.canTriageAlerts(analystUser.role), 'canTriageAlerts must return true');
  });

  runTest('Test 12: Security Engineer, IT Ops, and Super Admin are strictly unauthorized for alert:triage', () => {
    assert(!AuthorizationService.hasPermission(engineerUser.role, 'alert:triage'), 'Engineer must NOT have alert:triage');
    assert(!AuthorizationService.hasPermission(itOpsUser.role, 'alert:triage'), 'IT Ops must NOT have alert:triage');
    assert(!AuthorizationService.hasPermission(adminUser.role, 'alert:triage'), 'Super Admin must NOT have alert:triage');
  });

  console.log('\n-- Group 5: Sequential Execution, Partial Failure Tracking & Single-Alert Triage --');

  await runTest('Test 13: Single-alert status update executes cleanly via LocalAlertRepository', async () => {
    const alertRepo = new LocalAlertRepository();
    await alertRepo.resetToDefault();

    const targetAlertId = 'ALT-2026-1049';
    const updated = await alertRepo.updateAlertStatus(analystUser, targetAlertId, 'in_triage');
    assert(updated.status === 'in_triage', 'Expected alert status to be in_triage');
    assert(updated.assignedAnalyst === analystUser.name, 'Analyst name should be bound');
  });

  await runTest('Test 14: Non-analyst role is rejected from updateAlertStatus by assertion guard', async () => {
    const alertRepo = new LocalAlertRepository();
    let rejected = false;
    try {
      await alertRepo.updateAlertStatus(engineerUser, 'ALT-2026-1049', 'resolved');
    } catch (e: any) {
      if (e instanceof AccessDeniedError) {
        rejected = true;
      }
    }
    assert(rejected, 'Security Engineer must be rejected with AccessDeniedError');
  });

  await runTest('Test 15: Simulates multi-alert sequential execution with partial failure handling', async () => {
    const alertRepo = new LocalAlertRepository();
    await alertRepo.resetToDefault();

    const targetIds = ['ALT-2026-1049', 'ALT-NONEXISTENT', 'ALT-2026-1047'];
    const succeeded: string[] = [];
    const failed: Array<{ id: string; error: string }> = [];

    for (const id of targetIds) {
      try {
        await alertRepo.updateAlertStatus(analystUser, id, 'in_triage');
        succeeded.push(id);
      } catch (err: any) {
        failed.push({ id, error: err.message });
      }
    }

    assert(succeeded.length === 2, `Expected 2 successes, got ${succeeded.length}`);
    assert(succeeded.includes('ALT-2026-1049'), 'ALT-2026-1049 should succeed');
    assert(succeeded.includes('ALT-2026-1047'), 'ALT-2026-1047 should succeed');
    assert(failed.length === 1, `Expected 1 failure, got ${failed.length}`);
    assert(failed[0].id === 'ALT-NONEXISTENT', 'ALT-NONEXISTENT should be recorded in failed list');

    // Selection reconciliation: Deselect succeeded, keep failed selected for retry
    let selectedIds = [...targetIds];
    selectedIds = selectedIds.filter((id) => !succeeded.includes(id));
    assert(selectedIds.length === 1 && selectedIds[0] === 'ALT-NONEXISTENT', 'Only failed ID must remain selected');
  });

  console.log(`\n=== COMPLETED: ${passedTests} of 15 WORKFLOW REFINEMENT TESTS PASSED ===`);
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
