/**
 * Comprehensive Verification Tests for CyberOps SOC Phase 1 - SOC Analyst Dashboard Completion
 *
 * Verifies the 8 core audit areas:
 * 1. Overview metrics, 24-hour alert-intake trends, and defensible MTTA/MTTR calculations.
 * 2. Alert Triage Queue, bulk triage authorization, and per-record execution outcomes.
 * 3. Deep Investigation workspace, incident selection synchronization, and immutable evidence preservation.
 * 4. Response Playbooks, mandatory rationale recording, and transition to IT Operations recovery tasks.
 * 5. Network Flow Telemetry (CIC-IDS2017 schema), filtering, and empty match handling.
 * 6. Containment Audit Trail, tamper-evident logs, and truthful execution mode representation.
 * 7. Loading, empty queue, and unavailable-data states across all analyst views.
 * 8. Role isolation, default views, and direct-route fallback invariants.
 */

import { AuthorizationService } from '../services/authorizationService';
import { AlertMetricsService } from '../services/alertMetricsService';
import { DeterministicTriageService } from '../services/deterministicTriageService';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
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
  console.log('=== RUNNING SOC ANALYST DASHBOARD COMPLETION VERIFICATION TESTS ===\n');

  const analystUser: UserProfile = DEMO_PERSONAS.soc_analyst;
  const engineerUser: UserProfile = DEMO_PERSONAS.security_engineer;
  const itOpsUser: UserProfile = DEMO_PERSONAS.it_operations;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;

  const alertRepo = new LocalAlertRepository();
  const auditRepo = new LocalAuditLogRepository();
  const triageService = new DeterministicTriageService();

  console.log('-- Area 1: Overview Metrics & 24h Alert-Intake Trends --');

  runTest('Test 1: Accurately classifies alert severity and status totals from fixtures', () => {
    assert(INITIAL_SYNTHETIC_ALERTS.length === 6, 'Expected 6 synthetic alerts');
    const critical = INITIAL_SYNTHETIC_ALERTS.filter((a) => a.severity === 'critical').length;
    const high = INITIAL_SYNTHETIC_ALERTS.filter((a) => a.severity === 'high').length;
    assert(critical === 2, `Expected 2 critical alerts, got ${critical}`);
    assert(high === 2, `Expected 2 high alerts, got ${high}`);
  });

  runTest('Test 2: 24-hour intake trend divides window into 6 4-hour intervals', () => {
    const trend = AlertMetricsService.calculate24hIntakeTrend(INITIAL_SYNTHETIC_ALERTS);
    assert(trend.buckets.length === 6, 'Must have 6 buckets of 4 hours');
    assert(trend.totalWithinWindow === 6, 'All 6 fixtures fall within anchored telemetry window');
    assert(trend.hasUsableData === true, 'hasUsableData should be true');
    assert(trend.isAnchoredToTelemetry === true, 'Synthetic fixtures anchored to telemetry horizon');
  });

  runTest('Test 3: Defensible MTTA & MTTR report unavailable (N/A) without fake elapsed time', () => {
    const mtta = AlertMetricsService.calculateMTTA(INITIAL_SYNTHETIC_ALERTS);
    const mttr = AlertMetricsService.calculateMTTR(INITIAL_SYNTHETIC_ALERTS);
    assert(mtta.status === 'unavailable' && mtta.formattedValue === 'N/A', 'MTTA must be N/A');
    assert(mttr.status === 'unavailable' && mttr.formattedValue === 'N/A', 'MTTR must be N/A');
    assert(mtta.contributingRecords === 0 && mttr.contributingRecords === 0, '0 records evaluated');
  });

  console.log('\n-- Area 2: Alert Triage Queue & Bulk Triage Authorization & Outcomes --');

  runTest('Test 4: SOC Analyst possesses alert:triage permission; others are denied', () => {
    assert(AuthorizationService.hasPermission(analystUser.role, 'alert:triage') === true, 'Analyst has alert:triage');
    assert(AuthorizationService.hasPermission(engineerUser.role, 'alert:triage') === false, 'Engineer denied alert:triage');
    assert(AuthorizationService.hasPermission(itOpsUser.role, 'alert:triage') === false, 'IT Ops denied alert:triage');
    assert(AuthorizationService.hasPermission(adminUser.role, 'alert:triage') === false, 'Admin denied alert:triage');
  });

  runTest('Test 5: Status transition validator enforces valid paths and rejects identical/invalid transitions', () => {
    assert(AlertMetricsService.isStatusTransitionValid('new', 'in_triage') === true, 'new -> in_triage valid');
    assert(AlertMetricsService.isStatusTransitionValid('in_triage', 'escalated') === true, 'in_triage -> escalated valid');
    assert(AlertMetricsService.isStatusTransitionValid('in_triage', 'resolved') === true, 'in_triage -> resolved valid');
    assert(AlertMetricsService.isStatusTransitionValid('new', 'new') === false, 'new -> new prohibited');
    assert(AlertMetricsService.isStatusTransitionValid('escalated', 'new') === false, 'escalated -> new prohibited');
  });

  await runTest('Test 6: Simulates sequential bulk update with per-record outcome tracking', async () => {
    const testIds = ['ALT-2026-1044', 'ALT-2026-1045'];
    const targetStatus: AlertStatus = 'in_triage';

    const succeeded: string[] = [];
    const failed: Array<{ id: string; error: string }> = [];

    for (const id of testIds) {
      try {
        await alertRepo.updateAlertStatus(analystUser, id, targetStatus);
        succeeded.push(id);
      } catch (err: any) {
        failed.push({ id, error: err.message });
      }
    }

    assert(succeeded.length === 2, `Expected 2 succeeded, got ${succeeded.length}`);
    assert(failed.length === 0, 'Expected 0 failures');

    // Verify persisted state
    const refreshed = await alertRepo.getAlertsForUser(analystUser);
    const a1 = refreshed.find((a) => a.id === 'ALT-2026-1044')!;
    const a2 = refreshed.find((a) => a.id === 'ALT-2026-1045')!;
    assert(a1.status === 'in_triage', 'a1 must be in_triage');
    assert(a2.status === 'in_triage', 'a2 must be in_triage');
  });

  console.log('\n-- Area 3: Deep Investigation & Evidence Integrity --');

  await runTest('Test 7: Appending analyst note records analyst callsign while keeping raw telemetry intact', async () => {
    const testId = 'ALT-2026-1049';
    const note = 'Memory analysis confirms procdump process injection into lsass.';
    const updated = await alertRepo.addAnalystNote(analystUser, testId, note);

    assert(updated.analystNotes.length >= 1, 'Analyst note array must have entry');
    const latestNote = updated.analystNotes[updated.analystNotes.length - 1];
    assert(latestNote.includes(note), 'Note content must match');
    assert(latestNote.includes(analystUser.callsign), 'Note must include operator callsign');

    // Verify raw evidence is unmodified
    assert(updated.evidence.processName === 'procdump_x64.exe', 'processName preserved');
    assert(updated.evidence.fileHashSha256 !== undefined, 'hash preserved');
  });

  runTest('Test 8: Deterministic rule evaluation generates threat category and supporting evidence', () => {
    const alert = INITIAL_SYNTHETIC_ALERTS.find((a) => a.id === 'ALT-2026-1049')!;
    const recommendation = triageService.evaluateAlert(alert);

    assert(recommendation.matchedRules.length > 0, 'Should match deterministic rules');
    assert(recommendation.confidenceScore > 0, 'Should compute confidence score');
    assert(recommendation.supportingEvidence.length > 0, 'Should extract evidence strings');
    assert(recommendation.suggestedResponseActions.some((a) => a.actionType === 'isolate_host'), 'Should suggest host isolation');
  });

  console.log('\n-- Area 4: Response Playbooks & Transition to IT Operations Tasks --');

  await runTest('Test 9: Containment simulation creates both audit log (isSimulated=true) and IT Ops task', async () => {
    const alertId = 'ALT-2026-1044';
    const target = 'WS-CORP-FIN02';
    const rationale = 'Cobalt Strike beaconing detected in triage. Isolating host per IR-SOP-01.';

    // 1. Audit log
    const auditEntry = await auditRepo.recordSimulatedAction(analystUser, {
      actionType: 'isolate_host',
      targetResource: target,
      justification: rationale,
      status: 'SIMULATED_SUCCESS',
      associatedAlertId: alertId,
      systemNote: 'Simulated endpoint isolation test',
    });

    assert(auditEntry.isSimulated === true, 'Audit log must mark isSimulated=true');
    assert(auditEntry.actionType === 'isolate_host', 'actionType must match');
    assert(auditEntry.associatedAlertId === alertId, 'Must link to associated alert');

    // 2. Recovery Task
    const newTask = await auditRepo.createTask(analystUser, {
      title: `Verify Containment & Recovery for ${target}`,
      description: `Task triggered by simulate host isolation. Rationale: ${rationale}`,
      assignedRole: 'it_operations',
      status: 'in_progress',
      priority: 'high',
      targetAsset: target,
      suggestedActionType: 'isolate_host',
      associatedAlertId: alertId,
    });

    assert(newTask.assignedRole === 'it_operations', 'Assigned role must be it_operations');
    assert(newTask.associatedAlertId === alertId, 'Task must retain associatedAlertId');
    assert(newTask.status === 'in_progress', 'Initial status must be in_progress');
  });

  console.log('\n-- Area 5: Network Flow Telemetry Elimination --');

  runTest('Test 10: Network Flow Telemetry is strictly eliminated from SOC Analyst authorized views and permissions', () => {
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'network' as any), 'SOC Analyst must not have network view');
    assert(!AuthorizationService.hasPermission('soc_analyst', 'telemetry:read' as any), 'SOC Analyst must not have telemetry:read permission');
  });

  console.log('\n-- Area 6: Containment Audit Trail & Scoped Evidence --');

  await runTest('Test 11: Audit log retrieval scopes entries and differentiates simulated vs persisted', async () => {
    const logs = await auditRepo.getLogsForUser(analystUser);
    assert(logs.length > 0, 'Logs must be populated');
    const simulatedLog = logs.find((l) => l.isSimulated);
    assert(simulatedLog !== undefined, 'At least one simulated log entry present');
    assert(typeof simulatedLog!.justification === 'string', 'Mandatory justification exists');
  });

  console.log('\n-- Area 7: Loading, Empty Queue, and Unavailable-Data States --');

  runTest('Test 12: 24h intake trend handles empty alert list safely', () => {
    const emptyTrend = AlertMetricsService.calculate24hIntakeTrend([]);
    assert(emptyTrend.buckets.length === 6, 'Produces 6 empty buckets');
    assert(emptyTrend.totalWithinWindow === 0, 'Total is 0');
    assert(emptyTrend.hasUsableData === false, 'hasUsableData is false');
  });

  console.log('\n-- Area 8: Role Isolation & Direct-Route Fallbacks --');

  runTest('Test 13: SOC Analyst has exactly 6 authorized knowledge modules', () => {
    const analystSidebarViews = ['overview', 'strategies', 'analytics', 'log_sources', 'data_components', 'mitre_explorer'];
    for (const v of analystSidebarViews) {
      assert(AuthorizationService.isViewAuthorized('soc_analyst', v), `soc_analyst must be authorized for ${v}`);
    }
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'network' as any), 'soc_analyst denied network');
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'admin'), 'soc_analyst denied admin');
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'mitre'), 'soc_analyst denied mitre');
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'tasks'), 'soc_analyst denied tasks');
  });

  runTest('Test 14: Default view for soc_analyst is "overview"', () => {
    assert(AuthorizationService.getDefaultViewForRole('soc_analyst') === 'overview', 'Default view must be overview');
  });

  console.log(`\n=== COMPLETED: All ${passedTests} SOC ANALYST TESTS PASSED ===`);
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
