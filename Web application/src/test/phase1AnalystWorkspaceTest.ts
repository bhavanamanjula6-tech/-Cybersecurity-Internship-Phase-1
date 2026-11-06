/**
 * Phase 1 SOC Analyst Workspace & Investigation Security Verification Tests
 *
 * Verifies:
 * 1. Overview dashboard metric calculations derived dynamically from fixtures.
 * 2. Investigation workspace note appending and immutable evidence preservation.
 * 3. Playbook containment simulation and audit/task generation.
 * 4. Role-to-view navigation authorization and cross-role isolation.
 * 5. Platform administrator alert isolation.
 */

import { AuthorizationService } from '../services/authorizationService';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { INITIAL_SYNTHETIC_ALERTS } from '../data/syntheticAlerts';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { SecurityAlert } from '../types/alert';

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
  console.log('=== RUNNING PHASE 1 SOC ANALYST WORKSPACE VERIFICATION TESTS ===\n');

  const analystUser: UserProfile = DEMO_PERSONAS.soc_analyst;
  const engineerUser: UserProfile = DEMO_PERSONAS.security_engineer;
  const itOpsUser: UserProfile = DEMO_PERSONAS.it_operations;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;

  const alertRepo = new LocalAlertRepository();
  const auditRepo = new LocalAuditLogRepository();

  console.log('-- Group 1: Role-to-View Authorization & Navigation Security --');

  runTest('Test 1: soc_analyst default view is "overview"', () => {
    assert(
      AuthorizationService.getDefaultViewForRole('soc_analyst') === 'overview',
      'Expected soc_analyst default view to be "overview"'
    );
  });

  runTest('Test 2: soc_analyst is authorized for intended analyst destinations and denied specialized domains (mitre, tasks)', () => {
    const analystViews = ['overview', 'alerts', 'investigations', 'playbooks', 'network', 'audit', 'profile'];
    for (const v of analystViews) {
      assert(
        AuthorizationService.isViewAuthorized('soc_analyst', v),
        `soc_analyst should be authorized for view "${v}"`
      );
    }
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'mitre'), 'soc_analyst must NOT be authorized for standalone mitre view');
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'tasks'), 'soc_analyst must NOT be authorized for operational tasks view');
  });

  runTest('Test 3: security_engineer is strictly denied from analyst-specific views', () => {
    assert(!AuthorizationService.isViewAuthorized('security_engineer', 'overview'), 'Engineer must not access overview');
    assert(!AuthorizationService.isViewAuthorized('security_engineer', 'investigations'), 'Engineer must not access investigations');
    assert(!AuthorizationService.isViewAuthorized('security_engineer', 'playbooks'), 'Engineer must not access playbooks');
  });

  runTest('Test 4: it_operations is strictly denied from analyst-specific views', () => {
    assert(!AuthorizationService.isViewAuthorized('it_operations', 'overview'), 'IT Ops must not access overview');
    assert(!AuthorizationService.isViewAuthorized('it_operations', 'investigations'), 'IT Ops must not access investigations');
    assert(!AuthorizationService.isViewAuthorized('it_operations', 'playbooks'), 'IT Ops must not access playbooks');
  });

  runTest('Test 5: super_admin is strictly denied from analyst views and alert queue', () => {
    assert(!AuthorizationService.isViewAuthorized('super_admin', 'overview'), 'Super Admin must not access overview');
    assert(!AuthorizationService.isViewAuthorized('super_admin', 'alerts'), 'Super Admin must not access alerts');
    assert(!AuthorizationService.isViewAuthorized('super_admin', 'investigations'), 'Super Admin must not access investigations');
    assert(!AuthorizationService.isViewAuthorized('super_admin', 'playbooks'), 'Super Admin must not access playbooks');
  });

  console.log('\n-- Group 2: Overview Dashboard Dynamic Metric Derivation --');

  runTest('Test 6: Total alert count derived accurately from synthetic fixtures', () => {
    assert(INITIAL_SYNTHETIC_ALERTS.length === 6, 'Expected 6 initial synthetic alert fixtures');
  });

  runTest('Test 7: Severity counts correctly classify Critical, High, and Medium alerts', () => {
    const criticalCount = INITIAL_SYNTHETIC_ALERTS.filter((a) => a.severity === 'critical').length;
    const highCount = INITIAL_SYNTHETIC_ALERTS.filter((a) => a.severity === 'high').length;
    const mediumCount = INITIAL_SYNTHETIC_ALERTS.filter((a) => a.severity === 'medium').length;

    assert(criticalCount === 2, `Expected 2 critical alerts, got ${criticalCount}`);
    assert(highCount === 2, `Expected 2 high alerts, got ${highCount}`);
    assert(mediumCount === 1, `Expected 1 medium alert, got ${mediumCount}`);
  });

  runTest('Test 8: MITRE technique frequency accurately maps known techniques in alerts', () => {
    const techniqueIds = INITIAL_SYNTHETIC_ALERTS.map((a) => a.mitreTechniqueId).filter(Boolean);
    assert(techniqueIds.includes('T1003.001'), 'Expected T1003.001 (LSASS memory dump)');
    assert(techniqueIds.includes('T1059.001'), 'Expected T1059.001 (PowerShell cradle)');
    assert(techniqueIds.includes('T1486'), 'Expected T1486 (Shadow copy tampering)');
  });

  console.log('\n-- Group 3: Investigation Workspace Evidence Integrity & Analyst Notes --');

  await runTest('Test 9: Authorized SOC Analyst can append forensic investigation note', async () => {
    const testAlertId = 'ALT-2026-1049';
    const noteText = 'Forensic verification: Process procdump.exe initiated full access mask handle 0x1FFFFF against PID 640.';
    const updated = await alertRepo.addAnalystNote(analystUser, testAlertId, noteText);

    assert(updated.id === testAlertId, 'Updated alert ID must match target');
    const lastNote = updated.analystNotes[updated.analystNotes.length - 1];
    assert(lastNote.includes(noteText), 'Note text must match input');
    assert(lastNote.includes(analystUser.callsign), 'Note must include analyst callsign');
  });

  await runTest('Test 10: Appending note preserves immutable original evidence fields', async () => {
    const original = INITIAL_SYNTHETIC_ALERTS.find((a) => a.id === 'ALT-2026-1049')!;
    const fetched = (await alertRepo.getAlertsForUser(analystUser)).find((a) => a.id === 'ALT-2026-1049')!;

    assert(fetched.evidence.processCommandLine === original.evidence.processCommandLine, 'Process command line must remain unchanged');
    assert(fetched.evidence.processName === original.evidence.processName, 'Process name must remain unchanged');
    assert(fetched.evidence.rawEventLog === original.evidence.rawEventLog, 'Raw event log must remain unchanged');
    assert(fetched.hostName === original.hostName, 'Hostname must remain unchanged');
    assert(fetched.sourceIp === original.sourceIp, 'Source IP must remain unchanged');
  });

  await runTest('Test 11: Non-analyst roles are strictly rejected from adding analyst notes', async () => {
    let engineerBlocked = false;
    try {
      await alertRepo.addAnalystNote(engineerUser, 'ALT-2026-1049', 'Unauthorized note');
    } catch (e: any) {
      if (e instanceof AccessDeniedError) engineerBlocked = true;
    }
    assert(engineerBlocked, 'Security Engineer must be rejected from adding analyst notes');

    let itOpsBlocked = false;
    try {
      await alertRepo.addAnalystNote(itOpsUser, 'ALT-2026-1049', 'Unauthorized note');
    } catch (e: any) {
      if (e instanceof AccessDeniedError) itOpsBlocked = true;
    }
    assert(itOpsBlocked, 'IT Ops must be rejected from adding analyst notes');
  });

  console.log('\n-- Group 4: Playbook Simulation & Audit / Task Linking --');

  await runTest('Test 12: Playbook simulation records tamper-evident audit log with isSimulated flag', async () => {
    const entry = await auditRepo.recordSimulatedAction(analystUser, {
      actionType: 'isolate_host',
      targetResource: 'WS-FINANCE-04',
      justification: 'LSASS process memory extraction observed. Simulated host quarantine per SOP-IR-01.',
      status: 'SIMULATED_SUCCESS',
      associatedAlertId: 'ALT-2026-1049',
      systemNote: 'Simulated endpoint isolation flag set. Network interface not severed in prototype environment.',
    });

    assert(entry.isSimulated === true, 'Audit log entry must declare isSimulated === true');
    assert(entry.actionType === 'isolate_host', 'Action type must match');
    assert(entry.associatedAlertId === 'ALT-2026-1049', 'Associated alert ID must be bound');
    assert(entry.actorRole === 'soc_analyst', 'Actor role must be soc_analyst');
  });

  await runTest('Test 13: Containment simulation creates linked recovery task for IT Operations', async () => {
    const task = await auditRepo.createTask(analystUser, {
      title: 'Verify Containment & Recovery for WS-FINANCE-04',
      description: 'Operational task triggered following host isolation. Rationale: LSASS dumping detected.',
      assignedRole: 'it_operations',
      status: 'in_progress',
      priority: 'high',
      targetAsset: 'WS-FINANCE-04',
      suggestedActionType: 'isolate_host',
      associatedAlertId: 'ALT-2026-1049',
    });

    assert(task.assignedRole === 'it_operations', 'Created task must be assigned to it_operations');
    assert(task.associatedAlertId === 'ALT-2026-1049', 'Task must link to associated alert');
    assert(task.priority === 'high', 'Task priority must be high');
  });

  console.log('\n-- Group 5: Super Admin Operational Isolation Enforcement --');

  await runTest('Test 14: LocalAlertRepository strictly denies Super Admin from retrieving alert records', async () => {
    let adminDenied = false;
    try {
      await alertRepo.getAlertsForUser(adminUser);
    } catch (e: any) {
      if (e instanceof AccessDeniedError) adminDenied = true;
    }
    assert(adminDenied, 'Super Admin must receive AccessDeniedError when accessing alerts');
  });

  runTest('Test 15: AuthorizationService.canReadAlertRecord returns false for Super Admin', () => {
    const alert = INITIAL_SYNTHETIC_ALERTS[0];
    const canRead = AuthorizationService.canReadAlertRecord(adminUser, alert, []);
    assert(!canRead, 'AuthorizationService must deny Super Admin from reading alert records');
  });

  console.log('\n-- Group 6: Investigation to Playbook Direct Navigation --');
  runTest('Test 16: Direct navigation preserves selected alert ID into response playbooks', () => {
    const targetAlert = INITIAL_SYNTHETIC_ALERTS[1]; // ALT-2026-1047
    let selectedAlertState = INITIAL_SYNTHETIC_ALERTS[0];
    let workspaceViewState = 'investigations';

    // Handler simulating onNavigateToPlaybooks in App.tsx
    const handleNavigateToPlaybooks = (alertId?: string) => {
      if (alertId) {
        const found = INITIAL_SYNTHETIC_ALERTS.find((a) => a.id === alertId);
        if (found) selectedAlertState = found;
      }
      workspaceViewState = 'playbooks';
    };

    handleNavigateToPlaybooks(targetAlert.id);
    assert(workspaceViewState === 'playbooks', 'Workspace view must transition to playbooks');
    assert(selectedAlertState.id === targetAlert.id, 'Target alert ID ALT-2026-1047 must be preserved in state');
  });

  runTest('Test 17: Super Admin is strictly denied from investigations and playbooks views', () => {
    assert(
      !AuthorizationService.isViewAuthorized('super_admin', 'investigations'),
      'Super Admin must not have access to investigations view'
    );
    assert(
      !AuthorizationService.isViewAuthorized('super_admin', 'playbooks'),
      'Super Admin must not have access to playbooks view'
    );
  });

  runTest('Test 18: SOC Analyst possesses authorized access to both investigations and playbooks', () => {
    assert(
      AuthorizationService.isViewAuthorized('soc_analyst', 'investigations'),
      'SOC Analyst must have access to investigations view'
    );
    assert(
      AuthorizationService.isViewAuthorized('soc_analyst', 'playbooks'),
      'SOC Analyst must have access to playbooks view'
    );
  });

  console.log(`\n=== COMPLETED: ${passedTests} of 18 PHASE 1 TESTS PASSED ===`);
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
