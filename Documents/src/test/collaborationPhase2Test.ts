/**
 * Automated Verification Test for Collaboration Phase 2:
 * SOC Analyst Remediation Review and Approval
 *
 * Verifies:
 * 1. SOC Analyst approval: task remains completed, approval record appended, audit event emitted.
 * 2. SOC Analyst rework request: task transitions completed -> in_progress, rework instructions appended, audit event emitted.
 * 3. Mandatory rework instructions: non-empty, minimum length validation.
 * 4. Unauthorized role rejection: IT Ops, Security Engineer, Super Admin denied review actions.
 * 5. Duplicate review prevention: cannot review already-approved tasks or non-completed tasks.
 * 6. Evidence preservation: original submission, rework instructions, resubmission, and approval records all preserved.
 * 7. Audit event creation: action_type 'remediation_approved' and 'remediation_rework_requested' recorded.
 * 8. IT Operations rework visibility & resubmission: reviewState reflects rework, resubmission appends new report.
 * 9. Approval state detection: never treats completed status alone as approval.
 * 10. Incident closure guard: blocks alert resolution until all linked tasks have explicit analyst approval.
 * 11. Role isolation & regression: Super Admin isolation and IT Ops scoping maintained.
 */

import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { IncidentTask } from '../types/audit';
import {
  getTaskReviewState,
  parseRemediationHistory,
  formatApprovalNotes,
  formatReworkNotes,
  formatResubmissionNotes,
  checkAlertClosureEligibility,
} from '../utils/remediationReview';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`[ASSERTION FAILED]: ${message}`);
  }
}

async function runTest(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
  } catch (err: any) {
    console.error(`  [FAIL] ${name}:`, err.message);
    throw err;
  }
}

async function main() {
  console.log('=== RUNNING COLLABORATION PHASE 2 VERIFICATION TESTS ===\n');

  const analyst: UserProfile = DEMO_PERSONAS.soc_analyst;
  const itOps: UserProfile = DEMO_PERSONAS.it_operations;
  const engineer: UserProfile = DEMO_PERSONAS.security_engineer;
  const admin: UserProfile = DEMO_PERSONAS.super_admin;

  const repo = new LocalAuditLogRepository();
  const alertId = 'ALT-2026-TEST-P2';

  // Helper to create and complete a test task
  async function createCompletedTask(title: string): Promise<IncidentTask> {
    const created = await repo.createTask(analyst, {
      title,
      description: 'Remediate detected vulnerability and report findings',
      assignedRole: 'it_operations',
      status: 'pending',
      priority: 'high',
      targetAsset: 'ENDPOINT-SEC-01',
      associatedAlertId: alertId,
    });

    // IT Ops claims task
    await repo.updateTaskStatus(itOps, created.id, 'in_progress');

    // IT Ops completes task with verification package
    const initialReport = [
      'Work Performed:\nApplied firewall block on TCP 4444 and quarantined process.',
      '--- VERIFIED REMEDIATION CHECKLIST (4/4) ---\n[X] Asset Target State Confirmed\n[X] Remediation Procedure Executed\n[X] Threat Telemetry Cleaned\n[X] Restoral Completed',
      '--- TECHNICAL EVIDENCE & REFERENCE ---\nhttps://firewall.internal/logs/FW-8849',
      '--- ATTESTATION ---\nOperator certified independent technical verification on target asset "ENDPOINT-SEC-01"',
    ].join('\n');

    return await repo.updateTaskStatus(itOps, created.id, 'completed', initialReport);
  }

  console.log('-- Group 1: SOC Analyst Approval & Invariants --');

  await runTest('Test 1: SOC Analyst can approve completed remediation', async () => {
    const completed = await createCompletedTask('Test Approval Task 1');
    assert(completed.status === 'completed', 'Task should be in completed status initially');

    const approved = await repo.reviewRemediationTask(
      analyst,
      completed.id,
      'approved',
      'Evidence and telemetry reviewed. All quarantine conditions satisfied.'
    );

    // Invariant: status remains completed
    assert(approved.status === 'completed', 'Approved task status must remain completed');
    assert(
      Boolean(approved.completionNotes?.includes('--- SOC ANALYST REVIEW: APPROVED ---')),
      'completionNotes must contain approved review block'
    );
    assert(
      Boolean(approved.completionNotes?.includes(analyst.name)),
      'completionNotes must record reviewing analyst name'
    );
  });

  await runTest('Test 2: Approval emits immutable operational audit log', async () => {
    const completed = await createCompletedTask('Test Approval Task 2');
    await repo.reviewRemediationTask(analyst, completed.id, 'approved', 'All verification validated.');

    const logs = await repo.getLogsForUser(analyst);
    const auditLog = logs.find(
      (l) => l.actionType === 'remediation_approved' && l.systemNote.includes(completed.id)
    );

    assert(Boolean(auditLog), 'remediation_approved audit log must be recorded');
    assert(auditLog?.actorRole === 'soc_analyst', 'Audit actor role must be soc_analyst');
    assert(auditLog?.associatedAlertId === alertId, 'Audit log must link to associated alert ID');
  });

  console.log('\n-- Group 2: SOC Analyst Rework Request --');

  await runTest('Test 3: Requesting rework changes status from completed to in_progress', async () => {
    const completed = await createCompletedTask('Test Rework Task 1');

    const reworkInstructions = 'Firewall rules incomplete: outbound port 8443 still open. Re-scan and re-submit evidence.';
    const reworked = await repo.reviewRemediationTask(
      analyst,
      completed.id,
      'rework_requested',
      reworkInstructions
    );

    // Invariant: status transitions from completed to in_progress
    assert(reworked.status === 'in_progress', 'Reworked task status must change to in_progress');
    assert(
      Boolean(reworked.completionNotes?.includes('--- SOC ANALYST REVIEW: REWORK REQUESTED ---')),
      'completionNotes must contain rework requested block'
    );
    assert(
      Boolean(reworked.completionNotes?.includes(reworkInstructions)),
      'completionNotes must contain the exact rework instructions'
    );
  });

  await runTest('Test 4: Rework request emits remediation_rework_requested audit log', async () => {
    const completed = await createCompletedTask('Test Rework Task 2');
    await repo.reviewRemediationTask(
      analyst,
      completed.id,
      'rework_requested',
      'Please verify offline backup volume integrity before sign-off.'
    );

    const logs = await repo.getLogsForUser(analyst);
    const auditLog = logs.find(
      (l) => l.actionType === 'remediation_rework_requested' && l.systemNote.includes(completed.id)
    );

    assert(Boolean(auditLog), 'remediation_rework_requested audit log must be recorded');
    assert(auditLog?.actorRole === 'soc_analyst', 'Audit actor role must be soc_analyst');
    assert(auditLog?.associatedAlertId === alertId, 'Audit log must link to associated alert ID');
  });

  console.log('\n-- Group 3: Input Validation & Duplicate Prevention --');

  await runTest('Test 5: Mandatory rework instructions require at least 10 non-whitespace chars', async () => {
    const completed = await createCompletedTask('Test Validation Task');

    let threwEmpty = false;
    try {
      await repo.reviewRemediationTask(analyst, completed.id, 'rework_requested', '   ');
    } catch (err: any) {
      threwEmpty = true;
      assert(err.message.includes('at least 10 characters'), 'Must indicate minimum length requirement');
    }
    assert(threwEmpty, 'Should reject whitespace-only rework instructions');

    let threwShort = false;
    try {
      await repo.reviewRemediationTask(analyst, completed.id, 'rework_requested', 'Fix it');
    } catch (err: any) {
      threwShort = true;
      assert(err.message.includes('at least 10 characters'), 'Must indicate minimum length requirement');
    }
    assert(threwShort, 'Should reject short rework instructions');
  });

  await runTest('Test 6: Prevents duplicate review decisions on already approved tasks', async () => {
    const completed = await createCompletedTask('Test Duplicate Task');
    await repo.reviewRemediationTask(analyst, completed.id, 'approved', 'Remediation approved.');

    let threwDuplicate = false;
    try {
      // Attempting to approve again
      await repo.reviewRemediationTask(analyst, completed.id, 'approved', 'Approving second time.');
    } catch (err: any) {
      threwDuplicate = true;
      assert(err.message.includes('already been approved'), 'Must indicate task has already been approved');
    }
    assert(threwDuplicate, 'Should prevent duplicate approval');
  });

  await runTest('Test 7: Prevents reviewing tasks that are not in completed status', async () => {
    const created = await repo.createTask(analyst, {
      title: 'Pending Task Test',
      description: 'Pending task',
      assignedRole: 'it_operations',
      status: 'pending',
      priority: 'low',
      targetAsset: 'ASSET-01',
      associatedAlertId: alertId,
    });

    let threwPending = false;
    try {
      await repo.reviewRemediationTask(analyst, created.id, 'approved', 'Trying to approve pending task.');
    } catch (err: any) {
      threwPending = true;
      assert(err.message.includes('Only completed remediation tasks can be reviewed'), 'Must reject non-completed review');
    }
    assert(threwPending, 'Should reject reviewing pending task');
  });

  console.log('\n-- Group 4: Role Authorization & Super Admin Isolation --');

  await runTest('Test 8: Rejects review requests from non-analyst roles (IT Ops, Sec Eng, Super Admin)', async () => {
    const completed = await createCompletedTask('Test Unauthorized Review');

    // IT Operations cannot review
    let itThrew = false;
    try {
      await repo.reviewRemediationTask(itOps, completed.id, 'approved', 'IT Ops trying to approve');
    } catch (err: any) {
      itThrew = true;
      assert(err instanceof AccessDeniedError, 'Should throw AccessDeniedError');
    }
    assert(itThrew, 'IT Operations must be denied review authorization');

    // Security Engineer cannot review
    let engThrew = false;
    try {
      await repo.reviewRemediationTask(engineer, completed.id, 'approved', 'Sec Eng trying to approve');
    } catch (err: any) {
      engThrew = true;
      assert(err instanceof AccessDeniedError, 'Should throw AccessDeniedError');
    }
    assert(engThrew, 'Security Engineer must be denied review authorization');

    // Super Admin cannot review
    let adminThrew = false;
    try {
      await repo.reviewRemediationTask(admin, completed.id, 'approved', 'Super Admin trying to approve');
    } catch (err: any) {
      adminThrew = true;
      assert(err instanceof AccessDeniedError, 'Should throw AccessDeniedError');
    }
    assert(adminThrew, 'Super Admin must be denied review authorization');
  });

  await runTest('Test 9: Super Admin receives empty incident tasks list (Strict Isolation)', async () => {
    const adminTasks = await repo.getIncidentTasksForUser(admin);
    assert(Array.isArray(adminTasks) && adminTasks.length === 0, 'Super Admin must receive empty task list');
  });

  console.log('\n-- Group 5: Evidence Preservation & Resubmission Lifecycle --');

  await runTest('Test 10: Preserves full lifecycle history across rework and resubmission', async () => {
    const completed = await createCompletedTask('Test Full Lifecycle Task');

    // Step 1: SOC Analyst requests rework
    const reworkInstructions = 'Evidence link returned 404. Provide valid firewall log screenshot URL.';
    const reworked = await repo.reviewRemediationTask(
      analyst,
      completed.id,
      'rework_requested',
      reworkInstructions
    );

    // Verify IT Ops review state detection
    const stateAfterRework = getTaskReviewState(reworked);
    assert(stateAfterRework.status === 'rework_requested', 'Task state should be rework_requested');
    assert(stateAfterRework.latestReworkInstructions === reworkInstructions, 'Rework instructions must be readable');

    // Step 2: IT Ops resubmits via formatResubmissionNotes or append
    const resubmissionReport = [
      'Work Performed:\nRe-exported firewall log artifact and confirmed host isolated.',
      '--- VERIFIED REMEDIATION CHECKLIST (4/4) ---\n[X] Asset Target State Confirmed\n[X] Remediation Procedure Executed\n[X] Threat Telemetry Cleaned\n[X] Restoral Completed',
      '--- TECHNICAL EVIDENCE & REFERENCE ---\nhttps://firewall.internal/logs/FW-8849-VALID.png',
      '--- ATTESTATION ---\nOperator certified updated technical verification on target asset "ENDPOINT-SEC-01"',
    ].join('\n');

    const resubmittedNotes = formatResubmissionNotes(reworked.completionNotes, itOps, resubmissionReport);
    const resubmitted = await repo.updateTaskStatus(itOps, reworked.id, 'completed', resubmittedNotes);

    // Verify state after resubmission
    const stateAfterResub = getTaskReviewState(resubmitted);
    assert(stateAfterResub.status === 'awaiting_review', 'Resubmitted task should be awaiting_review');
    assert(stateAfterResub.canApprove === true, 'Resubmitted task should allow analyst approval');

    // Step 3: SOC Analyst approves resubmitted task
    const finalApproved = await repo.reviewRemediationTask(
      analyst,
      resubmitted.id,
      'approved',
      'Valid screenshot received. Remediation verified and complete.'
    );

    const parsedFinal = parseRemediationHistory(finalApproved.completionNotes);
    assert(parsedFinal.reviews.length === 2, 'Should preserve both rework and approval reviews in history');
    assert(parsedFinal.reviews[0].decision === 'rework_requested', 'First review must be rework_requested');
    assert(parsedFinal.reviews[1].decision === 'approved', 'Second review must be approved');
    assert(parsedFinal.resubmissionCount >= 1, 'Resubmission report marker must be preserved');
    assert(
      Boolean(finalApproved.completionNotes?.includes('FW-8849-VALID.png')),
      'New evidence reference must be present'
    );
    assert(
      Boolean(finalApproved.completionNotes?.includes('FW-8849')),
      'Original evidence reference must still be present'
    );
  });

  console.log('\n-- Group 6: Approval State Detection & Incident Closure Guard --');

  await runTest('Test 11: Never treats completed status alone as proof of SOC Analyst approval', async () => {
    const rawCompletedTask: IncidentTask = {
      id: 'TSK-MOCK-01',
      title: 'Mock Completed Task Without Review',
      description: 'Remediation completed by IT Ops only',
      assignedRole: 'it_operations',
      status: 'completed',
      priority: 'high',
      createdAt: new Date().toISOString(),
      targetAsset: 'SRV-01',
      associatedAlertId: 'ALT-MOCK-01',
      completionNotes: 'Work Performed: Fixed issue.\n--- ATTESTATION ---\nOperator certified at 2026-10-12',
    };

    const reviewState = getTaskReviewState(rawCompletedTask);
    assert(
      reviewState.status === 'awaiting_review',
      'Completed task without analyst approval must be awaiting_review'
    );
    assert(reviewState.status !== 'approved', 'Must NOT be marked approved without explicit analyst sign-off');
  });

  await runTest('Test 12: Incident Closure Guard blocks resolution when tasks are unapproved', async () => {
    const testAlertId = 'ALT-CLOSURE-TEST-01';

    const unapprovedTask: IncidentTask = {
      id: 'TSK-UNAPPROVED-01',
      title: 'Unapproved Task',
      description: 'Pending analyst signoff',
      assignedRole: 'it_operations',
      status: 'completed',
      priority: 'high',
      createdAt: new Date().toISOString(),
      targetAsset: 'SRV-01',
      associatedAlertId: testAlertId,
      completionNotes: 'Work Performed: Done.\n--- ATTESTATION ---\nOperator certified',
    };

    const eligibility = checkAlertClosureEligibility(testAlertId, [unapprovedTask]);
    assert(eligibility.eligible === false, 'Alert closure must be blocked');
    assert(eligibility.unapprovedTasks.length === 1, 'Should identify 1 unapproved task');
    assert(
      Boolean(eligibility.reason?.includes('TSK-UNAPPROVED-01')),
      'Feedback reason must name the blocking task ID'
    );
  });

  await runTest('Test 13: Incident Closure Guard permits resolution when all linked tasks are approved', async () => {
    const testAlertId = 'ALT-CLOSURE-TEST-02';

    const approvedNotes = formatApprovalNotes(
      'Work Performed: Done.\n--- ATTESTATION ---\nOperator certified',
      analyst,
      'Signed off'
    );

    const approvedTask: IncidentTask = {
      id: 'TSK-APPROVED-01',
      title: 'Approved Task',
      description: 'Signed off by analyst',
      assignedRole: 'it_operations',
      status: 'completed',
      priority: 'high',
      createdAt: new Date().toISOString(),
      targetAsset: 'SRV-01',
      associatedAlertId: testAlertId,
      completionNotes: approvedNotes,
    };

    const eligibility = checkAlertClosureEligibility(testAlertId, [approvedTask]);
    assert(eligibility.eligible === true, 'Alert closure must be permitted when all tasks are approved');
    assert(eligibility.unapprovedTasks.length === 0, 'Unapproved tasks count must be 0');
  });

  await runTest('Test 14: Alerts without associated remediation tasks retain existing closure behavior', async () => {
    const unassociatedAlertId = 'ALT-NO-TASKS-01';
    const unrelatedTasks: IncidentTask[] = [
      {
        id: 'TSK-UNRELATED-01',
        title: 'Unrelated Task',
        description: 'Linked to other alert',
        assignedRole: 'it_operations',
        status: 'pending',
        priority: 'low',
        createdAt: new Date().toISOString(),
        targetAsset: 'SRV-02',
        associatedAlertId: 'ALT-OTHER-99',
      },
    ];

    const eligibility = checkAlertClosureEligibility(unassociatedAlertId, unrelatedTasks);
    assert(eligibility.eligible === true, 'Alerts without tasks must be eligible for closure');
    assert(eligibility.linkedTasks.length === 0, 'Linked tasks count should be 0');
  });

  console.log('\n=== ALL COLLABORATION PHASE 2 VERIFICATION TESTS PASSED (14/14) ===\n');
}

main().catch((err) => {
  console.error('Fatal error running Phase 2 verification tests:', err);
  process.exit(1);
});
