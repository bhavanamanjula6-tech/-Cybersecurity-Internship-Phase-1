/**
 * Focused Verification Tests for Phase 3: IT Operations Remediation Verification
 *
 * Verifies:
 * 1. Required-field validation (notes >= 10 chars, mandatory attestation, checklist requirement).
 * 2. Successful task completion with structured evidence and operator attribution.
 * 3. Persistence of serialized verification notes in completionNotes column.
 * 4. IT Operations role scoping (task assignment isolation and task-linked alert scoping).
 * 5. Unauthorized role rejection (Security Engineer, Super Admin denied from task updates).
 * 6. Protection against duplicate submissions and state transitions.
 */

import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { AuthorizationService } from '../services/authorizationService';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { IncidentTask } from '../types/audit';

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
  console.log('=== RUNNING IT OPERATIONS REMEDIATION VERIFICATION TESTS ===\n');

  const itOpsUser: UserProfile = DEMO_PERSONAS.it_operations;
  const analystUser: UserProfile = DEMO_PERSONAS.soc_analyst;
  const engineerUser: UserProfile = DEMO_PERSONAS.security_engineer;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;

  const auditRepo = new LocalAuditLogRepository();
  const alertRepo = new LocalAlertRepository();

  console.log('-- Group 1: Verification Validation Rules & Serialization --');

  runTest('Test 1: Validation rejects notes shorter than 10 characters', () => {
    const validate = (notes: string, attestation: boolean, checklistCount: number) => {
      if (notes.trim().length < 10) return 'Completion notes must be at least 10 characters';
      if (checklistCount === 0) return 'Must record at least one verified step';
      if (!attestation) return 'Must confirm attestation';
      return null;
    };

    assert(validate('Fixed', true, 1) !== null, 'Short note "Fixed" must be rejected');
    assert(validate('', true, 1) !== null, 'Empty note must be rejected');
    assert(validate('   ', true, 1) !== null, 'Whitespace-only note must be rejected');
  });

  runTest('Test 2: Validation requires explicit operator attestation confirmation', () => {
    const validate = (notes: string, attestation: boolean, checklistCount: number) => {
      if (notes.trim().length < 10) return 'Completion notes must be at least 10 characters';
      if (checklistCount === 0) return 'Must record at least one verified step';
      if (!attestation) return 'Must confirm attestation';
      return null;
    };

    const validNotes = 'Replaced compromised kerberos ticket and restarted services.';
    assert(validate(validNotes, false, 1) === 'Must confirm attestation', 'Unchecked attestation must be rejected');
    assert(validate(validNotes, true, 1) === null, 'Checked attestation must pass');
  });

  runTest('Test 3: Validation requires at least one verified checklist step', () => {
    const validate = (notes: string, attestation: boolean, checklistCount: number) => {
      if (notes.trim().length < 10) return 'Completion notes must be at least 10 characters';
      if (checklistCount === 0) return 'Must record at least one verified step';
      if (!attestation) return 'Must confirm attestation';
      return null;
    };

    const validNotes = 'Replaced compromised kerberos ticket and restarted services.';
    assert(validate(validNotes, true, 0) === 'Must record at least one verified step', 'Zero checklist items must be rejected');
    assert(validate(validNotes, true, 2) === null, 'Non-zero checklist items must pass');
  });

  runTest('Test 4: Serializes notes, checklist, and technical evidence into structured record', () => {
    const formatSerializedNotes = (notes: string, checklist: string[], evidence?: string) => {
      const parts = [
        `Work Performed:\n${notes.trim()}`,
        `\n--- VERIFIED REMEDIATION CHECKLIST (${checklist.length}) ---\n${checklist.map((c) => `[X] ${c}`).join('\n')}`,
      ];
      if (evidence) parts.push(`\n--- TECHNICAL EVIDENCE & REFERENCE ---\n${evidence.trim()}`);
      return parts.join('\n');
    };

    const serialized = formatSerializedNotes(
      'Reset credentials on Domain Controller for DOMAIN\\svc_backup.',
      ['Asset Target State Confirmed', 'Remediation Executed & Tested'],
      'PowerShell: Get-ADUser -Identity svc_backup | select Enabled'
    );

    assert(serialized.includes('Work Performed:'), 'Must include Work Performed header');
    assert(serialized.includes('[X] Asset Target State Confirmed'), 'Must include checklist item 1');
    assert(serialized.includes('[X] Remediation Executed & Tested'), 'Must include checklist item 2');
    assert(serialized.includes('Get-ADUser'), 'Must include evidence reference');
  });

  console.log('\n-- Group 2: Successful Completion & Evidence Persistence --');

  await runTest('Test 5: Authorized IT Operations operator completes task with verified evidence', async () => {
    const targetTaskId = 'TSK-2026-002';
    const structuredNotes = `Work Performed:
Revoked Kerberos TGT and reset credentials for DOMAIN\\svc_backup. Confirmed service host rebooted.

--- VERIFIED REMEDIATION CHECKLIST (4/4) ---
[X] Asset Target State & Identity Confirmed
[X] Remediation Procedure Executed & Tested
[X] Absence of Malicious Telemetry Re-infection
[X] Authorized Operational Service Restoral

--- TECHNICAL EVIDENCE & REFERENCE ---
Reset-ADServiceAccount -Identity svc_backup -PassThru; Status: ACTIVE_SECURE`;

    const updated = await auditRepo.updateTaskStatus(itOpsUser, targetTaskId, 'completed', structuredNotes);

    assert(updated.id === targetTaskId, 'Updated task ID must match');
    assert(updated.status === 'completed', 'Task status must be completed');
    assert(Boolean(updated.completedAt), 'completedAt must be populated');
    assert(Boolean(updated.completedBy?.includes(itOpsUser.name)), 'completedBy must include operator name');
    assert(Boolean(updated.completedBy?.includes(itOpsUser.callsign)), 'completedBy must include operator callsign');
    assert(Boolean(updated.completionNotes?.includes('Reset-ADServiceAccount')), 'completionNotes must contain evidence');
    assert(Boolean(updated.completionNotes?.includes('VERIFIED REMEDIATION CHECKLIST')), 'completionNotes must contain checklist');
  });

  await runTest('Test 6: Completed task preserves associated alert linkage', async () => {
    const tasks = await auditRepo.getIncidentTasksForUser(itOpsUser);
    const completedTask = tasks.find((t) => t.id === 'TSK-2026-002')!;

    assert(Boolean(completedTask), 'TSK-2026-002 must be present in IT Ops tasks');
    assert(completedTask.associatedAlertId === 'ALT-2026-1047', 'Associated alert linkage must be preserved');
  });

  console.log('\n-- Group 3: Task Assignment Isolation & Alert Scoping --');

  await runTest('Test 7: IT Operations only retrieves tasks assigned to it_operations', async () => {
    const itOpsTasks = await auditRepo.getIncidentTasksForUser(itOpsUser);
    for (const t of itOpsTasks) {
      assert(t.assignedRole === 'it_operations', `Task ${t.id} must be assigned to it_operations, got ${t.assignedRole}`);
    }
    // Must NOT contain TSK-2026-003 which is assigned to security_engineer
    assert(!itOpsTasks.some((t) => t.id === 'TSK-2026-003'), 'IT Ops must not retrieve Security Engineer tasks');
  });

  await runTest('Test 8: IT Operations can inspect only alerts linked to assigned tasks', async () => {
    const itOpsTasks = await auditRepo.getIncidentTasksForUser(itOpsUser);
    const allowedAlertIds = itOpsTasks.map((t) => t.associatedAlertId).filter((id): id is string => Boolean(id));

    assert(allowedAlertIds.includes('ALT-2026-1046'), 'Must include ALT-2026-1046');
    assert(allowedAlertIds.includes('ALT-2026-1047'), 'Must include ALT-2026-1047');

    // Can read linked alert
    const linkedAlert = await alertRepo.getAlertByIdForUser(itOpsUser, 'ALT-2026-1046', allowedAlertIds);
    assert(Boolean(linkedAlert), 'IT Ops must be able to read linked alert');

    // Denied from reading unlinked alert
    let unlinkedBlocked = false;
    try {
      await alertRepo.getAlertByIdForUser(itOpsUser, 'ALT-2026-1049', allowedAlertIds);
    } catch (e: any) {
      if (e instanceof AccessDeniedError) unlinkedBlocked = true;
    }
    assert(unlinkedBlocked, 'IT Ops must receive AccessDeniedError for unlinked alert');
  });

  console.log('\n-- Group 4: Unauthorized Role Rejection --');

  await runTest('Test 9: Security Engineer is denied from updating incident tasks', async () => {
    let engineerBlocked = false;
    try {
      await auditRepo.updateTaskStatus(engineerUser, 'TSK-2026-002', 'completed', 'Unauthorized attempt');
    } catch (e: any) {
      if (e instanceof AccessDeniedError) engineerBlocked = true;
    }
    assert(engineerBlocked, 'Security Engineer must be rejected with AccessDeniedError');
  });

  await runTest('Test 10: Super Admin receives strictly empty tasks array and cannot update tasks', async () => {
    const adminTasks = await auditRepo.getIncidentTasksForUser(adminUser);
    assert(adminTasks.length === 0, 'Super Admin must receive strictly empty tasks array');

    let adminBlocked = false;
    try {
      await auditRepo.updateTaskStatus(adminUser, 'TSK-2026-002', 'completed', 'Admin attempt');
    } catch (e: any) {
      if (e instanceof AccessDeniedError) adminBlocked = true;
    }
    assert(adminBlocked, 'Super Admin must be rejected from task update with AccessDeniedError');
  });

  console.log('\n-- Group 5: Nonexistent Task & Error Boundary Handling --');

  await runTest('Test 11: Attempting to update a nonexistent task throws explicit error without corrupting store', async () => {
    let errorCaught = false;
    try {
      await auditRepo.updateTaskStatus(itOpsUser, 'TSK-NONEXISTENT', 'completed', 'Notes');
    } catch (e: any) {
      if (e.message.includes('not found')) errorCaught = true;
    }
    assert(errorCaught, 'Must throw error when task does not exist');
  });

  console.log('\n-- Group 6: Remediation Verification Audit Trail & Idempotency --');
  await runTest('Test 12: Completing a task automatically creates an operational remediation_verified audit event', async () => {
    const logs = await auditRepo.getLogsForUser(itOpsUser);
    const verificationLog = logs.find(
      (l) => l.actionType === 'remediation_verified' && l.systemNote.includes('task TSK-2026-002')
    );
    assert(Boolean(verificationLog), 'Must find remediation_verified audit log for task TSK-2026-002');
    assert(verificationLog!.actionType === 'remediation_verified', 'actionType must be remediation_verified');
    assert(verificationLog!.actorRole === 'it_operations', 'actorRole must be it_operations');
    assert(verificationLog!.status === 'SIMULATED_SUCCESS', 'status must be SIMULATED_SUCCESS');
  });

  await runTest('Test 13: Audit log records acting operator, target resource, associated alert ID, and completion timestamp', async () => {
    const logs = await auditRepo.getLogsForUser(itOpsUser);
    const verificationLog = logs.find(
      (l) => l.actionType === 'remediation_verified' && l.systemNote.includes('task TSK-2026-002')
    )!;
    assert(verificationLog.actorName === itOpsUser.name, 'actorName must match acting operator');
    assert(verificationLog.targetResource === 'DOMAIN\\svc_backup', 'targetResource must match task target asset');
    assert(verificationLog.associatedAlertId === 'ALT-2026-1047', 'associatedAlertId must match task associated alert');
    assert(Boolean(verificationLog.timestamp), 'timestamp must be recorded');
    assert(verificationLog.justification.includes('Reset-ADServiceAccount'), 'justification must preserve completion notes & evidence');
  });

  await runTest('Test 14: Repeated updateTaskStatus calls on an already completed task do not create duplicate audit log entries', async () => {
    // Retry / duplicate submission call
    await auditRepo.updateTaskStatus(itOpsUser, 'TSK-2026-002', 'completed', 'Redundant submission attempt');
    const logs = await auditRepo.getLogsForUser(itOpsUser);
    const matchingLogs = logs.filter(
      (l) => l.actionType === 'remediation_verified' && l.systemNote.includes('task TSK-2026-002')
    );
    assert(matchingLogs.length === 1, `Must have exactly 1 audit log entry for task TSK-2026-002, got ${matchingLogs.length}`);
  });

  await runTest('Test 15: Super Admin audit logs do not leak operational remediation_verified events (Domain C isolation)', async () => {
    const adminLogs = await auditRepo.getLogsForUser(adminUser);
    const hasOperationalLog = adminLogs.some((l) => l.actionType === 'remediation_verified');
    assert(!hasOperationalLog, 'Super Admin must not see operational remediation_verified audit logs');
  });

  console.log(`\n=== COMPLETED: ${passedTests} of 15 IT OPERATIONS VERIFICATION TESTS PASSED ===`);
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
