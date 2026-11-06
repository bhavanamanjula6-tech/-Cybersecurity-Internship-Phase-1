/**
 * Automated Verification Test for Collaboration Phase 1
 *
 * Verifies:
 * 1. SOC Analysts can manually create remediation tasks from an alert and assign them to IT Operations.
 * 2. Required fields validation (title, description, targetAsset, associatedAlertId).
 * 3. Invariants: assignedRole = 'it_operations', status = 'pending', associatedAlertId correctly linked.
 * 4. Role Authorization: SOC Analyst allowed; IT Operations, Security Engineer, Super Admin denied.
 * 5. Retrieval by IT Operations: IT Ops retrieves the created task.
 * 6. Super Admin operational isolation: Super Admin receives empty task list.
 */

import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { IncidentTask } from '../types/audit';

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
  console.log('=== RUNNING COLLABORATION PHASE 1 VERIFICATION TESTS ===\n');

  const analystUser: UserProfile = DEMO_PERSONAS.soc_analyst;
  const itOpsUser: UserProfile = DEMO_PERSONAS.it_operations;
  const engineerUser: UserProfile = DEMO_PERSONAS.security_engineer;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;

  const auditRepo = new LocalAuditLogRepository();
  const alertRepo = new LocalAlertRepository();

  const targetAlertId = 'ALT-2026-1049';

  console.log('-- Group 1: Required Fields & Input Validation --');

  await runTest('Test 1: Rejects task creation when title is missing or empty', async () => {
    let threw = false;
    try {
      await auditRepo.createTask(analystUser, {
        title: '   ',
        description: 'Quarantine host from local subnet',
        targetAsset: 'SRV-CORP-01',
        priority: 'high',
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: targetAlertId,
      });
    } catch (err: any) {
      threw = true;
      assert(err.message.includes('Task title is required'), `Unexpected error: ${err.message}`);
    }
    assert(threw, 'Expected missing title to throw');
  });

  await runTest('Test 2: Rejects task creation when description is missing or empty', async () => {
    let threw = false;
    try {
      await auditRepo.createTask(analystUser, {
        title: 'Quarantine host',
        description: '',
        targetAsset: 'SRV-CORP-01',
        priority: 'high',
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: targetAlertId,
      });
    } catch (err: any) {
      threw = true;
      assert(err.message.includes('Task description and remediation instructions are required'), `Unexpected error: ${err.message}`);
    }
    assert(threw, 'Expected missing description to throw');
  });

  await runTest('Test 3: Rejects task creation when target asset is missing or empty', async () => {
    let threw = false;
    try {
      await auditRepo.createTask(analystUser, {
        title: 'Quarantine host',
        description: 'Execute host isolation procedure per IR-01',
        targetAsset: '  ',
        priority: 'high',
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: targetAlertId,
      });
    } catch (err: any) {
      threw = true;
      assert(err.message.includes('Target asset is required'), `Unexpected error: ${err.message}`);
    }
    assert(threw, 'Expected missing targetAsset to throw');
  });

  await runTest('Test 4: Rejects task creation when associatedAlertId is missing or empty', async () => {
    let threw = false;
    try {
      await auditRepo.createTask(analystUser, {
        title: 'Quarantine host',
        description: 'Execute host isolation procedure per IR-01',
        targetAsset: 'SRV-CORP-01',
        priority: 'high',
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: '',
      });
    } catch (err: any) {
      threw = true;
      assert(err.message.includes('Associated alert ID is required'), `Unexpected error: ${err.message}`);
    }
    assert(threw, 'Expected missing associatedAlertId to throw');
  });

  console.log('\n-- Group 2: Role Authorization Invariants --');

  await runTest('Test 5: SOC Analyst is authorized to create tasks', async () => {
    const task = await auditRepo.createTask(analystUser, {
      title: 'Quarantine compromised endpoint',
      description: 'Host observed performing LSASS memory dump. Isolate from subnet and verify shadow copy integrity.',
      targetAsset: 'WS-FINANCE-04 (192.168.20.44)',
      priority: 'critical',
      assignedRole: 'it_operations',
      status: 'pending',
      associatedAlertId: targetAlertId,
    });

    assert(Boolean(task.id), 'Task ID must be generated');
    assert(task.id.startsWith('TSK-2026-'), `Task ID must follow format TSK-2026-###, got ${task.id}`);
    assert(task.assignedRole === 'it_operations', `Assigned role must be it_operations, got ${task.assignedRole}`);
    assert(task.status === 'pending', `Status must be pending, got ${task.status}`);
    assert(task.associatedAlertId === targetAlertId, `Associated alert ID must be ${targetAlertId}`);
    assert(task.priority === 'critical', `Priority must be critical, got ${task.priority}`);
    assert(Boolean(task.createdAt), 'CreatedAt timestamp must exist');
  });

  await runTest('Test 6: IT Operations is denied from creating tasks (AccessDeniedError)', async () => {
    let threw = false;
    try {
      await auditRepo.createTask(itOpsUser, {
        title: 'Unauthorized IT Ops task',
        description: 'IT Ops attempting to create an incident task',
        targetAsset: 'SRV-01',
        priority: 'medium',
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: targetAlertId,
      });
    } catch (err: any) {
      threw = true;
      assert(err instanceof AccessDeniedError, 'Expected AccessDeniedError');
      assert(err.userRole === 'it_operations', 'Error should identify userRole');
    }
    assert(threw, 'Expected IT Operations creation to be rejected');
  });

  await runTest('Test 7: Security Engineer is denied from creating tasks (AccessDeniedError)', async () => {
    let threw = false;
    try {
      await auditRepo.createTask(engineerUser, {
        title: 'Unauthorized Engineer task',
        description: 'Engineer attempting to create an incident task',
        targetAsset: 'SRV-01',
        priority: 'medium',
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: targetAlertId,
      });
    } catch (err: any) {
      threw = true;
      assert(err instanceof AccessDeniedError, 'Expected AccessDeniedError');
      assert(err.userRole === 'security_engineer', 'Error should identify userRole');
    }
    assert(threw, 'Expected Security Engineer creation to be rejected');
  });

  await runTest('Test 8: Super Admin is denied from creating tasks (AccessDeniedError)', async () => {
    let threw = false;
    try {
      await auditRepo.createTask(adminUser, {
        title: 'Unauthorized Admin task',
        description: 'Super Admin attempting to create an incident task',
        targetAsset: 'SRV-01',
        priority: 'medium',
        assignedRole: 'it_operations',
        status: 'pending',
        associatedAlertId: targetAlertId,
      });
    } catch (err: any) {
      threw = true;
      assert(err instanceof AccessDeniedError, 'Expected AccessDeniedError');
      assert(err.userRole === 'super_admin', 'Error should identify userRole');
    }
    assert(threw, 'Expected Super Admin creation to be rejected');
  });

  console.log('\n-- Group 3: Task Retrieval & Cross-Role Visibility --');

  await runTest('Test 9: IT Operations retrieves assigned task in their task queue', async () => {
    // Create a specific identifiable task
    const testTitle = `Specific IT Ops Remediation ${Date.now()}`;
    const created = await auditRepo.createTask(analystUser, {
      title: testTitle,
      description: 'Reset Kerberos tickets for compromised domain admin account.',
      targetAsset: 'DC-PRIMARY-01',
      priority: 'high',
      assignedRole: 'it_operations',
      status: 'pending',
      associatedAlertId: targetAlertId,
    });

    const itOpsTasks = await auditRepo.getIncidentTasksForUser(itOpsUser);
    const found = itOpsTasks.find((t) => t.id === created.id);

    assert(Boolean(found), `Task ${created.id} must be visible to IT Operations`);
    assert(found?.title === testTitle, 'Task title must match');
    assert(found?.status === 'pending', 'Task status must be pending');
    assert(found?.assignedRole === 'it_operations', 'Task assignedRole must be it_operations');
    assert(found?.associatedAlertId === targetAlertId, 'Associated alert ID must match');
  });

  await runTest('Test 10: Super Admin receives empty task list (Domain Isolation Invariant)', async () => {
    const adminTasks = await auditRepo.getIncidentTasksForUser(adminUser);
    assert(Array.isArray(adminTasks), 'Expected array');
    assert(adminTasks.length === 0, `Super Admin must receive 0 incident tasks, got ${adminTasks.length}`);
  });

  await runTest('Test 11: IT Operations can inspect the alert linked to the assigned task', async () => {
    const alert = await alertRepo.getAlertByIdForUser(itOpsUser, targetAlertId, [targetAlertId]);
    assert(Boolean(alert), `IT Operations must be able to inspect alert ${targetAlertId}`);
    assert(alert?.id === targetAlertId, 'Alert ID must match');
  });

  console.log('\n=== ALL COLLABORATION PHASE 1 VERIFICATION TESTS PASSED SUCCESSFULLY ===');
}

main().catch((err) => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
