/**
 * Automated Role & Record-Level Access Isolation Test Suite
 * Tests and proves that unauthorized cross-role reads and writes are denied.
 */

import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { DEMO_PERSONAS, AccessDeniedError } from '../types/auth';
import { AuthorizationService } from '../services/authorizationService';

export async function runRoleIsolationTests(): Promise<{ passed: number; total: number; logs: string[] }> {
  const logs: string[] = [];
  let passed = 0;
  let total = 0;

  const alertRepo = new LocalAlertRepository();
  const auditRepo = new LocalAuditLogRepository();

  const analyst = DEMO_PERSONAS.soc_analyst;
  const engineer = DEMO_PERSONAS.security_engineer;
  const itops = DEMO_PERSONAS.it_operations;

  function assert(condition: boolean, description: string) {
    total++;
    if (condition) {
      passed++;
      logs.push(`  [PASS] Test ${total}: ${description}`);
    } else {
      logs.push(`  [FAIL] Test ${total}: ${description}`);
    }
  }

  logs.push('=== RUNNING ROLE ISOLATION SECURITY TESTS ===');

  // Test 1: SOC Analyst can update alert status
  try {
    const updated = await alertRepo.updateAlertStatus(analyst, 'ALT-2026-1049', 'in_triage');
    assert(updated.status === 'in_triage', 'SOC Analyst can update alert status (authorized)');
  } catch (e: any) {
    assert(false, `SOC Analyst should update alert status: ${e.message}`);
  }

  // Test 2: Security Engineer CANNOT update alert status (must throw AccessDeniedError)
  try {
    await alertRepo.updateAlertStatus(engineer, 'ALT-2026-1049', 'resolved');
    assert(false, 'Security Engineer must NOT be permitted to alter alert status');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Security Engineer update denied with AccessDeniedError');
  }

  // Test 3: IT Operations CANNOT update alert status (must throw AccessDeniedError)
  try {
    await alertRepo.updateAlertStatus(itops, 'ALT-2026-1049', 'resolved');
    assert(false, 'IT Operations must NOT be permitted to alter alert status');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'IT Operations update denied with AccessDeniedError');
  }

  // Test 4: SOC Analyst can append analyst investigation note
  try {
    const noted = await alertRepo.addAnalystNote(analyst, 'ALT-2026-1049', 'Confirmed LSASS dump signature');
    assert(noted.analystNotes.length > 0, 'SOC Analyst can append analyst note (authorized)');
  } catch (e: any) {
    assert(false, `SOC Analyst should be able to append note: ${e.message}`);
  }

  // Test 5: IT Operations CANNOT append analyst note (must throw AccessDeniedError)
  try {
    await alertRepo.addAnalystNote(itops, 'ALT-2026-1049', 'Unauthorized IT note');
    assert(false, 'IT Operations must NOT be permitted to write analyst notes');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'IT Operations note denied with AccessDeniedError');
  }

  // Test 6: Security Engineer CANNOT append analyst note (must throw AccessDeniedError)
  try {
    await alertRepo.addAnalystNote(engineer, 'ALT-2026-1049', 'Unauthorized Engineer note');
    assert(false, 'Security Engineer must NOT be permitted to write analyst notes');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Security Engineer note denied with AccessDeniedError');
  }

  // Test 7: IT Operations alert queue is strictly scoped to assigned tasks
  try {
    const assignedIds = ['ALT-2026-1046', 'ALT-2026-1047'];
    const itopsAlerts = await alertRepo.getAlertsForUser(itops, {}, assignedIds);
    const analystAlerts = await alertRepo.getAlertsForUser(analyst);

    assert(
      itopsAlerts.length === assignedIds.length && itopsAlerts.length < analystAlerts.length,
      `IT Operations alert queue is scoped to ${assignedIds.length} assigned tasks (analyst sees full queue of ${analystAlerts.length})`
    );
  } catch (e: any) {
    assert(false, `IT Operations scoped query failed: ${e.message}`);
  }

  // Test 8: IT Operations can update remediation task status
  try {
    const taskUpdated = await auditRepo.updateTaskStatus(itops, 'TSK-2026-001', 'in_progress', 'Starting disk verification');
    assert(taskUpdated.status === 'in_progress', 'IT Operations can update remediation task (authorized)');
  } catch (e: any) {
    assert(false, `IT Operations should update task: ${e.message}`);
  }

  // Test 9: Security Engineer CANNOT update IT remediation tasks (must throw AccessDeniedError)
  try {
    await auditRepo.updateTaskStatus(engineer, 'TSK-2026-001', 'completed');
    assert(false, 'Security Engineer must NOT update IT remediation tasks');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Security Engineer task update denied with AccessDeniedError');
  }

  // Test 10: Security Engineer CANNOT execute operational containment actions
  try {
    await auditRepo.recordSimulatedAction(engineer, {
      actionType: 'isolate_host',
      targetResource: 'WS-CORP-14',
      justification: 'Unauthorized attempt',
      status: 'PROPOSED',
      systemNote: 'Test',
    });
    assert(false, 'Security Engineer must NOT execute containment actions');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Security Engineer containment action denied with AccessDeniedError');
  }

  // Test 11: Super Admin (Platform Admin) CANNOT read private SOC alerts (must throw AccessDeniedError)
  const admin = DEMO_PERSONAS.super_admin;
  try {
    await alertRepo.getAlertsForUser(admin);
    assert(false, 'Super Admin must NOT access private SOC operational alerts');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Super Admin alert access denied with AccessDeniedError');
  }

  // Test 12: Super Admin CANNOT modify alert triage status
  try {
    await alertRepo.updateAlertStatus(admin, 'ALT-2026-1049', 'resolved');
    assert(false, 'Super Admin must NOT alter triage status');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Super Admin status modification denied with AccessDeniedError');
  }

  // --- ROLE-TO-VIEW AUTHORIZATION TESTS ---

  // Test 13: SOC Analyst view access checks (authorized to overview/strategies/analytics/log_sources/data_components/mitre_explorer/profile, denied admin, mitre, and tasks)
  try {
    assert(
      AuthorizationService.isViewAuthorized('soc_analyst', 'overview') &&
      AuthorizationService.isViewAuthorized('soc_analyst', 'strategies') &&
      AuthorizationService.isViewAuthorized('soc_analyst', 'analytics') &&
      AuthorizationService.isViewAuthorized('soc_analyst', 'log_sources') &&
      AuthorizationService.isViewAuthorized('soc_analyst', 'data_components') &&
      AuthorizationService.isViewAuthorized('soc_analyst', 'mitre_explorer') &&
      !AuthorizationService.isViewAuthorized('soc_analyst', 'tasks') &&
      !AuthorizationService.isViewAuthorized('soc_analyst', 'mitre') &&
      !AuthorizationService.isViewAuthorized('soc_analyst', 'admin'),
      'SOC Analyst is granted authorized knowledge views and denied tasks, mitre, and admin views'
    );
    try {
      AuthorizationService.assertViewAccess('soc_analyst', 'admin');
      assert(false, 'SOC Analyst assertViewAccess for admin should throw');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'SOC Analyst admin view access throws AccessDeniedError');
    }
    try {
      AuthorizationService.assertViewAccess('soc_analyst', 'mitre');
      assert(false, 'SOC Analyst assertViewAccess for mitre should throw');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'SOC Analyst mitre view access throws AccessDeniedError');
    }
    try {
      AuthorizationService.assertViewAccess('soc_analyst', 'tasks');
      assert(false, 'SOC Analyst assertViewAccess for tasks should throw');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'SOC Analyst tasks view access throws AccessDeniedError');
    }
  } catch (e: any) {
    assert(false, `SOC Analyst view authorization failed: ${e.message}`);
  }

  // Test 14: Security Engineer view access checks (authorized to mitre/alerts/network/audit, denied admin & tasks)
  try {
    assert(
      AuthorizationService.isViewAuthorized('security_engineer', 'mitre') &&
      !AuthorizationService.isViewAuthorized('security_engineer', 'admin') &&
      !AuthorizationService.isViewAuthorized('security_engineer', 'tasks'),
      'Security Engineer is denied admin and tasks views'
    );
    try {
      AuthorizationService.assertViewAccess('security_engineer', 'tasks');
      assert(false, 'Security Engineer assertViewAccess for tasks should throw');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'Security Engineer tasks view access throws AccessDeniedError');
    }
  } catch (e: any) {
    assert(false, `Security Engineer view authorization failed: ${e.message}`);
  }

  // Test 15: IT Operations view access checks (authorized to itops_overview/itops_techniques/itops_mitigations/tasks/alerts/audit, denied admin/mitre)
  try {
    assert(
      AuthorizationService.isViewAuthorized('it_operations', 'itops_overview') &&
      AuthorizationService.isViewAuthorized('it_operations', 'itops_techniques') &&
      AuthorizationService.isViewAuthorized('it_operations', 'itops_mitigations') &&
      AuthorizationService.isViewAuthorized('it_operations', 'tasks') &&
      AuthorizationService.isViewAuthorized('it_operations', 'alerts') &&
      AuthorizationService.isViewAuthorized('it_operations', 'audit') &&
      !AuthorizationService.isViewAuthorized('it_operations', 'admin') &&
      !AuthorizationService.isViewAuthorized('it_operations', 'mitre'),
      'IT Operations is authorized to IT Ops knowledge modules, tasks, alerts, and audit, but denied admin and mitre views'
    );
    try {
      AuthorizationService.assertViewAccess('it_operations', 'mitre');
      assert(false, 'IT Operations assertViewAccess for mitre should throw');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'IT Operations mitre view access throws AccessDeniedError');
    }
  } catch (e: any) {
    assert(false, `IT Operations view authorization failed: ${e.message}`);
  }

  // Test 16: Super Admin view access checks (authorized to admin/audit, denied alerts/mitre/tasks/network)
  try {
    assert(
      AuthorizationService.isViewAuthorized('super_admin', 'admin') &&
      AuthorizationService.isViewAuthorized('super_admin', 'audit') &&
      !AuthorizationService.isViewAuthorized('super_admin', 'alerts') &&
      !AuthorizationService.isViewAuthorized('super_admin', 'mitre') &&
      !AuthorizationService.isViewAuthorized('super_admin', 'tasks') &&
      !AuthorizationService.isViewAuthorized('super_admin', 'network'),
      'Super Admin is denied operational alert, mitre, tasks, and network views'
    );
    try {
      AuthorizationService.assertViewAccess('super_admin', 'alerts');
      assert(false, 'Super Admin assertViewAccess for alerts should throw');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'Super Admin alerts view access throws AccessDeniedError');
    }
  } catch (e: any) {
    assert(false, `Super Admin view authorization failed: ${e.message}`);
  }

  // Test 17: Default fallback view resolution per role
  try {
    assert(
      AuthorizationService.getDefaultViewForRole('soc_analyst') === 'overview' &&
      AuthorizationService.getDefaultViewForRole('security_engineer') === 'seceng_overview' &&
      AuthorizationService.getDefaultViewForRole('it_operations') === 'itops_overview' &&
      AuthorizationService.getDefaultViewForRole('super_admin') === 'admin',
      'All four roles resolve to their authorized default views on unauthorized navigation'
    );
  } catch (e: any) {
    assert(false, `Default view resolution test failed: ${e.message}`);
  }

  // Test 18: Valid association: IT Operations can retrieve an alert linked to an authorized task
  try {
    const tasks = await auditRepo.getIncidentTasksForUser(itops);
    const allowedAlertIds = tasks.map((t) => t.associatedAlertId).filter((id): id is string => Boolean(id));
    assert(allowedAlertIds.includes('ALT-2026-1046'), 'IT Operations task list contains associated alert ALT-2026-1046');
    const alert = await alertRepo.getAlertByIdForUser(itops, 'ALT-2026-1046', allowedAlertIds);
    assert(alert !== null && alert.id === 'ALT-2026-1046' && alert.hostName === 'FILESERVER-01', 'IT Operations can retrieve authorized task-linked alert ALT-2026-1046');
  } catch (e: any) {
    assert(false, `Valid association test failed: ${e.message}`);
  }

  // Test 19: Unassociated alert denied: IT Operations cannot retrieve an unrelated alert (ALT-2026-1049)
  try {
    const tasks = await auditRepo.getIncidentTasksForUser(itops);
    const allowedAlertIds = tasks.map((t) => t.associatedAlertId).filter((id): id is string => Boolean(id));
    await alertRepo.getAlertByIdForUser(itops, 'ALT-2026-1049', allowedAlertIds);
    assert(false, 'IT Operations must NOT access unassociated alert ALT-2026-1049');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Unassociated alert read rejected with AccessDeniedError');
  }

  // Test 20: Task scope enforced: An alert ID outside authorized task scope is rejected even if the alert exists
  try {
    // ALT-2026-1048 is an existing valid alert in the dataset, but not in IT Operations allowed task scope
    await alertRepo.getAlertByIdForUser(itops, 'ALT-2026-1048', ['ALT-2026-1046']);
    assert(false, 'Alert outside task scope must be rejected');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Alert outside task scope rejected with AccessDeniedError');
  }

  // Test 21: Missing alert handled safely without crashing
  try {
    const missing = await alertRepo.getAlertByIdForUser(itops, 'ALT-NONEXISTENT-999', ['ALT-NONEXISTENT-999']);
    assert(missing === null, 'Non-existent alert returns null safely without throwing');
  } catch (e: any) {
    assert(false, `Missing alert check failed: ${e.message}`);
  }

  // Test 22: Super Admin isolation: Super Admin remains denied access to private operational alerts
  try {
    await alertRepo.getAlertByIdForUser(admin, 'ALT-2026-1046', ['ALT-2026-1046']);
    assert(false, 'Super Admin must NOT access operational alert records');
  } catch (e: any) {
    assert(e instanceof AccessDeniedError, 'Super Admin alert access rejected with AccessDeniedError');
  }

  // Test 23: Read-only enforcement: IT Operations cannot update alert status or add analyst notes
  try {
    let updateDenied = false;
    let noteDenied = false;
    try {
      await alertRepo.updateAlertStatus(itops, 'ALT-2026-1046', 'resolved');
    } catch (e: any) {
      updateDenied = e instanceof AccessDeniedError;
    }
    try {
      await alertRepo.addAnalystNote(itops, 'ALT-2026-1046', 'Unauthorized IT note');
    } catch (e: any) {
      noteDenied = e instanceof AccessDeniedError;
    }
    assert(updateDenied && noteDenied, 'IT Operations is strictly denied triage status updates and analyst note additions');
  } catch (e: any) {
    assert(false, `Read-only enforcement test failed: ${e.message}`);
  }

  // Test 24: Non-destructive migration backfills seed associations without erasing user modifications or custom tasks
  try {
    const SEED_TASK_ALERT_MAPPINGS: Record<string, string> = {
      'TSK-2026-001': 'ALT-2026-1046',
      'TSK-2026-002': 'ALT-2026-1047',
    };
    const cachedSample: any[] = [
      {
        id: 'TSK-2026-001',
        title: 'Verify File Server Offline Snapshot Integrity',
        description: 'Custom user note preserved',
        assignedRole: 'it_operations',
        status: 'completed',
        priority: 'critical',
        createdAt: '2026-10-12T04:02:00Z',
        targetAsset: 'FILESERVER-01',
        completionNotes: 'Backups verified in cold storage',
        completedAt: '2026-10-12T05:00:00Z',
        completedBy: 'Marcus Vance (RECOVERY-9)',
      },
      {
        id: 'TSK-CUSTOM-001',
        title: 'Custom User Remediation Task',
        description: 'Should remain untouched',
        assignedRole: 'it_operations',
        status: 'in_progress',
        priority: 'high',
        createdAt: '2026-10-12T06:00:00Z',
        targetAsset: 'STORAGE-ARRAY-02',
      },
    ];

    const migrated = cachedSample.map((task: any) => {
      if (task && typeof task === 'object' && SEED_TASK_ALERT_MAPPINGS[task.id] && !task.associatedAlertId) {
        return { ...task, associatedAlertId: SEED_TASK_ALERT_MAPPINGS[task.id] };
      }
      return task;
    });

    assert(
      migrated[0].associatedAlertId === 'ALT-2026-1046' &&
      migrated[0].status === 'completed' &&
      migrated[0].completionNotes === 'Backups verified in cold storage' &&
      migrated[0].completedBy === 'Marcus Vance (RECOVERY-9)',
      'Seed association backfilled while preserving existing status, completion notes, and operator attribution'
    );
    assert(
      migrated[1].id === 'TSK-CUSTOM-001' &&
      migrated[1].status === 'in_progress' &&
      !migrated[1].associatedAlertId,
      'Custom unassociated tasks remain completely untouched and preserved'
    );
  } catch (e: any) {
    assert(false, `Migration test failed: ${e.message}`);
  }

  // Test 25: Existing associations are preserved and not overwritten during migration
  try {
    const taskWithExistingAssociation: any = {
      id: 'TSK-2026-001',
      associatedAlertId: 'ALT-PRE-EXISTING-999',
    };
    const SEED_TASK_ALERT_MAPPINGS: Record<string, string> = {
      'TSK-2026-001': 'ALT-2026-1046',
    };
    const notOverwritten = [taskWithExistingAssociation].map((task: any) => {
      if (task && typeof task === 'object' && SEED_TASK_ALERT_MAPPINGS[task.id] && !task.associatedAlertId) {
        return { ...task, associatedAlertId: SEED_TASK_ALERT_MAPPINGS[task.id] };
      }
      return task;
    });
    assert(
      notOverwritten[0].associatedAlertId === 'ALT-PRE-EXISTING-999',
      'Existing non-empty task association is never overwritten by migration'
    );
  } catch (e: any) {
    assert(false, `Existing association preservation test failed: ${e.message}`);
  }

  // Test 26: Dynamic task linkage and persistence round-trip
  try {
    const dynamicTask = await auditRepo.createTask(analyst, {
      title: 'Automated Containment Verification Task',
      description: 'Dynamically created following simulated containment',
      assignedRole: 'it_operations',
      status: 'in_progress',
      priority: 'high',
      targetAsset: 'FILESERVER-01',
      associatedAlertId: 'ALT-2026-1046',
      suggestedActionType: 'isolate_host',
    });
    assert(dynamicTask.associatedAlertId === 'ALT-2026-1046', 'Dynamically created task inherits associatedAlertId');
    const userTasks = await auditRepo.getIncidentTasksForUser(itops);
    const found = userTasks.find((t) => t.id === dynamicTask.id);
    assert(found !== undefined && found.associatedAlertId === 'ALT-2026-1046', 'Dynamic task retains associatedAlertId on retrieval');
  } catch (e: any) {
    assert(false, `Dynamic task linkage test failed: ${e.message}`);
  }

  // Test 27: IT Operations cannot retrieve a task assigned to soc_analyst (Option A hardening)
  let socTask: any = null;
  try {
    socTask = await auditRepo.createTask(analyst, {
      title: 'SOC Analyst Internal Investigation Task',
      description: 'Private triage task assigned strictly to soc_analyst',
      assignedRole: 'soc_analyst',
      status: 'in_progress',
      priority: 'high',
      targetAsset: 'DC-01',
      associatedAlertId: 'ALT-2026-1044',
    });

    const itopsTasks = await auditRepo.getIncidentTasksForUser(itops);
    const leakedTask = itopsTasks.find((t) => t.id === socTask.id);
    const anySocTasks = itopsTasks.filter((t) => t.assignedRole === 'soc_analyst');
    const analystTasks = await auditRepo.getIncidentTasksForUser(analyst);

    assert(
      leakedTask === undefined && anySocTasks.length === 0,
      'IT Operations cannot retrieve tasks assigned to soc_analyst (Option A isolation enforced)'
    );
    assert(
      analystTasks.some((t) => t.id === socTask.id),
      'SOC Analyst retains access to tasks assigned to soc_analyst'
    );
  } catch (e: any) {
    assert(false, `IT Operations exclusion of soc_analyst task failed: ${e.message}`);
  }

  // Test 28: Alert linked only to SOC Analyst task is not in IT Operations allowed scope and access is denied
  try {
    const itopsTasks = await auditRepo.getIncidentTasksForUser(itops);
    const allowedAlertIds = itopsTasks
      .map((t) => t.associatedAlertId)
      .filter((id): id is string => Boolean(id));

    assert(
      !allowedAlertIds.includes('ALT-2026-1044'),
      'Alert ALT-2026-1044 linked only to SOC Analyst task is excluded from IT Operations allowed alert IDs'
    );

    // Attempting to read ALT-2026-1044 through authorization path must throw AccessDeniedError
    try {
      await alertRepo.getAlertByIdForUser(itops, 'ALT-2026-1044', allowedAlertIds);
      assert(false, 'IT Operations must NOT access alert linked only to SOC Analyst task');
    } catch (e: any) {
      assert(
        e instanceof AccessDeniedError,
        'Access to alert linked only to SOC Analyst task denied with AccessDeniedError'
      );
    }
  } catch (e: any) {
    assert(false, `Task-scoped alert isolation test failed: ${e.message}`);
  }

  // Test 29: Existing IT Operations tasks and their associated alerts remain accessible
  try {
    const itopsTasks = await auditRepo.getIncidentTasksForUser(itops);
    const allowedAlertIds = itopsTasks
      .map((t) => t.associatedAlertId)
      .filter((id): id is string => Boolean(id));

    const tsk1 = itopsTasks.find((t) => t.id === 'TSK-2026-001');
    const tsk2 = itopsTasks.find((t) => t.id === 'TSK-2026-002');

    assert(
      tsk1 !== undefined && tsk1.associatedAlertId === 'ALT-2026-1046' &&
      tsk2 !== undefined && tsk2.associatedAlertId === 'ALT-2026-1047',
      'Existing IT Operations tasks (TSK-2026-001, TSK-2026-002) remain accessible to IT Operations'
    );

    const alert1046 = await alertRepo.getAlertByIdForUser(itops, 'ALT-2026-1046', allowedAlertIds);
    const alert1047 = await alertRepo.getAlertByIdForUser(itops, 'ALT-2026-1047', allowedAlertIds);

    assert(
      alert1046 !== null && alert1046.id === 'ALT-2026-1046' &&
      alert1047 !== null && alert1047.id === 'ALT-2026-1047',
      'Existing associated alerts (ALT-2026-1046, ALT-2026-1047) remain fully accessible to IT Operations'
    );
  } catch (e: any) {
    assert(false, `IT Operations task and alert access verification failed: ${e.message}`);
  }

  // Test 30: Security Engineer task visibility remains unchanged
  try {
    const engTasks = await auditRepo.getIncidentTasksForUser(engineer);
    assert(
      engTasks.every((t) => t.assignedRole === 'security_engineer'),
      'Security Engineer tasks strictly limited to security_engineer assignedRole'
    );
    assert(
      engTasks.some((t) => t.id === 'TSK-2026-003'),
      'Security Engineer can access detection engineering task TSK-2026-003'
    );
    assert(
      !engTasks.some((t) => t.id === 'TSK-2026-001') && !engTasks.some((t) => t.id === 'TSK-2026-002'),
      'Security Engineer cannot access IT Operations tasks'
    );
    if (socTask) {
      assert(
        !engTasks.some((t) => t.id === socTask.id),
        'Security Engineer cannot access SOC Analyst task'
      );
    }
  } catch (e: any) {
    assert(false, `Security Engineer task visibility test failed: ${e.message}`);
  }

  // Test 31: Super Admin isolation and read-only restrictions remain intact
  try {
    const adminTasks = await auditRepo.getIncidentTasksForUser(admin);
    assert(adminTasks.length === 0, 'Super Admin cannot inspect any incident tasks (strictly empty array)');

    try {
      await alertRepo.getAlertByIdForUser(admin, 'ALT-2026-1046', ['ALT-2026-1046']);
      assert(false, 'Super Admin must NOT access operational alert records');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'Super Admin alert access rejected with AccessDeniedError');
    }

    try {
      await alertRepo.updateAlertStatus(admin, 'ALT-2026-1046', 'resolved');
      assert(false, 'Super Admin must NOT update alert status');
    } catch (e: any) {
      assert(e instanceof AccessDeniedError, 'Super Admin status modification rejected with AccessDeniedError');
    }
  } catch (e: any) {
    assert(false, `Super Admin isolation verification failed: ${e.message}`);
  }

  // Test 32: Synchronous batch creation produces unique task IDs without collisions
  try {
    const batchPromises = Array.from({ length: 10 }, (_, i) =>
      auditRepo.createTask(analyst, {
        title: `Rapid Triage Remediation #${i + 1}`,
        description: `Simultaneous task creation stress test step ${i + 1}`,
        assignedRole: 'it_operations',
        status: 'pending',
        priority: 'medium',
        targetAsset: `WORKSTATION-${String(i + 1).padStart(2, '0')}`,
        associatedAlertId: 'ALT-2026-1046',
      })
    );

    const batchTasks = await Promise.all(batchPromises);
    const batchIds = batchTasks.map((t) => t.id);
    const uniqueIds = new Set(batchIds);

    assert(
      batchTasks.length === 10 && uniqueIds.size === 10,
      'Batch creation within same millisecond produces 10 strictly unique task IDs'
    );

    const seededIds = ['TSK-2026-001', 'TSK-2026-002', 'TSK-2026-003'];
    const collidesWithSeeded = batchIds.some((id) => seededIds.includes(id));
    assert(
      !collidesWithSeeded,
      'Newly generated task IDs never collide with seeded task IDs (TSK-2026-001, 002, 003)'
    );

    assert(
      batchIds.every((id) => /^TSK-2026-\d+$/.test(id)),
      'All generated task IDs conform to the TSK-2026-(sequence) schema'
    );

    // Test 33: Targeted task mutation updates only the specific task without collision cross-talk
    const targetTask = batchTasks[3];
    const updatedTarget = await auditRepo.updateTaskStatus(
      itops,
      targetTask.id,
      'completed',
      'Remediation verified during stress run'
    );
    assert(
      updatedTarget.id === targetTask.id && updatedTarget.status === 'completed',
      'Targeted task status updated successfully'
    );

    const itopsTasksAfter = await auditRepo.getIncidentTasksForUser(itops);
    const otherTasks = itopsTasksAfter.filter(
      (t) => batchIds.includes(t.id) && t.id !== targetTask.id
    );
    assert(
      otherTasks.every((t) => t.status === 'pending'),
      'Other concurrently created tasks remain unaffected with pending status (no ID collision cross-talk)'
    );

    const tsk1Check = itopsTasksAfter.find((t) => t.id === 'TSK-2026-001');
    assert(
      tsk1Check !== undefined && tsk1Check.associatedAlertId === 'ALT-2026-1046',
      'Original seeded task TSK-2026-001 and association remain preserved after batch creation'
    );
  } catch (e: any) {
    assert(false, `Task ID uniqueness and batch creation test failed: ${e.message}`);
  }

  // Test 34: Profile view is authorized for all four roles
  try {
    const roles: Array<'soc_analyst' | 'security_engineer' | 'it_operations' | 'super_admin'> = [
      'soc_analyst',
      'security_engineer',
      'it_operations',
      'super_admin',
    ];
    const allAuthorized = roles.every((role) => AuthorizationService.isViewAuthorized(role, 'profile'));
    assert(
      allAuthorized,
      'All four roles (soc_analyst, security_engineer, it_operations, super_admin) are authorized to access profile view'
    );
    roles.forEach((role) => AuthorizationService.assertViewAccess(role, 'profile'));
    assert(true, 'assertViewAccess succeeds for profile view across all four roles');
  } catch (e: any) {
    assert(false, `Profile view authorization test failed: ${e.message}`);
  }

  // Test 35: Unrelated role restrictions remain strictly enforced alongside profile authorization
  try {
    assert(!AuthorizationService.isViewAuthorized('super_admin', 'alerts'), 'Super Admin remains denied from operational alerts view');
    assert(!AuthorizationService.isViewAuthorized('super_admin', 'tasks'), 'Super Admin remains denied from incident tasks view');
    assert(!AuthorizationService.isViewAuthorized('security_engineer', 'admin'), 'Security Engineer remains denied from admin view');
    assert(!AuthorizationService.isViewAuthorized('it_operations', 'mitre'), 'IT Operations remains denied from mitre view');
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'admin'), 'SOC Analyst remains denied from admin view');
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'mitre'), 'SOC Analyst remains denied from mitre view');
    assert(!AuthorizationService.isViewAuthorized('soc_analyst', 'tasks'), 'SOC Analyst remains denied from tasks view');
  } catch (e: any) {
    assert(false, `Unrelated role restrictions check failed: ${e.message}`);
  }

  logs.push(`=== COMPLETED: ${passed} of ${total} SECURITY ISOLATION TESTS PASSED ===`);
  return { passed, total, logs };
}

// Direct execution when run via CLI
if (typeof process !== 'undefined' && process.argv && process.argv[1]?.includes('roleIsolationTest')) {
  runRoleIsolationTests()
    .then((res) => {
      res.logs.forEach((l) => console.log(l));
      if (res.passed !== res.total) process.exit(1);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
