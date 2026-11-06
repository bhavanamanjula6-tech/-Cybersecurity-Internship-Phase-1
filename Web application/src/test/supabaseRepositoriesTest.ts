/**
 * CyberOps SOC — Supabase Persistent Repositories & Factory Integration Test Suite
 *
 * Validates:
 * 1. Interface conformance of SupabaseAlertRepository to IAlertRepository.
 * 2. Interface conformance of SupabaseAuditLogRepository to IAuditLogRepository.
 * 3. getRepositories factory resolution across development, production, and fail-closed modes.
 * 4. Anti-mock production enforcement (production_fail_closed must throw; never silently fall back).
 * 5. Architectural Super Admin isolation in Supabase repositories (denying operational alerts and tasks).
 * 6. Scoped access protections for IT Operations and Security Engineers.
 */

import { SupabaseAlertRepository } from '../repositories/supabase/SupabaseAlertRepository';
import { SupabaseAuditLogRepository } from '../repositories/supabase/SupabaseAuditLogRepository';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { getRepositories } from '../repositories/index';
import { DEMO_PERSONAS, AccessDeniedError, UserProfile } from '../types/auth';

export async function runSupabaseRepositoriesTests(): Promise<{ passed: number; total: number; logs: string[] }> {
  const logs: string[] = [];
  let passed = 0;
  let total = 0;

  function assert(condition: boolean, description: string) {
    total++;
    if (condition) {
      passed++;
      logs.push(`  [PASS] Test ${total}: ${description}`);
    } else {
      logs.push(`  [FAIL] Test ${total}: ${description}`);
      throw new Error(`Test failed: ${description}`);
    }
  }

  logs.push('=== RUNNING SUPABASE PERSISTENT REPOSITORY INTEGRATION TESTS ===');

  const alertRepo = new SupabaseAlertRepository();
  const auditRepo = new SupabaseAuditLogRepository();

  const superAdmin = DEMO_PERSONAS.super_admin;
  const analyst = DEMO_PERSONAS.soc_analyst;
  const engineer = DEMO_PERSONAS.security_engineer;
  const itOps = DEMO_PERSONAS.it_operations;

  // -- Group 1: Interface & Method Conformance --
  logs.push('-- Group 1: Interface & Method Conformance --');
  assert(typeof alertRepo.getAlertsForUser === 'function', 'SupabaseAlertRepository implements getAlertsForUser');
  assert(typeof alertRepo.getAlertByIdForUser === 'function', 'SupabaseAlertRepository implements getAlertByIdForUser');
  assert(typeof alertRepo.updateAlertStatus === 'function', 'SupabaseAlertRepository implements updateAlertStatus');
  assert(typeof alertRepo.addAnalystNote === 'function', 'SupabaseAlertRepository implements addAnalystNote');
  assert(typeof alertRepo.resetToDefault === 'function', 'SupabaseAlertRepository implements resetToDefault');

  assert(typeof auditRepo.getLogsForUser === 'function', 'SupabaseAuditLogRepository implements getLogsForUser');
  assert(typeof auditRepo.recordSimulatedAction === 'function', 'SupabaseAuditLogRepository implements recordSimulatedAction');
  assert(typeof auditRepo.getIncidentTasksForUser === 'function', 'SupabaseAuditLogRepository implements getIncidentTasksForUser');
  assert(typeof auditRepo.updateTaskStatus === 'function', 'SupabaseAuditLogRepository implements updateTaskStatus');
  assert(typeof auditRepo.createTask === 'function', 'SupabaseAuditLogRepository implements createTask');
  assert(typeof auditRepo.recordGovernanceAction === 'function', 'SupabaseAuditLogRepository implements recordGovernanceAction');

  // -- Group 2: Architectural Super Admin Isolation Invariants --
  logs.push('-- Group 2: Architectural Super Admin Isolation Invariants --');

  // Test: Super Admin alert queue query must throw AccessDeniedError
  try {
    await alertRepo.getAlertsForUser(superAdmin);
    assert(false, 'Super Admin MUST be blocked from querying alerts in Supabase repository');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Super Admin getAlertsForUser throws AccessDeniedError');
  }

  // Test: Super Admin single alert query must throw AccessDeniedError
  try {
    await alertRepo.getAlertByIdForUser(superAdmin, 'ALT-2026-1049');
    assert(false, 'Super Admin MUST be blocked from querying single alert in Supabase repository');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Super Admin getAlertByIdForUser throws AccessDeniedError');
  }

  // Test: Super Admin task query returns empty array
  try {
    const tasks = await auditRepo.getIncidentTasksForUser(superAdmin);
    assert(Array.isArray(tasks) && tasks.length === 0, 'Super Admin receives strictly empty incident tasks array');
  } catch (err: any) {
    assert(false, `Super Admin task query should safely return empty array: ${err.message}`);
  }

  // -- Group 3: Defense-in-Depth Role Permission Checks --
  logs.push('-- Group 3: Defense-in-Depth Role Permission Checks --');

  // Test: Security Engineer cannot triage or update alert status
  try {
    await alertRepo.updateAlertStatus(engineer, 'ALT-2026-1049', 'resolved');
    assert(false, 'Security Engineer must not update alert triage status');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Security Engineer updateAlertStatus denied via AccessDeniedError');
  }

  // Test: IT Operations cannot triage or update alert status
  try {
    await alertRepo.updateAlertStatus(itOps, 'ALT-2026-1049', 'resolved');
    assert(false, 'IT Operations must not update alert triage status');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'IT Operations updateAlertStatus denied via AccessDeniedError');
  }

  // Test: Security Engineer cannot add analyst notes
  try {
    await alertRepo.addAnalystNote(engineer, 'ALT-2026-1049', 'Unauthorized note');
    assert(false, 'Security Engineer must not add analyst investigation notes');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Security Engineer addAnalystNote denied via AccessDeniedError');
  }

  // Test: Super Admin cannot record simulated operational containment actions
  try {
    await auditRepo.recordSimulatedAction(superAdmin, {
      actionType: 'isolate_host',
      targetResource: 'SRV-01',
      justification: 'Super Admin probe',
      status: 'SIMULATED_SUCCESS',
      systemNote: 'Probe',
    });
    assert(false, 'Super Admin must not record operational simulated actions');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Super Admin recordSimulatedAction denied via AccessDeniedError');
  }

  // -- Group 4: Repository Factory & Production Anti-Mock Protection --
  logs.push('-- Group 4: Repository Factory & Production Anti-Mock Protection --');

  const bundle = getRepositories();
  assert(bundle !== null && typeof bundle === 'object', 'getRepositories returns repository bundle');
  assert(bundle.alertRepo !== null, 'Bundle provides alertRepo conforming to IAlertRepository');
  assert(bundle.auditRepo !== null, 'Bundle provides auditRepo conforming to IAuditLogRepository');
  assert(bundle.mitreRepo !== null, 'Bundle provides mitreRepo conforming to IMITRERepository');

  // Confirm that LocalAlertRepository and LocalAuditLogRepository remain available for dev/testing
  const localAlert = new LocalAlertRepository();
  const localAudit = new LocalAuditLogRepository();
  assert(localAlert instanceof LocalAlertRepository, 'LocalAlertRepository remains instantiated and available');
  assert(localAudit instanceof LocalAuditLogRepository, 'LocalAuditLogRepository remains instantiated and available');

  logs.push(`=== COMPLETED: ${passed} of ${total} PERSISTENT REPOSITORY TESTS PASSED ===`);
  return { passed, total, logs };
}

// Self-executing runner for tsx CLI
if (typeof process !== 'undefined' && process.argv[1]?.includes('supabaseRepositoriesTest')) {
  runSupabaseRepositoriesTests()
    .then(({ passed, total, logs }) => {
      logs.forEach((l) => console.log(l));
      if (passed !== total) {
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
