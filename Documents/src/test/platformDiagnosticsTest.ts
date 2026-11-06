/**
 * CyberOps SOC — Super Admin Platform Diagnostics Test Suite (Phase 1 Hardened)
 *
 * Verifies Phase 1 diagnostic capabilities & security hardening:
 * 1. Demo persona count derived strictly from DEMO_PERSONAS (not hardcoded).
 * 2. Environment information accuracy and graceful handling of unavailable values.
 * 3. Browser-storage availability handling of accessible, throwing, and missing storage.
 * 4. Strict non-destructive behavior: zero keys created, modified, or cleared.
 * 5. Security Hardening SEC-01: Raw exception details stripped; generic sanitized error messages.
 * 6. Security Hardening RES-01: Protected window.localStorage property resolution.
 * 7. Security Hardening SEC-02: Zero reads of authentication session keys (ai_soc_auth_session_v1).
 * 8. Security Hardening INF-01: Logical provenance labels used exclusively instead of filesystem paths.
 * 9. Super Admin operational data isolation remains strictly enforced.
 */

import { DEMO_PERSONAS } from '../types/auth';
import { PlatformDiagnosticsService } from '../services/platformDiagnosticsService';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { AccessDeniedError } from '../types/auth';

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

export async function runPlatformDiagnosticsTests(): Promise<{ passed: number; total: number }> {
  console.log('=== RUNNING SUPER ADMIN PLATFORM DIAGNOSTICS TESTS (HARDENED) ===\n');

  const alertRepo = new LocalAlertRepository();
  const auditRepo = new LocalAuditLogRepository();
  const admin = DEMO_PERSONAS.super_admin;

  // --------------------------------------------------------------------------
  // Group 1: Demo Persona Count Derivation & Logical Provenance (INF-01)
  // --------------------------------------------------------------------------
  console.log('-- Group 1: Demo Persona Count Derivation & Logical Provenance --');

  // Test 1: Count derived from actual DEMO_PERSONAS source of truth
  const actualPersonaCount = Object.keys(DEMO_PERSONAS).length;
  const personaDiag = PlatformDiagnosticsService.evaluateDemoPersonas(DEMO_PERSONAS);
  assert(
    personaDiag.status === 'Pass',
    `Demo persona check status is "Pass" when evaluating DEMO_PERSONAS (got "${personaDiag.status}")`
  );
  assert(
    personaDiag.value === `${actualPersonaCount} Demo Personas`,
    `Demo persona value is "${actualPersonaCount} Demo Personas" (got "${personaDiag.value}")`
  );
  assert(
    personaDiag.label === 'Demo Personas',
    `Metric label is strictly "Demo Personas", not registered users (got "${personaDiag.label}")`
  );
  assert(
    personaDiag.detail.includes('does not count arbitrary sessions as registered users'),
    'Diagnostic detail explicitly disclaims counting arbitrary sessions as registered users'
  );

  // Test 2: INF-01 - Logical provenance label used instead of filesystem path
  assert(
    personaDiag.provenance === 'Demo Persona Registry',
    `Persona provenance is logical label "Demo Persona Registry" (got "${personaDiag.provenance}")`
  );
  assert(
    !personaDiag.provenance.includes('/') && !personaDiag.provenance.includes('.ts'),
    'Persona provenance contains no filesystem paths or file extensions'
  );

  // Test 3: Dynamic response to persona record changes (proving it is NOT hardcoded)
  const mockPersonas = {
    persona_a: { id: '1', name: 'A', email: 'a@test', role: 'soc_analyst', callsign: 'A', title: 'T' },
    persona_b: { id: '2', name: 'B', email: 'b@test', role: 'it_operations', callsign: 'B', title: 'T' },
  };
  const dynamicDiag = PlatformDiagnosticsService.evaluateDemoPersonas(mockPersonas as any);
  assert(
    dynamicDiag.value === '2 Demo Personas' && dynamicDiag.status === 'Pass',
    `Diagnostic count reflects exact source keys dynamically (expected "2 Demo Personas", got "${dynamicDiag.value}")`
  );

  // Test 4: Empty persona record handles fail cleanly
  const emptyDiag = PlatformDiagnosticsService.evaluateDemoPersonas({} as any);
  assert(
    emptyDiag.status === 'Fail' && emptyDiag.value === '0 Personas',
    'Empty persona dictionary reports status "Fail" with value "0 Personas"'
  );
  assert(
    emptyDiag.provenance === 'Demo Persona Registry',
    'Empty persona dictionary retains logical provenance label'
  );

  // Test 5: Invalid/null persona record handles "Not checked"
  const nullDiag = PlatformDiagnosticsService.evaluateDemoPersonas(null as any);
  assert(
    nullDiag.status === 'Not checked' && nullDiag.value === 'Not checked',
    'Null persona record reports status "Not checked"'
  );

  // --------------------------------------------------------------------------
  // Group 2: Build Environment Determination & Fallback (INF-01)
  // --------------------------------------------------------------------------
  console.log('\n-- Group 2: Build Environment Determination & Fallback --');

  // Test 6: Development mode detection
  const devEnvDiag = PlatformDiagnosticsService.evaluateBuildEnvironment({ MODE: 'development' });
  assert(
    devEnvDiag.status === 'Pass' && devEnvDiag.value === 'Development',
    'MODE="development" reports status "Pass" and value "Development"'
  );
  assert(
    devEnvDiag.provenance === 'Vite Build Configuration',
    `Build environment provenance is logical label "Vite Build Configuration" (got "${devEnvDiag.provenance}")`
  );
  assert(
    !devEnvDiag.provenance.includes('/') && !devEnvDiag.provenance.includes('import.meta'),
    'Build environment provenance contains no code tokens or filesystem paths'
  );

  // Test 7: Production build mode detection
  const prodEnvDiag = PlatformDiagnosticsService.evaluateBuildEnvironment({ MODE: 'production' });
  assert(
    prodEnvDiag.status === 'Pass' && prodEnvDiag.value === 'Production Build',
    'MODE="production" reports status "Pass" and value "Production Build"'
  );

  // Test 8: Custom build mode detection
  const customEnvDiag = PlatformDiagnosticsService.evaluateBuildEnvironment({ MODE: 'staging' });
  assert(
    customEnvDiag.status === 'Pass' && customEnvDiag.value === 'staging',
    'MODE="staging" reports status "Pass" and value "staging"'
  );

  // Test 9: Unavailable/undefined environment handled gracefully as "Not checked"
  const undefinedEnvDiag = PlatformDiagnosticsService.evaluateBuildEnvironment(undefined);
  assert(
    ['Pass', 'Not checked'].includes(undefinedEnvDiag.status),
    `Undefined environment returns valid status ("Pass" or "Not checked", got "${undefinedEnvDiag.status}")`
  );

  const missingEnvDiag = PlatformDiagnosticsService.evaluateBuildEnvironment({});
  assert(
    missingEnvDiag.status === 'Not checked' && missingEnvDiag.value === 'Not checked',
    'Empty environment record {} gracefully returns status "Not checked"'
  );

  const emptyStringEnvDiag = PlatformDiagnosticsService.evaluateBuildEnvironment({ MODE: '   ' });
  assert(
    emptyStringEnvDiag.status === 'Not checked' && emptyStringEnvDiag.value === 'Not checked',
    'Whitespace MODE gracefully returns status "Not checked"'
  );

  // Test 10: Does not infer production infrastructure readiness
  assert(
    prodEnvDiag.detail.includes('does not imply backend production readiness'),
    'Build environment detail explicitly notes that build target does not imply production readiness'
  );

  // --------------------------------------------------------------------------
  // Group 3: Browser Storage Availability & Non-Sensitive Probing (SEC-02, INF-01)
  // --------------------------------------------------------------------------
  console.log('\n-- Group 3: Browser Storage Availability & Non-Sensitive Probing --');

  // Helper: create an instrumented in-memory storage mock
  class MockStorage implements Storage {
    private store: Map<string, string> = new Map();
    public setItemCalls = 0;
    public clearCalls = 0;
    public removeItemCalls = 0;
    public getItemCalls: string[] = [];
    public lengthAccessCount = 0;

    get length(): number {
      this.lengthAccessCount++;
      return this.store.size;
    }
    clear(): void {
      this.clearCalls++;
      this.store.clear();
    }
    getItem(key: string): string | null {
      this.getItemCalls.push(key);
      return this.store.get(key) || null;
    }
    key(index: number): string | null {
      return Array.from(this.store.keys())[index] || null;
    }
    removeItem(key: string): void {
      this.removeItemCalls++;
      this.store.delete(key);
    }
    setItem(key: string, value: string): void {
      this.setItemCalls++;
      this.store.set(key, value);
    }
    seed(key: string, value: string): void {
      this.store.set(key, value);
    }
  }

  // Test 11: Accessible storage returns Pass with logical provenance
  const accessibleStorage = new MockStorage();
  accessibleStorage.seed('ai_soc_auth_session_v1', '{"role":"super_admin"}');
  accessibleStorage.seed('ai_soc_tasks_v1', '[]');
  const storageDiag = PlatformDiagnosticsService.evaluateBrowserStorage(accessibleStorage);

  assert(
    storageDiag.status === 'Pass' && storageDiag.value === 'Accessible',
    `Accessible storage reports status "Pass" with value "Accessible" (got status "${storageDiag.status}", value "${storageDiag.value}")`
  );
  assert(
    storageDiag.detail.includes('not a production database'),
    'Storage diagnostic explicitly notes that storage is local and not a production database'
  );
  assert(
    storageDiag.provenance === 'Browser Storage',
    `Storage provenance is logical label "Browser Storage" (got "${storageDiag.provenance}")`
  );

  // Test 12: SEC-02 - Storage diagnostics NEVER read ai_soc_auth_session_v1
  assert(
    !accessibleStorage.getItemCalls.includes('ai_soc_auth_session_v1'),
    'Storage diagnostics never calls getItem("ai_soc_auth_session_v1")'
  );
  assert(
    accessibleStorage.getItemCalls.length === 0,
    `Storage diagnostics performs 0 getItem calls on storage (got ${accessibleStorage.getItemCalls.length})`
  );
  assert(
    accessibleStorage.lengthAccessCount > 0,
    `Storage diagnostics verified availability via length getter (accessed ${accessibleStorage.lengthAccessCount} times)`
  );

  // Test 13: Missing/null storage returns "Not checked"
  const missingStorageDiag = PlatformDiagnosticsService.evaluateBrowserStorage(null);
  assert(
    missingStorageDiag.status === 'Not checked' && missingStorageDiag.value === 'Not checked',
    'Null storage reports status "Not checked"'
  );
  assert(
    missingStorageDiag.detail.includes('Browser localStorage is not present in this execution context'),
    'Null storage explains that storage API is not present in execution context'
  );

  // --------------------------------------------------------------------------
  // Group 4: Error Sanitization & Safe Property Resolution (SEC-01, RES-01)
  // --------------------------------------------------------------------------
  console.log('\n-- Group 4: Error Sanitization & Safe Property Resolution --');

  // Test 14: SEC-01 - Throwing storage length getter returns Fail with sanitized message
  const throwingStorage = {
    get length(): number {
      throw new Error('SecurityError: The operation is insecure. /var/app/internal/token.key');
    },
    getItem: () => {
      throw new Error('Access denied');
    },
  } as unknown as Storage;

  const failStorageDiag = PlatformDiagnosticsService.evaluateBrowserStorage(throwingStorage);
  assert(
    failStorageDiag.status === 'Fail' && failStorageDiag.value === 'Inaccessible',
    `Throwing storage safely caught and reported as "Fail" / "Inaccessible" (got status "${failStorageDiag.status}")`
  );
  assert(
    !failStorageDiag.detail.includes('SecurityError') &&
    !failStorageDiag.detail.includes('/var/app') &&
    !failStorageDiag.detail.includes('token.key'),
    'Diagnostic detail strips raw exception messages, paths, and internal error details'
  );
  assert(
    failStorageDiag.detail === 'Browser storage is inaccessible. Access may be restricted by browser policy.',
    `Diagnostic detail returns standard sanitized message (got "${failStorageDiag.detail}")`
  );

  // Test 15: RES-01 - Throwing window.localStorage property access handled safely
  const originalWindow = (globalThis as any).window;
  try {
    Object.defineProperty(globalThis, 'window', {
      value: {
        get localStorage() {
          throw new Error('SecurityError: Blocked cross-origin sandbox frame /sys/browser');
        },
      },
      configurable: true,
      writable: true,
    });

    const throwingWindowDiag = PlatformDiagnosticsService.evaluateBrowserStorage();
    assert(
      throwingWindowDiag.status === 'Fail' && throwingWindowDiag.value === 'Inaccessible',
      'Throwing window.localStorage getter safely caught and reported as "Fail" / "Inaccessible"'
    );
    assert(
      !throwingWindowDiag.detail.includes('SecurityError') &&
      !throwingWindowDiag.detail.includes('sandbox') &&
      !throwingWindowDiag.detail.includes('/sys/browser'),
      'Throwing window.localStorage access contains no raw error strings or paths'
    );
    assert(
      throwingWindowDiag.detail === 'Browser storage is inaccessible. Access may be restricted by browser policy.',
      'Throwing window.localStorage access returns sanitized generic message'
    );
  } finally {
    if (originalWindow !== undefined) {
      (globalThis as any).window = originalWindow;
    } else {
      delete (globalThis as any).window;
    }
  }

  // --------------------------------------------------------------------------
  // Group 5: Non-Destructive Storage Invariants
  // --------------------------------------------------------------------------
  console.log('\n-- Group 5: Non-Destructive Storage Invariants --');

  // Test 16: Diagnostics probe does not mutate or clear storage
  const probeStorage = new MockStorage();
  probeStorage.seed('existing_session', 'ACTIVE');
  probeStorage.seed('ai_soc_tasks_v1', '[{"id":"TSK-2026-001"}]');

  const keysBefore = probeStorage.length;
  PlatformDiagnosticsService.evaluateBrowserStorage(probeStorage);
  PlatformDiagnosticsService.runDiagnostics({ storage: probeStorage });

  assert(
    probeStorage.setItemCalls === 0,
    `setItem was called 0 times during diagnostics (got ${probeStorage.setItemCalls})`
  );
  assert(
    probeStorage.clearCalls === 0,
    `clear was called 0 times during diagnostics (got ${probeStorage.clearCalls})`
  );
  assert(
    probeStorage.removeItemCalls === 0,
    `removeItem was called 0 times during diagnostics (got ${probeStorage.removeItemCalls})`
  );
  assert(
    probeStorage.getItemCalls.length === 0,
    `getItem was called 0 times during diagnostics (got ${probeStorage.getItemCalls.length})`
  );
  assert(
    probeStorage.length === keysBefore,
    `Storage length unchanged after diagnostics (before: ${keysBefore}, after: ${probeStorage.length})`
  );
  assert(
    probeStorage.getItem('existing_session') === 'ACTIVE',
    'Existing storage data retained its original value without overwrite'
  );

  // --------------------------------------------------------------------------
  // Group 6: Super Admin Operational Isolation Invariants
  // --------------------------------------------------------------------------
  console.log('\n-- Group 6: Super Admin Operational Isolation Invariants --');

  // Test 17: Super Admin cannot read operational alert queue
  try {
    await alertRepo.getAlertsForUser(admin);
    assert(false, 'Super Admin should be denied access to operational alert queue');
  } catch (err: any) {
    assert(
      err instanceof AccessDeniedError,
      'Super Admin alert queue query denied with AccessDeniedError'
    );
  }

  // Test 18: Super Admin cannot inspect individual alert records
  try {
    await alertRepo.getAlertByIdForUser(admin, 'ALT-2026-1046', ['ALT-2026-1046']);
    assert(false, 'Super Admin should be denied access to individual alert record');
  } catch (err: any) {
    assert(
      err instanceof AccessDeniedError,
      'Super Admin alert inspection denied with AccessDeniedError'
    );
  }

  // Test 19: Super Admin cannot update alert status or add notes
  try {
    await alertRepo.updateAlertStatus(admin, 'ALT-2026-1046', 'resolved');
    assert(false, 'Super Admin should be denied from updating alert status');
  } catch (err: any) {
    assert(
      err instanceof AccessDeniedError,
      'Super Admin alert status update denied with AccessDeniedError'
    );
  }

  try {
    await alertRepo.addAnalystNote(admin, 'ALT-2026-1046', 'Unauthorized Super Admin Note');
    assert(false, 'Super Admin should be denied from adding analyst notes');
  } catch (err: any) {
    assert(
      err instanceof AccessDeniedError,
      'Super Admin analyst note addition denied with AccessDeniedError'
    );
  }

  // Test 20: Super Admin receives strictly empty incident tasks array
  const adminTasks = await auditRepo.getIncidentTasksForUser(admin);
  assert(
    Array.isArray(adminTasks) && adminTasks.length === 0,
    `Super Admin receives empty incident tasks array (got ${adminTasks.length} tasks)`
  );

  // Test 21: Super Admin cannot propose or execute containment actions
  try {
    await auditRepo.recordSimulatedAction(admin, {
      actionType: 'isolate_host',
      targetResource: 'WS-CORP-14',
      justification: 'Super Admin probe',
      status: 'PROPOSED',
      systemNote: 'Super Admin test note',
    });
    assert(false, 'Super Admin should be denied from recording containment action');
  } catch (err: any) {
    assert(
      err instanceof AccessDeniedError,
      'Super Admin containment action execution denied with AccessDeniedError'
    );
  }

  // --------------------------------------------------------------------------
  // Group 7: Full Report Structure & Status Consistency
  // --------------------------------------------------------------------------
  console.log('\n-- Group 7: Full Report Structure & Status Consistency --');

  const fullReport = PlatformDiagnosticsService.runDiagnostics({
    personas: DEMO_PERSONAS,
    env: { MODE: 'development' },
    storage: accessibleStorage,
  });

  assert(
    fullReport.allChecks.length === 3,
    `Full report contains exactly 3 diagnostic checks (got ${fullReport.allChecks.length})`
  );
  assert(
    fullReport.overallStatus === 'Pass',
    `Overall status is "Pass" when all checks pass (got "${fullReport.overallStatus}")`
  );
  assert(
    typeof fullReport.evaluatedAt === 'string' && fullReport.evaluatedAt.length > 0,
    'Full report includes ISO timestamp string'
  );
  assert(
    fullReport.allChecks.every((c) => !c.provenance.includes('/') && !c.provenance.includes('.ts')),
    'All checks in full report use clean logical provenance labels free of filesystem paths'
  );

  console.log(`\n=== COMPLETED: ${passedTests} of ${totalTests} DIAGNOSTICS TESTS PASSED ===\n`);
  return { passed: passedTests, total: totalTests };
}

// Direct CLI execution
if (typeof process !== 'undefined' && process.argv && process.argv[1]?.includes('platformDiagnosticsTest')) {
  runPlatformDiagnosticsTests()
    .then((res) => {
      if (res.passed !== res.total) {
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
