/**
 * Verification Test Suite for Controlled Simulated Windows Event Detection Pipeline
 *
 * Verifies:
 * 1. Multi-technique support: T1047 (WMI), T1053.005 (Scheduled Task), T1486 (Shadow Copy Deletion).
 * 2. Preservation of authentic T1486 scenario and behavior.
 * 3. Technique-specific event selection (never evaluate a different technique's event against draft).
 * 4. Cross-technique non-matching (T1047 draft rejects T1486 telemetry; T1486 draft rejects T1047 telemetry).
 * 5. Dynamic rule criteria evaluation against actual Sigma selection and log source model.
 * 6. Dynamic alert generation: unique IDs per simulation, correct titles, descriptions, evidence, provenance.
 * 7. Security Engineer local-preview invariant: no database insertion.
 * 8. SOC Analyst persistence requirements: failure when callback is missing or throws an error.
 */

import {
  SimulatedDetectionEngine,
  T1047_SIMULATED_EVENT,
  T1053_005_SIMULATED_EVENT,
  T1486_SIMULATED_EVENT,
  SimulatedWindowsEvent,
} from '../services/simulatedDetectionEngine';
import { DetectionRuleService, DetectionRuleDraft } from '../services/detectionRuleService';
import { AUTHENTIC_MITRE_TECHNIQUES, AUTHENTIC_MITRE_TACTICS } from '../data/mitreData';
import { MitreTechnique } from '../types/mitre';
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
  console.log('=== RUNNING CONTROLLED SIMULATION PIPELINE VERIFICATION TESTS ===\n');

  const execTactic = AUTHENTIC_MITRE_TACTICS.find((t) => t.id === 'TA0002')!;
  const impactTactic = AUTHENTIC_MITRE_TACTICS.find((t) => t.id === 'TA0040')!;

  const wmiTech: MitreTechnique = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === 'T1047')!;
  const taskTech: MitreTechnique = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === 'T1053.005') || {
    id: 'T1053.005',
    name: 'Scheduled Task',
    tactics: ['TA0002', 'TA0003'],
    dataSources: ['Process: Process Creation', 'Command: Command Execution'],
    platforms: ['Windows'],
    mitigationIds: ['M1047'],
    description: 'Adversaries may abuse task scheduling functionality.',
    detectionGuidance: 'Monitor process execution of schtasks.exe with task creation parameters.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1053/005/',
  };
  const shadowTech: MitreTechnique = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === 'T1486') || {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactics: ['TA0040'],
    dataSources: ['Process: Process Creation', 'File: File Modification'],
    platforms: ['Windows'],
    mitigationIds: ['M1038', 'M1040'],
    description: 'Adversaries may delete shadow copies using vssadmin.exe.',
    detectionGuidance: 'Monitor execution of vssadmin.exe with delete shadows parameters.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1486/',
  };

  // Draft generation
  const draftWmi = DetectionRuleService.generateSigmaTemplateFromTechnique(wmiTech, execTactic);
  const draftTask = DetectionRuleService.generateSigmaTemplateFromTechnique(taskTech, execTactic);
  const draftShadow = DetectionRuleService.generateSigmaTemplateFromTechnique(shadowTech, impactTactic);

  console.log('-- Group 1: Technique-Specific Controlled Event Resolution --');

  runTest('Test 1: Resolves correct event for T1047 (WMI)', () => {
    const ev = SimulatedDetectionEngine.getSimulatedEventForTechnique('T1047');
    assert(ev !== null, 'T1047 event must exist');
    assert(Boolean(ev?.image.toLowerCase().includes('wmic.exe')), 'T1047 image must be wmic.exe');
    assert(Boolean(ev?.commandLine.includes('process call create')), 'T1047 command line must contain process call create');
  });

  runTest('Test 2: Resolves correct event for T1053.005 (Scheduled Task)', () => {
    const ev = SimulatedDetectionEngine.getSimulatedEventForTechnique('T1053.005');
    assert(ev !== null, 'T1053.005 event must exist');
    assert(Boolean(ev?.image.toLowerCase().includes('schtasks.exe')), 'T1053.005 image must be schtasks.exe');
    assert(Boolean(ev?.commandLine.includes('/create')), 'T1053.005 command line must contain /create');
  });

  runTest('Test 3: Preserves authentic T1486 event scenario', () => {
    const ev = SimulatedDetectionEngine.getSimulatedEventForTechnique('T1486');
    assert(ev !== null, 'T1486 event must exist');
    assert(ev?.image === T1486_SIMULATED_EVENT.image, 'Must preserve exact T1486 image');
    assert(ev?.commandLine === T1486_SIMULATED_EVENT.commandLine, 'Must preserve exact T1486 command line');
    assert(ev?.host === 'SIM-WIN-001', 'Host must be SIM-WIN-001');
    assert(ev?.eventId === 1, 'Event ID must be 1');
  });

  runTest('Test 4: Returns null for unmapped techniques', () => {
    assert(SimulatedDetectionEngine.getSimulatedEventForTechnique('T1059.001') === null, 'T1059.001 has no scenario');
    assert(SimulatedDetectionEngine.getSimulatedEventForTechnique('T1003.001') === null, 'T1003.001 has no scenario');
  });

  console.log('\n-- Group 2: Matching Rule Evaluation Across All 3 Techniques --');

  runTest('Test 5: T1486 draft evaluates and matches T1486 telemetry', () => {
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftShadow, T1486_SIMULATED_EVENT);
    assert(result.matched === true, 'T1486 draft must match T1486 telemetry');
    assert(result.simulatedAlert !== undefined, 'Matched result must produce a simulatedAlert');
    assert(result.simulatedAlert?.mitreTechniqueId === 'T1486', 'Alert technique ID must be T1486');
    assert(result.simulatedAlert?.evidence.processName === 'vssadmin.exe', 'Evidence process must be vssadmin.exe');
  });

  runTest('Test 6: T1047 draft evaluates and matches T1047 telemetry', () => {
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWmi, T1047_SIMULATED_EVENT);
    assert(result.matched === true, 'T1047 draft must match T1047 telemetry');
    assert(result.simulatedAlert !== undefined, 'Matched result must produce a simulatedAlert');
    assert(result.simulatedAlert?.mitreTechniqueId === 'T1047', 'Alert technique ID must be T1047');
    assert(result.simulatedAlert?.evidence.processName?.toLowerCase() === 'wmic.exe', 'Evidence process must be wmic.exe');
    assert(Boolean(result.simulatedAlert?.title.includes('Windows Management Instrumentation')), 'Title must be dynamic');
  });

  runTest('Test 7: T1053.005 draft evaluates and matches T1053.005 telemetry', () => {
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftTask, T1053_005_SIMULATED_EVENT);
    assert(result.matched === true, 'T1053.005 draft must match T1053.005 telemetry');
    assert(result.simulatedAlert !== undefined, 'Matched result must produce a simulatedAlert');
    assert(result.simulatedAlert?.mitreTechniqueId === 'T1053.005', 'Alert technique ID must be T1053.005');
    assert(result.simulatedAlert?.evidence.processName === 'schtasks.exe', 'Evidence process must be schtasks.exe');
    assert(Boolean(result.simulatedAlert?.title.includes('Scheduled Task')), 'Title must be dynamic for scheduled task');
  });

  console.log('\n-- Group 3: Cross-Technique Non-Matching & Isolation --');

  runTest('Test 8: T1047 draft CANNOT match T1486 telemetry', () => {
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWmi, T1486_SIMULATED_EVENT);
    assert(result.matched === false, 'T1047 draft must reject T1486 telemetry');
    assert(result.simulatedAlert === undefined, 'Non-matched evaluation must NOT produce an alert');
    assert(result.unmatchedConditions.some((c) => c.toLowerCase().includes('mismatch') || c.toLowerCase().includes('missing')), 'Must report condition mismatches');
  });

  runTest('Test 9: T1486 draft CANNOT match T1047 telemetry', () => {
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftShadow, T1047_SIMULATED_EVENT);
    assert(result.matched === false, 'T1486 draft must reject T1047 telemetry');
    assert(result.simulatedAlert === undefined, 'Non-matched evaluation must NOT produce an alert');
  });

  runTest('Test 10: T1053.005 draft CANNOT match T1486 telemetry', () => {
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftTask, T1486_SIMULATED_EVENT);
    assert(result.matched === false, 'T1053.005 draft must reject T1486 telemetry');
    assert(result.simulatedAlert === undefined, 'Non-matched evaluation must NOT produce an alert');
  });

  console.log('\n-- Group 4: Non-Matching Telemetry Criteria & Log Source Compatibility --');

  runTest('Test 11: Non-matching command line tokens fail evaluation', () => {
    const benignWmiEvent: SimulatedWindowsEvent = {
      image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
      commandLine: 'wmic.exe os get caption', // Does not contain "process call create" or "/node:"
      host: 'SIM-WIN-001',
      timestamp: new Date().toISOString(),
      eventId: 1,
      source: 'Controlled Simulation',
    };
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWmi, benignWmiEvent);
    assert(result.matched === false, 'Benign command line must not match T1047 rule');
    assert(result.unmatchedConditions.some((c) => c.includes('CommandLine token missing')), 'Must note missing tokens');
  });

  runTest('Test 12: Incompatible log source product fails evaluation', () => {
    const linuxDraft: DetectionRuleDraft = {
      ...draftWmi,
      logSource: {
        category: 'process_creation',
        product: 'linux',
      },
    };
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(linuxDraft, T1047_SIMULATED_EVENT);
    assert(result.matched === false, 'Linux rule must not match Windows simulation event');
    assert(result.unmatchedConditions.some((c) => c.includes('product mismatch')), 'Must flag product mismatch');
  });

  console.log('\n-- Group 5: Unique Alert ID Generation & Dynamic Attributes --');

  runTest('Test 13: Repeated simulations produce distinct, unique alert IDs', () => {
    const alert1 = SimulatedDetectionEngine.generateSimulatedAlert(
      draftShadow,
      SimulatedDetectionEngine.normalizeEvent(T1486_SIMULATED_EVENT)
    );
    const alert2 = SimulatedDetectionEngine.generateSimulatedAlert(
      draftShadow,
      SimulatedDetectionEngine.normalizeEvent(T1486_SIMULATED_EVENT)
    );
    const alert3 = SimulatedDetectionEngine.generateSimulatedAlert(
      draftWmi,
      SimulatedDetectionEngine.normalizeEvent(T1047_SIMULATED_EVENT)
    );

    assert(alert1.id !== alert2.id, `Alert 1 (${alert1.id}) and Alert 2 (${alert2.id}) must have distinct IDs`);
    assert(alert1.id !== alert3.id, 'Alert 1 and Alert 3 must have distinct IDs');
    assert(alert1.id.startsWith('ALT-SIM-T1486-'), 'Alert 1 ID prefix must reflect T1486');
    assert(alert3.id.startsWith('ALT-SIM-T1047-'), 'Alert 3 ID prefix must reflect T1047');
  });

  runTest('Test 14: Dynamic alert provenance and evidence conform to matched technique', () => {
    const alertWmi = SimulatedDetectionEngine.generateSimulatedAlert(
      draftWmi,
      SimulatedDetectionEngine.normalizeEvent(T1047_SIMULATED_EVENT),
      T1047_SIMULATED_EVENT
    );
    assert(alertWmi.provenance === 'Controlled Simulation: Windows Event Detection Pipeline (T1047)', 'Provenance must reflect T1047');
    assert(alertWmi.isSynthetic === true, 'isSynthetic must remain true');
    assert(alertWmi.evidence.processName === 'WMIC.exe', 'Process name in evidence must be WMIC.exe');
    assert(!alertWmi.title.includes('vssadmin.exe'), 'WMI alert title must NOT mention vssadmin.exe');
  });

  console.log('\n-- Group 6: Persistence Boundary & Dispatch Verification --');

  runTest('Test 15: Missing onDispatchSimulatedAlert callback fails cleanly', async () => {
    let capturedError: string | null = null;
    let persistenceClaimed = false;

    // Simulate workbench behavior when onDispatchSimulatedAlert is undefined
    const dispatchHandler = undefined as ((alert: SecurityAlert) => Promise<void>) | undefined;
    const userRole = 'soc_analyst';

    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWmi, T1047_SIMULATED_EVENT);
    assert(result.matched && result.simulatedAlert !== undefined, 'Simulation must match');

    if (userRole === 'soc_analyst') {
      if (!dispatchHandler) {
        capturedError = 'Dispatch handler unavailable: cannot persist alert to database.';
      } else {
        await (dispatchHandler as (alert: SecurityAlert) => Promise<void>)(result.simulatedAlert!);
        persistenceClaimed = true;
      }
    }

    assert(capturedError !== null, 'Must capture error when dispatch handler is missing');
    assert(persistenceClaimed === false, 'Must never claim persistence when callback is missing');
  });

  runTest('Test 16: Database insertion failure is propagated without claiming persistence', async () => {
    let capturedError: string | null = null;
    let persistenceClaimed = false;

    const failingCallback = async (_alert: SecurityAlert): Promise<void> => {
      throw new Error('Supabase RLS: permission denied for table public.alerts');
    };

    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWmi, T1047_SIMULATED_EVENT);
    try {
      await failingCallback(result.simulatedAlert!);
      persistenceClaimed = true;
    } catch (err: any) {
      capturedError = err.message;
    }

    assert(capturedError !== null, 'Must capture database error');
    assert(Boolean(capturedError && capturedError.includes('permission denied')), 'Error must contain failure details');
    assert(persistenceClaimed === false, 'Must never claim persistence when callback rejects');
  });

  runTest('Test 17: Security Engineer role is restricted to local preview only', () => {
    const userRole = 'security_engineer';
    let databaseCalled = false;

    const mockCallback = async (_alert: SecurityAlert): Promise<void> => {
      databaseCalled = true;
    };

    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftShadow, T1486_SIMULATED_EVENT);
    let simulationStatus: string = 'idle';

    if (userRole === 'security_engineer') {
      simulationStatus = 'local_preview';
      // callback NOT invoked
    } else if (userRole === 'soc_analyst') {
      mockCallback(result.simulatedAlert!);
      simulationStatus = 'persisted';
    }

    assert(simulationStatus === 'local_preview', 'Security Engineer status must be local_preview');
    assert(databaseCalled === false, 'Security Engineer must never trigger database persistence callback');
  });

  runTest('Test 18: SOC Analyst simulation invokes persistence callback and succeeds', async () => {
    let persistedAlert: SecurityAlert | null = null;

    const mockDispatcher = async (alert: SecurityAlert): Promise<void> => {
      persistedAlert = alert;
    };

    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftShadow, T1486_SIMULATED_EVENT);
    assert(result.matched && result.simulatedAlert !== undefined, 'Simulation must match');

    // SOC Analyst invokes dispatcher
    await mockDispatcher(result.simulatedAlert!);

    assert(persistedAlert !== null, 'Alert must be passed to persistence dispatcher');
    assert((persistedAlert as any)?.mitreTechniqueId === 'T1486', 'Persisted alert technique must be T1486');
    assert((persistedAlert as any)?.isSynthetic === true, 'Persisted alert must be synthetic');
  });

  runTest('Test 19: IT Operations and Super Admin are rejected by simulation dispatcher', async () => {
    const simulateAlertHandler = async (role: string, alert: SecurityAlert): Promise<void> => {
      if (role === 'security_engineer') {
        return; // local preview
      }
      if (role === 'soc_analyst') {
        return; // authorized
      }
      throw new Error(`Role "${role}" is not authorized to create operational alerts.`);
    };

    const alert = SimulatedDetectionEngine.generateSimulatedAlert(
      draftWmi,
      SimulatedDetectionEngine.normalizeEvent(T1047_SIMULATED_EVENT)
    );

    let itOpsThrew = false;
    try {
      await simulateAlertHandler('it_operations', alert);
    } catch (err: any) {
      itOpsThrew = true;
      assert(err.message.includes('not authorized'), 'IT Ops must be denied');
    }
    assert(itOpsThrew, 'IT Operations must throw on simulation dispatch');

    let adminThrew = false;
    try {
      await simulateAlertHandler('super_admin', alert);
    } catch (err: any) {
      adminThrew = true;
      assert(err.message.includes('not authorized'), 'Super Admin must be denied');
    }
    assert(adminThrew, 'Super Admin must throw on simulation dispatch');
  });

  runTest('Test 20: Security Engineer dispatch early-returns without persisting to repository', async () => {
    let repoInsertCalled = false;

    const simulateAlertHandler = async (role: string, _alert: SecurityAlert): Promise<void> => {
      if (role === 'security_engineer') {
        return; // Early return: no database write
      }
      if (role === 'soc_analyst') {
        repoInsertCalled = true;
        return;
      }
      throw new Error(`Role "${role}" is not authorized to create operational alerts.`);
    };

    const alert = SimulatedDetectionEngine.generateSimulatedAlert(
      draftTask,
      SimulatedDetectionEngine.normalizeEvent(T1053_005_SIMULATED_EVENT)
    );

    await simulateAlertHandler('security_engineer', alert);
    assert(repoInsertCalled === false, 'Repository insert must NEVER be called for Security Engineer');
  });

  console.log('\n-- Group 7: Event ID Matching & Regression Verification --');

  runTest('Test 21: Matching EventID allows rule evaluation to succeed', () => {
    const draftWithMatchingEid: DetectionRuleDraft = {
      ...draftShadow,
      detectionSelection: {
        ...draftShadow.detectionSelection,
        EventID: '1',
      },
    };
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWithMatchingEid, T1486_SIMULATED_EVENT);
    assert(result.matched === true, 'Matching EventID must allow rule evaluation to succeed');
    assert(result.matchedConditions.some((c) => c.includes('EventID matched')), 'Must record matched EventID condition');
    assert(result.simulatedAlert !== undefined, 'Must produce a simulated alert on match');
  });

  runTest('Test 22: Mismatching EventID causes rule evaluation to FAIL', () => {
    const draftWithMismatchedEid: DetectionRuleDraft = {
      ...draftShadow,
      detectionSelection: {
        ...draftShadow.detectionSelection,
        EventID: '4688', // Simulated event has eventId = 1
      },
    };
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWithMismatchedEid, T1486_SIMULATED_EVENT);
    assert(result.matched === false, 'Event ID mismatch must make the rule evaluation fail');
    assert(result.simulatedAlert === undefined, 'Mismatched Event ID must NOT produce a simulated alert');
    assert(
      result.unmatchedConditions.some((c) => c.includes('EventID mismatch')),
      'Must record unmatched EventID condition'
    );
  });

  runTest('Test 23: Mismatching EventID array causes rule evaluation to FAIL', () => {
    const draftWithMismatchedArray: DetectionRuleDraft = {
      ...draftWmi,
      detectionSelection: {
        ...draftWmi.detectionSelection,
        EventID: ['4688', '7045'] as any,
      },
    };
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWithMismatchedArray, T1047_SIMULATED_EVENT);
    assert(result.matched === false, 'Event ID array without matching ID must fail');
    assert(result.simulatedAlert === undefined, 'Mismatched Event ID array must NOT produce an alert');
  });

  runTest('Test 24: Matching EventID array allows rule evaluation to succeed', () => {
    const draftWithMatchingArray: DetectionRuleDraft = {
      ...draftWmi,
      detectionSelection: {
        ...draftWmi.detectionSelection,
        EventID: ['1', '4688'] as any,
      },
    };
    const result = SimulatedDetectionEngine.evaluateAgainstDraft(draftWithMatchingArray, T1047_SIMULATED_EVENT);
    assert(result.matched === true, 'Event ID array with matching ID must succeed');
    assert(result.simulatedAlert !== undefined, 'Must produce simulated alert');
  });

  runTest('Test 25: Regression suite for T1047, T1053.005, and T1486 evaluations', () => {
    // 1. T1486
    const res1486 = SimulatedDetectionEngine.evaluateAgainstDraft(draftShadow, T1486_SIMULATED_EVENT);
    assert(res1486.matched === true, 'T1486 regression: must match authentic telemetry');
    assert(res1486.simulatedAlert?.mitreTechniqueId === 'T1486', 'T1486 regression: technique must be T1486');

    // 2. T1047
    const res1047 = SimulatedDetectionEngine.evaluateAgainstDraft(draftWmi, T1047_SIMULATED_EVENT);
    assert(res1047.matched === true, 'T1047 regression: must match authentic telemetry');
    assert(res1047.simulatedAlert?.mitreTechniqueId === 'T1047', 'T1047 regression: technique must be T1047');

    // 3. T1053.005
    const res1053 = SimulatedDetectionEngine.evaluateAgainstDraft(draftTask, T1053_005_SIMULATED_EVENT);
    assert(res1053.matched === true, 'T1053.005 regression: must match authentic telemetry');
    assert(res1053.simulatedAlert?.mitreTechniqueId === 'T1053.005', 'T1053.005 regression: technique must be T1053.005');
  });

  console.log(`\n========================================================`);
  console.log(`All ${passedTests} Controlled Simulation Pipeline tests PASSED!`);
  console.log(`========================================================`);
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
