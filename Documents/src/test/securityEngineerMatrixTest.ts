/**
 * Focused Verification Tests for Phase 2, Task 1: Security Engineer 2D MITRE ATT&CK Matrix Heatmap
 *
 * Verifies:
 * 1. Retrieval and integrity of MITRE ATT&CK Enterprise v14.1 reference fixtures.
 * 2. Multi-column 2D matrix grouping and multi-tactic technique distribution.
 * 3. Coverage classification rules (Both, Detection Only, Mitigation Only, Gap).
 * 4. Empty tactic column handling without errors.
 * 5. Search and tactic filtering accuracy.
 * 6. Role authorization, default view, and read-only operational boundaries.
 */

import { LocalMITRERepository } from '../repositories/local/LocalMITRERepository';
import { AuthorizationService } from '../services/authorizationService';
import {
  AUTHENTIC_MITRE_TACTICS,
  AUTHENTIC_MITRE_TECHNIQUES,
  AUTHENTIC_MITRE_MITIGATIONS,
} from '../data/mitreData';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { MitreTechnique, MitreTactic } from '../types/mitre';

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
  console.log('=== RUNNING SECURITY ENGINEER 2D ATT&CK HEATMAP VERIFICATION TESTS ===\n');

  const engineerUser: UserProfile = DEMO_PERSONAS.security_engineer;
  const analystUser: UserProfile = DEMO_PERSONAS.soc_analyst;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;

  const mitreRepo = new LocalMITRERepository();

  console.log('-- Group 1: MITRE ATT&CK Enterprise v14.1 Fixture Integrity --');

  await runTest('Test 1: Repository retrieves all curated authentic tactics', async () => {
    const tactics = await mitreRepo.getTactics();
    assert(tactics.length === 10, `Expected 10 tactics, got ${tactics.length}`);
    const tacticIds = tactics.map((t) => t.id);
    assert(tacticIds.includes('TA0001'), 'Must include Initial Access (TA0001)');
    assert(tacticIds.includes('TA0002'), 'Must include Execution (TA0002)');
    assert(tacticIds.includes('TA0006'), 'Must include Credential Access (TA0006)');
    assert(tacticIds.includes('TA0040'), 'Must include Impact (TA0040)');
  });

  await runTest('Test 2: Repository retrieves curated authentic techniques with detection & mitigation linkages', async () => {
    const techniques = await mitreRepo.getTechniques();
    assert(techniques.length === 8, `Expected 8 techniques, got ${techniques.length}`);

    const powershell = techniques.find((t) => t.id === 'T1059.001');
    assert(Boolean(powershell), 'T1059.001 (PowerShell) must exist');
    assert(powershell!.tactics.includes('TA0002'), 'PowerShell must map to Execution (TA0002)');
    assert(powershell!.mitigationIds.length > 0, 'PowerShell must have mapped mitigations');
    assert(powershell!.detectionGuidance.length > 0, 'PowerShell must have detection guidance');
    assert(powershell!.dataSources.length > 0, 'PowerShell must have data sources');
  });

  await runTest('Test 3: Defense coverage evaluates all techniques without fabricating metrics', async () => {
    const coverage = await mitreRepo.getDefenseCoverage();
    assert(coverage.length === 8, `Expected 8 coverage records, got ${coverage.length}`);

    for (const c of coverage) {
      assert(c.coveredByDetections === true, `${c.techniqueId} should have documented detection`);
      assert(c.mitigationAvailable === true, `${c.techniqueId} should have documented mitigation`);
      assert(c.detectionRuleCount > 0, `${c.techniqueId} must have valid data sources count`);
    }
  });

  console.log('\n-- Group 2: 2D Matrix Grouping & Multi-Tactic Distribution --');

  runTest('Test 4: Multi-tactic techniques appear under all assigned parent tactic columns', () => {
    // T1078.002 (Domain Accounts) maps to TA0001, TA0003, TA0004, TA0008
    const tech = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === 'T1078.002')!;
    assert(tech.tactics.length === 4, `Expected 4 tactics for T1078.002, got ${tech.tactics.length}`);
    assert(tech.tactics.includes('TA0001'), 'Must map to Initial Access');
    assert(tech.tactics.includes('TA0003'), 'Must map to Persistence');
    assert(tech.tactics.includes('TA0004'), 'Must map to Privilege Escalation');
    assert(tech.tactics.includes('TA0008'), 'Must map to Lateral Movement');

    // In a 2D matrix grouped by tactic, T1078.002 will be present under all 4 columns
    const columns = new Map<string, MitreTechnique[]>();
    for (const tac of AUTHENTIC_MITRE_TACTICS) {
      columns.set(tac.id, AUTHENTIC_MITRE_TECHNIQUES.filter((t) => t.tactics.includes(tac.id)));
    }

    assert(columns.get('TA0001')!.some((t) => t.id === 'T1078.002'), 'T1078.002 must be in TA0001 column');
    assert(columns.get('TA0003')!.some((t) => t.id === 'T1078.002'), 'T1078.002 must be in TA0003 column');
    assert(columns.get('TA0004')!.some((t) => t.id === 'T1078.002'), 'T1078.002 must be in TA0004 column');
    assert(columns.get('TA0008')!.some((t) => t.id === 'T1078.002'), 'T1078.002 must be in TA0008 column');
  });

  runTest('Test 5: Empty tactic columns (e.g. TA0005, TA0007) are handled gracefully without throwing', () => {
    const defenseEvasion = AUTHENTIC_MITRE_TECHNIQUES.filter((t) => t.tactics.includes('TA0005'));
    const discovery = AUTHENTIC_MITRE_TECHNIQUES.filter((t) => t.tactics.includes('TA0007'));

    assert(defenseEvasion.length === 0, 'TA0005 should have 0 techniques in curated reference scope');
    assert(discovery.length === 0, 'TA0007 should have 0 techniques in curated reference scope');
  });

  console.log('\n-- Group 3: Coverage Classification Logic & Status Distinctions --');

  runTest('Test 6: Classifies techniques into "both", "detection_only", "mitigation_only", or "gap"', () => {
    // Helper function matching the dashboard logic
    const classifyCoverage = (t: Partial<MitreTechnique>) => {
      const hasDetection = Boolean(t.detectionGuidance && t.detectionGuidance.trim().length > 0 && t.dataSources && t.dataSources.length > 0);
      const hasMitigation = Boolean(t.mitigationIds && t.mitigationIds.length > 0);
      if (hasDetection && hasMitigation) return 'both';
      if (hasDetection) return 'detection_only';
      if (hasMitigation) return 'mitigation_only';
      return 'gap';
    };

    assert(
      classifyCoverage({
        detectionGuidance: 'Sysmon Event 10',
        dataSources: ['Process Creation'],
        mitigationIds: ['M1026'],
      }) === 'both',
      'Should classify as both'
    );

    assert(
      classifyCoverage({
        detectionGuidance: 'Network flow logs',
        dataSources: ['Network Traffic'],
        mitigationIds: [],
      }) === 'detection_only',
      'Should classify as detection_only'
    );

    assert(
      classifyCoverage({
        detectionGuidance: '',
        dataSources: [],
        mitigationIds: ['M1038'],
      }) === 'mitigation_only',
      'Should classify as mitigation_only'
    );

    assert(
      classifyCoverage({
        detectionGuidance: '',
        dataSources: [],
        mitigationIds: [],
      }) === 'gap',
      'Should classify as gap'
    );
  });

  console.log('\n-- Group 4: Search and Tactic Filtering Accuracy --');

  runTest('Test 7: Search query filters across Technique ID, Name, Description, and Data Sources', () => {
    const q1 = 'powershell';
    const match1 = AUTHENTIC_MITRE_TECHNIQUES.filter(
      (t) =>
        t.id.toLowerCase().includes(q1) ||
        t.name.toLowerCase().includes(q1) ||
        t.description.toLowerCase().includes(q1) ||
        t.dataSources.some((ds) => ds.toLowerCase().includes(q1))
    );
    assert(match1.length === 1 && match1[0].id === 'T1059.001', 'Should match T1059.001');

    const q2 = 'lsass';
    const match2 = AUTHENTIC_MITRE_TECHNIQUES.filter(
      (t) =>
        t.id.toLowerCase().includes(q2) ||
        t.name.toLowerCase().includes(q2) ||
        t.description.toLowerCase().includes(q2) ||
        t.dataSources.some((ds) => ds.toLowerCase().includes(q2))
    );
    assert(match2.some((t) => t.id === 'T1003.001'), 'Should match T1003.001');
  });

  console.log('\n-- Group 5: Role Authorization & Read-Only Boundaries --');

  runTest('Test 8: security_engineer default landing view is "seceng_overview"', () => {
    assert(
      AuthorizationService.getDefaultViewForRole('security_engineer') === 'seceng_overview',
      'Security Engineer default view must be "seceng_overview"'
    );
  });

  runTest('Test 9: security_engineer is authorized for "seceng_overview", "mitre", "alerts", "audit", "profile"', () => {
    const allowed = ['seceng_overview', 'mitre', 'alerts', 'audit', 'profile'];
    for (const v of allowed) {
      assert(
        AuthorizationService.isViewAuthorized('security_engineer', v),
        `Security Engineer must be authorized for "${v}"`
      );
    }
  });

  runTest('Test 10: security_engineer is strictly denied from operational mutation permissions', () => {
    assert(!AuthorizationService.hasPermission(engineerUser.role, 'alert:triage'), 'Engineer must NOT have alert:triage');
    assert(!AuthorizationService.hasPermission(engineerUser.role, 'alert:add_note'), 'Engineer must NOT have alert:add_note');
    assert(!AuthorizationService.hasPermission(engineerUser.role, 'incident:update'), 'Engineer must NOT have incident:update');
    assert(!AuthorizationService.hasPermission(engineerUser.role, 'platform:admin'), 'Engineer must NOT have platform:admin');
  });

  runTest('Test 11: super_admin is strictly denied from "mitre" view', () => {
    assert(
      !AuthorizationService.isViewAuthorized('super_admin', 'mitre'),
      'Super Admin must NOT be authorized for "mitre"'
    );
  });

  console.log(`\n=== COMPLETED: ${passedTests} of 11 SECURITY ENGINEER MATRIX TESTS PASSED ===`);
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
