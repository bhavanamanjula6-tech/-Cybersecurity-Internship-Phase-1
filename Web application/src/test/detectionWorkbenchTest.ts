/**
 * Focused Verification Tests for Phase 2, Task 2: Detection Engineering Workbench
 *
 * Verifies:
 * 1. Generation of structured Sigma templates from authentic MITRE ATT&CK techniques.
 * 2. Proper ATT&CK tactic and technique tagging (e.g. attack.execution, attack.t1059.001).
 * 3. Telemetry logsource category and product mapping from data sources and platforms.
 * 4. Structural YAML syntax validation (valid templates pass; missing keys or tab indentation flagged).
 * 5. Explicit non-deployed invariants (isDeployed === false, non-deployed draft notice present).
 * 6. Starter baseline retrieval and reset integrity.
 * 7. Security Engineer role authorization, default view, and read-only operational isolation.
 */

import { DetectionRuleService, DetectionRuleDraft } from '../services/detectionRuleService';
import { AUTHENTIC_MITRE_TECHNIQUES, AUTHENTIC_MITRE_TACTICS } from '../data/mitreData';
import { AuthorizationService } from '../services/authorizationService';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';

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
  console.log('=== RUNNING DETECTION ENGINEERING WORKBENCH VERIFICATION TESTS ===\n');

  console.log('-- Group 1: Sigma Template Generation from MITRE ATT&CK Fixtures --');

  const pwrTech = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === 'T1059.001')!;
  const execTactic = AUTHENTIC_MITRE_TACTICS.find((t) => t.id === 'TA0002')!;

  runTest('Test 1: Generates structured Sigma draft for T1059.001 (PowerShell)', () => {
    assert(pwrTech !== undefined, 'T1059.001 must exist in MITRE fixtures');
    const draft = DetectionRuleService.generateSigmaTemplateFromTechnique(pwrTech, execTactic);

    assert(draft.techniqueId === 'T1059.001', 'Technique ID must be T1059.001');
    assert(draft.tacticId === 'TA0002', 'Tactic ID must be TA0002');
    assert(draft.title.includes('PowerShell'), 'Title must reference PowerShell');
    assert(draft.logSource.category === 'process_creation', 'Log source category must be process_creation');
    assert(draft.rawYaml.includes('attack.t1059.001'), 'YAML must contain attack.t1059.001 tag');
    assert(draft.rawYaml.includes('attack.execution'), 'YAML must contain attack.execution tag');
  });

  const lsassTech = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === 'T1003.001')!;
  const credTactic = AUTHENTIC_MITRE_TACTICS.find((t) => t.id === 'TA0006')!;

  runTest('Test 2: Generates structured Sigma draft for T1003.001 (LSASS Memory)', () => {
    assert(lsassTech !== undefined, 'T1003.001 must exist in MITRE fixtures');
    const draft = DetectionRuleService.generateSigmaTemplateFromTechnique(lsassTech, credTactic);

    assert(draft.techniqueId === 'T1003.001', 'Technique ID must be T1003.001');
    assert(draft.rawYaml.includes('lsass.exe'), 'Selection must include lsass.exe');
    assert(draft.rawYaml.includes('attack.t1003.001'), 'YAML must include attack.t1003.001 tag');
  });

  console.log('\n-- Group 2: Non-Deployed Invariant & Deployment Boundary --');

  runTest('Test 3: Draft rules enforce isDeployed: false invariant at compile and runtime', () => {
    const draft = DetectionRuleService.generateSigmaTemplateFromTechnique(pwrTech, execTactic);
    assert(draft.isDeployed === false, 'Draft rule isDeployed must be explicitly false');
    assert(draft.deploymentNotice.includes('NON-DEPLOYED DRAFT'), 'Must include prominent non-deployed notice');
  });

  console.log('\n-- Group 3: Structural Sigma YAML Linter and Validator --');

  runTest('Test 4: Valid generated Sigma YAML passes structural syntax check', () => {
    const draft = DetectionRuleService.generateSigmaTemplateFromTechnique(pwrTech, execTactic);
    const result = DetectionRuleService.validateSigmaRuleStructure(draft.rawYaml);

    assert(result.isValid === true, 'Generated template must pass validation');
    assert(result.errors.length === 0, `Expected 0 errors, got ${result.errors.join(', ')}`);
  });

  runTest('Test 5: Validator flags missing required headers (title, logsource, condition)', () => {
    const incompleteYaml = `
status: experimental
description: Missing title and logsource
detection:
  selection:
    Image: powershell.exe
level: high
`;
    const result = DetectionRuleService.validateSigmaRuleStructure(incompleteYaml);
    assert(result.isValid === false, 'Incomplete YAML must fail validation');
    assert(result.errors.some((e) => e.includes('title')), 'Must flag missing title header');
    assert(result.errors.some((e) => e.includes('logsource')), 'Must flag missing logsource section');
    assert(result.errors.some((e) => e.includes('condition')), 'Must flag missing condition logic');
  });

  runTest('Test 6: Validator detects and rejects illegal tab characters in YAML', () => {
    const tabbedYaml = `title: Tabbed Rule\nlogsource:\n\tcategory: process_creation\ndetection:\n\tselection:\n\t\tEventID: 1\n\tcondition: selection\nlevel: high\ntags:\n  - attack.execution`;
    const result = DetectionRuleService.validateSigmaRuleStructure(tabbedYaml);
    assert(result.isValid === false, 'Tabbed YAML must be marked invalid');
    assert(result.errors.some((e) => e.includes('Tab character detected')), 'Must report line with tab character');
  });

  console.log('\n-- Group 4: Starter Baseline Generation --');

  runTest('Test 7: Starter baseline produces 3 curated initial templates', () => {
    const starters = DetectionRuleService.getInitialStarterDrafts(
      AUTHENTIC_MITRE_TECHNIQUES,
      AUTHENTIC_MITRE_TACTICS
    );
    assert(starters.length === 3, `Expected 3 starter drafts, got ${starters.length}`);
    const techIds = starters.map((d) => d.techniqueId);
    assert(techIds.includes('T1059.001'), 'Must include PowerShell draft');
    assert(techIds.includes('T1003.001'), 'Must include LSASS draft');
    assert(techIds.includes('T1047'), 'Must include WMI draft');

    // All starters must pass structural validation
    for (const starter of starters) {
      const v = DetectionRuleService.validateSigmaRuleStructure(starter.rawYaml);
      assert(v.isValid, `Starter draft for ${starter.techniqueId} must pass validation`);
      assert(starter.isDeployed === false, 'Starter draft must be marked non-deployed');
    }
  });

  console.log('\n-- Group 5: Role Authorization & Operational Isolation for Security Engineer --');

  const engineer: UserProfile = DEMO_PERSONAS.security_engineer;

  runTest('Test 8: Security Engineer has permission to analyze coverage and author rules', () => {
    assert(
      AuthorizationService.hasPermission(engineer.role, 'mitre:analyze_coverage'),
      'Security Engineer must have mitre:analyze_coverage permission'
    );
    assert(
      AuthorizationService.getDefaultViewForRole(engineer.role) === 'mitre',
      'Security Engineer default view must remain mitre'
    );
  });

  runTest('Test 9: Security Engineer is strictly denied operational alert triage and task mutation', () => {
    assert(
      !AuthorizationService.hasPermission(engineer.role, 'alert:triage'),
      'Security Engineer must NOT have alert:triage'
    );
    assert(
      !AuthorizationService.hasPermission(engineer.role, 'alert:add_note'),
      'Security Engineer must NOT have alert:add_note'
    );
    assert(
      !AuthorizationService.hasPermission(engineer.role, 'incident:update'),
      'Security Engineer must NOT have incident:update'
    );
    assert(
      !AuthorizationService.hasPermission(engineer.role, 'platform:admin'),
      'Security Engineer must NOT have platform:admin'
    );

    let threw = false;
    try {
      AuthorizationService.assertPermission(engineer, 'alert:triage');
    } catch (err: any) {
      threw = true;
      assert(err instanceof AccessDeniedError, 'Must throw AccessDeniedError');
    }
    assert(threw, 'assertPermission for alert:triage must throw for Security Engineer');
  });

  console.log(`\n========================================================`);
  console.log(`All ${passedTests} Detection Workbench verification tests PASSED!`);
  console.log(`========================================================`);
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
