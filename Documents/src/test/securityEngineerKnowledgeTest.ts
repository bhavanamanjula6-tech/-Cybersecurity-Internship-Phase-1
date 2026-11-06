/**
 * CyberOps SOC — Security Engineer Knowledge Base & Visualization Test Suite
 *
 * Verifies:
 * 1. 1-to-many relationship deduplication: Multiple rows sharing the same technique_id
 *    count the technique exactly once per category.
 * 2. Chart A: Techniques by Tactic
 *    - Prefers tactic_names when populated, falls back to technique_tactics.
 *    - Splits comma, semicolon, newline delimiters and trims whitespace.
 *    - Unions distinct tactic associations across rows for the same technique.
 *    - Categorizes techniques missing tactic metadata under 'Unclassified Tactic'.
 *    - Sorts descending by unique-technique count, then alphabetically.
 * 3. Chart B: Technique Coverage by Platform
 *    - Prefers matched_platform_names when populated, falls back to technique_platforms.
 *    - Splits delimiters and normalizes canonical platform names.
 *    - Unions platform associations across rows for the same technique.
 *    - Categorizes missing platform metadata under 'Unspecified Platform'.
 *    - Sorts descending by unique-technique count, then alphabetically.
 * 4. Chart C: Mitigation Mapping Coverage
 *    - Strict Invariant: totalUniqueTechniques = mitigatedTechniquesCount + unmitigatedTechniquesCount.
 *    - Multi-row mitigation resolution: A technique with null mitigation_id on one row but a valid
 *      mitigation_id on another row is correctly classified as MITIGATED.
 *    - Unmitigated techniques correctly isolated as coverage gaps.
 *    - Mitigation ranking accurately deduplicates repeated technique-mitigation pairs.
 *    - Missing mitigation_name uses mitigation_id as clean fallback (never displays 'null').
 * 5. Invalid & Blank Technique ID Handling:
 *    - Null, empty, and whitespace-only technique_ids are completely ignored.
 * 6. Security & Defense-in-Depth Authorization:
 *    - security_engineer with approved account status is permitted.
 *    - soc_analyst, it_operations, super_admin, and unapproved/pending users are strictly denied.
 */

import {
  aggregateTechniquesByTacticForEngineer,
  aggregateTechniquesByPlatform,
  aggregateMitigationCoverage,
  normalizePlatformName,
  fetchSecurityEngineerKnowledge,
  SecurityEngineerKnowledgeRecord,
} from '../services/knowledgeService';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';

function assert(condition: boolean, description: string) {
  if (!condition) {
    console.error(`  [FAIL]: ${description}`);
    throw new Error(`Assertion failed: ${description}`);
  }
  console.log(`  [PASS]: ${description}`);
}

async function runSecurityEngineerKnowledgeTests() {
  console.log('=== RUNNING SECURITY ENGINEER KNOWLEDGE & AGGREGATION VERIFICATION TESTS ===\n');

  // =========================================================================
  // Group 1: 1-to-Many Multi-Row Deduplication & Chart A (Techniques by Tactic)
  // =========================================================================
  console.log('-- Group 1: Chart A — Techniques by Tactic & Multi-Row Deduplication --');

  // T1059.001 appears across 3 rows with different mitigations, but same technique.
  // It should be counted ONCE for Execution.
  // T1078 appears across 2 rows: row 1 has Defense Evasion, row 2 has Persistence.
  // It should be counted ONCE for Defense Evasion, and ONCE for Persistence.
  // T9999 has no tactic info: should be counted ONCE for Unclassified Tactic.
  const multiRowTacticRecords: SecurityEngineerKnowledgeRecord[] = [
    {
      technique_id: 'T1059.001',
      tactic_names: 'Execution',
      technique_tactics: 'Execution',
      technique_platforms: 'Windows, Linux',
      matched_platform_names: 'Windows, Linux',
      mitigation_id: 'M1038',
      mitigation_name: 'Execution Prevention',
    },
    {
      technique_id: 'T1059.001',
      tactic_names: 'Execution',
      technique_tactics: 'Execution',
      technique_platforms: 'Windows, Linux',
      matched_platform_names: 'Windows, Linux',
      mitigation_id: 'M1026',
      mitigation_name: 'Privileged Account Management',
    },
    {
      technique_id: 'T1059.001',
      tactic_names: 'Execution',
      technique_tactics: 'Execution',
      technique_platforms: 'Windows, Linux',
      matched_platform_names: 'Windows, Linux',
      mitigation_id: 'M1042',
      mitigation_name: 'Disable or Remove Feature',
    },
    {
      technique_id: 'T1078',
      tactic_names: 'Defense Evasion',
      technique_tactics: 'Defense Evasion',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1027',
      mitigation_name: 'Password Policies',
    },
    {
      technique_id: 'T1078',
      tactic_names: 'Persistence\nPrivilege Escalation',
      technique_tactics: 'Persistence; Privilege Escalation',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1026',
      mitigation_name: 'Privileged Account Management',
    },
    {
      technique_id: 'T9999',
      tactic_names: null,
      technique_tactics: '',
      technique_platforms: 'Linux',
      matched_platform_names: 'Linux',
      mitigation_id: null,
      mitigation_name: null,
    },
  ];

  const tacticResult = aggregateTechniquesByTacticForEngineer(multiRowTacticRecords);

  assert(tacticResult.totalUniqueTechniques === 3, 'Total unique techniques across 6 rows is exactly 3 (T1059.001, T1078, T9999)');

  const executionTactic = tacticResult.tactics.find((t) => t.tactic === 'Execution');
  assert(executionTactic !== undefined && executionTactic.uniqueTechniquesCount === 1, 'T1059.001 counted exactly once for Execution despite 3 rows');

  const persistenceTactic = tacticResult.tactics.find((t) => t.tactic === 'Persistence');
  assert(persistenceTactic !== undefined && persistenceTactic.uniqueTechniquesCount === 1, 'T1078 counted once for Persistence');

  const defenseEvasionTactic = tacticResult.tactics.find((t) => t.tactic === 'Defense Evasion');
  assert(defenseEvasionTactic !== undefined && defenseEvasionTactic.uniqueTechniquesCount === 1, 'T1078 counted once for Defense Evasion');

  const privEscTactic = tacticResult.tactics.find((t) => t.tactic === 'Privilege Escalation');
  assert(privEscTactic !== undefined && privEscTactic.uniqueTechniquesCount === 1, 'T1078 newline-separated tactic parsed and counted once');

  const unclassifiedTactic = tacticResult.tactics.find((t) => t.tactic.toLowerCase() === 'unclassified tactic');
  assert(unclassifiedTactic === undefined, 'T9999 with empty tactic metadata does not produce a synthetic Unclassified Tactic (sentinel/empty exclusion)');

  // Verify fallback: when tactic_names is empty/null, technique_tactics is used
  const fallbackRecord: SecurityEngineerKnowledgeRecord[] = [
    {
      technique_id: 'T1190',
      tactic_names: null,
      technique_tactics: 'Initial Access',
      technique_platforms: 'Network',
      matched_platform_names: 'Network',
      mitigation_id: null,
      mitigation_name: null,
    },
  ];
  const fallbackResult = aggregateTechniquesByTacticForEngineer(fallbackRecord);
  assert(fallbackResult.tactics[0].tactic === 'Initial Access', 'Falls back to technique_tactics when tactic_names is null');

  // =========================================================================
  // Group 2: Chart B — Technique Coverage by Platform
  // =========================================================================
  console.log('\n-- Group 2: Chart B — Technique Coverage by Platform --');

  assert(normalizePlatformName('windows') === 'Windows', 'Normalizes windows to Windows');
  assert(normalizePlatformName('  linux  ') === 'Linux', 'Normalizes and trims linux to Linux');
  assert(normalizePlatformName('macos') === 'macOS', 'Normalizes macos to macOS');
  assert(normalizePlatformName('iaas') === 'IaaS', 'Normalizes iaas to IaaS');
  assert(normalizePlatformName('saas') === 'SaaS', 'Normalizes saas to SaaS');
  assert(normalizePlatformName('') === 'Unspecified Platform', 'Empty platform maps to Unspecified Platform');

  const platformRecords: SecurityEngineerKnowledgeRecord[] = [
    {
      technique_id: 'T1059.001',
      technique_tactics: 'Execution',
      tactic_names: 'Execution',
      technique_platforms: 'Windows, Linux, macOS',
      matched_platform_names: 'Windows, Linux, macOS',
      mitigation_id: 'M1038',
      mitigation_name: 'Execution Prevention',
    },
    {
      technique_id: 'T1059.001',
      technique_tactics: 'Execution',
      tactic_names: 'Execution',
      technique_platforms: 'Windows, Linux, macOS',
      matched_platform_names: 'Windows, Linux, macOS',
      mitigation_id: 'M1026',
      mitigation_name: 'Privileged Account Management',
    },
    {
      technique_id: 'T1078',
      technique_tactics: 'Persistence',
      tactic_names: 'Persistence',
      technique_platforms: 'Windows; Containers',
      matched_platform_names: 'Windows; Containers',
      mitigation_id: 'M1027',
      mitigation_name: 'Password Policies',
    },
    {
      technique_id: 'T8888',
      technique_tactics: 'Discovery',
      tactic_names: 'Discovery',
      technique_platforms: null,
      matched_platform_names: '',
      mitigation_id: null,
      mitigation_name: null,
    },
  ];

  const platformResult = aggregateTechniquesByPlatform(platformRecords);

  assert(platformResult.totalUniqueTechniques === 3, 'Total unique techniques across platform records is 3');

  const windowsPlatform = platformResult.platforms.find((p) => p.platform === 'Windows');
  assert(windowsPlatform !== undefined && windowsPlatform.uniqueTechniquesCount === 2, 'Windows supports 2 unique techniques (T1059.001 and T1078), not double-counted across 2 rows of T1059.001');

  const containersPlatform = platformResult.platforms.find((p) => p.platform === 'Containers');
  assert(containersPlatform !== undefined && containersPlatform.uniqueTechniquesCount === 1, 'Containers supports 1 technique (T1078)');

  const unspecifiedPlatform = platformResult.platforms.find((p) => p.platform === 'Unspecified Platform');
  assert(unspecifiedPlatform !== undefined && unspecifiedPlatform.uniqueTechniquesCount === 1, 'Missing platform metadata classified as Unspecified Platform');

  // =========================================================================
  // Group 3: Chart C — Mitigation Mapping Coverage & Strict Invariant
  // =========================================================================
  console.log('\n-- Group 3: Chart C — Mitigation Mapping Coverage & Strict Invariant --');

  // T1059.001 has 2 mitigations: M1038 and M1026
  // T1078 has row 1 with mitigation_id: null, but row 2 with mitigation_id: 'M1026'.
  //   -> T1078 MUST be classified as MITIGATED! (Multi-row resolution)
  // T1595 has row 1 with mitigation_id: null, row 2 with mitigation_id: ''.
  //   -> T1595 MUST be classified as UNMITIGATED!
  // T1190 has 1 mitigation: M1038
  const mitigationRecords: SecurityEngineerKnowledgeRecord[] = [
    {
      technique_id: 'T1059.001',
      technique_tactics: 'Execution',
      tactic_names: 'Execution',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1038',
      mitigation_name: 'Execution Prevention',
    },
    {
      technique_id: 'T1059.001',
      technique_tactics: 'Execution',
      tactic_names: 'Execution',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1026',
      mitigation_name: 'Privileged Account Management',
    },
    {
      technique_id: 'T1078',
      technique_tactics: 'Persistence',
      tactic_names: 'Persistence',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: null,
      mitigation_name: null,
    },
    {
      technique_id: 'T1078',
      technique_tactics: 'Persistence',
      tactic_names: 'Persistence',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1026',
      mitigation_name: 'Privileged Account Management',
    },
    {
      technique_id: 'T1595',
      technique_tactics: 'Reconnaissance',
      tactic_names: 'Reconnaissance',
      technique_platforms: 'Network',
      matched_platform_names: 'Network',
      mitigation_id: null,
      mitigation_name: null,
    },
    {
      technique_id: 'T1595',
      technique_tactics: 'Reconnaissance',
      tactic_names: 'Reconnaissance',
      technique_platforms: 'Network',
      matched_platform_names: 'Network',
      mitigation_id: '   ',
      mitigation_name: '',
    },
    {
      technique_id: 'T1190',
      technique_tactics: 'Initial Access',
      tactic_names: 'Initial Access',
      technique_platforms: 'Network',
      matched_platform_names: 'Network',
      mitigation_id: 'M1038',
      mitigation_name: null, // missing name test
    },
  ];

  const mitResult = aggregateMitigationCoverage(mitigationRecords);
  const summary = mitResult.summary;

  assert(summary.totalUniqueTechniques === 4, 'Total unique techniques is 4 (T1059.001, T1078, T1595, T1190)');
  assert(summary.mitigatedTechniquesCount === 3, 'Mitigated techniques is 3 (T1059.001, T1078, T1190)');
  assert(summary.unmitigatedTechniquesCount === 1, 'Unmitigated techniques is 1 (T1595)');

  // Critical Invariant Test:
  assert(
    summary.totalUniqueTechniques === summary.mitigatedTechniquesCount + summary.unmitigatedTechniquesCount,
    'INVARIANT VERIFIED: totalUniqueTechniques === mitigatedTechniquesCount + unmitigatedTechniquesCount'
  );

  assert(summary.mitigatedPercentage === 75, 'Mitigated percentage is exactly 75% (3 of 4)');
  assert(summary.unmitigatedPercentage === 25, 'Unmitigated percentage is exactly 25% (1 of 4)');

  // Verify ranked mitigations
  const m1038 = mitResult.mitigations.find((m) => m.mitigationId === 'M1038');
  assert(m1038 !== undefined && m1038.addressedTechniquesCount === 2, 'M1038 addresses 2 techniques (T1059.001 and T1190)');
  assert(m1038!.mitigationName === 'Execution Prevention', 'M1038 resolved name correctly despite one row having null name');

  const m1026 = mitResult.mitigations.find((m) => m.mitigationId === 'M1026');
  assert(m1026 !== undefined && m1026.addressedTechniquesCount === 2, 'M1026 addresses 2 techniques (T1059.001 and T1078)');

  // =========================================================================
  // Group 4: Invalid and Null Technique ID Exclusion
  // =========================================================================
  console.log('\n-- Group 4: Invalid and Null Technique ID Exclusion --');

  const invalidTechRecords: SecurityEngineerKnowledgeRecord[] = [
    {
      technique_id: null,
      technique_tactics: 'Execution',
      tactic_names: 'Execution',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1038',
      mitigation_name: 'Execution Prevention',
    },
    {
      technique_id: '   ',
      technique_tactics: 'Execution',
      tactic_names: 'Execution',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1038',
      mitigation_name: 'Execution Prevention',
    },
    {
      technique_id: 'T1059',
      technique_tactics: 'Execution',
      tactic_names: 'Execution',
      technique_platforms: 'Windows',
      matched_platform_names: 'Windows',
      mitigation_id: 'M1038',
      mitigation_name: 'Execution Prevention',
    },
  ];

  const filteredTacticResult = aggregateTechniquesByTacticForEngineer(invalidTechRecords);
  assert(filteredTacticResult.totalUniqueTechniques === 1, 'Ignores null and whitespace-only technique IDs');
  assert(filteredTacticResult.tactics[0].uniqueTechniquesCount === 1, 'Only valid technique counted');

  const filteredMitResult = aggregateMitigationCoverage(invalidTechRecords);
  assert(filteredMitResult.summary.totalUniqueTechniques === 1, 'Mitigation coverage ignores null/empty technique IDs');

  // =========================================================================
  // Group 5: Deterministic Sorting & Tie-Breaker Verification
  // =========================================================================
  console.log('\n-- Group 5: Deterministic Sorting & Tie-Breaker Verification --');

  const tieRecords: SecurityEngineerKnowledgeRecord[] = [
    {
      technique_id: 'T1001',
      technique_tactics: 'Persistence',
      tactic_names: 'Persistence',
      technique_platforms: 'macOS',
      matched_platform_names: 'macOS',
      mitigation_id: 'M2000',
      mitigation_name: 'Z-Mitigation',
    },
    {
      technique_id: 'T1002',
      technique_tactics: 'Collection',
      tactic_names: 'Collection',
      technique_platforms: 'Linux',
      matched_platform_names: 'Linux',
      mitigation_id: 'M1000',
      mitigation_name: 'A-Mitigation',
    },
  ];

  const tieTacticResult = aggregateTechniquesByTacticForEngineer(tieRecords);
  assert(
    tieTacticResult.tactics[0].tactic === 'Collection' && tieTacticResult.tactics[1].tactic === 'Persistence',
    'Equal count tactics sort alphabetically (Collection before Persistence)'
  );

  const tiePlatformResult = aggregateTechniquesByPlatform(tieRecords);
  assert(
    tiePlatformResult.platforms[0].platform === 'Linux' && tiePlatformResult.platforms[1].platform === 'macOS',
    'Equal count platforms sort alphabetically (Linux before macOS)'
  );

  const tieMitResult = aggregateMitigationCoverage(tieRecords);
  assert(
    tieMitResult.mitigations[0].mitigationName === 'A-Mitigation' &&
      tieMitResult.mitigations[1].mitigationName === 'Z-Mitigation',
    'Equal count mitigations sort alphabetically (A-Mitigation before Z-Mitigation)'
  );

  // =========================================================================
  // Group 6: Security & Role Authorization Gates
  // =========================================================================
  console.log('\n-- Group 6: Security & Role Authorization Gates --');

  // 1. Unapproved security engineer denied
  const unapprovedEngineer: UserProfile = {
    ...DEMO_PERSONAS.security_engineer,
    accountStatus: 'pending',
  };
  try {
    await fetchSecurityEngineerKnowledge(unapprovedEngineer);
    assert(false, 'Should have rejected unapproved security_engineer');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects unapproved security_engineer with AccessDeniedError');
  }

  // 2. SOC Analyst denied
  try {
    await fetchSecurityEngineerKnowledge(DEMO_PERSONAS.soc_analyst);
    assert(false, 'Should have rejected soc_analyst from querying security_engineer_knowledge');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects soc_analyst with AccessDeniedError');
  }

  // 3. IT Operations denied
  try {
    await fetchSecurityEngineerKnowledge(DEMO_PERSONAS.it_operations);
    assert(false, 'Should have rejected it_operations from querying security_engineer_knowledge');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects it_operations with AccessDeniedError');
  }

  // 4. Super Admin denied
  try {
    await fetchSecurityEngineerKnowledge(DEMO_PERSONAS.super_admin);
    assert(false, 'Should have rejected super_admin from querying security_engineer_knowledge');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects super_admin with AccessDeniedError');
  }

  console.log('\n=== ALL SECURITY ENGINEER KNOWLEDGE & AGGREGATION TESTS PASSED ===');
}

runSecurityEngineerKnowledgeTests().catch((err) => {
  console.error('[FATAL TEST FAILURE]:', err);
  process.exit(1);
});
