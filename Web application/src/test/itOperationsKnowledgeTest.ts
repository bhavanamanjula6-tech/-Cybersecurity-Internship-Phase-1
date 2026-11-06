/**
 * CyberOps SOC — IT Operations Knowledge Base & Visualization Test Suite
 *
 * Verifies:
 * 1. 1-to-many relationship deduplication: Multiple rows sharing the same technique_id
 *    count the technique exactly once per tactic and platform.
 * 2. Chart A: Techniques by Tactic for IT Operations
 *    - Prefers tactic_name when populated, falls back to technique_tactics when blank.
 *    - Splits comma, semicolon, newline delimiters and trims whitespace.
 *    - Unions distinct tactic associations across rows for the same technique.
 *    - Categorizes techniques missing tactic metadata under 'Unclassified Tactic'.
 *    - Sorts descending by unique-technique count, then alphabetically.
 * 3. Chart B: Technique Coverage by Platform for IT Operations
 *    - Prefers platform_name when populated, falls back to technique_platforms when blank.
 *    - Splits delimiters and normalizes canonical platform names.
 *    - Unions platform associations across rows for the same technique.
 *    - Categorizes missing platform metadata under 'Unspecified Platform'.
 *    - Sorts descending by unique-technique count, then alphabetically.
 * 4. Invalid & Blank Technique ID Handling:
 *    - Null, empty, and whitespace-only technique_ids are completely excluded from counts.
 * 5. Deterministic Sorting & Tie-Breakers:
 *    - Secondary alphabetical sort when unique-technique counts are tied.
 * 6. Security & Defense-in-Depth Authorization:
 *    - it_operations with approved account status is permitted.
 *    - soc_analyst, security_engineer, super_admin, and unapproved/pending users are strictly denied.
 */

import {
  aggregateTechniquesByTacticForItOps,
  aggregateTechniquesByPlatformForItOps,
  fetchItOperationsKnowledge,
  ItOperationsKnowledgeRecord,
} from '../services/knowledgeService';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';

function assert(condition: boolean, description: string) {
  if (!condition) {
    console.error(`  [FAIL]: ${description}`);
    throw new Error(`Assertion failed: ${description}`);
  }
  console.log(`  [PASS]: ${description}`);
}

async function runItOperationsKnowledgeTests() {
  console.log('=== RUNNING IT OPERATIONS KNOWLEDGE & AGGREGATION VERIFICATION TESTS ===\n');

  // =========================================================================
  // Group 1: Chart A — Techniques by Tactic & Multi-Row Deduplication
  // =========================================================================
  console.log('-- Group 1: Chart A — Techniques by Tactic & Multi-Row Deduplication --');

  // T1059.001 appears across 3 rows: row 1 has tactic_name: "Execution", row 2 has "Execution", row 3 has "Execution".
  // Count for Execution should be 1.
  // T1078 appears across 2 rows: row 1 has tactic_name: "Defense Evasion", row 2 has "Persistence; Privilege Escalation"
  // Should union associations: Defense Evasion = 1, Persistence = 1, Privilege Escalation = 1.
  // T9999 has null tactic_name and empty technique_tactics -> Unclassified Tactic.
  const multiRowTacticRecords: ItOperationsKnowledgeRecord[] = [
    {
      technique_id: 'T1059.001',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Windows',
      technique_platforms: 'Windows, Linux',
    },
    {
      technique_id: 'T1059.001',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Linux',
      technique_platforms: 'Windows, Linux',
    },
    {
      technique_id: 'T1059.001',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'macOS',
      technique_platforms: 'Windows, Linux, macOS',
    },
    {
      technique_id: 'T1078',
      tactic_name: 'Defense Evasion',
      technique_tactics: 'Defense Evasion',
      platform_name: 'Windows',
      technique_platforms: 'Windows',
    },
    {
      technique_id: 'T1078',
      tactic_name: 'Persistence\nPrivilege Escalation',
      technique_tactics: 'Persistence; Privilege Escalation',
      platform_name: 'Windows',
      technique_platforms: 'Windows',
    },
    {
      technique_id: 'T9999',
      tactic_name: null,
      technique_tactics: '',
      platform_name: 'Linux',
      technique_platforms: 'Linux',
    },
  ];

  const tacticResult = aggregateTechniquesByTacticForItOps(multiRowTacticRecords);

  assert(
    tacticResult.totalUniqueTechniques === 3,
    'Total unique techniques across 6 rows is exactly 3 (T1059.001, T1078, T9999)'
  );

  const executionTactic = tacticResult.tactics.find((t) => t.tactic === 'Execution');
  assert(
    executionTactic !== undefined && executionTactic.uniqueTechniquesCount === 1,
    'T1059.001 counted exactly once for Execution despite 3 rows'
  );

  const persistenceTactic = tacticResult.tactics.find((t) => t.tactic === 'Persistence');
  assert(
    persistenceTactic !== undefined && persistenceTactic.uniqueTechniquesCount === 1,
    'T1078 counted once for Persistence'
  );

  const defenseEvasionTactic = tacticResult.tactics.find((t) => t.tactic === 'Defense Evasion');
  assert(
    defenseEvasionTactic !== undefined && defenseEvasionTactic.uniqueTechniquesCount === 1,
    'T1078 counted once for Defense Evasion'
  );

  const privEscTactic = tacticResult.tactics.find((t) => t.tactic === 'Privilege Escalation');
  assert(
    privEscTactic !== undefined && privEscTactic.uniqueTechniquesCount === 1,
    'T1078 newline-separated tactic parsed and counted once for Privilege Escalation'
  );

  const unclassifiedTactic = tacticResult.tactics.find((t) => t.tactic === 'Unclassified Tactic');
  assert(
    unclassifiedTactic !== undefined && unclassifiedTactic.uniqueTechniquesCount === 1,
    'T9999 with empty tactics mapped to Unclassified Tactic'
  );

  // Preferred-field precedence and fallback verification:
  const fallbackRecords: ItOperationsKnowledgeRecord[] = [
    {
      technique_id: 'T1190',
      tactic_name: 'Initial Access',
      technique_tactics: 'Execution', // tactic_name should override technique_tactics
      platform_name: 'Network',
      technique_platforms: 'Network',
    },
    {
      technique_id: 'T1003',
      tactic_name: null, // should fall back to technique_tactics
      technique_tactics: 'Credential Access',
      platform_name: 'Windows',
      technique_platforms: 'Windows',
    },
  ];
  const precedenceResult = aggregateTechniquesByTacticForItOps(fallbackRecords);
  const t1190Tactic = precedenceResult.tactics.find((t) => t.tactic === 'Initial Access');
  assert(
    t1190Tactic !== undefined && t1190Tactic.uniqueTechniquesCount === 1,
    'Preferred field tactic_name takes precedence over technique_tactics'
  );
  const t1003Tactic = precedenceResult.tactics.find((t) => t.tactic === 'Credential Access');
  assert(
    t1003Tactic !== undefined && t1003Tactic.uniqueTechniquesCount === 1,
    'Falls back to technique_tactics when tactic_name is null'
  );

  // =========================================================================
  // Group 2: Chart B — Technique Coverage by Platform
  // =========================================================================
  console.log('\n-- Group 2: Chart B — Technique Coverage by Platform --');

  const multiRowPlatformRecords: ItOperationsKnowledgeRecord[] = [
    {
      technique_id: 'T1059.001',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Windows',
      technique_platforms: 'Windows, Linux',
    },
    {
      technique_id: 'T1059.001',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Windows',
      technique_platforms: 'Windows, Linux',
    },
    {
      technique_id: 'T1059.001',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Linux',
      technique_platforms: 'Windows, Linux',
    },
    {
      technique_id: 'T1078',
      tactic_name: 'Persistence',
      technique_tactics: 'Persistence',
      platform_name: 'Windows; Containers',
      technique_platforms: 'Windows',
    },
    {
      technique_id: 'T8888',
      tactic_name: 'Discovery',
      technique_tactics: 'Discovery',
      platform_name: null,
      technique_platforms: '',
    },
  ];

  const platformResult = aggregateTechniquesByPlatformForItOps(multiRowPlatformRecords);

  assert(
    platformResult.totalUniqueTechniques === 3,
    'Total unique techniques across platform records is 3'
  );

  const windowsPlatform = platformResult.platforms.find((p) => p.platform === 'Windows');
  assert(
    windowsPlatform !== undefined && windowsPlatform.uniqueTechniquesCount === 2,
    'Windows supports 2 unique techniques (T1059.001 and T1078), not double-counted across 2 rows of T1059.001'
  );

  const linuxPlatform = platformResult.platforms.find((p) => p.platform === 'Linux');
  assert(
    linuxPlatform !== undefined && linuxPlatform.uniqueTechniquesCount === 1,
    'Linux supports 1 technique (T1059.001)'
  );

  const containersPlatform = platformResult.platforms.find((p) => p.platform === 'Containers');
  assert(
    containersPlatform !== undefined && containersPlatform.uniqueTechniquesCount === 1,
    'Containers supports 1 technique (T1078)'
  );

  const unspecifiedPlatform = platformResult.platforms.find((p) => p.platform === 'Unspecified Platform');
  assert(
    unspecifiedPlatform !== undefined && unspecifiedPlatform.uniqueTechniquesCount === 1,
    'T8888 missing platform metadata classified as Unspecified Platform'
  );

  // Platform fallback test:
  const platformFallbackRecords: ItOperationsKnowledgeRecord[] = [
    {
      technique_id: 'T1047',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: null, // should fall back to technique_platforms
      technique_platforms: 'macOS, IaaS',
    },
  ];
  const platformFallbackResult = aggregateTechniquesByPlatformForItOps(platformFallbackRecords);
  assert(
    platformFallbackResult.platforms.some((p) => p.platform === 'macOS') &&
      platformFallbackResult.platforms.some((p) => p.platform === 'IaaS'),
    'Falls back to technique_platforms and normalizes macOS and IaaS when platform_name is null'
  );

  // =========================================================================
  // Group 3: Invalid and Blank Technique ID Exclusion
  // =========================================================================
  console.log('\n-- Group 3: Invalid and Blank Technique ID Exclusion --');

  const invalidTechRecords: ItOperationsKnowledgeRecord[] = [
    {
      technique_id: null,
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Windows',
      technique_platforms: 'Windows',
    },
    {
      technique_id: '   ',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Windows',
      technique_platforms: 'Windows',
    },
    {
      technique_id: 'T1059',
      tactic_name: 'Execution',
      technique_tactics: 'Execution',
      platform_name: 'Windows',
      technique_platforms: 'Windows',
    },
  ];

  const filteredTacticResult = aggregateTechniquesByTacticForItOps(invalidTechRecords);
  assert(
    filteredTacticResult.totalUniqueTechniques === 1,
    'Ignores null and whitespace-only technique IDs in tactic aggregation'
  );
  assert(
    filteredTacticResult.tactics[0].uniqueTechniquesCount === 1,
    'Only valid technique counted in tactic aggregation'
  );

  const filteredPlatformResult = aggregateTechniquesByPlatformForItOps(invalidTechRecords);
  assert(
    filteredPlatformResult.totalUniqueTechniques === 1,
    'Ignores null and whitespace-only technique IDs in platform aggregation'
  );

  // =========================================================================
  // Group 4: Deterministic Sorting & Tie-Breaker Verification
  // =========================================================================
  console.log('\n-- Group 4: Deterministic Sorting & Tie-Breaker Verification --');

  const tieRecords: ItOperationsKnowledgeRecord[] = [
    {
      technique_id: 'T1001',
      tactic_name: 'Persistence',
      technique_tactics: 'Persistence',
      platform_name: 'macOS',
      technique_platforms: 'macOS',
    },
    {
      technique_id: 'T1002',
      tactic_name: 'Collection',
      technique_tactics: 'Collection',
      platform_name: 'Linux',
      technique_platforms: 'Linux',
    },
  ];

  const tieTacticResult = aggregateTechniquesByTacticForItOps(tieRecords);
  assert(
    tieTacticResult.tactics[0].tactic === 'Collection' && tieTacticResult.tactics[1].tactic === 'Persistence',
    'Equal count tactics sort alphabetically (Collection before Persistence)'
  );

  const tiePlatformResult = aggregateTechniquesByPlatformForItOps(tieRecords);
  assert(
    tiePlatformResult.platforms[0].platform === 'Linux' && tiePlatformResult.platforms[1].platform === 'macOS',
    'Equal count platforms sort alphabetically (Linux before macOS)'
  );

  // =========================================================================
  // Group 5: Security & Role Authorization Gates
  // =========================================================================
  console.log('\n-- Group 5: Security & Role Authorization Gates --');

  // 1. Unapproved it_operations user denied
  const unapprovedItOps: UserProfile = {
    ...DEMO_PERSONAS.it_operations,
    accountStatus: 'pending',
  };
  try {
    await fetchItOperationsKnowledge(unapprovedItOps);
    assert(false, 'Should have rejected unapproved it_operations user');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects unapproved it_operations user with AccessDeniedError');
  }

  // 2. SOC Analyst denied
  try {
    await fetchItOperationsKnowledge(DEMO_PERSONAS.soc_analyst);
    assert(false, 'Should have rejected soc_analyst from querying it_operations_knowledge');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects soc_analyst with AccessDeniedError');
  }

  // 3. Security Engineer denied
  try {
    await fetchItOperationsKnowledge(DEMO_PERSONAS.security_engineer);
    assert(false, 'Should have rejected security_engineer from querying it_operations_knowledge');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects security_engineer with AccessDeniedError');
  }

  // 4. Super Admin denied
  try {
    await fetchItOperationsKnowledge(DEMO_PERSONAS.super_admin);
    assert(false, 'Should have rejected super_admin from querying it_operations_knowledge');
  } catch (err: any) {
    assert(err instanceof AccessDeniedError, 'Rejects super_admin with AccessDeniedError');
  }

  console.log('\n=== ALL IT OPERATIONS KNOWLEDGE & AGGREGATION TESTS PASSED ===');
}

runItOperationsKnowledgeTests().catch((err) => {
  console.error('[FATAL TEST FAILURE]:', err);
  process.exit(1);
});
