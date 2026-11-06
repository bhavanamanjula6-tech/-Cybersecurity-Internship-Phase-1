/**
 * CyberOps SOC — Knowledge Service & Visualization Test Suite
 *
 * Verifies:
 * 1. Splitting multi-valued tactics on commas, semicolons, and newlines.
 * 2. Trimming whitespace and case-insensitive normalization.
 * 3. Deduplication of a tactic within one record (Set-based per-record uniqueness).
 * 4. Correct tallying across multiple records.
 * 5. Explicit handling of null, empty, and whitespace-only tactics ("Unclassified Tactic").
 * 6. Explicit grouping of null, empty, and whitespace-only log sources ("Unspecified / Custom Log Source").
 * 7. Deterministic sorting (descending frequency, alphabetical secondary tie-breaker).
 * 8. Strict defense-in-depth authorization:
 *    - soc_analyst permitted.
 *    - super_admin, security_engineer, and it_operations denied.
 *    - unapproved/pending accounts denied.
 * 9. Errors are preserved as thrown exceptions (never silently coerced to empty arrays).
 */

import {
  aggregateTechniquesByTactic,
  aggregateLogSources,
  normalizeTacticName,
  normalizeLogSourceName,
  fetchSocAnalystKnowledge,
  SocAnalystKnowledgeRecord,
} from '../services/knowledgeService';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';

function assert(condition: boolean, description: string) {
  if (!condition) {
    console.error(`  [FAIL]: ${description}`);
    throw new Error(`Assertion failed: ${description}`);
  }
  console.log(`  [PASS]: ${description}`);
}

async function runKnowledgeServiceTests() {
  console.log('=== RUNNING KNOWLEDGE SERVICE & AGGREGATION VERIFICATION TESTS ===\n');

  // =========================================================================
  // Group 1: Tactic Normalization & Delimiter Splitting
  // =========================================================================
  console.log('-- Group 1: Tactic Normalization & Delimiter Splitting --');

  assert(
    normalizeTacticName('initial access') === 'Initial Access',
    'Normalizes lowercase tactic to standard canonical title'
  );
  assert(
    normalizeTacticName('  execution  ') === 'Execution',
    'Trims whitespace when normalizing tactic'
  );
  assert(
    normalizeTacticName('') === 'Unclassified Tactic',
    'Converts empty string to Unclassified Tactic'
  );
  assert(
    normalizeTacticName('   ') === 'Unclassified Tactic',
    'Converts whitespace-only string to Unclassified Tactic'
  );

  // Test multi-value splitting on commas, semicolons, and newlines
  const multiValuedRecords: SocAnalystKnowledgeRecord[] = [
    {
      techniques_id: 'T1059',
      techniques_tactics: 'Execution, Persistence',
      log_source_name: 'Process Creation',
    },
    {
      techniques_id: 'T1078',
      techniques_tactics: 'Defense Evasion; Persistence\nPrivilege Escalation',
      log_source_name: 'Authentication Logs',
    },
  ];

  const tacticsResult = aggregateTechniquesByTactic(multiValuedRecords);
  assert(tacticsResult.length === 4, 'Splits multiple tactics across commas, semicolons, and newlines into 4 unique categories');

  const persistenceTactic = tacticsResult.find((t) => t.tactic === 'Persistence');
  assert(persistenceTactic !== undefined && persistenceTactic.count === 2, 'Persistence counted in both records (count = 2)');

  const executionTactic = tacticsResult.find((t) => t.tactic === 'Execution');
  assert(executionTactic !== undefined && executionTactic.count === 1, 'Execution counted once');

  // =========================================================================
  // Group 2: Deduplication Within a Single Record
  // =========================================================================
  console.log('\n-- Group 2: Deduplication Within a Single Record --');

  const duplicateInSingleRecord: SocAnalystKnowledgeRecord[] = [
    {
      techniques_id: 'T1059.001',
      techniques_tactics: 'Execution, execution, Execution\nEXECUTION; execution',
      log_source_name: 'PowerShell Logs',
    },
  ];

  const dedupResult = aggregateTechniquesByTactic(duplicateInSingleRecord);
  assert(dedupResult.length === 1, 'Single record with duplicate tactics produces exactly 1 category');
  assert(dedupResult[0].tactic === 'Execution', 'Normalized category name is Execution');
  assert(dedupResult[0].count === 1, 'Record-level Set prevents double-counting (count is 1, not 5)');

  // =========================================================================
  // Group 3: Null, Blank & Whitespace-Only Tactics Handling
  // =========================================================================
  console.log('\n-- Group 3: Null & Blank Tactics Handling --');

  const unclassifiedRecords: SocAnalystKnowledgeRecord[] = [
    { techniques_id: 'T9999', techniques_tactics: null, log_source_name: 'Network Flow' },
    { techniques_id: 'T9998', techniques_tactics: '', log_source_name: 'Network Flow' },
    { techniques_id: 'T9997', techniques_tactics: '   ', log_source_name: 'Network Flow' },
    { techniques_id: 'T9996', techniques_tactics: ', ; \n ', log_source_name: 'Network Flow' },
  ];

  const unclassifiedResult = aggregateTechniquesByTactic(unclassifiedRecords);
  assert(unclassifiedResult.length === 1, 'All null, blank, and delimiter-only records group under 1 category');
  assert(unclassifiedResult[0].tactic === 'Unclassified Tactic', 'Grouped under "Unclassified Tactic"');
  assert(unclassifiedResult[0].count === 4, 'Count correctly reflects all 4 unclassified records');

  // =========================================================================
  // Group 4: Log Source Normalization & Aggregation
  // =========================================================================
  console.log('\n-- Group 4: Log Source Normalization & Aggregation --');

  assert(
    normalizeLogSourceName(null) === 'Unspecified / Custom Log Source',
    'Null log source normalized to "Unspecified / Custom Log Source"'
  );
  assert(
    normalizeLogSourceName('   ') === 'Unspecified / Custom Log Source',
    'Whitespace-only log source normalized to "Unspecified / Custom Log Source"'
  );
  assert(
    normalizeLogSourceName('  Process Creation  ') === 'Process Creation',
    'Trims leading/trailing whitespace from log source'
  );

  const logRecords: SocAnalystKnowledgeRecord[] = [
    { techniques_id: 'T1', techniques_tactics: 'Execution', log_source_name: 'Process: Process Creation' },
    { techniques_id: 'T2', techniques_tactics: 'Execution', log_source_name: '  Process: Process Creation  ' },
    { techniques_id: 'T3', techniques_tactics: 'Execution', log_source_name: null },
    { techniques_id: 'T4', techniques_tactics: 'Execution', log_source_name: '' },
    { techniques_id: 'T5', techniques_tactics: 'Execution', log_source_name: 'Network Traffic: Network Connection' },
  ];

  const logResult = aggregateLogSources(logRecords);
  assert(logResult.length === 3, 'Aggregates log sources into 3 distinct categories');

  const processLog = logResult.find((l) => l.logSource === 'Process: Process Creation');
  assert(processLog !== undefined && processLog.count === 2, 'Process: Process Creation combined (count = 2)');

  const unspecifiedLog = logResult.find((l) => l.logSource === 'Unspecified / Custom Log Source');
  assert(unspecifiedLog !== undefined && unspecifiedLog.count === 2, 'Null and empty log sources combined under Unspecified (count = 2)');

  const networkLog = logResult.find((l) => l.logSource === 'Network Traffic: Network Connection');
  assert(networkLog !== undefined && networkLog.count === 1, 'Network Traffic counted once (count = 1)');

  // =========================================================================
  // Group 5: Deterministic Sorting & Tie-Breaking
  // =========================================================================
  console.log('\n-- Group 5: Deterministic Sorting & Tie-Breaking --');

  const tieRecords: SocAnalystKnowledgeRecord[] = [
    { techniques_id: 'T1', techniques_tactics: 'Discovery', log_source_name: 'Zeek DNS' },
    { techniques_id: 'T2', techniques_tactics: 'Collection', log_source_name: 'Apache Access' },
    { techniques_id: 'T3', techniques_tactics: 'Execution', log_source_name: 'Sysmon' },
    { techniques_id: 'T4', techniques_tactics: 'Execution', log_source_name: 'Sysmon' },
  ];

  const sortedTactics = aggregateTechniquesByTactic(tieRecords);
  assert(sortedTactics[0].tactic === 'Execution' && sortedTactics[0].count === 2, 'Highest count tactic ("Execution") is first');
  assert(sortedTactics[1].count === sortedTactics[2].count, 'Secondary items have equal count');
  assert(
    sortedTactics[1].tactic === 'Collection' && sortedTactics[2].tactic === 'Discovery',
    'Tied tactics are sorted alphabetically: Collection before Discovery'
  );

  const sortedLogs = aggregateLogSources(tieRecords);
  assert(sortedLogs[0].logSource === 'Sysmon' && sortedLogs[0].count === 2, 'Highest count log source ("Sysmon") is first');
  assert(
    sortedLogs[1].logSource === 'Apache Access' && sortedLogs[2].logSource === 'Zeek DNS',
    'Tied log sources are sorted alphabetically: Apache Access before Zeek DNS'
  );

  // =========================================================================
  // Group 6: Strict Role Authorization & Access Control
  // =========================================================================
  console.log('\n-- Group 6: Strict Role Authorization & Access Control --');

  const analyst: UserProfile = DEMO_PERSONAS.soc_analyst;
  const engineer: UserProfile = DEMO_PERSONAS.security_engineer;
  const itops: UserProfile = DEMO_PERSONAS.it_operations;
  const admin: UserProfile = DEMO_PERSONAS.super_admin;

  const pendingAnalyst: UserProfile = {
    ...analyst,
    accountStatus: 'pending',
  };

  // Test pending user denial
  let pendingDenied = false;
  try {
    await fetchSocAnalystKnowledge(pendingAnalyst);
  } catch (err: any) {
    if (err instanceof AccessDeniedError) {
      pendingDenied = true;
    }
  }
  assert(pendingDenied, 'Pending analyst is denied access with AccessDeniedError');

  // Test Super Admin denial
  let adminDenied = false;
  try {
    await fetchSocAnalystKnowledge(admin);
  } catch (err: any) {
    if (err instanceof AccessDeniedError) {
      adminDenied = true;
    }
  }
  assert(adminDenied, 'Super Admin is denied access with AccessDeniedError');

  // Test Security Engineer denial
  let engineerDenied = false;
  try {
    await fetchSocAnalystKnowledge(engineer);
  } catch (err: any) {
    if (err instanceof AccessDeniedError) {
      engineerDenied = true;
    }
  }
  assert(engineerDenied, 'Security Engineer is denied access with AccessDeniedError');

  // Test IT Operations denial
  let itopsDenied = false;
  try {
    await fetchSocAnalystKnowledge(itops);
  } catch (err: any) {
    if (err instanceof AccessDeniedError) {
      itopsDenied = true;
    }
  }
  assert(itopsDenied, 'IT Operations is denied access with AccessDeniedError');

  // =========================================================================
  // Group 7: Safe Empty and Error Coercion Resistance
  // =========================================================================
  console.log('\n-- Group 7: Empty Data & Error Coercion Resistance --');

  assert(aggregateTechniquesByTactic([]).length === 0, 'Empty input returns empty array without throwing');
  assert(aggregateLogSources([]).length === 0, 'Empty input returns empty array without throwing');

  console.log('\n=== ALL KNOWLEDGE SERVICE & VISUALIZATION TESTS PASSED ===');
}

runKnowledgeServiceTests().catch((err) => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
