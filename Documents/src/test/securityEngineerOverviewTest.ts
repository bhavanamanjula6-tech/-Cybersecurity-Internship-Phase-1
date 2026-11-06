/**
 * CyberOps SOC — Security Engineer Overview Test Suite
 *
 * Verifies:
 * 1. calculateSecurityEngineerKpis:
 *    - Unique Techniques: counts distinct valid non-sentinel technique IDs
 *    - Unique Mitigations: counts distinct valid non-sentinel mitigation IDs
 *    - Mitigation Mapping Coverage: (mitigated techniques / unique techniques) * 100 formatted to 2 decimal places (e.g. 84.07%)
 *    - Total Mapping Records: records.length (1,559)
 * 2. Sentinel value exclusion:
 *    - isSentinelOrEmpty detects 'none', 'null', 'n/a', 'na', 'unknown', '-', '', '   ', undefined, null.
 *    - Sentinel technique_ids and mitigation_ids are rejected and never counted.
 * 3. aggregateMitigationCoverage:
 *    - Formats coverage percentage to 2 decimal places.
 *    - Deduplicates repeated technique-mitigation mappings within and across records.
 *    - Ranks mitigations descending by distinct techniques addressed.
 * 4. aggregateTechniquesByMitigationCount (Chart 2):
 *    - Groups distinct valid mitigations per technique.
 *    - Sorts descending by distinct mitigation count.
 *    - Deterministic tie-breaking by techniqueId ascending.
 * 5. aggregateTechniquesByTacticForEngineer (Chart 3):
 *    - Splits multi-valued tactic tokens on commas, semicolons, pipes, and newlines.
 *    - Deduplicates technique IDs per individual tactic.
 *    - Rejects sentinel tactic tokens.
 * 6. Pagination logic verification:
 *    - Paging with pageSize = 500 across 1,559 items retrieves all 1,559 items in 4 iterations.
 * 7. Empty dataset handling:
 *    - Empty records array returns zeroed KPIs and empty aggregations without crashing.
 */

import {
  isSentinelOrEmpty,
  calculateSecurityEngineerKpis,
  aggregateMitigationCoverage,
  aggregateTechniquesByMitigationCount,
  aggregateTechniquesByTacticForEngineer,
  SecurityEngineerKnowledgeRecord,
} from '../services/knowledgeService';

let passed = 0;
let failed = 0;

function assert(condition: boolean, description: string) {
  if (!condition) {
    console.error(`  [FAIL]: ${description}`);
    failed++;
    throw new Error(`Assertion failed: ${description}`);
  }
  console.log(`  [PASS]: ${description}`);
  passed++;
}

function createRecord(partial: Partial<SecurityEngineerKnowledgeRecord>): SecurityEngineerKnowledgeRecord {
  return {
    technique_id: null,
    technique_name: null,
    technique_description: null,
    technique_tactics: null,
    technique_platforms: null,
    tactic_ids: null,
    tactic_names: null,
    matched_platform_names: null,
    addressed_source_id: null,
    addressed_target_id: null,
    mapping_type: null,
    mitigation_id: null,
    mitigation_name: null,
    mitigation_description: null,
    ...partial,
  };
}

async function runSecurityEngineerOverviewTests() {
  console.log('=== RUNNING SECURITY ENGINEER OVERVIEW TEST SUITE ===\n');

  // =========================================================================
  // Test 1: Sentinel Value Filtering
  // =========================================================================
  console.log('-- Test 1: Sentinel Value Filtering --');
  assert(isSentinelOrEmpty(null) === true, 'null is recognized as sentinel');
  assert(isSentinelOrEmpty(undefined) === true, 'undefined is recognized as sentinel');
  assert(isSentinelOrEmpty('') === true, 'empty string is recognized as sentinel');
  assert(isSentinelOrEmpty('   ') === true, 'whitespace string is recognized as sentinel');
  assert(isSentinelOrEmpty('none') === true, 'none is recognized as sentinel');
  assert(isSentinelOrEmpty('NONE') === true, 'uppercase NONE is recognized as sentinel');
  assert(isSentinelOrEmpty('null') === true, 'null string is recognized as sentinel');
  assert(isSentinelOrEmpty('n/a') === true, 'n/a is recognized as sentinel');
  assert(isSentinelOrEmpty('N/A') === true, 'uppercase N/A is recognized as sentinel');
  assert(isSentinelOrEmpty('unknown') === true, 'unknown is recognized as sentinel');
  assert(isSentinelOrEmpty('-') === true, 'hyphen is recognized as sentinel');
  assert(isSentinelOrEmpty('T1059') === false, 'T1059 is a valid non-sentinel technique');
  assert(isSentinelOrEmpty('M1047') === false, 'M1047 is a valid non-sentinel mitigation');

  // =========================================================================
  // Test 2: KPI Calculations & 2-Decimal Precision (84.07%)
  // =========================================================================
  console.log('\n-- Test 2: KPI Calculations & 2-Decimal Precision --');

  // Construct a controlled fixture mirroring the real proportions:
  // 697 total techniques: 586 mitigated, 111 unmitigated. 44 distinct mitigations.
  const fixtureRecords: SecurityEngineerKnowledgeRecord[] = [];

  // Generate 44 distinct mitigations: M1001 to M1044
  const mitigationPool = Array.from({ length: 44 }, (_, i) => `M${1001 + i}`);

  // Create 586 mitigated techniques (T1001 to T1586)
  for (let i = 1; i <= 586; i++) {
    const techId = `T${1000 + i}`;
    const mitId = mitigationPool[i % 44]; // distribute across 44 mitigations
    fixtureRecords.push(
      createRecord({
        technique_id: techId,
        technique_name: `Technique ${techId}`,
        mitigation_id: mitId,
        mitigation_name: `Mitigation ${mitId}`,
        tactic_names: 'Execution, Persistence',
      })
    );
  }

  // Add some denormalized duplicate mappings (e.g. multi-platform rows for same technique and mitigation)
  for (let i = 1; i <= 862; i++) {
    const techIndex = (i % 586) + 1;
    const techId = `T${1000 + techIndex}`;
    const mitId = mitigationPool[techIndex % 44];
    fixtureRecords.push(
      createRecord({
        technique_id: techId,
        technique_name: `Technique ${techId}`,
        mitigation_id: mitId,
        mitigation_name: `Mitigation ${mitId}`,
        tactic_names: 'Execution',
      })
    );
  }

  // Create 111 unmitigated techniques (T2001 to T2111) with null or sentinel mitigations
  for (let i = 1; i <= 111; i++) {
    const techId = `T${2000 + i}`;
    fixtureRecords.push(
      createRecord({
        technique_id: techId,
        technique_name: `Technique ${techId}`,
        mitigation_id: i % 2 === 0 ? null : 'none',
        tactic_names: 'Defense Evasion',
      })
    );
  }

  // Total records created: 586 + 862 + 111 = 1,559 records!
  assert(fixtureRecords.length === 1559, `Constructed fixture with exactly 1,559 rows, got ${fixtureRecords.length}`);

  const kpis = calculateSecurityEngineerKpis(fixtureRecords);
  assert(kpis.totalMappingRecords === 1559, 'Total mapping records equals 1,559');
  assert(kpis.uniqueTechniques === 697, `Unique techniques equals 697, got ${kpis.uniqueTechniques}`);
  assert(kpis.uniqueMitigations === 44, `Unique mitigations equals 44, got ${kpis.uniqueMitigations}`);
  assert(kpis.mitigatedTechniques === 586, `Mitigated techniques equals 586, got ${kpis.mitigatedTechniques}`);
  assert(kpis.unmitigatedTechniques === 111, `Unmitigated techniques equals 111, got ${kpis.unmitigatedTechniques}`);
  assert(
    kpis.mitigationCoveragePercent === 84.07,
    `Mitigation coverage number equals 84.07, got ${kpis.mitigationCoveragePercent}`
  );
  assert(
    kpis.mitigationCoverageDisplay === '84.07%',
    `Mitigation coverage formatted display equals "84.07%", got ${kpis.mitigationCoverageDisplay}`
  );

  // =========================================================================
  // Test 3: Sentinel Rejection in KPI & Aggregations
  // =========================================================================
  console.log('\n-- Test 3: Sentinel Rejection in KPI & Aggregations --');
  const sentinelRecords: SecurityEngineerKnowledgeRecord[] = [
    createRecord({ technique_id: 'none', mitigation_id: 'M1047' }),
    createRecord({ technique_id: 'null', mitigation_id: 'M1047' }),
    createRecord({ technique_id: 'n/a', mitigation_id: 'M1047' }),
    createRecord({ technique_id: '   ', mitigation_id: 'M1047' }),
    createRecord({ technique_id: 'T1059', mitigation_id: 'none' }),
    createRecord({ technique_id: 'T1059', mitigation_id: 'unknown' }),
    createRecord({ technique_id: 'T1059', mitigation_id: '-' }),
    createRecord({ technique_id: 'T1059', mitigation_id: 'null' }),
  ];

  const sentinelKpi = calculateSecurityEngineerKpis(sentinelRecords);
  assert(sentinelKpi.uniqueTechniques === 1, 'Only 1 valid technique ID (T1059) recognized');
  assert(sentinelKpi.uniqueMitigations === 0, 'Zero valid mitigations recognized (all were sentinels)');
  assert(sentinelKpi.mitigatedTechniques === 0, 'T1059 remains unmitigated');
  assert(sentinelKpi.unmitigatedTechniques === 1, '1 unmitigated technique');
  assert(sentinelKpi.mitigationCoverageDisplay === '0.00%', 'Coverage is 0.00%');

  // =========================================================================
  // Test 4: Chart 1 — Top 5 Mitigations by Technique Coverage
  // =========================================================================
  console.log('\n-- Test 4: Chart 1 — Top 5 Mitigations by Technique Coverage --');
  const coverageData = aggregateMitigationCoverage(fixtureRecords);
  assert(
    coverageData.summary.formattedCoverage === '84.07%',
    'aggregateMitigationCoverage summary formattedCoverage is 84.07%'
  );
  assert(
    coverageData.summary.uniqueMitigationsCount === 44,
    `aggregateMitigationCoverage summary uniqueMitigationsCount is 44, got ${coverageData.summary.uniqueMitigationsCount}`
  );
  assert(
    coverageData.mitigations.length === 44,
    `aggregateMitigationCoverage returned all 44 mitigations, got ${coverageData.mitigations.length}`
  );
  // Verify sorted descending
  for (let i = 0; i < coverageData.mitigations.length - 1; i++) {
    assert(
      coverageData.mitigations[i].addressedTechniquesCount >=
        coverageData.mitigations[i + 1].addressedTechniquesCount,
      `Mitigation rank ${i} count >= rank ${i + 1} count`
    );
  }

  // =========================================================================
  // Test 5: Chart 2 — Top Techniques by Mitigation Count & Tie-Breaking
  // =========================================================================
  console.log('\n-- Test 5: Chart 2 — Top Techniques by Mitigation Count & Tie-Breaking --');
  const tieBreakingRecords: SecurityEngineerKnowledgeRecord[] = [
    // T1078 has 3 mitigations: M1027, M1028, M1029
    createRecord({ technique_id: 'T1078', technique_name: 'Valid Accounts', mitigation_id: 'M1027' }),
    createRecord({ technique_id: 'T1078', technique_name: 'Valid Accounts', mitigation_id: 'M1028' }),
    createRecord({ technique_id: 'T1078', technique_name: 'Valid Accounts', mitigation_id: 'M1029' }),
    // T1059 has 2 mitigations: M1047, M1038
    createRecord({ technique_id: 'T1059', technique_name: 'Command and Scripting', mitigation_id: 'M1047' }),
    createRecord({ technique_id: 'T1059', technique_name: 'Command and Scripting', mitigation_id: 'M1038' }),
    // T1053 also has 2 mitigations: M1047, M1028 (tied with T1059)
    createRecord({ technique_id: 'T1053', technique_name: 'Scheduled Task', mitigation_id: 'M1047' }),
    createRecord({ technique_id: 'T1053', technique_name: 'Scheduled Task', mitigation_id: 'M1028' }),
    // Duplicate mapping for T1053 - should NOT increase count
    createRecord({ technique_id: 'T1053', technique_name: 'Scheduled Task', mitigation_id: 'M1028' }),
    // T1003 has 1 mitigation
    createRecord({ technique_id: 'T1003', technique_name: 'OS Credential Dumping', mitigation_id: 'M1043' }),
  ];

  const techniquesByMit = aggregateTechniquesByMitigationCount(tieBreakingRecords);
  assert(techniquesByMit.length === 4, `Expected 4 techniques with mitigations, got ${techniquesByMit.length}`);
  assert(techniquesByMit[0].techniqueId === 'T1078' && techniquesByMit[0].distinctMitigationsCount === 3, 'T1078 is rank 1 with 3 mitigations');
  // T1053 and T1059 both have 2 mitigations.
  // Tie-breaker: techniqueId ascending: 'T1053' before 'T1059'
  assert(
    techniquesByMit[1].techniqueId === 'T1053' && techniquesByMit[1].distinctMitigationsCount === 2,
    `T1053 is rank 2 by alphabetical tie-breaker (T1053 < T1059), got ${techniquesByMit[1].techniqueId}`
  );
  assert(
    techniquesByMit[2].techniqueId === 'T1059' && techniquesByMit[2].distinctMitigationsCount === 2,
    `T1059 is rank 3 with 2 mitigations, got ${techniquesByMit[2].techniqueId}`
  );
  assert(techniquesByMit[3].techniqueId === 'T1003' && techniquesByMit[3].distinctMitigationsCount === 1, 'T1003 is rank 4 with 1 mitigation');

  // =========================================================================
  // Test 6: Chart 3 — Techniques by Individual Tactic & Multi-Tactic Splitting
  // =========================================================================
  console.log('\n-- Test 6: Chart 3 — Techniques by Individual Tactic & Multi-Tactic Splitting --');
  const multiTacticRecords: SecurityEngineerKnowledgeRecord[] = [
    // T1059 has Execution and Persistence
    createRecord({ technique_id: 'T1059', tactic_names: 'Execution, Persistence' }),
    // Repeated row for T1059 in another mitigation mapping
    createRecord({ technique_id: 'T1059', tactic_names: 'Execution; Persistence' }),
    // T1078 has Execution, Persistence, Defense Evasion, Initial Access
    createRecord({ technique_id: 'T1078', tactic_names: 'Execution|Persistence\nDefense Evasion, Initial Access' }),
    // T1082 has Discovery only
    createRecord({ technique_id: 'T1082', tactic_names: 'Discovery' }),
    // Record with sentinels in tactic tokens
    createRecord({ technique_id: 'T1003', tactic_names: 'Credential Access, none, null, n/a, unknown, -' }),
  ];

  const tacticResult = aggregateTechniquesByTacticForEngineer(multiTacticRecords);
  assert(tacticResult.tactics.length === 6, `Expected 6 distinct tactics, got ${tacticResult.tactics.length}`);

  const execTactic = tacticResult.tactics.find((t) => t.tactic === 'Execution');
  assert(execTactic !== undefined && execTactic.uniqueTechniquesCount === 2, 'Execution has 2 distinct techniques (T1059, T1078)');

  const persistTactic = tacticResult.tactics.find((t) => t.tactic === 'Persistence');
  assert(persistTactic !== undefined && persistTactic.uniqueTechniquesCount === 2, 'Persistence has 2 distinct techniques (T1059, T1078)');

  const credTactic = tacticResult.tactics.find((t) => t.tactic === 'Credential Access');
  assert(credTactic !== undefined && credTactic.uniqueTechniquesCount === 1, 'Credential Access has 1 technique');

  // Check no sentinels are recognized as tactics
  const hasSentinelTactic = tacticResult.tactics.some((t) =>
    ['none', 'null', 'n/a', 'unknown', '-', 'unclassified tactic'].includes(t.tactic.toLowerCase())
  );
  assert(!hasSentinelTactic, 'No sentinel tactics present in aggregated tactic results');

  // Verify exact dataset label preservation (no normalization to alternate canonical MITRE names)
  const exactLabelRecords = [
    createRecord({ technique_id: 'T1059', tactic_names: 'Custom Tactic ABC, specific_tactic_xyz' }),
  ];
  const exactLabelResult = aggregateTechniquesByTacticForEngineer(exactLabelRecords);
  assert(
    exactLabelResult.tactics.some((t) => t.tactic === 'Custom Tactic ABC'),
    'Exact dataset label "Custom Tactic ABC" is preserved verbatim'
  );
  assert(
    exactLabelResult.tactics.some((t) => t.tactic === 'specific_tactic_xyz'),
    'Exact dataset label "specific_tactic_xyz" is preserved without case coercion'
  );

  // =========================================================================
  // Test 7: Pagination Logic Loop
  // =========================================================================
  console.log('\n-- Test 7: Pagination Logic Simulation --');
  // Simulate range(from, to) on a dataset of 1,559 items with pageSize = 500
  const mockDbTable = Array.from({ length: 1559 }, (_, idx) => ({
    id: idx + 1,
    technique_id: `T${1000 + (idx % 697)}`,
  }));

  const simulatedFetch = async (pageSize = 500) => {
    const fetched: any[] = [];
    let from = 0;
    let hasMore = true;
    let iterationCount = 0;

    while (hasMore) {
      iterationCount++;
      const to = from + pageSize - 1;
      const page = mockDbTable.slice(from, to + 1);
      fetched.push(...page);

      if (page.length < pageSize) {
        hasMore = false;
      } else {
        from += pageSize;
      }
    }

    return { fetched, iterationCount };
  };

  const paginationSim = await simulatedFetch(500);
  assert(paginationSim.fetched.length === 1559, `Retrieved all 1,559 items across pages, got ${paginationSim.fetched.length}`);
  assert(paginationSim.iterationCount === 4, `Pagination loop executed exactly 4 iterations, got ${paginationSim.iterationCount}`);

  // =========================================================================
  // Test 8: Empty Dataset Handling
  // =========================================================================
  console.log('\n-- Test 8: Empty Dataset Handling --');
  const emptyKpis = calculateSecurityEngineerKpis([]);
  assert(emptyKpis.uniqueTechniques === 0, 'Empty KPI uniqueTechniques is 0');
  assert(emptyKpis.uniqueMitigations === 0, 'Empty KPI uniqueMitigations is 0');
  assert(emptyKpis.mitigationCoverageDisplay === '0.00%', 'Empty KPI coverage is 0.00%');
  assert(emptyKpis.totalMappingRecords === 0, 'Empty KPI totalMappingRecords is 0');

  const emptyMitigations = aggregateMitigationCoverage([]);
  assert(emptyMitigations.mitigations.length === 0, 'Empty mitigation aggregations returns empty array');
  assert(emptyMitigations.summary.totalUniqueTechniques === 0, 'Empty mitigation summary total is 0');

  const emptyTechByMit = aggregateTechniquesByMitigationCount([]);
  assert(emptyTechByMit.length === 0, 'Empty technique by mitigation returns empty array');

  const emptyTactics = aggregateTechniquesByTacticForEngineer([]);
  assert(emptyTactics.tactics.length === 0, 'Empty tactic aggregation returns empty array');

  console.log(`\n========================================`);
  console.log(`TEST SUMMARY: ${passed} passed, ${failed} failed.`);
  console.log(`========================================`);

  if (failed > 0) {
    process.exit(1);
  }
}

runSecurityEngineerOverviewTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
