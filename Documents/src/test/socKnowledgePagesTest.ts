/**
 * CyberOps SOC — SOC Analyst Six Knowledge Pages & Filter Engine Verification Test Suite
 *
 * Verifies:
 * 1. 5 Distinct Count KPIs (Techniques, Detection Strategies, Analytics, Log Sources, Data Components).
 * 2. 4 Interactive Chart Aggregations (Tactics, Log Sources, Platforms, Detection Strategies).
 * 3. Delimiter parsing on `[,;|\r\n]+` for multi-valued fields.
 * 4. Cross-filtering engine:
 *    - AND logic across different dimensions.
 *    - OR logic within the same dimension.
 *    - Exact token matching for multi-valued fields.
 *    - Full-text search across all 12 columns.
 * 5. Dynamic recalculation of KPIs and charts after applying filters.
 * 6. Active filter chips generation, removal, and Clear All.
 * 7. Entity extractors for all 6 pages (Strategies, Analytics, Log Sources, Data Components, Techniques).
 * 8. Invariant verification: Zero mitigation fields/leakage in the SOC Analyst domain.
 */

import { SocAnalystKnowledgeRecord } from '../services/knowledgeService';
import {
  splitTokens,
  normalizeTacticToken,
  normalizePlatformToken,
  normalizeLogSourceToken,
  applySocKnowledgeFilters,
  computeSocOverviewKpis,
  aggregateTechniquesByTacticFromRecords,
  aggregateAnalyticsByLogSource,
  aggregateTechniquesByPlatform,
  aggregateStrategiesByTechniques,
  extractTechniques,
  extractDetectionStrategies,
  extractAnalytics,
  extractLogSources,
  extractDataComponents,
  buildActiveFilterChips,
  INITIAL_SOC_FILTERS,
} from '../components/analyst/knowledge/filterUtils';
import { SocKnowledgeFilters } from '../components/analyst/knowledge/types';

function assert(condition: boolean, description: string) {
  if (!condition) {
    console.error(`  [FAIL]: ${description}`);
    throw new Error(`Assertion failed: ${description}`);
  }
  console.log(`  [PASS]: ${description}`);
}

async function runSocKnowledgePagesTests() {
  console.log('=== RUNNING SOC ANALYST SIX KNOWLEDGE PAGES VERIFICATION TESTS ===\n');

  // Comprehensive test dataset with realistic multi-valued fields, delimiters, and cross-entity mappings
  const mockRecords: SocAnalystKnowledgeRecord[] = [
    {
      techniques_id: 'T1059.001',
      techniques_name: 'PowerShell',
      techniques_description: 'Adversaries may abuse PowerShell commands and scripts for execution.',
      techniques_tactics: 'Execution',
      techniques_platforms: 'Windows, macOS, Linux',
      detection_strategy_attack_id: 'DS-001',
      detection_strategy_name: 'PowerShell Script Execution Detection',
      analytic_id: 'AN-1001',
      analytic_name: 'PowerShell Encoded Command Execution',
      log_source_name: 'Process: Process Creation, Script: Script Execution',
      data_components_id: 'DC-001',
      data_components_name: 'Process Creation',
    },
    {
      techniques_id: 'T1059.003',
      techniques_name: 'Windows Command Shell',
      techniques_description: 'Adversaries may abuse cmd.exe for execution.',
      techniques_tactics: 'Execution',
      techniques_platforms: 'Windows',
      detection_strategy_attack_id: 'DS-001',
      detection_strategy_name: 'PowerShell Script Execution Detection',
      analytic_id: 'AN-1002',
      analytic_name: 'Cmd.exe Spawning Reconnaissance Tools',
      log_source_name: 'Process: Process Creation',
      data_components_id: 'DC-001',
      data_components_name: 'Process Creation',
    },
    {
      techniques_id: 'T1078',
      techniques_name: 'Valid Accounts',
      techniques_description: 'Adversaries may obtain and abuse credentials of existing accounts.',
      techniques_tactics: 'Defense Evasion; Persistence\r\nPrivilege Escalation, Initial Access',
      techniques_platforms: 'Windows | Linux | macOS | SaaS | Cloud',
      detection_strategy_attack_id: 'DS-002',
      detection_strategy_name: 'Anomalous Account Authentication',
      analytic_id: 'AN-2001',
      analytic_name: 'Logon from Unusual Geolocation',
      log_source_name: 'Authentication Logs; Logon Session Creation',
      data_components_id: 'DC-002',
      data_components_name: 'User Account Authentication',
    },
    {
      techniques_id: 'T1003.001',
      techniques_name: 'LSASS Memory',
      techniques_description: 'Adversaries may attempt to access credential material stored in LSASS.',
      techniques_tactics: 'Credential Access',
      techniques_platforms: 'Windows',
      detection_strategy_attack_id: 'DS-003',
      detection_strategy_name: 'Credential Dumping Safeguards',
      analytic_id: 'AN-3001',
      analytic_name: 'LSASS Memory Read Operations',
      log_source_name: 'Process: Process Access',
      data_components_id: 'DC-003',
      data_components_name: 'Process Access',
    },
    {
      techniques_id: 'T1071.001',
      techniques_name: 'Web Protocols',
      techniques_description: 'Adversaries may communicate using application layer protocols (HTTP/HTTPS).',
      techniques_tactics: 'Command and Control',
      techniques_platforms: 'Linux, Windows, macOS, Containers',
      detection_strategy_attack_id: 'DS-004',
      detection_strategy_name: 'C2 Beaconing Detection',
      analytic_id: 'AN-4001',
      analytic_name: 'Periodic Outbound Web Traffic',
      log_source_name: 'Network Traffic: Network Connection Creation',
      data_components_id: 'DC-004',
      data_components_name: 'Network Connection',
    },
  ];

  // =========================================================================
  // Test Area 1: Delimiter Splitting & Normalization
  // =========================================================================
  console.log('-- Area 1: Delimiter Splitting on [,;|\\r\\n]+ & Token Normalization --');

  const splitTest = splitTokens('Windows, Linux; macOS | Cloud\r\nContainers');
  assert(splitTest.length === 5, 'Splits mixed commas, semicolons, pipes, and CRLF newlines into 5 tokens');
  assert(splitTest.includes('Windows') && splitTest.includes('Containers'), 'Contains Windows and Containers');

  assert(normalizeTacticToken('initial access') === 'Initial Access', 'Normalizes tactic casing');
  assert(normalizeTacticToken('defense evasion') === 'Defense Evasion', 'Normalizes defense evasion');
  assert(normalizePlatformToken('macos') === 'macOS', 'Normalizes macOS canonical casing');
  assert(normalizePlatformToken('k8s') === 'Kubernetes', 'Normalizes Kubernetes token');

  // =========================================================================
  // Test Area 2: 5 Distinct Count KPIs (Unfiltered)
  // =========================================================================
  console.log('\n-- Area 2: Distinct Count KPIs (Unfiltered Baseline) --');

  const kpis = computeSocOverviewKpis(mockRecords);
  assert(kpis.distinctTechniques === 5, `Expected 5 distinct techniques, got ${kpis.distinctTechniques}`);
  assert(kpis.distinctDetectionStrategies === 4, `Expected 4 distinct strategies (DS-001..DS-004), got ${kpis.distinctDetectionStrategies}`);
  assert(kpis.distinctAnalytics === 5, `Expected 5 distinct analytics, got ${kpis.distinctAnalytics}`);
  assert(kpis.distinctDataComponents === 4, `Expected 4 distinct data components, got ${kpis.distinctDataComponents}`);
  assert(kpis.distinctLogSources >= 5, `Expected at least 5 distinct log sources, got ${kpis.distinctLogSources}`);
  assert(kpis.totalRecords === 5, 'Total records equals 5');

  // =========================================================================
  // Test Area 3: 4 Interactive Charts Aggregations
  // =========================================================================
  console.log('\n-- Area 3: 4 Interactive Chart Aggregations --');

  // Chart 1: Tactics
  const tacticsChart = aggregateTechniquesByTacticFromRecords(mockRecords);
  const execTactic = tacticsChart.find((t) => t.tactic === 'Execution');
  assert(execTactic !== undefined && execTactic.distinctTechniques === 2, 'Execution tactic maps to 2 techniques (T1059.001, T1059.003)');
  const credTactic = tacticsChart.find((t) => t.tactic === 'Credential Access');
  assert(credTactic !== undefined && credTactic.distinctTechniques === 1, 'Credential Access maps to 1 technique');

  // Chart 2: Analytics by Log Source
  const logSourceChart = aggregateAnalyticsByLogSource(mockRecords);
  const processCreationSource = logSourceChart.find((l) => l.logSource === 'Process: Process Creation');
  assert(processCreationSource !== undefined && processCreationSource.distinctAnalytics === 2, 'Process Creation maps to 2 analytics (AN-1001, AN-1002)');

  // Chart 3: Platforms
  const platformChart = aggregateTechniquesByPlatform(mockRecords);
  const winPlatform = platformChart.find((p) => p.platform === 'Windows');
  assert(winPlatform !== undefined && winPlatform.distinctTechniques === 5, 'Windows platform maps to all 5 techniques');
  const linuxPlatform = platformChart.find((p) => p.platform === 'Linux');
  assert(linuxPlatform !== undefined && linuxPlatform.distinctTechniques === 3, 'Linux platform maps to 3 techniques');

  // Chart 4: Detection Strategies by Techniques
  const stratChart = aggregateStrategiesByTechniques(mockRecords);
  const ds1 = stratChart.find((s) => s.strategyId === 'DS-001');
  assert(ds1 !== undefined && ds1.distinctTechniques === 2, 'DS-001 covers 2 distinct techniques');

  // =========================================================================
  // Test Area 4: Cross-Filtering Engine (AND across dimensions, OR within)
  // =========================================================================
  console.log('\n-- Area 4: Cross-Filtering Engine (AND across dimensions, OR within) --');

  // Test 4.1: OR logic within same dimension (Tactics: Execution OR Credential Access)
  const orTacticFilters: SocKnowledgeFilters = {
    ...INITIAL_SOC_FILTERS,
    selectedTactics: ['Execution', 'Credential Access'],
  };
  const orTacticResult = applySocKnowledgeFilters(mockRecords, orTacticFilters);
  assert(
    orTacticResult.length === 3,
    `Tactics Execution OR Credential Access matches 3 records (T1059.001, T1059.003, T1003.001), got ${orTacticResult.length}`
  );

  // Test 4.2: AND logic across dimensions (Tactic: Execution AND Platform: Linux)
  const andCrossFilters: SocKnowledgeFilters = {
    ...INITIAL_SOC_FILTERS,
    selectedTactics: ['Execution'],
    selectedPlatforms: ['Linux'],
  };
  const andCrossResult = applySocKnowledgeFilters(mockRecords, andCrossFilters);
  assert(
    andCrossResult.length === 1 && andCrossResult[0].techniques_id === 'T1059.001',
    'Execution AND Linux narrows strictly to T1059.001 (PowerShell on Linux), excluding T1059.003 (Windows only)'
  );

  // Test 4.3: AND logic with Log Source filter
  const logSourceFilter: SocKnowledgeFilters = {
    ...INITIAL_SOC_FILTERS,
    selectedLogSources: ['Authentication Logs'],
  };
  const logSourceResult = applySocKnowledgeFilters(mockRecords, logSourceFilter);
  assert(
    logSourceResult.length === 1 && logSourceResult[0].techniques_id === 'T1078',
    'Log source Authentication Logs matches T1078'
  );

  // Test 4.4: Full-text search matching across multiple fields
  const searchFilter: SocKnowledgeFilters = {
    ...INITIAL_SOC_FILTERS,
    searchQuery: 'LSASS',
  };
  const searchResult = applySocKnowledgeFilters(mockRecords, searchFilter);
  assert(
    searchResult.length === 1 && searchResult[0].techniques_id === 'T1003.001',
    'Free text "LSASS" matches T1003.001'
  );

  // =========================================================================
  // Test Area 5: Dynamic Recalculation After Filtering
  // =========================================================================
  console.log('\n-- Area 5: Dynamic Recalculation After Filtering --');

  // Filter for Credential Access only
  const filteredRecords = applySocKnowledgeFilters(mockRecords, {
    ...INITIAL_SOC_FILTERS,
    selectedTactics: ['Credential Access'],
  });
  const filteredKpis = computeSocOverviewKpis(filteredRecords);
  assert(filteredKpis.distinctTechniques === 1, 'Filtered distinct techniques is 1');
  assert(filteredKpis.distinctDetectionStrategies === 1, 'Filtered distinct strategies is 1 (DS-003)');
  assert(filteredKpis.distinctAnalytics === 1, 'Filtered distinct analytics is 1 (AN-3001)');

  const filteredTacticsChart = aggregateTechniquesByTacticFromRecords(filteredRecords);
  assert(filteredTacticsChart.length === 1 && filteredTacticsChart[0].tactic === 'Credential Access', 'Filtered chart shows only Credential Access');

  // =========================================================================
  // Test Area 6: Active Filter Chips
  // =========================================================================
  console.log('\n-- Area 6: Active Filter Chips Generation --');

  const chips = buildActiveFilterChips({
    searchQuery: 'beacon',
    selectedTactics: ['Command and Control'],
    selectedPlatforms: ['Containers'],
    selectedLogSources: ['Network Traffic: Network Connection Creation'],
    selectedDataComponents: ['Network Connection'],
    selectedStrategies: ['DS-004'],
  });
  assert(chips.length === 6, `Generated 6 filter chips, got ${chips.length}`);
  assert(chips.some((c) => c.dimension === 'search' && c.label.includes('beacon')), 'Search chip present');
  assert(chips.some((c) => c.dimension === 'tactic' && c.label.includes('Command and Control')), 'Tactic chip present');
  assert(chips.some((c) => c.dimension === 'strategy' && c.label.includes('DS-004')), 'Strategy chip present');

  // =========================================================================
  // Test Area 7: Entity Extractors for Pages 2 to 6
  // =========================================================================
  console.log('\n-- Area 7: Entity Extractors for Pages 2 to 6 --');

  // Page 2: Detection Strategies
  const strategies = extractDetectionStrategies(mockRecords);
  assert(strategies.length === 4, `Extracted 4 unique strategies, got ${strategies.length}`);
  const s1 = strategies.find((s) => s.strategyId === 'DS-001');
  assert(s1 !== undefined && s1.associatedTechniques.length === 2, 'DS-001 has 2 associated techniques');

  // Page 3: Analytics
  const analytics = extractAnalytics(mockRecords);
  assert(analytics.length === 5, `Extracted 5 unique analytics, got ${analytics.length}`);
  const a1 = analytics.find((a) => a.analyticId === 'AN-1001');
  assert(a1 !== undefined && a1.associatedTechniques[0].id === 'T1059.001', 'AN-1001 mapped to T1059.001');

  // Page 4: Log Sources
  const logSources = extractLogSources(mockRecords);
  assert(logSources.length >= 5, `Extracted ${logSources.length} unique log sources`);

  // Page 5: Data Components
  const dataComponents = extractDataComponents(mockRecords);
  assert(dataComponents.length === 4, `Extracted 4 unique data components, got ${dataComponents.length}`);
  const dc1 = dataComponents.find((d) => d.componentId === 'DC-001');
  assert(dc1 !== undefined && dc1.associatedTechniques.length === 2, 'DC-001 mapped to 2 techniques');

  // Page 6: Techniques
  const techniques = extractTechniques(mockRecords);
  assert(techniques.length === 5, `Extracted 5 unique techniques, got ${techniques.length}`);
  const t1 = techniques.find((t) => t.id === 'T1078');
  assert(t1 !== undefined && t1.tactics.length === 4, 'T1078 has 4 parsed tactics');
  assert(t1 !== undefined && t1.platforms.length === 5, 'T1078 has 5 parsed platforms');

  // =========================================================================
  // Test Area 8: Strict Role Isolation & No Mitigation Fields
  // =========================================================================
  console.log('\n-- Area 8: Invariant Check — No Mitigation Fields in SOC Analyst Model --');

  const techniqueKeys = Object.keys(techniques[0]);
  assert(!techniqueKeys.includes('mitigations'), 'AggregatedTechnique must NOT have mitigations field');
  assert(!techniqueKeys.includes('mitigation_id'), 'AggregatedTechnique must NOT have mitigation_id field');

  console.log('\n=== ALL SOC ANALYST SIX KNOWLEDGE PAGES TESTS PASSED ===');
}

runSocKnowledgePagesTests().catch((err) => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
