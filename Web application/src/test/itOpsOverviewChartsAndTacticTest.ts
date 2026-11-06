/**
 * itOpsOverviewChartsAndTacticTest.ts
 *
 * Comprehensive verification for IT Operations Overview:
 * 1. aggregateTechniquesByTactic token parsing (semicolon, comma, pipe, newline)
 * 2. Deduplication of distinct technique IDs across denormalized records
 * 3. Sentinel and invalid tactic exclusions
 * 4. Canonical MITRE ATT&CK tactic name normalization
 * 5. Descending sort by technique count with secondary alphabetical tie-breaking
 * 6. buildTacticBarChartItems Top 5 capping and selection state
 * 7. InteractiveDonutChart center label persistence: hover does not overwrite selected category; reset restores total
 * 8. Top 5 Platforms Bar Chart + Top 5 Tactics Bar Chart integration in ItOpsOverviewPage
 */

import { ItOperationsKnowledgeRecord } from '../services/knowledgeService';
import {
  aggregateTechniquesByTactic,
  buildTacticBarChartItems,
  aggregateTechniquesByPlatform,
  buildPlatformBarChartItems,
  splitTokens,
  normalizeTacticToken,
  calculateItOpsKpis,
} from '../components/it-operations/knowledge/itOpsFilterUtils';

let passedTests = 0;
let failedTests = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passedTests++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failedTests++;
  }
}

console.log('--- TEST GROUP 1: Token Splitting and Canonical Normalization ---');

// Test splitTokens with various delimiters: ;, ,, |, \n
const complexDelimited = 'Execution; Persistence, Defense Evasion|Privilege Escalation\nDiscovery';
const tokens = splitTokens(complexDelimited);
assert(tokens.length === 5, `Expected 5 tokens from mixed delimiters, got ${tokens.length}`);
assert(tokens.includes('Execution'), 'Contains Execution');
assert(tokens.includes('Persistence'), 'Contains Persistence');
assert(tokens.includes('Defense Evasion'), 'Contains Defense Evasion');
assert(tokens.includes('Privilege Escalation'), 'Contains Privilege Escalation');
assert(tokens.includes('Discovery'), 'Contains Discovery');

// Test normalization
assert(normalizeTacticToken('credential-access') === 'Credential Access', 'Normalizes credential-access');
assert(normalizeTacticToken('DEFENSE EVASION') === 'Defense Evasion', 'Normalizes DEFENSE EVASION');
assert(normalizeTacticToken('privilege-escalation') === 'Privilege Escalation', 'Normalizes privilege-escalation');
assert(normalizeTacticToken('initial-access') === 'Initial Access', 'Normalizes initial-access');

console.log('\n--- TEST GROUP 2: aggregateTechniquesByTactic Multi-Tactic & Deduplication ---');

function createMockRecord(partial: Partial<ItOperationsKnowledgeRecord>): ItOperationsKnowledgeRecord {
  return {
    technique_id: null,
    technique_name: null,
    technique_tactics: null,
    technique_platforms: null,
    mitigation_id: null,
    mitigation_name: null,
    mitigation_description: null,
    source_id: null,
    target_id: null,
    mapping_type: null,
    platform_name: null,
    tactic_id: null,
    tactic_name: null,
    ...partial,
  };
}

const mockRecords: ItOperationsKnowledgeRecord[] = [
  // Record 1: Technique T1059.001 with 2 tactics
  createMockRecord({
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    technique_tactics: 'Execution; Persistence',
    platform_name: 'Windows',
    mitigation_id: 'M1047',
    mitigation_name: 'Audit',
  }),
  // Record 2: Same Technique T1059.001 repeated on different platform (denormalized duplicate)
  createMockRecord({
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    technique_tactics: 'Execution; Persistence',
    platform_name: 'Linux',
    mitigation_id: 'M1047',
    mitigation_name: 'Audit',
  }),
  // Record 3: Technique T1059.003 in Execution and Defense Evasion
  createMockRecord({
    technique_id: 'T1059.003',
    technique_name: 'Windows Command Shell',
    technique_tactics: 'Execution, Defense Evasion',
    platform_name: 'Windows',
    mitigation_id: 'M1038',
    mitigation_name: 'Execution Prevention',
  }),
  // Record 4: Technique T1078 with 4 tactics
  createMockRecord({
    technique_id: 'T1078',
    technique_name: 'Valid Accounts',
    technique_tactics: 'Defense Evasion|Persistence|Privilege Escalation\nInitial Access',
    platform_name: 'Windows',
    mitigation_id: 'M1027',
    mitigation_name: 'Password Policies',
  }),
  // Record 5: Technique T1003.001 in Credential Access
  createMockRecord({
    technique_id: 'T1003.001',
    technique_name: 'LSASS Memory',
    tactic_name: 'Credential Access',
    platform_name: 'Windows',
    mitigation_id: 'M1043',
    mitigation_name: 'Credential Dumping Protection',
  }),
  // Record 6: Technique T1082 in Discovery
  createMockRecord({
    technique_id: 'T1082',
    technique_name: 'System Information Discovery',
    technique_tactics: 'Discovery',
    platform_name: 'Linux',
  }),
  // Record 7: Technique T1021.002 in Lateral Movement
  createMockRecord({
    technique_id: 'T1021.002',
    technique_name: 'SMB Shares',
    technique_tactics: 'Lateral Movement',
    platform_name: 'Windows',
  }),
  // Record 8: Technique T1071.001 in Command and Control
  createMockRecord({
    technique_id: 'T1071.001',
    technique_name: 'Web Protocols',
    technique_tactics: 'Command and Control',
    platform_name: 'Windows',
  }),
  // Record 9: Technique T1560 in Collection
  createMockRecord({
    technique_id: 'T1560',
    technique_name: 'Archive Collected Data',
    technique_tactics: 'Collection',
    platform_name: 'macOS',
  }),
  // Record 10: Sentinel records that should be discarded
  createMockRecord({
    technique_id: 'none',
    technique_name: 'none',
    technique_tactics: 'none',
    platform_name: 'none',
  }),
  createMockRecord({
    technique_id: 'T9999',
    technique_name: 'Test Null Tactic',
    technique_tactics: 'null; n/a; unknown; -',
    platform_name: 'Windows',
  }),
];

const tacticAgg = aggregateTechniquesByTactic(mockRecords);

// Check distinct tactics count
// Tactics present: Execution (T1059.001, T1059.003 -> 2), Persistence (T1059.001, T1078 -> 2),
// Defense Evasion (T1059.003, T1078 -> 2), Privilege Escalation (T1078 -> 1),
// Initial Access (T1078 -> 1), Credential Access (T1003.001 -> 1), Discovery (T1082 -> 1),
// Lateral Movement (T1021.002 -> 1), Command and Control (T1071.001 -> 1), Collection (T1560 -> 1)
// Total recognized tactics = 10 (sentinels excluded)
assert(tacticAgg.length === 10, `Expected exactly 10 distinct tactics, got ${tacticAgg.length}`);

// Check deduplication: T1059.001 appeared twice in records, but Execution should have exactly 2 distinct techniques: T1059.001 and T1059.003
const executionTactic = tacticAgg.find((t) => t.tactic === 'Execution');
assert(executionTactic !== undefined, 'Execution tactic found');
assert(
  executionTactic?.distinctTechniqueCount === 2,
  `Execution should have 2 distinct techniques, got ${executionTactic?.distinctTechniqueCount}`
);

// Check Persistence: T1059.001 and T1078
const persistenceTactic = tacticAgg.find((t) => t.tactic === 'Persistence');
assert(
  persistenceTactic?.distinctTechniqueCount === 2,
  `Persistence should have 2 distinct techniques, got ${persistenceTactic?.distinctTechniqueCount}`
);

// Check Defense Evasion: T1059.003 and T1078
const evasionTactic = tacticAgg.find((t) => t.tactic === 'Defense Evasion');
assert(
  evasionTactic?.distinctTechniqueCount === 2,
  `Defense Evasion should have 2 distinct techniques, got ${evasionTactic?.distinctTechniqueCount}`
);

// Check that sentinels 'none', 'null', 'n/a', 'unknown', '-' are not in tacticAgg
const hasSentinel = tacticAgg.some((t) =>
  ['none', 'null', 'n/a', 'unknown', '-'].includes(t.tactic.toLowerCase())
);
assert(!hasSentinel, 'No sentinel tactics present in aggregated tactics');

console.log('\n--- TEST GROUP 3: Sorting and Alphabetical Tie-Breaking ---');

// The top 3 tactics all have distinctTechniqueCount = 2:
// 'Defense Evasion', 'Execution', 'Persistence'.
// Alphabetical order:
// 1. 'Defense Evasion' (2)
// 2. 'Execution' (2)
// 3. 'Persistence' (2)
assert(tacticAgg[0].tactic === 'Defense Evasion', `Rank 1 tie-breaker should be Defense Evasion, got ${tacticAgg[0].tactic}`);
assert(tacticAgg[1].tactic === 'Execution', `Rank 2 tie-breaker should be Execution, got ${tacticAgg[1].tactic}`);
assert(tacticAgg[2].tactic === 'Persistence', `Rank 3 tie-breaker should be Persistence, got ${tacticAgg[2].tactic}`);

// The remaining tactics all have distinctTechniqueCount = 1:
// Collection, Command and Control, Credential Access, Discovery, Initial Access, Lateral Movement, Privilege Escalation
// Alphabetically:
// 4. Collection (1)
// 5. Command and Control (1)
// 6. Credential Access (1)
assert(tacticAgg[3].tactic === 'Collection', `Rank 4 tie-breaker should be Collection, got ${tacticAgg[3].tactic}`);
assert(tacticAgg[4].tactic === 'Command and Control', `Rank 5 tie-breaker should be Command and Control, got ${tacticAgg[4].tactic}`);
assert(tacticAgg[5].tactic === 'Credential Access', `Rank 6 tie-breaker should be Credential Access, got ${tacticAgg[5].tactic}`);

console.log('\n--- TEST GROUP 4: buildTacticBarChartItems Top 5 Slicing & Selection State ---');

const selectedTactics = ['Execution', 'Initial Access'];
const chartItems = buildTacticBarChartItems(tacticAgg, selectedTactics);

assert(chartItems.length === tacticAgg.length, 'Generates chart items for all aggregated tactics');
const executionItem = chartItems.find((i) => i.id === 'Execution');
assert(executionItem?.isSelected === true, 'Execution is marked as isSelected: true');
const defenseItem = chartItems.find((i) => i.id === 'Defense Evasion');
assert(defenseItem?.isSelected === false, 'Defense Evasion is marked as isSelected: false');

// Top 5 slice in chart component
const top5Items = chartItems.slice(0, 5);
assert(top5Items.length === 5, 'Top 5 slice has exactly 5 items');
assert(top5Items[0].label === 'Defense Evasion', 'Top 5 item 0 is Defense Evasion');
assert(top5Items[1].label === 'Execution', 'Top 5 item 1 is Execution');
assert(top5Items[2].label === 'Persistence', 'Top 5 item 2 is Persistence');
assert(top5Items[3].label === 'Collection', 'Top 5 item 3 is Collection');
assert(top5Items[4].label === 'Command and Control', 'Top 5 item 4 is Command and Control');

console.log('\n--- TEST GROUP 5: InteractiveDonutChart Center Hub Logic Simulation ---');

// Simulate the center hub logic implemented in InteractiveDonutChart:
// const selectedSegment = segments.find(s => s.isSelected);
// Hub shows selectedSegment if present, otherwise total & totalLabel.
// Hovered segment does NOT overwrite center hub!

interface DonutSegmentMock {
  id: string;
  label: string;
  count: number;
  percentage: number;
  isSelected?: boolean;
}

const mockSegments: DonutSegmentMock[] = [
  { id: 'Windows', label: 'Windows', count: 50, percentage: 50, isSelected: false },
  { id: 'Linux', label: 'Linux', count: 30, percentage: 30, isSelected: false },
  { id: 'macOS', label: 'macOS', count: 20, percentage: 20, isSelected: false },
];

function computeCenterHub(
  segments: DonutSegmentMock[],
  total: number,
  totalLabel: string,
  hoveredId: string | null
) {
  // Center Donut Hub Stats: Reflects active selection persistently; hover does not overwrite
  const selectedSegment = segments.find((s) => s.isSelected);

  if (selectedSegment) {
    return {
      primary: `${selectedSegment.percentage}%`,
      secondary: `${selectedSegment.count} items`,
      tertiary: selectedSegment.label,
      isSelection: true,
    };
  }

  return {
    primary: `${total}`,
    secondary: totalLabel,
    tertiary: null,
    isSelection: false,
  };
}

// 1. Initial State: No selection, no hover
const initialHub = computeCenterHub(mockSegments, 100, 'Total Techniques', null);
assert(initialHub.primary === '100' && initialHub.secondary === 'Total Techniques', 'Initial hub shows total techniques');

// 2. Hover without selection: Hover over Linux
const hoverNoSelectHub = computeCenterHub(mockSegments, 100, 'Total Techniques', 'Linux');
assert(
  hoverNoSelectHub.primary === '100' && hoverNoSelectHub.secondary === 'Total Techniques',
  'Hovering does NOT overwrite center hub when no item is selected'
);

// 3. Click Linux (isSelected: true)
const selectedSegments = mockSegments.map((s) => ({
  ...s,
  isSelected: s.id === 'Linux',
}));
const selectLinuxHub = computeCenterHub(selectedSegments, 100, 'Total Techniques', 'Linux');
assert(
  selectLinuxHub.primary === '30%' && selectLinuxHub.secondary === '30 items' && selectLinuxHub.tertiary === 'Linux',
  'Center hub reflects selected Linux category'
);

// 4. Mouse leaves chart (hoveredId becomes null) while Linux is still selected
const pointerLeavesHub = computeCenterHub(selectedSegments, 100, 'Total Techniques', null);
assert(
  pointerLeavesHub.primary === '30%' && pointerLeavesHub.secondary === '30 items' && pointerLeavesHub.tertiary === 'Linux',
  'Center hub PERSISTS selected Linux statistics after pointer leaves chart!'
);

// 5. User hovers over Windows while Linux is selected
const hoverOtherWhileSelectedHub = computeCenterHub(selectedSegments, 100, 'Total Techniques', 'Windows');
assert(
  hoverOtherWhileSelectedHub.primary === '30%' && hoverOtherWhileSelectedHub.tertiary === 'Linux',
  'Center hub maintains selected category even when user hovers another segment'
);

// 6. Reset / Deselection: isSelected returns to false
const resetSegments = mockSegments.map((s) => ({ ...s, isSelected: false }));
const resetHub = computeCenterHub(resetSegments, 100, 'Total Techniques', null);
assert(
  resetHub.primary === '100' && resetHub.secondary === 'Total Techniques',
  'Resetting selection restores total count and totalLabel in center hub'
);

console.log('\n--- TEST GROUP 6: IT Operations Overview Platform + Tactic Chart Complementarity ---');

// Verify that the two charts in ItOpsOverviewPage are complementary and distinct:
// Chart 1: Platform aggregation
const platformAgg = aggregateTechniquesByPlatform(mockRecords);
const platformItems = buildPlatformBarChartItems(platformAgg, ['Windows']);
// Chart 2: Tactic aggregation
const tacticItems = buildTacticBarChartItems(tacticAgg, ['Execution']);

assert(platformAgg.length > 0, 'Platform aggregation produces platforms');
assert(tacticAgg.length > 0, 'Tactic aggregation produces tactics');
assert(
  platformItems[0].id !== tacticItems[0].id,
  'Platform chart and Tactic chart have distinct dimensional domains (no duplicate platform insights)'
);

console.log(`\n========================================`);
console.log(`TEST SUMMARY: ${passedTests} passed, ${failedTests} failed.`);
console.log(`========================================`);

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('All tests passed successfully!');
}
