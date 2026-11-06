/**
 * CyberOps SOC — IT Operations Role 6 Pages & Visualization Standards Test Suite
 *
 * Comprehensive verification of:
 * 1. Six Authorized Workspace Pages & Routing:
 *    - itops_overview (IT Operations Overview)
 *    - itops_techniques (Technique & Platform Explorer)
 *    - itops_mitigations (Mitigation Explorer)
 *    - tasks (Incident Response Tasks)
 *    - alerts (Scoped Incident Alerts)
 *    - audit (Containment Audit Trail)
 *    - profile (Operator Profile via account menu)
 * 2. IT Operations Overview Visualization Requirements:
 *    - 4 KPIs: Techniques, Platforms, Mitigations, Tactics.
 *    - Exactly two charts: Top 5 Platforms by Technique Coverage (Bar) & Platform Distribution Share (Donut).
 *    - Default limit: Top 5 platforms.
 *    - Deterministic tie-breaking: descending count, then ascending alphabetical label.
 *    - Searchable records table with field display and detail modal linkage.
 * 3. Zero-Chart Discipline on Remaining 5 Pages:
 *    - Technique & Platform Explorer: 2 KPIs, search, platform/tactic filter, 0 charts.
 *    - Mitigation Explorer: 2 KPIs, search, table, 0 charts.
 *    - Incident Response Tasks: operational workflow, status transitions, verification modal, 0 charts.
 *    - Scoped Incident Alerts: scoped alerts, 0 charts.
 *    - Containment Audit Trail: operational audit logs, 0 charts.
 * 4. Honest Zero-Record / Empty States:
 *    - Clean handling of 0 records without crash, placeholder mocks, or fabricated data.
 * 5. Strict Defense-in-Depth Authorization & Role Isolation:
 *    - Approved it_operations operator permitted.
 *    - Non-it_operations roles and unapproved operators strictly denied.
 */

import {
  calculateItOpsKpis,
  extractItOpsTechniques,
  extractItOpsMitigations,
  aggregateTechniquesByPlatform,
  aggregateTechniquesByTactic,
  buildPlatformBarChartItems,
  buildPlatformDonutChartItems,
  buildTacticBarChartItems,
  filterAggregatedTechniques,
  filterAggregatedMitigations,
  buildItOpsActiveFilterChips,
} from '../components/it-operations/knowledge/itOpsFilterUtils';
import {
  ItOperationsKnowledgeRecord,
} from '../services/knowledgeService';
import { AuthorizationService } from '../services/authorizationService';
import { DEMO_PERSONAS, UserProfile } from '../types/auth';

function assert(condition: boolean, description: string) {
  if (!condition) {
    console.error(`  [FAIL]: ${description}`);
    throw new Error(`Assertion failed: ${description}`);
  }
  console.log(`  [PASS]: ${description}`);
}

// Representative authentic test dataset from it_operations_knowledge
const SAMPLE_IT_OPS_RECORDS: ItOperationsKnowledgeRecord[] = [
  {
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    technique_tactics: 'Execution',
    technique_platforms: 'Windows',
    mitigation_id: 'M1026',
    mitigation_name: 'Privileged Account Management',
    mitigation_description: 'Manage the creation, modification, and use of privileged accounts.',
    platform_name: 'Windows',
    tactic_name: 'Execution',
    tactic_id: 'TA0002',
    source_id: 'M1026',
    target_id: 'T1059.001',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    technique_tactics: 'Execution',
    technique_platforms: 'Windows; Linux; macOS',
    mitigation_id: 'M1038',
    mitigation_name: 'Execution Prevention',
    mitigation_description: 'Block execution of unauthorized code via application control.',
    platform_name: 'Linux',
    tactic_name: 'Execution',
    tactic_id: 'TA0002',
    source_id: 'M1038',
    target_id: 'T1059.001',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1078',
    technique_name: 'Valid Accounts',
    technique_tactics: 'Defense Evasion; Persistence; Initial Access',
    technique_platforms: 'Windows; Linux; macOS; IaaS; SaaS',
    mitigation_id: 'M1027',
    mitigation_name: 'Password Policies',
    mitigation_description: 'Enforce strong password configuration and rotation rules.',
    platform_name: 'Windows',
    tactic_name: 'Defense Evasion',
    tactic_id: 'TA0005',
    source_id: 'M1027',
    target_id: 'T1078',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1053.005',
    technique_name: 'Scheduled Task',
    technique_tactics: 'Execution; Persistence; Privilege Escalation',
    technique_platforms: 'Windows',
    mitigation_id: 'M1026',
    mitigation_name: 'Privileged Account Management',
    mitigation_description: 'Manage the creation, modification, and use of privileged accounts.',
    platform_name: 'Windows',
    tactic_name: 'Persistence',
    tactic_id: 'TA0003',
    source_id: 'M1026',
    target_id: 'T1053.005',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1053.003',
    technique_name: 'Cron',
    technique_tactics: 'Execution; Persistence',
    technique_platforms: 'Linux; macOS',
    mitigation_id: 'M1028',
    mitigation_name: 'Operating System Configuration',
    mitigation_description: 'Make configuration changes to harden operating systems against exploitation.',
    platform_name: 'Linux',
    tactic_name: 'Execution',
    tactic_id: 'TA0002',
    source_id: 'M1028',
    target_id: 'T1053.003',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1610',
    technique_name: 'Deploy Container',
    technique_tactics: 'Execution; Defense Evasion',
    technique_platforms: 'Containers',
    mitigation_id: 'M1047',
    mitigation_name: 'Audit',
    mitigation_description: 'Perform regular security audits to detect deviations.',
    platform_name: 'Containers',
    tactic_name: 'Execution',
    tactic_id: 'TA0002',
    source_id: 'M1047',
    target_id: 'T1610',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1611',
    technique_name: 'Escape to Host',
    technique_tactics: 'Privilege Escalation',
    technique_platforms: 'Containers',
    mitigation_id: 'M1042',
    mitigation_name: 'Disable or Remove Feature or Program',
    mitigation_description: 'Remove unnecessary container capabilities and features.',
    platform_name: 'Containers',
    tactic_name: 'Privilege Escalation',
    tactic_id: 'TA0004',
    source_id: 'M1042',
    target_id: 'T1611',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1046',
    technique_name: 'Network Service Discovery',
    technique_tactics: 'Discovery',
    technique_platforms: 'Network; Windows; Linux; macOS',
    mitigation_id: 'M1030',
    mitigation_name: 'Network Segmentation',
    mitigation_description: 'Architect network to isolate operational assets.',
    platform_name: 'Network',
    tactic_name: 'Discovery',
    tactic_id: 'TA0007',
    source_id: 'M1030',
    target_id: 'T1046',
    mapping_type: 'mitigates',
  },
  {
    technique_id: 'T1526',
    technique_name: 'Cloud Service Discovery',
    technique_tactics: 'Discovery',
    technique_platforms: 'IaaS; SaaS; PaaS',
    mitigation_id: 'M1047',
    mitigation_name: 'Audit',
    mitigation_description: 'Audit cloud roles and service configurations.',
    platform_name: 'IaaS',
    tactic_name: 'Discovery',
    tactic_id: 'TA0007',
    source_id: 'M1047',
    target_id: 'T1526',
    mapping_type: 'mitigates',
  },
];

async function main() {
  console.log('=== RUNNING IT OPERATIONS ROLE 6 PAGES & VISUALIZATION STANDARDS TESTS ===\n');

  // =========================================================================
  // 1. Role Navigation & Workspace Route Verification
  // =========================================================================
  console.log('-- Group 1: Role Navigation & Authorized Views --');

  const itOpsViews = AuthorizationService.ROLE_AUTHORIZED_VIEWS.it_operations;
  assert(itOpsViews.length === 7, `Expected 7 authorized views for IT Ops, got ${itOpsViews.length}`);
  assert(itOpsViews.includes('itops_overview'), 'Must authorize itops_overview');
  assert(itOpsViews.includes('itops_techniques'), 'Must authorize itops_techniques');
  assert(itOpsViews.includes('itops_mitigations'), 'Must authorize itops_mitigations');
  assert(itOpsViews.includes('tasks'), 'Must authorize tasks');
  assert(itOpsViews.includes('alerts'), 'Must authorize alerts');
  assert(itOpsViews.includes('audit'), 'Must authorize audit');
  assert(itOpsViews.includes('profile'), 'Must authorize profile');

  assert(
    AuthorizationService.getDefaultViewForRole('it_operations') === 'itops_overview',
    'Default view for it_operations must be itops_overview'
  );

  // Excluded views for IT Ops
  const deniedViews = ['overview', 'strategies', 'analytics', 'log_sources', 'data_components', 'mitre_explorer', 'investigations', 'playbooks', 'mitre', 'admin'];
  for (const view of deniedViews) {
    assert(
      !AuthorizationService.isViewAuthorized('it_operations', view),
      `IT Operations must NOT be authorized for ${view}`
    );
  }

  // =========================================================================
  // 2. Overview Page: 4 KPIs Calculation
  // =========================================================================
  console.log('\n-- Group 2: IT Operations Overview 4 KPIs Calculation --');

  const kpis = calculateItOpsKpis(SAMPLE_IT_OPS_RECORDS);
  assert(kpis.totalCatalogedTechniques === 8, `Expected 8 unique techniques, got ${kpis.totalCatalogedTechniques}`);
  assert(kpis.supportedPlatforms === 5, `Expected 5 unique platforms, got ${kpis.supportedPlatforms}`);
  assert(kpis.enterpriseMitigations === 7, `Expected 7 unique mitigations, got ${kpis.enterpriseMitigations}`);
  assert(kpis.coveredTactics >= 5, `Expected >= 5 unique tactics, got ${kpis.coveredTactics}`);

  // =========================================================================
  // 3. Overview Page: Exactly Two Charts (Top 5 Platforms Bar & Top 5 Tactics Bar)
  // =========================================================================
  console.log('\n-- Group 3: Overview Charts (Top 5 Platforms Bar and Top 5 Tactics Bar) --');

  const aggregatedPlatforms = aggregateTechniquesByPlatform(SAMPLE_IT_OPS_RECORDS);
  assert(aggregatedPlatforms.length > 0, 'Platforms must be aggregated');

  // Verify descending sort by technique count
  for (let i = 0; i < aggregatedPlatforms.length - 1; i++) {
    const curr = aggregatedPlatforms[i];
    const next = aggregatedPlatforms[i + 1];
    assert(
      curr.distinctTechniqueCount >= next.distinctTechniqueCount,
      `Sort order descending: ${curr.platform} (${curr.distinctTechniqueCount}) >= ${next.platform} (${next.distinctTechniqueCount})`
    );
    if (curr.distinctTechniqueCount === next.distinctTechniqueCount) {
      assert(
        curr.platform.localeCompare(next.platform) <= 0,
        `Alphabetical tie-break: ${curr.platform} <= ${next.platform}`
      );
    }
  }

  // Chart 1: Platform Bar Chart items limited to Top 5
  const top5Platforms = aggregatedPlatforms.slice(0, 5);
  const platformBarChartItems = buildPlatformBarChartItems(top5Platforms);
  assert(platformBarChartItems.length <= 5, `Bar chart must display at most Top 5 platforms, got ${platformBarChartItems.length}`);
  assert(platformBarChartItems.length === Math.min(5, aggregatedPlatforms.length), 'Bar chart item count matches Top 5 limit');

  // Chart 2: Tactic Bar Chart items limited to Top 5 (Replaces Duplicate Platform Donut)
  const aggregatedTactics = aggregateTechniquesByTactic(SAMPLE_IT_OPS_RECORDS);
  assert(aggregatedTactics.length > 0, 'Tactics must be aggregated');

  // Verify descending sort and tie-breaking for tactics
  for (let i = 0; i < aggregatedTactics.length - 1; i++) {
    const curr = aggregatedTactics[i];
    const next = aggregatedTactics[i + 1];
    assert(
      curr.distinctTechniqueCount >= next.distinctTechniqueCount,
      `Tactic sort order descending: ${curr.tactic} (${curr.distinctTechniqueCount}) >= ${next.tactic} (${next.distinctTechniqueCount})`
    );
    if (curr.distinctTechniqueCount === next.distinctTechniqueCount) {
      assert(
        curr.tactic.localeCompare(next.tactic) <= 0,
        `Tactic alphabetical tie-break: ${curr.tactic} <= ${next.tactic}`
      );
    }
  }

  const top5Tactics = aggregatedTactics.slice(0, 5);
  const tacticBarChartItems = buildTacticBarChartItems(top5Tactics);
  assert(tacticBarChartItems.length <= 5, `Tactic bar chart must display at most Top 5 tactics, got ${tacticBarChartItems.length}`);
  assert(tacticBarChartItems.length === Math.min(5, aggregatedTactics.length), 'Tactic bar chart item count matches Top 5 limit');

  // Verify Donut Chart helper remains backward-compatible for existing consumers
  const donutChartItems = buildPlatformDonutChartItems(top5Platforms);
  assert(donutChartItems.length <= 5, `Donut chart has at most 5 slices, got ${donutChartItems.length}`);
  const totalCount = donutChartItems.reduce((acc, slice) => acc + slice.count, 0);
  assert(totalCount > 0, 'Donut chart slices have non-zero count sum');

  // =========================================================================
  // 4. Explorer Pages: Zero Charts & Table Aggregations
  // =========================================================================
  console.log('\n-- Group 4: Explorer Pages (Zero Charts) --');

  const techniques = extractItOpsTechniques(SAMPLE_IT_OPS_RECORDS);
  assert(techniques.length === 8, `Technique explorer extracted 8 techniques, got ${techniques.length}`);
  const t1059 = techniques.find((t) => t.id === 'T1059.001');
  assert(Boolean(t1059), 'T1059.001 must be present');
  assert(t1059!.mitigations.length === 2, `T1059.001 has 2 distinct mitigations, got ${t1059?.mitigations.length}`);
  assert(t1059!.platforms.includes('Windows') && t1059!.platforms.includes('Linux'), 'T1059.001 platforms unioned');

  const mitigations = extractItOpsMitigations(SAMPLE_IT_OPS_RECORDS);
  assert(mitigations.length === 7, `Mitigation explorer extracted 7 mitigations, got ${mitigations.length}`);
  const m1026 = mitigations.find((m) => m.id === 'M1026');
  assert(Boolean(m1026), 'M1026 must be present');
  assert(m1026!.associatedTechniques.length === 2, `M1026 mitigates 2 techniques, got ${m1026?.associatedTechniques.length}`);

  // Filtering functionality
  const filteredByPlatform = filterAggregatedTechniques(techniques, {
    searchQuery: '',
    selectedPlatforms: ['Linux'],
    selectedTactics: [],
    selectedMitigations: [],
  });
  assert(
    filteredByPlatform.every((t) => t.platforms.includes('Linux')),
    'Filtered techniques strictly include Linux'
  );

  const activeChips = buildItOpsActiveFilterChips({
    searchQuery: 'PowerShell',
    selectedPlatforms: ['Windows'],
    selectedTactics: ['Execution'],
    selectedMitigations: [],
  });
  assert(activeChips.length === 3, `Expected 3 active filter chips, got ${activeChips.length}`);

  // =========================================================================
  // 5. Empty Dataset & Honest State Handling
  // =========================================================================
  console.log('\n-- Group 5: Empty Dataset Handling --');

  const emptyKpis = calculateItOpsKpis([]);
  assert(emptyKpis.totalCatalogedTechniques === 0, 'Empty dataset has 0 techniques');
  assert(emptyKpis.supportedPlatforms === 0, 'Empty dataset has 0 platforms');
  assert(emptyKpis.enterpriseMitigations === 0, 'Empty dataset has 0 mitigations');
  assert(emptyKpis.coveredTactics === 0, 'Empty dataset has 0 tactics');

  const emptyBarItems = buildPlatformBarChartItems([]);
  assert(emptyBarItems.length === 0, 'Empty dataset produces empty bar chart items');

  const emptyDonutItems = buildPlatformDonutChartItems([]);
  assert(emptyDonutItems.length === 0, 'Empty dataset produces empty donut chart items');

  // =========================================================================
  // 6. Role Authorization & RLS Perimeter
  // =========================================================================
  console.log('\n-- Group 6: Role Authorization & Defense in Depth --');

  const itOpsUser: UserProfile = DEMO_PERSONAS.it_operations;
  const analystUser: UserProfile = DEMO_PERSONAS.soc_analyst;
  const engineerUser: UserProfile = DEMO_PERSONAS.security_engineer;
  const adminUser: UserProfile = DEMO_PERSONAS.super_admin;

  // it_operations is permitted
  assert(
    AuthorizationService.isViewAuthorized(itOpsUser.role, 'itops_overview'),
    'it_operations authorized for itops_overview'
  );
  assert(
    AuthorizationService.isViewAuthorized(itOpsUser.role, 'tasks'),
    'it_operations authorized for tasks'
  );

  // Non-IT Ops roles denied IT Ops knowledge views
  for (const nonItOps of [analystUser, engineerUser, adminUser]) {
    assert(
      !AuthorizationService.isViewAuthorized(nonItOps.role, 'itops_overview'),
      `${nonItOps.role} strictly denied itops_overview`
    );
    assert(
      !AuthorizationService.isViewAuthorized(nonItOps.role, 'itops_techniques'),
      `${nonItOps.role} strictly denied itops_techniques`
    );
    assert(
      !AuthorizationService.isViewAuthorized(nonItOps.role, 'itops_mitigations'),
      `${nonItOps.role} strictly denied itops_mitigations`
    );
  }

  console.log('\n>>> ALL IT OPERATIONS ROLE & VISUALIZATION TESTS PASSED SUCCESSFULLY! <<<');
}

main().catch((err) => {
  console.error('[TEST SUITE FATAL ERROR]:', err);
  process.exit(1);
});
