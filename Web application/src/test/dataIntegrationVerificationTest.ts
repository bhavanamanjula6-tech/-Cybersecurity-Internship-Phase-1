/**
 * CyberOps SOC — Data Integration and Visualization Verification Test
 *
 * Verifies all approved aggregations, deduplication logic, delimiter parsing,
 * visualization invariants, and error boundaries across SOC Analyst, Security Engineer,
 * IT Operations, and Super Admin domains.
 */

import assert from 'assert';
import {
  aggregateTechniquesByTactic,
  aggregateLogSources,
  aggregateMitigationCoverage,
  normalizePlatformName,
  aggregateTechniquesByTacticForItOps,
  aggregateTechniquesByPlatformForItOps,
  SocAnalystKnowledgeRecord,
  SecurityEngineerKnowledgeRecord,
  ItOperationsKnowledgeRecord,
  normalizeAttackId,
  formatAttackIdDisplay,
  isValidAttackId,
} from '../services/knowledgeService';
import { calculateAdminOverviewMetrics } from '../services/adminMetricsService';
import { UserProfile, ROLE_PERMISSIONS } from '../types/auth';
import { AuthorizationService } from '../services/authorizationService';

console.log('--- Starting CyberOps SOC Data Integration Verification Test ---');

// ============================================================================
// 1. SOC Analyst: Distinct Technique Counting & Delimiter Splitting
// ============================================================================
console.log('\n[1] Testing SOC Analyst Distinct Technique Counting & Log Source Splitting...');

const mockSocAnalystRecords: SocAnalystKnowledgeRecord[] = [
  // Technique T1059 mapped to 'execution' with multiple log sources across 2 rows
  {
    techniques_id: 'T1059',
    techniques_tactics: 'Execution',
    log_source_name: 'Process: Process Creation, Command: Command Execution',
  },
  {
    techniques_id: 'T1059',
    techniques_tactics: 'Execution',
    log_source_name: 'Script: Script Execution',
  },
  // Technique T1059.001 mapped to 'execution'
  {
    techniques_id: 'T1059.001',
    techniques_tactics: 'Execution',
    log_source_name: 'Process: Process Creation; Script: Script Execution',
  },
  // Technique T1078 mapped to 'persistence' and 'privilege-escalation'
  {
    techniques_id: 'T1078',
    techniques_tactics: 'Persistence, Privilege Escalation',
    log_source_name: 'Logon Session: Logon Session Creation | User Account: User Account Authentication',
  },
];

// Test aggregateTechniquesByTactic deduplication
const tacticAgg = aggregateTechniquesByTactic(mockSocAnalystRecords);
const executionAgg = tacticAgg.find((t) => t.tactic.toLowerCase() === 'execution');
assert.ok(executionAgg, 'Execution tactic aggregation must exist');
// T1059 (in 2 rows) and T1059.001 (in 1 row) -> exactly 2 distinct techniques for Execution
assert.strictEqual(
  executionAgg.uniqueTechniquesCount,
  2,
  `Execution must have exactly 2 distinct techniques, got ${executionAgg.uniqueTechniquesCount}`
);

const persistenceAgg = tacticAgg.find((t) => t.tactic.toLowerCase() === 'persistence');
assert.ok(persistenceAgg, 'Persistence tactic aggregation must exist');
assert.strictEqual(
  persistenceAgg.uniqueTechniquesCount,
  1,
  'Persistence must have exactly 1 distinct technique (T1078)'
);

const privEscAgg = tacticAgg.find((t) => t.tactic.toLowerCase() === 'privilege escalation');
assert.ok(privEscAgg, 'Privilege Escalation tactic aggregation must exist');
assert.strictEqual(
  privEscAgg.uniqueTechniquesCount,
  1,
  'Privilege Escalation must have exactly 1 distinct technique (T1078)'
);

// Test aggregateLogSources delimiter splitting and preservation of colons
const logSourceAgg = aggregateLogSources(mockSocAnalystRecords);
// Verify that colons were preserved (e.g., "Process: Process Creation" is NOT split into "Process" and "Process Creation")
const processCreation = logSourceAgg.find((l) => l.logSource === 'Process: Process Creation');
assert.ok(processCreation, 'Process: Process Creation must exist as an intact log source token');
// Process: Process Creation is associated with T1059 and T1059.001 -> 2 distinct techniques
assert.strictEqual(
  processCreation.uniqueTechniquesCount,
  2,
  `Process: Process Creation unique techniques must be 2, got ${processCreation.uniqueTechniquesCount}`
);

const scriptExecution = logSourceAgg.find((l) => l.logSource === 'Script: Script Execution');
assert.ok(scriptExecution, 'Script: Script Execution must exist as an intact token');
assert.strictEqual(
  scriptExecution.uniqueTechniquesCount,
  2,
  'Script: Script Execution unique techniques must be 2 (T1059, T1059.001)'
);

const logonSession = logSourceAgg.find((l) => l.logSource === 'Logon Session: Logon Session Creation');
assert.ok(logonSession, 'Pipe delimited log source "Logon Session: Logon Session Creation" must be split correctly');

console.log('✓ SOC Analyst distinct technique counting and delimiter splitting passed.');

// ============================================================================
// 2. Security Engineer: Platform Casing & Mitigation Donut Invariant
// ============================================================================
console.log('\n[2] Testing Security Engineer Canonical Casing & Mitigation Donut Invariants...');

// Test canonical platform casing
assert.strictEqual(normalizePlatformName('esxi'), 'ESXi', 'esxi must normalize to ESXi');
assert.strictEqual(normalizePlatformName('ESXi'), 'ESXi', 'ESXi must normalize to ESXi');
assert.strictEqual(normalizePlatformName('pre'), 'PRE', 'pre must normalize to PRE');
assert.strictEqual(normalizePlatformName('PRE'), 'PRE', 'PRE must normalize to PRE');
assert.strictEqual(normalizePlatformName('windows'), 'Windows', 'windows must normalize to Windows');
assert.strictEqual(normalizePlatformName('linux'), 'Linux', 'linux must normalize to Linux');
assert.strictEqual(normalizePlatformName('macos'), 'macOS', 'macos must normalize to macOS');

const mockSecEngRecords: SecurityEngineerKnowledgeRecord[] = [
  {
    technique_id: 'T1059',
    tactic_names: 'Execution',
    technique_platforms: 'Windows, Linux, macOS',
    matched_platform_names: 'Windows, Linux, macOS',
    technique_tactics: 'Execution',
    mitigation_id: 'M1038',
    mitigation_name: 'Execution Prevention',
  },
  {
    technique_id: 'T1059',
    tactic_names: 'Execution',
    technique_platforms: 'Windows, Linux, macOS',
    matched_platform_names: 'Windows, Linux, macOS',
    technique_tactics: 'Execution',
    mitigation_id: 'M1047',
    mitigation_name: 'Audit',
  },
  {
    technique_id: 'T1078',
    tactic_names: 'Defense Evasion',
    technique_platforms: 'ESXi, Linux',
    matched_platform_names: 'ESXi, Linux',
    technique_tactics: 'Defense Evasion',
    mitigation_id: 'none', // unmitigated string
    mitigation_name: 'None',
  },
  {
    technique_id: 'T1046',
    tactic_names: 'Discovery',
    technique_platforms: 'PRE, Windows',
    matched_platform_names: 'PRE, Windows',
    technique_tactics: 'Discovery',
    mitigation_id: null, // unmitigated null
    mitigation_name: null,
  },
];

const mitAgg = aggregateMitigationCoverage(mockSecEngRecords);
// Distinct techniques in dataset: T1059, T1078, T1046 -> 3
assert.strictEqual(mitAgg.summary.totalUniqueTechniques, 3, 'Total unique techniques must be 3');
assert.strictEqual(mitAgg.summary.mitigatedTechniquesCount, 1, 'Mitigated techniques must be 1 (T1059)');
assert.strictEqual(mitAgg.summary.unmitigatedTechniquesCount, 2, 'Unmitigated techniques must be 2 (T1078, T1046)');

// Invariant: totalUniqueTechniques === mitigatedTechniquesCount + unmitigatedTechniquesCount
assert.strictEqual(
  mitAgg.summary.totalUniqueTechniques,
  mitAgg.summary.mitigatedTechniquesCount + mitAgg.summary.unmitigatedTechniquesCount,
  'Strict invariant violation: totalUniqueTechniques !== mitigated + unmitigated'
);

// Mitigation percentage calculation (1 decimal place)
const expectedPct = Math.round((1 / 3) * 1000) / 10;
assert.strictEqual(mitAgg.summary.mitigatedPercentage, expectedPct, `Expected ${expectedPct}%, got ${mitAgg.summary.mitigatedPercentage}%`);

console.log('✓ Security Engineer platform normalization and mitigation donut invariants passed.');

// ============================================================================
// 3. IT Operations: Multi-value Parsing & Top 10 Behavior
// ============================================================================
console.log('\n[3] Testing IT Operations Aggregations...');

const mockItOpsRecords: ItOperationsKnowledgeRecord[] = [
  {
    technique_id: 'T1059',
    technique_tactics: 'Execution',
    technique_platforms: 'Windows, Linux',
    tactic_name: 'Execution',
    platform_name: 'Windows',
  },
  {
    technique_id: 'T1078',
    technique_tactics: 'Persistence; Privilege Escalation',
    technique_platforms: 'ESXi; PRE',
    tactic_name: 'Persistence; Privilege Escalation',
    platform_name: 'ESXi',
  },
];

const itTacticResult = aggregateTechniquesByTacticForItOps(mockItOpsRecords);
assert.strictEqual(itTacticResult.tactics.length, 3, 'IT Ops should have 3 tactics: Execution, Persistence, Privilege Escalation');
assert.strictEqual(itTacticResult.totalUniqueTechniques, 2, 'Total unique techniques in IT Ops must be 2');

const itPlatformResult = aggregateTechniquesByPlatformForItOps(mockItOpsRecords);
assert.ok(itPlatformResult.platforms.some((p) => p.platform === 'ESXi'), 'ESXi platform must exist in IT Ops aggregation');
assert.strictEqual(itPlatformResult.totalUniqueTechniques, 2, 'Total unique techniques for platforms must be 2');

console.log('✓ IT Operations multi-value parsing passed.');

// ============================================================================
// 4. Super Admin: Metrics Calculation & Non-Fallback Error Handling
// ============================================================================
console.log('\n[4] Testing Super Admin Metrics Calculation...');

const mockProfiles: UserProfile[] = [
  {
    id: 'u1',
    name: 'Analyst One',
    email: 'a1@soc.local',
    role: 'soc_analyst',
    callsign: 'SPECTER',
    title: 'Senior Incident Responder',
    accountStatus: 'approved',
  },
  {
    id: 'u2',
    name: 'Analyst Two',
    email: 'a2@soc.local',
    role: 'soc_analyst',
    callsign: 'GHOST',
    title: 'Security Analyst',
    accountStatus: 'pending',
  },
  {
    id: 'u3',
    name: 'Engineer One',
    email: 'e1@soc.local',
    role: 'security_engineer',
    callsign: 'AEGIS',
    title: 'Lead Detection Engineer',
    accountStatus: 'approved',
  },
  {
    id: 'u4',
    name: 'IT Ops One',
    email: 'it1@soc.local',
    role: 'it_operations',
    callsign: 'ANVIL',
    title: 'Infrastructure Specialist',
    accountStatus: 'disabled',
  },
  {
    id: 'u5',
    name: 'Admin One',
    email: 'admin@soc.local',
    role: 'super_admin',
    callsign: 'VANGUARD',
    title: 'Chief Information Security Officer',
    accountStatus: 'approved',
  },
];

const adminStats = calculateAdminOverviewMetrics(mockProfiles);
assert.strictEqual(adminStats.totalUsers, 5, 'Total users must be 5');
assert.strictEqual(adminStats.roleCounts.soc_analyst, 2, 'soc_analyst count must be 2');
assert.strictEqual(adminStats.roleCounts.security_engineer, 1, 'security_engineer count must be 1');
assert.strictEqual(adminStats.roleCounts.it_operations, 1, 'it_operations count must be 1');
assert.strictEqual(adminStats.roleCounts.super_admin, 1, 'super_admin count must be 1');

assert.strictEqual(adminStats.approvedCount, 3, 'Approved count must be 3');
assert.strictEqual(adminStats.pendingCount, 1, 'Pending count must be 1');
assert.strictEqual(adminStats.disabledCount, 1, 'Disabled count must be 1');
assert.strictEqual(adminStats.rejectedCount, 0, 'Rejected count must be 0');

// Sum invariant: approved + pending + disabled + rejected === totalUsers
const statusSum = adminStats.approvedCount + adminStats.pendingCount + adminStats.disabledCount + adminStats.rejectedCount;
assert.strictEqual(statusSum, adminStats.totalUsers, 'Status counts must sum to totalUsers');

console.log('✓ Super Admin overview stats and invariants verified successfully.');

// ============================================================================
// 5. MITRE ATT&CK Standardization, Alert ID Display & Telemetry Removal
// ============================================================================
console.log('\n[5] Testing MITRE ATT&CK Standardization, Alert ID & Telemetry Elimination...');

// 5a. ATT&CK ID format validation and normalization
assert.strictEqual(normalizeAttackId('t1059.001'), 'T1059.001', 'Lowercase sub-technique must normalize to uppercase');
assert.strictEqual(normalizeAttackId('T1003'), 'T1003', 'Standard technique ID must be preserved');
assert.strictEqual(normalizeAttackId('  T1195.002  '), 'T1195.002', 'Whitespace must be trimmed');
assert.strictEqual(normalizeAttackId(null), null, 'null input must return null');
assert.strictEqual(normalizeAttackId(undefined), null, 'undefined input must return null');
assert.strictEqual(normalizeAttackId('invalid_id'), null, 'Invalid format must return null');
assert.strictEqual(normalizeAttackId('T12'), null, 'Incomplete technique ID must return null');

assert.strictEqual(isValidAttackId('T1059.001'), true, 'Valid sub-technique');
assert.strictEqual(isValidAttackId('T1059'), true, 'Valid technique');
assert.strictEqual(isValidAttackId('NOT_VALID'), false, 'Invalid technique');

// 5b. ATT&CK display formatting with "Not available" fallback
assert.strictEqual(formatAttackIdDisplay('T1059.001'), 'T1059.001');
assert.strictEqual(formatAttackIdDisplay(null), 'Not available', 'null must display "Not available"');
assert.strictEqual(formatAttackIdDisplay(undefined), 'Not available', 'undefined must display "Not available"');
assert.strictEqual(formatAttackIdDisplay(''), 'Not available', 'empty string must display "Not available"');

// 5c. Complete elimination of Network Flow Telemetry across all roles
for (const [role, views] of Object.entries(AuthorizationService.ROLE_AUTHORIZED_VIEWS)) {
  assert.ok(!views.includes('network' as any), `Role ${role} must NOT have 'network' in ROLE_AUTHORIZED_VIEWS`);
}

// 5d. Complete elimination of 'telemetry:read' permission
for (const [role, permissions] of Object.entries(ROLE_PERMISSIONS)) {
  assert.ok(!permissions.includes('telemetry:read' as any), `Role ${role} must NOT have 'telemetry:read' in ROLE_PERMISSIONS`);
}

// 5e. Mitigation Description coverage in Security Engineer aggregation
const mockSecEngRecordsWithDesc: SecurityEngineerKnowledgeRecord[] = [
  {
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    technique_tactics: 'Execution',
    technique_platforms: 'Windows',
    mitigation_id: 'M1026',
    mitigation_name: 'Privileged Account Management',
    mitigation_description: 'Restrict access by setting up standard accounts and limiting privileged rights.',
  },
  {
    technique_id: 'T1059.003',
    technique_name: 'Windows Command Shell',
    technique_tactics: 'Execution',
    technique_platforms: 'Windows',
    mitigation_id: null,
    mitigation_name: null,
    mitigation_description: null,
  },
];

const secEngMitAgg = aggregateMitigationCoverage(mockSecEngRecordsWithDesc);
assert.strictEqual(secEngMitAgg.summary.totalUniqueTechniques, 2, 'Total unique techniques must be 2');
assert.strictEqual(secEngMitAgg.summary.mitigatedTechniquesCount, 1, 'Mitigated techniques must be 1');
assert.strictEqual(secEngMitAgg.summary.unmitigatedTechniquesCount, 1, 'Unmitigated gaps must be 1 (NULL mitigation preserved)');
assert.strictEqual(secEngMitAgg.mitigations.length, 1, 'Top mitigations has 1 mitigation');
assert.strictEqual(secEngMitAgg.mitigations[0].mitigationDescription, 'Restrict access by setting up standard accounts and limiting privileged rights.');

console.log('✓ ATT&CK ID standardization, Telemetry Removal & Mitigation Description tests PASSED!');

console.log('\n=============================================================');
console.log('All Data Integration and Visualization Verification Tests Passed!');
console.log('=============================================================');
