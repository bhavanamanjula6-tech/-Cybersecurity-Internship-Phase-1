/**
 * Phase 1 Verification Test Suite
 * Verifies repository contracts, deterministic triage scoring, and role-based permissions.
 */

import { DeterministicTriageService } from '../services/deterministicTriageService';
import { AuthorizationService } from '../services/authorizationService';
import { INITIAL_SYNTHETIC_ALERTS } from '../data/syntheticAlerts';
import { AUTHENTIC_MITRE_TECHNIQUES, AUTHENTIC_MITRE_TACTICS } from '../data/mitreData';

function runTests() {
  console.log('--- Starting Phase 1 Verification ---');

  // Test 1: MITRE ATT&CK Data Integrity
  console.log('1. Checking MITRE ATT&CK reference data...');
  if (AUTHENTIC_MITRE_TECHNIQUES.length < 5) {
    throw new Error('Expected at least 5 authentic MITRE techniques.');
  }
  if (AUTHENTIC_MITRE_TACTICS.length < 5) {
    throw new Error('Expected at least 5 authentic MITRE tactics.');
  }
  const lsassTech = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === 'T1003.001');
  if (!lsassTech || !lsassTech.name.includes('LSASS')) {
    throw new Error('T1003.001 missing or corrupted in MITRE dataset.');
  }
  console.log('   ✓ MITRE ATT&CK reference data verified.');

  // Test 2: Deterministic Triage Engine
  console.log('2. Testing Deterministic Triage Engine...');
  const triageService = new DeterministicTriageService();

  // Test LSASS alert
  const lsassAlert = INITIAL_SYNTHETIC_ALERTS.find((a) => a.id === 'ALT-2026-1049')!;
  const lsassResult = triageService.evaluateAlert(lsassAlert);
  if (lsassResult.recommendedSeverity !== 'critical') {
    throw new Error(`Expected critical for LSASS, got ${lsassResult.recommendedSeverity}`);
  }
  if (lsassResult.matchedRules.length === 0) {
    throw new Error('Expected at least 1 matched rule for LSASS.');
  }
  if (!lsassResult.isDeterministic) {
    throw new Error('Result must be marked deterministic.');
  }
  console.log('   ✓ LSASS rule matching verified.');

  // Test Encoded PowerShell alert
  const psAlert = INITIAL_SYNTHETIC_ALERTS.find((a) => a.id === 'ALT-2026-1048')!;
  const psResult = triageService.evaluateAlert(psAlert);
  if (psResult.matchedRules.length < 2) {
    throw new Error('Expected PowerShell and Macro detection rules to match.');
  }
  console.log('   ✓ PowerShell and Macro lineage rules verified.');

  // Test Benign alert
  const benignAlert = INITIAL_SYNTHETIC_ALERTS.find((a) => a.id === 'ALT-2026-1044')!;
  const benignResult = triageService.evaluateAlert(benignAlert);
  if (benignResult.recommendedSeverity !== 'informational') {
    throw new Error(`Expected informational for benign alert, got ${benignResult.recommendedSeverity}`);
  }
  console.log('   ✓ Benign baseline rule verified.');

  // Test 3: Role & Authorization boundary
  console.log('3. Checking Authorization Service...');
  if (!AuthorizationService.canTriageAlerts('soc_analyst')) {
    throw new Error('SOC Analyst must have alert:triage permission.');
  }
  if (!AuthorizationService.canAnalyzeMitreCoverage('security_engineer')) {
    throw new Error('Security Engineer must have mitre:analyze_coverage permission.');
  }
  if (!AuthorizationService.canAuthorizeSimulatedActions('it_operations')) {
    throw new Error('IT Operations must have action:authorize_simulated permission.');
  }
  console.log('   ✓ Role capabilities verified.');

  console.log('--- ALL VERIFICATION TESTS PASSED ---');
}

runTests();
