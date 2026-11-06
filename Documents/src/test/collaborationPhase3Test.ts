/**
 * Automated Verification Test for Collaboration Phase 3:
 * Security Engineer ↔ SOC Analyst Detection Improvement Recommendations
 *
 * Verifies:
 * 1. Security Engineer recommendation creation with required fields, MITRE links, and duplicate prevention.
 * 2. Immutable operational audit logging for all recommendation lifecycle events.
 * 3. Strict role authorization: Security Engineer creates/implements, SOC Analyst reviews/validates.
 * 4. Super Admin and IT Operations complete operational isolation (empty lists, denied mutations).
 * 5. SOC Analyst review decisions: Accept, Reject (mandatory feedback), Request Clarification (mandatory feedback).
 * 6. Security Engineer implementation tracking: in_progress -> completed with notes and Sigma draft reference.
 * 7. Pre-completion guard: Prevents SOC Analyst validation before implementation is marked completed.
 * 8. SOC Analyst final validation of completed detection improvements.
 * 9. Super Admin audit isolation: operational recommendation audit events remain invisible to Super Admin.
 */

import { LocalDetectionRecommendationRepository } from '../repositories/local/LocalDetectionRecommendationRepository';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { DEMO_PERSONAS, UserProfile, AccessDeniedError } from '../types/auth';
import { CreateRecommendationInput } from '../types/recommendation';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`[ASSERTION FAILED]: ${message}`);
  }
}

async function runTest(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
  } catch (err: any) {
    console.error(`  [FAIL] ${name}:`, err.message);
    throw err;
  }
}

async function main() {
  console.log('=== RUNNING COLLABORATION PHASE 3 VERIFICATION TESTS ===\n');

  const engineer: UserProfile = DEMO_PERSONAS.security_engineer;
  const analyst: UserProfile = DEMO_PERSONAS.soc_analyst;
  const itOps: UserProfile = DEMO_PERSONAS.it_operations;
  const admin: UserProfile = DEMO_PERSONAS.super_admin;

  const auditRepo = new LocalAuditLogRepository();
  const repo = new LocalDetectionRecommendationRepository(auditRepo);

  const sampleInput: CreateRecommendationInput = {
    title: 'PowerShell Encoded Command Detection Strategy',
    techniqueId: 'T1059.001',
    techniqueName: 'PowerShell',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    priority: 'high',
    detectionGap: 'Standard process logging does not decode -EncodedCommand payload strings in base64.',
    technicalExplanation: 'Attackers frequently utilize PowerShell -enc or -e flags to evade simple string matching in process commandline telemetry.',
    proposedImprovement: 'Author Sigma rule with base64 regex decoder and ScriptBlock logging (Event ID 4104) correlation.',
    supportingEvidence: 'Windows Security Event ID 4688, PowerShell Operational 4104',
    relatedRuleDraftId: 'SIG-DRAFT-T1059_001-AUTO',
  };

  console.log('-- Group 1: Security Engineer Creation & Required Fields --');

  await runTest('Test 1: Security Engineer can create a recommendation with all required fields', async () => {
    const created = await repo.createRecommendation(engineer, sampleInput);
    assert(Boolean(created.id), 'Created recommendation must have a valid ID');
    assert(created.status === 'proposed', 'Initial status must be "proposed"');
    assert(created.techniqueId === 'T1059.001', 'Technique ID must match');
    assert(created.createdBy === engineer.id, 'Creator ID must match');
    assert(created.createdByRole === 'security_engineer', 'Creator role must be security_engineer');
  });

  await runTest('Test 2: Rejects recommendation creation when required fields are missing or empty', async () => {
    let titleErr = false;
    try {
      await repo.createRecommendation(engineer, { ...sampleInput, title: '   ' });
    } catch {
      titleErr = true;
    }
    assert(titleErr, 'Should reject empty title');

    let gapErr = false;
    try {
      await repo.createRecommendation(engineer, { ...sampleInput, detectionGap: '' });
    } catch {
      gapErr = true;
    }
    assert(gapErr, 'Should reject empty detectionGap');

    let explErr = false;
    try {
      await repo.createRecommendation(engineer, { ...sampleInput, technicalExplanation: '' });
    } catch {
      explErr = true;
    }
    assert(explErr, 'Should reject empty technicalExplanation');
  });

  await runTest('Test 3: Prevents duplicate recommendation creation for same technique and title', async () => {
    let dupErr = false;
    try {
      await repo.createRecommendation(engineer, sampleInput);
    } catch (err: any) {
      dupErr = true;
      assert(err.message.includes('already exists'), 'Error message should describe duplicate existence');
    }
    assert(dupErr, 'Should prevent duplicate active recommendation');
  });

  await runTest('Test 4: Creation emits immutable operational audit log entry', async () => {
    const logs = await auditRepo.getLogsForUser(engineer);
    const creationLog = logs.find((l) => l.actionType === 'recommendation_created');
    assert(Boolean(creationLog), 'An audit entry with actionType recommendation_created must exist');
    assert(creationLog?.actorRole === 'security_engineer', 'Audit actor role must be security_engineer');
    assert(Boolean(creationLog?.targetResource.includes('T1059.001')), 'Target resource must reference technique ID');
  });

  console.log('\n-- Group 2: Role Authorization & Domain Isolation --');

  await runTest('Test 5: IT Operations is denied from creating recommendations', async () => {
    let itOpsErr = false;
    try {
      await repo.createRecommendation(itOps, { ...sampleInput, title: 'IT Ops Unauthorized Test' });
    } catch (err) {
      if (err instanceof AccessDeniedError) itOpsErr = true;
    }
    assert(itOpsErr, 'IT Operations must be denied from creating recommendations (AccessDeniedError)');
  });

  await runTest('Test 6: Super Admin is denied from creating recommendations', async () => {
    let adminErr = false;
    try {
      await repo.createRecommendation(admin, { ...sampleInput, title: 'Admin Unauthorized Test' });
    } catch (err) {
      if (err instanceof AccessDeniedError) adminErr = true;
    }
    assert(adminErr, 'Super Admin must be denied from creating recommendations (AccessDeniedError)');
  });

  await runTest('Test 7: SOC Analyst is denied from creating recommendations', async () => {
    let analystErr = false;
    try {
      await repo.createRecommendation(analyst, { ...sampleInput, title: 'Analyst Unauthorized Test' });
    } catch (err) {
      if (err instanceof AccessDeniedError) analystErr = true;
    }
    assert(analystErr, 'SOC Analyst must be denied from creating recommendations (AccessDeniedError)');
  });

  await runTest('Test 8: Super Admin receives empty recommendation list (Strict Isolation)', async () => {
    const adminRecs = await repo.getRecommendationsForUser(admin);
    assert(Array.isArray(adminRecs) && adminRecs.length === 0, 'Super Admin must receive an empty array');
  });

  await runTest('Test 9: IT Operations receives empty recommendation list (Operational Boundary Isolation)', async () => {
    const itOpsRecs = await repo.getRecommendationsForUser(itOps);
    assert(Array.isArray(itOpsRecs) && itOpsRecs.length === 0, 'IT Operations must receive an empty array');
  });

  await runTest('Test 10: Security Engineer and SOC Analyst can read submitted recommendations', async () => {
    const engRecs = await repo.getRecommendationsForUser(engineer);
    const analystRecs = await repo.getRecommendationsForUser(analyst);
    assert(engRecs.length > 0, 'Security Engineer must see recommendations');
    assert(analystRecs.length > 0, 'SOC Analyst must see recommendations');
    assert(engRecs.length === analystRecs.length, 'Both operational roles see the active recommendation items');
  });

  console.log('\n-- Group 3: SOC Analyst Review & Decision Workflow --');

  let testRecId = '';

  await runTest('Test 11: SOC Analyst can accept a proposed recommendation', async () => {
    const created = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'LSASS Memory Dumping Detection Rule',
      techniqueId: 'T1003.001',
      techniqueName: 'OS Credential Dumping: LSASS Memory',
    });
    testRecId = created.id;

    const accepted = await repo.reviewRecommendation(
      analyst,
      testRecId,
      'accept',
      'Approved for authoring. High priority telemetry gap.'
    );

    assert(accepted.status === 'accepted', 'Recommendation status must transition to "accepted"');
    assert(accepted.reviewedBy === analyst.id, 'Reviewer ID must match analyst');
    assert(Boolean(accepted.socFeedback?.includes('Approved for authoring')), 'SOC feedback must be saved');
  });

  await runTest('Test 12: Acceptance emits recommendation_accepted immutable operational audit log', async () => {
    const logs = await auditRepo.getLogsForUser(analyst);
    const acceptLog = logs.find((l) => l.actionType === 'recommendation_accepted');
    assert(Boolean(acceptLog), 'recommendation_accepted audit log must exist');
    assert(acceptLog?.actorRole === 'soc_analyst', 'Actor role must be soc_analyst');
  });

  await runTest('Test 13: Rejection requires mandatory non-empty feedback (minimum 10 characters)', async () => {
    const recForReject = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'WMI Process Execution Detection Rule',
      techniqueId: 'T1047',
      techniqueName: 'Windows Management Instrumentation',
    });

    let shortErr = false;
    try {
      await repo.reviewRecommendation(analyst, recForReject.id, 'reject', 'Too short');
    } catch (err: any) {
      shortErr = true;
      assert(err.message.includes('at least 10 characters'), 'Error must specify minimum length');
    }
    assert(shortErr, 'Must reject short or empty feedback on rejection');
  });

  await runTest('Test 14: SOC Analyst can reject recommendation with valid feedback', async () => {
    const recForReject = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'Scheduled Task Execution Detection Rule',
      techniqueId: 'T1053.005',
      techniqueName: 'Scheduled Task',
    });

    const rejected = await repo.reviewRecommendation(
      analyst,
      recForReject.id,
      'reject',
      'Telemetry stream already covered by existing EDR heuristic rule ED-441.'
    );

    assert(rejected.status === 'rejected', 'Status must be rejected');
    assert(Boolean(rejected.socFeedback?.includes('ED-441')), 'Rejection reason must be preserved');

    const logs = await auditRepo.getLogsForUser(analyst);
    const rejectLog = logs.find((l) => l.actionType === 'recommendation_rejected');
    assert(Boolean(rejectLog), 'recommendation_rejected audit log must exist');
  });

  await runTest('Test 15: Clarification request requires mandatory non-empty feedback', async () => {
    const recForClarify = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'Remote Services SMB Detection Rule',
      techniqueId: 'T1021.002',
      techniqueName: 'SMB/Windows Admin Shares',
    });

    let shortErr = false;
    try {
      await repo.reviewRecommendation(analyst, recForClarify.id, 'request_clarification', 'need info');
    } catch (err: any) {
      shortErr = true;
      assert(err.message.includes('at least 10 characters'), 'Error must specify minimum length');
    }
    assert(shortErr, 'Must reject short feedback on clarification request');
  });

  await runTest('Test 16: SOC Analyst can request clarification with valid feedback', async () => {
    const recForClarify = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'Account Discovery Domain Detection Rule',
      techniqueId: 'T1087.002',
      techniqueName: 'Account Discovery: Domain Account',
    });

    const clarified = await repo.reviewRecommendation(
      analyst,
      recForClarify.id,
      'request_clarification',
      'Please clarify expected false-positive volume from routine IT admin queries before proceeding.'
    );

    assert(clarified.status === 'clarification_requested', 'Status must be clarification_requested');

    const logs = await auditRepo.getLogsForUser(analyst);
    const clarifyLog = logs.find((l) => l.actionType === 'recommendation_clarification_requested');
    assert(Boolean(clarifyLog), 'recommendation_clarification_requested audit log must exist');
  });

  await runTest('Test 17: Non-analyst roles (IT Ops, Sec Eng, Super Admin) are denied from reviewing recommendations', async () => {
    const rec = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'Network Sniffing Detection Rule',
      techniqueId: 'T1040',
      techniqueName: 'Network Sniffing',
    });

    for (const unauthorizedUser of [engineer, itOps, admin]) {
      let denied = false;
      try {
        await repo.reviewRecommendation(unauthorizedUser, rec.id, 'accept', 'Valid notes but unauthorized user');
      } catch (err) {
        if (err instanceof AccessDeniedError) denied = true;
      }
      assert(denied, `Role "${unauthorizedUser.role}" must be denied from reviewing recommendations`);
    }
  });

  console.log('\n-- Group 4: Security Engineer Implementation & Sigma Drafting --');

  await runTest('Test 18: Security Engineer can transition accepted recommendation to in_progress', async () => {
    const started = await repo.updateImplementation(
      engineer,
      testRecId,
      'in_progress',
      'Drafting Sigma rule selection for LSASS process access masks.',
      'SIG-DRAFT-T1003_001-A'
    );

    assert(started.status === 'in_progress', 'Status must transition to in_progress');
    assert(started.sigmaDraftReference === 'SIG-DRAFT-T1003_001-A', 'Sigma draft reference must be attached');

    const logs = await auditRepo.getLogsForUser(engineer);
    const startedLog = logs.find((l) => l.actionType === 'recommendation_implementation_started');
    assert(Boolean(startedLog), 'recommendation_implementation_started audit log must exist');
  });

  await runTest('Test 19: Cannot start implementation on non-accepted recommendations', async () => {
    const proposedRec = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'Valid Proposed Record For Invariant',
      techniqueId: 'T1059.003',
      techniqueName: 'Windows Command Shell',
    });

    let errProposed = false;
    try {
      await repo.updateImplementation(engineer, proposedRec.id, 'in_progress');
    } catch (err: any) {
      errProposed = true;
      assert(err.message.includes('Must be in "accepted" status'), 'Should fail because status is proposed');
    }
    assert(errProposed, 'Cannot transition proposed directly to in_progress');
  });

  await runTest('Test 20: Completing implementation requires mandatory implementation notes', async () => {
    let shortErr = false;
    try {
      await repo.updateImplementation(engineer, testRecId, 'completed', 'Done');
    } catch (err: any) {
      shortErr = true;
      assert(err.message.includes('at least 10 characters'), 'Implementation notes must be at least 10 chars');
    }
    assert(shortErr, 'Must require non-empty implementation notes of at least 10 chars');
  });

  await runTest('Test 21: Security Engineer can complete implementation with valid notes and Sigma draft reference', async () => {
    const completed = await repo.updateImplementation(
      engineer,
      testRecId,
      'completed',
      'Authored Sigma rule verified with Sysmon Event ID 10 filters. Ready for SOC triage validation.',
      'SIG-DRAFT-T1003_001-FINAL'
    );

    assert(completed.status === 'completed', 'Status must be completed');
    assert(completed.sigmaDraftReference === 'SIG-DRAFT-T1003_001-FINAL', 'Sigma reference must match');
    assert(Boolean(completed.implementationNotes?.includes('Sysmon Event ID 10')), 'Implementation notes preserved');

    const logs = await auditRepo.getLogsForUser(engineer);
    const compLog = logs.find((l) => l.actionType === 'recommendation_implemented');
    assert(Boolean(compLog), 'recommendation_implemented audit log must exist');
  });

  await runTest('Test 22: Non-engineer roles are denied from updating implementation progress', async () => {
    for (const unauthorized of [analyst, itOps, admin]) {
      let denied = false;
      try {
        await repo.updateImplementation(unauthorized, testRecId, 'in_progress');
      } catch (err) {
        if (err instanceof AccessDeniedError) denied = true;
      }
      assert(denied, `Role "${unauthorized.role}" must be denied from updating implementation`);
    }
  });

  console.log('\n-- Group 5: SOC Analyst Final Validation & Pre-Completion Guard --');

  await runTest('Test 23: Pre-completion guard: Prevents SOC Analyst validation when status is NOT completed', async () => {
    const uncompletedRec = await repo.createRecommendation(engineer, {
      ...sampleInput,
      title: 'Pre-completion Guard Test Record',
      techniqueId: 'T1078',
      techniqueName: 'Valid Accounts',
    });

    let guardErr = false;
    try {
      await repo.validateRecommendation(analyst, uncompletedRec.id, 'Premature validation');
    } catch (err: any) {
      guardErr = true;
      assert(err.message.includes('must be "completed" before final SOC validation'), 'Error must cite completion requirement');
    }
    assert(guardErr, 'Pre-completion guard must block validation');
  });

  await runTest('Test 24: SOC Analyst can validate completed recommendation', async () => {
    const validated = await repo.validateRecommendation(
      analyst,
      testRecId,
      'Rule logic tested against adversary emulation logs. Approved for production SIEM ingestion.'
    );

    assert(validated.status === 'validated', 'Status must transition to "validated"');
    assert(Boolean(validated.socFeedback?.includes('VALIDATION CONFIRMED')), 'Validation confirmed stamp appended');

    const logs = await auditRepo.getLogsForUser(analyst);
    const valLog = logs.find((l) => l.actionType === 'recommendation_validated');
    assert(Boolean(valLog), 'recommendation_validated audit log must exist');
  });

  await runTest('Test 25: Non-analyst roles are denied from validating recommendations', async () => {
    for (const unauthorized of [engineer, itOps, admin]) {
      let denied = false;
      try {
        await repo.validateRecommendation(unauthorized, testRecId, 'Unauthorized validation');
      } catch (err) {
        if (err instanceof AccessDeniedError) denied = true;
      }
      assert(denied, `Role "${unauthorized.role}" must be denied from validating recommendations`);
    }
  });

  console.log('\n-- Group 6: Audit Segregation & Invariants --');

  await runTest('Test 26: Super Admin reading audit logs cannot see operational recommendation audit events', async () => {
    const adminLogs = await auditRepo.getLogsForUser(admin);
    const hasRecommendationLog = adminLogs.some((l) => l.actionType.startsWith('recommendation_'));
    assert(!hasRecommendationLog, 'Super Admin audit logs must NEVER contain operational recommendation events');
  });

  await runTest('Test 27: Operational roles can inspect recommendation audit events in operational audit trail', async () => {
    const analystLogs = await auditRepo.getLogsForUser(analyst);
    const recLogs = analystLogs.filter((l) => l.actionType.startsWith('recommendation_'));
    assert(recLogs.length >= 6, 'Operational audit trail must contain all emitted recommendation lifecycle events');
  });

  console.log('\n=== ALL COLLABORATION PHASE 3 VERIFICATION TESTS PASSED (27/27) ===');
}

main().catch((err) => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
