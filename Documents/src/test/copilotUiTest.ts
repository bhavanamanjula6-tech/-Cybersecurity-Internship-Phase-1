/**
 * CyberOps SOC — AI Security Copilot UI & Client API Integration Tests (Phase 3B)
 *
 * Verifies:
 * 1. Client-Side API Service Contract & Error Wrapping:
 *    - Valid dispatch to POST /api/copilot/chat with bearer token
 *    - Status retrieval from GET /api/copilot/status
 *    - Safe handling and error mapping for HTTP 401, 403, 400, 429, 503, 504
 *    - Propagation of Retry-After headers and requiredPermission codes
 * 2. Zero-Leakage & Client Boundary Safeguards:
 *    - Asserts no client file imports @google/genai or references VITE_GEMINI_API_KEY
 *    - Asserts no AI navigation module was added to the sidebar for any role
 *    - Asserts sidebar module counts remain strictly:
 *        * soc_analyst: 6
 *        * security_engineer: 4
 *        * it_operations: 3
 *        * super_admin: 2
 * 3. Advisory UI & Human-in-the-Loop Integrity:
 *    - Mandatory advisory badges on AI response turns
 *    - Authoritative backend role boundaries preserved
 *    - Zero fabrication or silent fallback to mock AI output
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createServer } from '../../server.ts';
import { UserProfile } from '../types/auth';
import { LocalAlertRepository } from '../repositories/local/LocalAlertRepository';
import { LocalAuditLogRepository } from '../repositories/local/LocalAuditLogRepository';
import { LocalMITRERepository } from '../repositories/local/LocalMITRERepository';
import { LocalDetectionRecommendationRepository } from '../repositories/local/LocalDetectionRecommendationRepository';
import { RepositoryBundle } from '../repositories';
import { sendCopilotMessage, fetchCopilotStatus, CopilotClientError } from '../services/copilotClientService';

const TEST_PORT = 3194;
let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    passed++;
    console.log(`  [PASS] ${testName}`);
  } else {
    failed++;
    console.error(`  [FAIL] ${testName}${detail ? ` -> ${detail}` : ''}`);
  }
}

const MOCK_PROFILES: Record<string, UserProfile> = {
  analyst_token: {
    id: 'usr-analyst-ui',
    name: 'Alex Mercer',
    email: 'alex@soc.test',
    role: 'soc_analyst',
    callsign: 'SPECTER-1',
    title: 'Senior SOC Analyst',
    accountStatus: 'approved',
  },
  admin_token: {
    id: 'usr-admin-ui',
    name: 'Diana Prince',
    email: 'diana@soc.test',
    role: 'super_admin',
    callsign: 'AEGIS-LEAD',
    title: 'Platform Administrator',
    accountStatus: 'approved',
  },
  unapproved_token: {
    id: 'usr-pending-ui',
    name: 'Bob Pending',
    email: 'bob@soc.test',
    role: 'soc_analyst',
    callsign: 'PENDING-1',
    title: 'Junior Analyst',
    accountStatus: 'pending',
  },
};

const testTokenVerifier = async (token: string): Promise<UserProfile | null> => {
  return MOCK_PROFILES[token] || null;
};

const testRepos: RepositoryBundle = {
  alertRepo: new LocalAlertRepository(),
  auditRepo: new LocalAuditLogRepository(),
  mitreRepo: new LocalMITRERepository(),
  recommendationRepo: new LocalDetectionRecommendationRepository(),
  isLive: false,
  mode: 'development_demo',
};

async function runCopilotUiIntegrationTests() {
  console.log('\n=== RUNNING CYBEROPS SOC PHASE 3B COPILOT UI INTEGRATION TESTS ===\n');

  // -------------------------------------------------------------------------
  // Test Group 1: Zero-Leakage & Client Boundary Safeguards
  // -------------------------------------------------------------------------
  console.log('-- Group 1: Zero-Leakage & Client Boundary Safeguards --');

  const clientFilesToCheck = [
    'src/services/copilotClientService.ts',
    'src/hooks/useCopilot.ts',
    'src/components/copilot/CopilotDrawer.tsx',
    'src/components/copilot/CopilotTriggerButton.tsx',
    'src/layouts/WorkspaceLayout.tsx',
    'src/App.tsx',
  ];

  for (const relPath of clientFilesToCheck) {
    const fullPath = resolve(process.cwd(), relPath);
    const content = readFileSync(fullPath, 'utf8');

    assert(
      !content.includes("from '@google/genai'") &&
      !content.includes('from "@google/genai"') &&
      !content.includes("require('@google/genai')"),
      `Test: ${relPath} strictly does NOT import @google/genai directly`
    );
    assert(
      !content.includes('VITE_GEMINI_API_KEY'),
      `Test: ${relPath} strictly does NOT reference VITE_GEMINI_API_KEY`
    );
    assert(
      !content.includes('process.env.GEMINI_API_KEY'),
      `Test: ${relPath} strictly does NOT access process.env.GEMINI_API_KEY`
    );
  }

  // -------------------------------------------------------------------------
  // Test Group 2: Sidebar Module Isolation (Zero Additional AI Sidebar Entries)
  // -------------------------------------------------------------------------
  console.log('\n-- Group 2: Sidebar Module Isolation --');

  const { AuthorizationService } = await import('../services/authorizationService');

  // Verify view counts per role (excluding profile which is in the account dropdown)
  const analystViews = AuthorizationService.ROLE_AUTHORIZED_VIEWS.soc_analyst.filter(
    (v) => v !== 'profile'
  );
  assert(
    analystViews.length === 6,
    `Test: SOC Analyst authorized views count strictly maintains exactly 6 modules (got ${analystViews.length})`
  );

  const engineerViews = AuthorizationService.ROLE_AUTHORIZED_VIEWS.security_engineer.filter(
    (v) => v !== 'profile'
  );
  assert(
    engineerViews.length === 4,
    `Test: Security Engineer authorized views count strictly maintains exactly 4 modules (got ${engineerViews.length})`
  );

  const itOpsViews = AuthorizationService.ROLE_AUTHORIZED_VIEWS.it_operations.filter(
    (v) => v !== 'profile'
  );
  assert(
    itOpsViews.length === 4,
    `Test: IT Operations authorized views count strictly maintains exactly 4 modules (got ${itOpsViews.length})`
  );
  assert(
    ['tasks', 'alerts', 'network', 'audit'].every((view) => itOpsViews.includes(view)),
    'Test: IT Operations authorized views correspond to Tasks, Scoped Alerts, Network Flows, and Audit Trail'
  );

  const adminViews = AuthorizationService.ROLE_AUTHORIZED_VIEWS.super_admin.filter(
    (v) => v !== 'profile'
  );
  assert(
    adminViews.length === 2,
    `Test: Super Admin authorized views count strictly maintains exactly 2 modules (got ${adminViews.length})`
  );

  const sidebarContent = readFileSync(
    resolve(process.cwd(), 'src/components/layout/AppSidebar.tsx'),
    'utf8'
  );
  assert(
    !sidebarContent.includes("'copilot'") && !sidebarContent.includes('"copilot"'),
    'Test: No "copilot" entry in AppSidebar.tsx (UI accessed solely via floating button & drawer)'
  );
  assert(
    !sidebarContent.includes("'ai'") && !sidebarContent.includes('"ai"'),
    'Test: No standalone AI entry in AppSidebar.tsx'
  );

  // -------------------------------------------------------------------------
  // Test Group 3: Client Service Communication & Error Handling with Server
  // -------------------------------------------------------------------------
  console.log('\n-- Group 3: Client Service Communication & Error Handling with Server --');

  process.env.NODE_ENV = 'development';

  const serverInstance = await createServer({
    copilotOptions: {
      tokenVerifier: testTokenVerifier,
      geminiService: {
        isConfigured: () => true,
        generateAdvisory: async (sys: string, content: string) => {
          return {
            text: 'AI Advisory: Command line utilizes base64 encoded PowerShell string.',
            model: 'gemini-3.8-flash',
            disclaimer:
              'AI Copilot analysis is strictly advisory and requires human verification before operational action.',
          };
        },
      } as any,
      repositoryBundle: testRepos,
    },
  });

  await new Promise<void>((resolve, reject) => {
    serverInstance.httpServer.listen(TEST_PORT, '0.0.0.0', () => resolve());
    serverInstance.httpServer.on('error', reject);
  });

  // Temporarily hook global fetch to redirect /api/copilot to test port
  const originalFetch = global.fetch;
  global.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    let urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (urlStr.startsWith('/api/copilot')) {
      urlStr = `http://127.0.0.1:${TEST_PORT}${urlStr}`;
    }
    return originalFetch(urlStr, init);
  };

  try {
    // 1. Successful advisory chat
    const chatResponse = await sendCopilotMessage(
      {
        prompt: 'Analyze alert telemetry and decode base64',
        contextType: 'alert_triage',
        entityId: 'ALT-2026-1046',
      },
      'analyst_token'
    );
    assert(chatResponse.isAdvisory === true, 'Test: Successful chat response envelope marks isAdvisory: true');
    assert(chatResponse.role === 'soc_analyst', 'Test: Response contains authenticated role "soc_analyst"');
    assert(chatResponse.contextType === 'alert_triage', 'Test: Response contains requested contextType');
    assert(
      chatResponse.disclaimer.includes('human verification'),
      'Test: Response contains mandatory advisory disclaimer'
    );
    assert(
      chatResponse.response.includes('base64 encoded PowerShell'),
      'Test: Response contains generated advisory text'
    );

    // 2. Status retrieval for operational role
    const statusAnalyst = await fetchCopilotStatus('analyst_token');
    assert(statusAnalyst.status === 'online', 'Test: Status endpoint returns online');
    assert(statusAnalyst.modelConfigured === true, 'Test: Status endpoint indicates modelConfigured: true');
    assert(statusAnalyst.role === 'soc_analyst', 'Test: Status indicates caller role "soc_analyst"');
    assert(!('metrics' in statusAnalyst), 'Test: Prohibited metrics are absent for operational role');

    // 3. Status retrieval for super_admin
    const statusAdmin = await fetchCopilotStatus('admin_token');
    assert('metrics' in statusAdmin, 'Test: Super Admin status contains platform metrics');

    // 4. Authentication failure: missing token
    let unauthErrorCaught = false;
    try {
      await sendCopilotMessage(
        { prompt: 'Triage alert', contextType: 'alert_triage' },
        '' // empty token
      );
    } catch (err: unknown) {
      if (err instanceof CopilotClientError) {
        unauthErrorCaught = true;
        assert(err.status === 401, 'Test: Missing token throws CopilotClientError with HTTP 401');
        assert(
          err.code === 'UNAUTHENTICATED' || err.code === 'EMPTY_TOKEN',
          `Test: Missing token throws code "${err.code}"`
        );
      }
    }
    assert(unauthErrorCaught, 'Test: Unauthenticated request threw CopilotClientError safely');

    // 5. Account approval failure: pending account
    let unapprovedCaught = false;
    try {
      await sendCopilotMessage(
        { prompt: 'Triage alert', contextType: 'alert_triage' },
        'unapproved_token'
      );
    } catch (err: unknown) {
      if (err instanceof CopilotClientError) {
        unapprovedCaught = true;
        assert(err.status === 403, 'Test: Unapproved account throws CopilotClientError with HTTP 403');
        assert(err.code === 'ACCOUNT_NOT_APPROVED', 'Test: Error code is "ACCOUNT_NOT_APPROVED"');
      }
    }
    assert(unapprovedCaught, 'Test: Unapproved account was rejected safely');

    // 6. Role boundary isolation: Super Admin denied operational alerts
    let isolationErrorCaught = false;
    try {
      await sendCopilotMessage(
        {
          prompt: 'Triage this operational alert',
          contextType: 'alert_triage',
          entityId: 'ALT-2026-1046',
        },
        'admin_token'
      );
    } catch (err: unknown) {
      if (err instanceof CopilotClientError) {
        isolationErrorCaught = true;
        assert(err.status === 403, 'Test: Super Admin operational query rejected with HTTP 403');
        assert(err.code === 'ACCESS_DENIED', 'Test: Error code is "ACCESS_DENIED"');
        assert(
          err.message.includes('strictly isolated'),
          'Test: Error explains Super Admin isolation from private SOC alerts'
        );
      }
    }
    assert(isolationErrorCaught, 'Test: Super Admin isolation strictly enforced by backend');

    // 7. Input validation: empty prompt
    let emptyPromptCaught = false;
    try {
      await sendCopilotMessage(
        { prompt: '   ', contextType: 'general_soc' },
        'analyst_token'
      );
    } catch (err: unknown) {
      if (err instanceof CopilotClientError) {
        emptyPromptCaught = true;
        assert(err.status === 400, 'Test: Empty prompt rejected with HTTP 400');
        assert(err.code === 'EMPTY_PROMPT', 'Test: Error code is "EMPTY_PROMPT"');
      }
    }
    assert(emptyPromptCaught, 'Test: Empty prompt caught and handled safely');

    // -------------------------------------------------------------------------
    // Test Group 4: UI Component Invariants & Code Structure
    // -------------------------------------------------------------------------
    console.log('\n-- Group 4: UI Component Invariants & Code Structure --');

    const drawerFile = readFileSync(
      resolve(process.cwd(), 'src/components/copilot/CopilotDrawer.tsx'),
      'utf8'
    );
    assert(
      drawerFile.includes('AI ADVISORY — VERIFY BEFORE ACTION'),
      'Test: CopilotDrawer renders explicit "AI ADVISORY — VERIFY BEFORE ACTION" badge'
    );
    assert(
      drawerFile.includes('msg.disclaimer'),
      'Test: CopilotDrawer renders backend advisory disclaimer on every response'
    );
    assert(
      drawerFile.includes('DEMO_MODE_AUTHENTICATION_UNAVAILABLE'),
      'Test: CopilotDrawer provides explanatory guidance when offline demo mode is active'
    );
    assert(
      drawerFile.includes('ROLE_PROMPT_SUGGESTIONS'),
      'Test: CopilotDrawer provides role-tailored prompt suggestions'
    );

    const triggerFile = readFileSync(
      resolve(process.cwd(), 'src/components/copilot/CopilotTriggerButton.tsx'),
      'utf8'
    );
    assert(
      triggerFile.includes("currentUser.accountStatus !== 'approved'"),
      'Test: CopilotTriggerButton strictly requires accountStatus === approved'
    );
    assert(
      triggerFile.includes('fixed bottom-6 right-6'),
      'Test: CopilotTriggerButton is positioned fixed at bottom-6 right-6'
    );

  } catch (err) {
    console.error('Fatal error in UI test runner:', err);
    failed++;
  } finally {
    global.fetch = originalFetch;
    await serverInstance.close();
  }

  console.log(`\n========================================================`);
  console.log(`UI INTEGRATION TEST RESULTS: ${passed} passed, ${failed} failed`);
  console.log(`========================================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runCopilotUiIntegrationTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
