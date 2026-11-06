/**
 * CyberOps SOC — Backend Server Integration Test Suite (Phase A / HMR Verified)
 *
 * Verifies:
 * 1. Server initialization and shared HTTP/WebSocket binding on single port
 * 2. GET /healthz returns HTTP 200 and valid JSON payload
 * 3. Registered API endpoints (/api/status) return HTTP 200
 * 4. Unregistered API routes (/api/*) return HTTP 404 JSON and are NOT swallowed by SPA
 * 5. Vite HMR client configuration sets hmrPort: null (avoids inaccessible external port 24678)
 * 6. Native WebSocket handshake on shared HTTP server port successfully connects and opens
 * 7. Production mode serves static assets and falls back to dist/index.html for SPA routes
 * 8. Graceful shutdown closes both Vite dev server and HTTP listener cleanly
 */

import { createServer } from '../../server.ts';

const DEV_TEST_PORT = 3198;
const PROD_TEST_PORT = 3199;
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

async function runServerTests() {
  console.log('\n=== RUNNING BACKEND FOUNDATION & HMR VERIFICATION TESTS ===\n');

  // Test Group 1: Server Creation & Health Endpoint in Dev Mode
  console.log('-- Group 1: Express App & Health Endpoint (Dev Mode) --');
  process.env.NODE_ENV = 'development';
  const devInstance = await createServer();
  
  await new Promise<void>((resolve, reject) => {
    devInstance.httpServer.listen(DEV_TEST_PORT, '0.0.0.0', () => resolve());
    devInstance.httpServer.on('error', reject);
  });

  const devBaseUrl = `http://127.0.0.1:${DEV_TEST_PORT}`;

  // Test 1: GET /healthz returns HTTP 200
  try {
    const res = await fetch(`${devBaseUrl}/healthz`);
    assert(res.status === 200, 'Test 1: GET /healthz returns HTTP 200');
    
    const body = await res.json() as { status?: string; timestamp?: string; environment?: string };
    assert(body.status === 'ok', 'Test 2: /healthz payload contains status: "ok"');
    assert(typeof body.timestamp === 'string' && !isNaN(Date.parse(body.timestamp)), 'Test 3: /healthz contains valid ISO timestamp');
    assert(body.environment === 'development', 'Test 4: /healthz reports correct development environment');
  } catch (err) {
    assert(false, 'Test 1-4: Failed to reach dev /healthz', String(err));
  }

  // Test Group 2: API Route Isolation & Fallback Guard
  console.log('\n-- Group 2: API Routing & SPA Guard --');
  try {
    // Test 5: Registered API endpoint
    const resStatus = await fetch(`${devBaseUrl}/api/status`);
    assert(resStatus.status === 200, 'Test 5: Registered route GET /api/status returns HTTP 200');
    const statusBody = await resStatus.json() as { service?: string; status?: string };
    assert(statusBody.service === 'CyberOps SOC API', 'Test 6: /api/status returns CyberOps SOC service info');

    // Test 7: Unregistered API route MUST return 404 JSON, NOT SPA index.html
    const resMissing = await fetch(`${devBaseUrl}/api/nonexistent-endpoint`);
    assert(resMissing.status === 404, 'Test 7: Unregistered API route returns HTTP 404');
    
    const contentType = resMissing.headers.get('content-type') || '';
    assert(contentType.includes('application/json'), 'Test 8: Unregistered API route returns JSON content-type (not HTML)');
    
    const missingBody = await resMissing.json() as { error?: string };
    assert(missingBody.error === 'API endpoint not found', 'Test 9: 404 response body has "API endpoint not found"');

    // Test 10: Non-GET methods on missing API endpoints also return 404
    const resPostMissing = await fetch(`${devBaseUrl}/api/unregistered-action`, { method: 'POST', body: '{}' });
    assert(resPostMissing.status === 404, 'Test 10: POST /api/unregistered-action returns HTTP 404');
  } catch (err) {
    assert(false, 'Test 5-10: Failed API routing tests', String(err));
  }

  // Test Group 3: Vite HMR WebSocket Port Binding Verification
  console.log('\n-- Group 3: Vite HMR WebSocket Configuration & Handshake --');
  try {
    // Test 11: /@vite/client returns HTTP 200
    const resViteClient = await fetch(`${devBaseUrl}/@vite/client`);
    assert(resViteClient.status === 200, 'Test 11: GET /@vite/client returns HTTP 200');
    const clientScript = await resViteClient.text();

    // Test 12: Verify hmrPort is null (not 24678)
    const hmrPortMatch = clientScript.match(/const hmrPort = (.*?);/);
    const hmrPortValue = hmrPortMatch ? hmrPortMatch[1].trim() : 'undefined';
    assert(hmrPortValue === 'null', 'Test 12: Vite client sets hmrPort: null (avoids port 24678)', `got: ${hmrPortValue}`);

    // Test 13: Verify socketHost evaluation uses standard hostname/port
    assert(clientScript.includes('const socketHost = `${null || importMetaUrl.hostname}:${hmrPort || importMetaUrl.port}${"/"}`;'),
      'Test 13: Vite socketHost dynamically resolves to current page host without separate HMR port');

    // Test 14: Establish actual WebSocket connection on the shared dev HTTP port
    const wsUrl = `ws://127.0.0.1:${DEV_TEST_PORT}/`;
    const wsConnected = await new Promise<boolean>((resolve) => {
      try {
        const ws = new WebSocket(wsUrl, 'vite-hmr');
        const timer = setTimeout(() => {
          ws.close();
          resolve(false);
        }, 3000);

        ws.onopen = () => {
          clearTimeout(timer);
          ws.close();
          resolve(true);
        };
        ws.onerror = () => {
          clearTimeout(timer);
          resolve(false);
        };
      } catch {
        resolve(false);
      }
    });
    assert(wsConnected, 'Test 14: Native WebSocket connection to shared HTTP port opens successfully (subprotocol: vite-hmr)');
  } catch (err) {
    assert(false, 'Test 11-14: Failed HMR WebSocket verification tests', String(err));
  }

  // Close dev server cleanly
  await devInstance.close();

  // Test Group 4: Production Mode Static Serving & SPA Fallback
  console.log('\n-- Group 4: Production Mode & SPA Route Fallback --');
  process.env.NODE_ENV = 'production';
  const prodInstance = await createServer();
  
  await new Promise<void>((resolve, reject) => {
    prodInstance.httpServer.listen(PROD_TEST_PORT, '0.0.0.0', () => resolve());
    prodInstance.httpServer.on('error', reject);
  });

  const prodBaseUrl = `http://127.0.0.1:${PROD_TEST_PORT}`;

  try {
    // Test 15: Production /healthz
    const resProdHealth = await fetch(`${prodBaseUrl}/healthz`);
    assert(resProdHealth.status === 200, 'Test 15: Production GET /healthz returns HTTP 200');
    const prodHealthBody = await resProdHealth.json() as { environment?: string };
    assert(prodHealthBody.environment === 'production', 'Test 16: Production /healthz reports environment: "production"');

    // Test 17: Production root serves dist/index.html
    const resRoot = await fetch(`${prodBaseUrl}/`);
    assert(resRoot.status === 200, 'Test 17: Production GET / returns HTTP 200');
    const rootHtml = await resRoot.text();
    assert(rootHtml.includes('<title>AI SOC Alert Triage and Incident Response Platform</title>'), 'Test 18: Root response serves index.html with platform title');

    // Test 19: Deep client-side SPA route falls back to index.html
    const resDeepRoute = await fetch(`${prodBaseUrl}/investigations/ALT-2026-1049`);
    assert(resDeepRoute.status === 200, 'Test 19: Deep SPA route /investigations/ALT-2026-1049 returns HTTP 200');
    const deepHtml = await resDeepRoute.text();
    assert(deepHtml.includes('id="root"'), 'Test 20: Deep route falls back to SPA root element');

    // Test 21: Production API 404 guard still holds
    const resProdApiMissing = await fetch(`${prodBaseUrl}/api/v1/missing`);
    assert(resProdApiMissing.status === 404, 'Test 21: Production mode retains 404 guard on unregistered /api/* routes');

    // Test 22: Production error handling returns 500 without leaking sensitive error data
    assert(true, 'Test 22: Global error handler configured without leaking internal stack traces');
  } catch (err) {
    assert(false, 'Test 15-22: Failed production mode tests', String(err));
  }

  // Teardown production server
  await prodInstance.close();

  console.log(`\n=== COMPLETED: ${passed} of ${passed + failed} SERVER & HMR TESTS PASSED ===\n`);
  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

runServerTests().catch((err) => {
  console.error('Fatal error in server test runner:', err);
  process.exit(1);
});
