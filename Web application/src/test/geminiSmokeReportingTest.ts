/**
 * CyberOps SOC — Gemini Smoke Test Reporting & Exit Code Offline Test
 *
 * Verifies that the smoke test correctly differentiates:
 * 1. Stage 1: Key presence
 * 2. Stage 2: Client configuration
 * 3. Stage 3: Content generation
 *
 * Crucially tests that:
 * - Successful generation exits with 0.
 * - HTTP 503 UNAVAILABLE does NOT pass Stage 3, is reported as BLOCKED, and returns non-zero exit code 2.
 * - Timeouts return non-zero exit code 3.
 * - Missing keys return non-zero exit code 1.
 * - All tests run OFFLINE without making live Gemini API calls.
 */

import { runGeminiSmokeTest } from './geminiLiveSmokeTest';
import { GeminiTimeoutError } from '../server/ai/geminiClient';

interface TestAssertion {
  name: string;
  fn: () => Promise<void>;
}

const tests: TestAssertion[] = [
  {
    name: 'Scenario 1 [Offline Mock]: Full success passes all 3 stages with exit code 0',
    fn: async () => {
      const outcome = await runGeminiSmokeTest({
        exitProcess: false,
        mockKey: 'mock_server_key_present',
        customGenerator: async () => 'PONG probe response verified.',
      });

      if (!outcome.stage1Passed) throw new Error('Expected stage1Passed to be true');
      if (!outcome.stage2Passed) throw new Error('Expected stage2Passed to be true');
      if (!outcome.stage3Passed) throw new Error('Expected stage3Passed to be true');
      if (outcome.stage3Status !== 'PASSED') throw new Error(`Expected stage3Status 'PASSED', got ${outcome.stage3Status}`);
      if (outcome.exitCode !== 0) throw new Error(`Expected exitCode 0, got ${outcome.exitCode}`);
      if (outcome.model !== 'gemini-3.8-flash') throw new Error(`Expected model gemini-3.8-flash, got ${outcome.model}`);
    },
  },
  {
    name: 'Scenario 2 [Offline Mock]: HTTP 503 UNAVAILABLE blocks Stage 3 with non-zero exit code 2',
    fn: async () => {
      const outcome = await runGeminiSmokeTest({
        exitProcess: false,
        mockKey: 'mock_server_key_present',
        customGenerator: async () => {
          throw new Error('503 UNAVAILABLE: This model is currently experiencing high demand. Please try again later.');
        },
      });

      if (!outcome.stage1Passed) throw new Error('Expected stage1Passed to be true');
      if (!outcome.stage2Passed) throw new Error('Expected stage2Passed to be true');
      // Stage 3 MUST NOT be passed!
      if (outcome.stage3Passed !== false) throw new Error('Stage 3 must NOT pass when 503 is returned');
      if (outcome.stage3Status !== 'BLOCKED') throw new Error(`Expected stage3Status 'BLOCKED', got ${outcome.stage3Status}`);
      if (outcome.exitCode !== 2) throw new Error(`Expected non-zero exit code 2 for 503 high demand, got ${outcome.exitCode}`);
      if (!outcome.gatewayAccepted) throw new Error('Expected gatewayAccepted to be true based on error context');
    },
  },
  {
    name: 'Scenario 3 [Offline Mock]: Timeout fails Stage 3 with non-zero exit code 3',
    fn: async () => {
      const outcome = await runGeminiSmokeTest({
        exitProcess: false,
        mockKey: 'mock_server_key_present',
        customGenerator: async () => {
          throw new GeminiTimeoutError('Gemini model request timed out after 30 seconds.');
        },
      });

      if (!outcome.stage1Passed) throw new Error('Expected stage1Passed to be true');
      if (!outcome.stage2Passed) throw new Error('Expected stage2Passed to be true');
      if (outcome.stage3Passed !== false) throw new Error('Stage 3 must NOT pass on timeout');
      if (outcome.stage3Status !== 'FAILED') throw new Error(`Expected stage3Status 'FAILED', got ${outcome.stage3Status}`);
      if (outcome.exitCode !== 3) throw new Error(`Expected non-zero exit code 3 for timeout, got ${outcome.exitCode}`);
    },
  },
  {
    name: 'Scenario 4 [Offline Mock]: Empty response text fails Stage 3 with non-zero exit code 1',
    fn: async () => {
      const outcome = await runGeminiSmokeTest({
        exitProcess: false,
        mockKey: 'mock_server_key_present',
        customGenerator: async () => '   ', // Blank response
      });

      if (!outcome.stage1Passed) throw new Error('Expected stage1Passed to be true');
      if (!outcome.stage2Passed) throw new Error('Expected stage2Passed to be true');
      if (outcome.stage3Passed !== false) throw new Error('Stage 3 must NOT pass on blank response');
      if (outcome.stage3Status !== 'FAILED') throw new Error(`Expected stage3Status 'FAILED', got ${outcome.stage3Status}`);
      if (outcome.exitCode !== 1) throw new Error(`Expected non-zero exit code 1 for empty text, got ${outcome.exitCode}`);
    },
  },
  {
    name: 'Scenario 5 [Offline Mock]: Missing key aborts at Stage 1 with non-zero exit code 1',
    fn: async () => {
      const outcome = await runGeminiSmokeTest({
        exitProcess: false,
        mockKey: '',
      });

      if (outcome.stage1Passed !== false) throw new Error('Expected stage1Passed to be false');
      if (outcome.stage2Passed !== false) throw new Error('Expected stage2Passed to be false');
      if (outcome.stage3Passed !== false) throw new Error('Expected stage3Passed to be false');
      if (outcome.exitCode !== 1) throw new Error(`Expected non-zero exit code 1 for missing key, got ${outcome.exitCode}`);
    },
  },
];

async function runAllTests(): Promise<void> {
  console.log('=== STARTING OFFLINE GEMINI SMOKE TEST REPORTING SUITE ===');
  let passed = 0;
  let failed = 0;

  for (const t of tests) {
    try {
      console.log(`\n--- Running: ${t.name} ---`);
      await t.fn();
      console.log(`[PASS] ${t.name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${t.name}:`, err instanceof Error ? err.message : err);
      failed++;
    }
  }

  console.log(`\n=== OFFLINE TEST SUMMARY: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) {
    process.exit(1);
  }
}

process.env.GEMINI_SMOKE_OFFLINE_TEST = 'true';
runAllTests().catch((fatal) => {
  console.error('Fatal test error:', fatal);
  process.exit(1);
});
