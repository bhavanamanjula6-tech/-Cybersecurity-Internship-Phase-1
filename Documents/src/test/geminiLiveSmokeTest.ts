/**
 * CyberOps SOC — Direct Gemini Client Smoke Test
 *
 * Safely verifies server-side connectivity to the Google Gemini API using
 * the configured GEMINI_API_KEY from process.env (or an injected test generator).
 *
 * STAGES REPORTED:
 * 1. Server-side key presence (process.env.GEMINI_API_KEY).
 * 2. GeminiCopilotService client configuration.
 * 3. Content generation (successful SDK response with non-empty text, expected model, disclaimer).
 *
 * EXIT CODES:
 * - 0: All 3 stages PASSED (full end-to-end generation success).
 * - 1: Stage 1/2 failure, unconfigured client, or unhandled generation error.
 * - 2: Stage 3 BLOCKED due to upstream HTTP 503 UNAVAILABLE (high demand).
 * - 3: Stage 3 FAIL due to timeout (GeminiTimeoutError).
 */

import {
  GeminiCopilotService,
  GeminiUnavailableError,
  GeminiTimeoutError,
  ModelGenerator,
} from '../server/ai/geminiClient';

export interface SmokeTestOutcome {
  stage1Passed: boolean;
  stage2Passed: boolean;
  stage3Passed: boolean;
  stage3Status: 'PASSED' | 'BLOCKED' | 'FAILED' | 'SKIPPED';
  exitCode: number;
  model?: string;
  gatewayAccepted?: boolean;
  errorMessage?: string;
}

export interface SmokeTestRunOptions {
  customGenerator?: ModelGenerator;
  mockKey?: string;
  exitProcess?: boolean;
  expectedModel?: string;
}

export async function runGeminiSmokeTest(
  options: SmokeTestRunOptions = {}
): Promise<SmokeTestOutcome> {
  const {
    customGenerator,
    mockKey,
    exitProcess = true,
    expectedModel = 'gemini-3.8-flash',
  } = options;

  console.log('=== RUNNING SERVER-SIDE GEMINI CONNECTIVITY SMOKE TEST ===');

  const rawKey = mockKey !== undefined ? mockKey : process.env.GEMINI_API_KEY;
  const isKeyPresent = Boolean(rawKey && rawKey.trim().length > 0);

  // STAGE 1: Key Presence
  console.log(
    `[STAGE 1 - KEY PRESENCE] ${isKeyPresent ? 'PASS: Server-side GEMINI_API_KEY detected.' : 'FAIL: GEMINI_API_KEY is missing or empty.'}`
  );

  if (!isKeyPresent && !customGenerator) {
    console.error('  [ABORT] Stage 1 failed. Cannot proceed with client initialization.');
    const outcome: SmokeTestOutcome = {
      stage1Passed: false,
      stage2Passed: false,
      stage3Passed: false,
      stage3Status: 'SKIPPED',
      exitCode: 1,
      errorMessage: 'GEMINI_API_KEY missing from environment',
    };
    if (exitProcess) process.exit(outcome.exitCode);
    return outcome;
  }

  // STAGE 2: Client Configuration
  const service = new GeminiCopilotService(
    {
      apiKey: rawKey,
      maxOutputTokens: 256,
      timeoutMs: 30000,
    },
    customGenerator
  );

  const isConfigured = service.isConfigured();
  console.log(
    `[STAGE 2 - CLIENT CONFIGURATION] ${isConfigured ? 'PASS: GeminiCopilotService initialized.' : 'FAIL: GeminiCopilotService reports unconfigured.'}`
  );

  if (!isConfigured) {
    console.error('  [ABORT] Stage 2 failed. Client is not properly configured.');
    const outcome: SmokeTestOutcome = {
      stage1Passed: isKeyPresent,
      stage2Passed: false,
      stage3Passed: false,
      stage3Status: 'SKIPPED',
      exitCode: 1,
      errorMessage: 'GeminiCopilotService failed to configure',
    };
    if (exitProcess) process.exit(outcome.exitCode);
    return outcome;
  }

  // STAGE 3: Content Generation
  console.log(`[STAGE 3 - CONTENT GENERATION] Dispatching probe to model (${expectedModel})...`);

  try {
    const startTime = Date.now();
    const result = await service.generateAdvisory(
      'You are a connectivity probe. Respond with the single word "PONG".',
      'Ping probe.'
    );
    const durationMs = Date.now() - startTime;

    const hasText = Boolean(result.text && result.text.trim().length > 0);
    const modelMatches = result.model === expectedModel;
    const hasDisclaimer = Boolean(result.disclaimer && result.disclaimer.length > 0);

    if (hasText && modelMatches && hasDisclaimer) {
      console.log(`  [PASS] Response received in ${durationMs}ms`);
      console.log(`  [PASS] Model verified: ${result.model}`);
      console.log(`  [PASS] Advisory disclaimer present: true`);
      console.log(`  [PASS] Response text non-empty: "${result.text.trim().slice(0, 50)}"`);
      console.log('[STAGE 3 - CONTENT GENERATION] PASS: Content generation completed successfully.');
      console.log('=== SMOKE TEST RESULT: ALL 3 STAGES PASSED (Exit Code: 0) ===');

      const outcome: SmokeTestOutcome = {
        stage1Passed: true,
        stage2Passed: true,
        stage3Passed: true,
        stage3Status: 'PASSED',
        exitCode: 0,
        model: result.model,
      };
      if (exitProcess) process.exit(0);
      return outcome;
    } else {
      console.error('  [FAIL] Content generation output failed validation criteria.');
      console.error(`    - Text non-empty: ${hasText}`);
      console.error(`    - Model match (${expectedModel}): ${modelMatches} (got "${result.model}")`);
      console.error(`    - Disclaimer present: ${hasDisclaimer}`);
      console.log('[STAGE 3 - CONTENT GENERATION] FAIL: Generation output incomplete or mismatched.');
      console.log('=== SMOKE TEST RESULT: FAILED AT STAGE 3 (Exit Code: 1) ===');

      const outcome: SmokeTestOutcome = {
        stage1Passed: true,
        stage2Passed: true,
        stage3Passed: false,
        stage3Status: 'FAILED',
        exitCode: 1,
        errorMessage: 'Generation output validation failed',
      };
      if (exitProcess) process.exit(1);
      return outcome;
    }
  } catch (err: unknown) {
    if (err instanceof GeminiTimeoutError) {
      console.error('  [FAIL] Request timed out after 30 seconds.');
      console.log('[STAGE 3 - CONTENT GENERATION] FAIL: Request timed out before model responded.');
      console.log('=== SMOKE TEST RESULT: FAILED AT STAGE 3 (Exit Code: 3) ===');

      const outcome: SmokeTestOutcome = {
        stage1Passed: true,
        stage2Passed: true,
        stage3Passed: false,
        stage3Status: 'FAILED',
        exitCode: 3,
        errorMessage: 'Request timed out after 30 seconds',
      };
      if (exitProcess) process.exit(3);
      return outcome;
    }

    const message = err instanceof Error ? err.message : String(err);

    // Sanitize any URL query strings or sensitive patterns from logs
    const sanitizedMessage = message
      .replace(/key=[A-Za-z0-9_-]+/g, 'key=[REDACTED]')
      .replace(/AIza[0-9A-Za-z-_]{35}/g, '[REDACTED_API_KEY]');

    if (
      sanitizedMessage.includes('503') ||
      sanitizedMessage.includes('high demand') ||
      sanitizedMessage.includes('UNAVAILABLE') ||
      (err instanceof GeminiUnavailableError && err.status === 503)
    ) {
      console.log('  [OBSERVATION] Upstream Google GenAI returned HTTP 503 UNAVAILABLE.');
      console.log('  [OBSERVATION] Gateway accepted authentication credentials, but model capacity is constrained.');
      console.log('[STAGE 3 - CONTENT GENERATION] BLOCKED: Upstream capacity constraint (HTTP 503).');
      console.log('=== SMOKE TEST RESULT: STAGE 3 BLOCKED / FAILED (Exit Code: 2) ===');

      const outcome: SmokeTestOutcome = {
        stage1Passed: true,
        stage2Passed: true,
        stage3Passed: false,
        stage3Status: 'BLOCKED',
        exitCode: 2,
        gatewayAccepted: true,
        errorMessage: sanitizedMessage,
      };
      if (exitProcess) process.exit(2);
      return outcome;
    }

    if (err instanceof GeminiUnavailableError) {
      console.error(`  [FAIL] Service unavailable error: ${err.message}`);
      console.log('[STAGE 3 - CONTENT GENERATION] FAIL: Service unavailable.');
      console.log('=== SMOKE TEST RESULT: FAILED AT STAGE 3 (Exit Code: 1) ===');

      const outcome: SmokeTestOutcome = {
        stage1Passed: true,
        stage2Passed: true,
        stage3Passed: false,
        stage3Status: 'FAILED',
        exitCode: 1,
        errorMessage: err.message,
      };
      if (exitProcess) process.exit(1);
      return outcome;
    }

    console.error(`  [FAIL] Model generation error: ${sanitizedMessage}`);
    console.log('[STAGE 3 - CONTENT GENERATION] FAIL: Unexpected generation failure.');
    console.log('=== SMOKE TEST RESULT: FAILED AT STAGE 3 (Exit Code: 1) ===');

    const outcome: SmokeTestOutcome = {
      stage1Passed: true,
      stage2Passed: true,
      stage3Passed: false,
      stage3Status: 'FAILED',
      exitCode: 1,
      errorMessage: sanitizedMessage,
    };
    if (exitProcess) process.exit(1);
    return outcome;
  }
}

// Only invoke automatically when run as the primary entry point script
const isDirectExecution =
  typeof process !== 'undefined' &&
  process.argv &&
  process.argv[1] &&
  (process.argv[1].endsWith('geminiLiveSmokeTest.ts') || process.argv[1].endsWith('geminiLiveSmokeTest.js'));

if (isDirectExecution && !process.env.GEMINI_SMOKE_OFFLINE_TEST) {
  runGeminiSmokeTest().catch((fatal) => {
    console.error('Fatal unhandled error:', fatal instanceof Error ? fatal.message : fatal);
    process.exit(1);
  });
}
