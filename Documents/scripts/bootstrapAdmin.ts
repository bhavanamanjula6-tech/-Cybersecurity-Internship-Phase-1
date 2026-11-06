/**
 * CyberOps SOC — Standalone Super Admin Bootstrap CLI
 *
 * Dedicated administrative utility to execute the one-time database bootstrap RPC.
 * Invoked ONLY by authorized administrators through explicit manual execution.
 * NEVER executed automatically at startup.
 *
 * Usage:
 *   npx tsx scripts/bootstrapAdmin.ts --confirm-project=<expected-project-host-or-ref>
 *
 * Required Environment Variables (loaded from environment or .env):
 *   - SUPABASE_URL (or VITE_SUPABASE_URL): The Supabase project HTTPS endpoint
 *   - SUPABASE_SERVICE_ROLE_KEY: Confidential service_role secret key (never logged)
 *   - INITIAL_SUPER_ADMIN_EMAIL: The verified email address of the registered initial administrator
 */

import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

/**
 * Loads environment variables with predictable, explicit precedence:
 * 1. Process environment (process.env): actively exported shell variables take highest priority and are never overwritten.
 * 2. Ephemeral bootstrap file (.env.bootstrap): loaded first into unset keys, overriding baseline .env.
 * 3. Baseline environment file (.env): loaded second into any remaining unset keys as fallback defaults.
 */
export function loadBootstrapEnvironment(options?: {
  envPath?: string;
  bootstrapPath?: string;
}) {
  // 1. Ephemeral .env.bootstrap loaded first without override (process.env wins)
  dotenv.config({ path: options?.bootstrapPath || '.env.bootstrap' });
  // 2. Baseline .env loaded second without override (process.env and .env.bootstrap win)
  dotenv.config({ path: options?.envPath || '.env' });
}

// Initialize environment configuration upon module load
loadBootstrapEnvironment();

export interface BootstrapConfig {
  supabaseUrl: string;
  serviceRoleKey: string;
  adminEmail: string;
  confirmedProject?: string;
}

export interface BootstrapValidationResult {
  valid: boolean;
  error?: string;
  sanitizedConfig?: {
    supabaseHost: string;
    adminEmail: string;
  };
}

/**
 * Resolves the bootstrap configuration from overrides and environment with strict precedence.
 */
export function resolveBootstrapConfig(envOverrides?: Partial<BootstrapConfig>): BootstrapConfig {
  return {
    supabaseUrl: (envOverrides?.supabaseUrl || process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '').trim(),
    serviceRoleKey: (envOverrides?.serviceRoleKey || process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim(),
    adminEmail: (envOverrides?.adminEmail || process.env.INITIAL_SUPER_ADMIN_EMAIL || '').trim(),
    confirmedProject: (envOverrides?.confirmedProject || process.env.CONFIRM_SUPABASE_PROJECT || '').trim(),
  };
}

/**
 * Strips secret tokens and passwords from error messages.
 */
export function sanitizeErrorMessage(message: string, secretKey?: string): string {
  if (!message) return 'Unknown error occurred.';
  let sanitized = message;
  if (secretKey && secretKey.length > 8) {
    sanitized = sanitized.split(secretKey).join('[REDACTED_SECRET]');
  }
  // Redact standard JWTs and service keys
  sanitized = sanitized.replace(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[REDACTED_TOKEN]');
  return sanitized;
}

/**
 * Validates bootstrap configuration without leaking secrets.
 */
export function validateBootstrapConfig(config: Partial<BootstrapConfig>, cliProjectArg?: string): BootstrapValidationResult {
  const url = (config.supabaseUrl || '').trim();
  const key = (config.serviceRoleKey || '').trim();
  const email = (config.adminEmail || '').trim().toLowerCase();
  const confirmedProject = (cliProjectArg || config.confirmedProject || '').trim();

  // Detect explicit project confirmation conflict between CLI and environment
  if (cliProjectArg && config.confirmedProject) {
    const normCli = cliProjectArg.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    const normEnv = config.confirmedProject.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (normCli !== normEnv) {
      return {
        valid: false,
        error: `Conflicting project confirmation: CLI argument ("${cliProjectArg}") does not match environment CONFIRM_SUPABASE_PROJECT ("${config.confirmedProject}").`,
      };
    }
  }

  if (!url) {
    return { valid: false, error: 'Missing SUPABASE_URL (or VITE_SUPABASE_URL) in environment.' };
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      return { valid: false, error: 'Invalid SUPABASE_URL protocol. Must be https:// (or http:// for local emulator).' };
    }
  } catch {
    return { valid: false, error: 'Malformed SUPABASE_URL format.' };
  }

  if (!key) {
    return { valid: false, error: 'Missing SUPABASE_SERVICE_ROLE_KEY in environment. Required for service_role bootstrap.' };
  }

  if (key.length < 20) {
    return { valid: false, error: 'Invalid SUPABASE_SERVICE_ROLE_KEY length. Expected a valid service-role secret.' };
  }

  if (!email || !email.includes('@') || email.startsWith('@') || email.endsWith('@')) {
    return { valid: false, error: 'Missing or invalid INITIAL_SUPER_ADMIN_EMAIL in environment.' };
  }

  if (!confirmedProject) {
    return {
      valid: false,
      error: `Project confirmation required. You must pass --confirm-project=${parsedUrl.hostname} or set CONFIRM_SUPABASE_PROJECT to prevent accidental execution against the wrong database.`,
    };
  }

  // Verify that the confirmed project matches the URL hostname or project reference
  const expectedHost = parsedUrl.hostname.toLowerCase();
  const projectRef = expectedHost.split('.')[0];
  const normalizedConfirmed = confirmedProject.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];

  if (normalizedConfirmed !== expectedHost && normalizedConfirmed !== projectRef) {
    return {
      valid: false,
      error: `Project confirmation mismatch: Expected "${expectedHost}" or "${projectRef}", but received "${confirmedProject}".`,
    };
  }

  return {
    valid: true,
    sanitizedConfig: {
      supabaseHost: expectedHost,
      adminEmail: email,
    },
  };
}

/**
 * Executes the bootstrap RPC securely.
 */
export async function runBootstrap(envOverrides?: Partial<BootstrapConfig>, cliProjectArg?: string) {
  const config: BootstrapConfig = resolveBootstrapConfig(envOverrides);

  const validation = validateBootstrapConfig(config, cliProjectArg);
  if (!validation.valid || !validation.sanitizedConfig) {
    const sanitizedError = sanitizeErrorMessage(validation.error || 'Configuration validation error', config.serviceRoleKey);
    console.error(`[BOOTSTRAP FAILED] Configuration Validation Error: ${sanitizedError}`);
    return { success: false, error: sanitizedError };
  }

  const { supabaseHost, adminEmail } = validation.sanitizedConfig;
  console.log(`[BOOTSTRAP INITIATING] Target Host: ${supabaseHost}`);
  console.log(`[BOOTSTRAP INITIATING] Designated Super Admin: ${adminEmail}`);

  try {
    // Create dedicated, scoped administrative client using service_role key
    const client = createClient(config.supabaseUrl, config.serviceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    console.log('[BOOTSTRAP] Calling database procedure "public.bootstrap_initial_super_admin"...');

    // Invoke ONLY the narrowly scoped database bootstrap RPC
    const { data, error } = await client.rpc('bootstrap_initial_super_admin', {
      admin_email: adminEmail,
    });

    if (error) {
      const sanitizedDbError = sanitizeErrorMessage(error.message, config.serviceRoleKey);
      console.error(`[BOOTSTRAP FAILED] Database Error: ${sanitizedDbError}`);
      return { success: false, error: sanitizedDbError };
    }

    if (!data || data.success !== true) {
      const msg = sanitizeErrorMessage(data?.message || 'Database returned unexpected bootstrap payload.', config.serviceRoleKey);
      console.error(`[BOOTSTRAP FAILED] Invariant Error: ${msg}`);
      return { success: false, error: msg };
    }

    console.log('\n============================================================');
    console.log('[BOOTSTRAP SUCCESS] Platform Initialized Successfully!');
    console.log(`  - Administrator Email : ${data.admin_email}`);
    console.log(`  - Administrator ID    : ${data.admin_id}`);
    console.log(`  - Governance Audit ID : ${data.audit_id}`);
    console.log(`  - Audit Action Type   : ${data.action_type || 'platform_bootstrap'}`);
    console.log(`  - Timestamp           : ${data.bootstrapped_at}`);
    console.log('============================================================\n');
    console.log('The designated administrator may now sign in to the application and access /admin.');

    return { success: true, data };
  } catch (err: any) {
    // Mask sensitive details and report clean error
    const rawMsg = err instanceof Error ? err.message : 'Unknown execution failure';
    const sanitizedMsg = sanitizeErrorMessage(rawMsg, config.serviceRoleKey);
    console.error(`[BOOTSTRAP FAILED] Unexpected Execution Error: ${sanitizedMsg}`);
    return { success: false, error: sanitizedMsg };
  }
}

// Direct execution from CLI
const isDirectCli = process.argv[1] && process.argv[1].endsWith('bootstrapAdmin.ts');
if (isDirectCli) {
  // Parse command line arguments (e.g. --confirm-project=...)
  let projectArg: string | undefined;
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith('--confirm-project=')) {
      projectArg = arg.split('=')[1];
    }
  }

  runBootstrap(undefined, projectArg).then((res) => {
    if (!res.success) {
      process.exit(1);
    }
  });
}
