/**
 * CyberOps SOC — Supabase Browser Client
 *
 * Provides a typed Supabase client configured strictly with public Vite environment variables.
 *
 * Security & Environment Safeguards:
 * 1. Reads ONLY public VITE_SUPABASE_URL and public client key variables
 *    (VITE_SUPABASE_ANON_KEY or VITE_SUPABASE_PUBLISHABLE_KEY).
 * 2. Deterministic precedence: VITE_SUPABASE_ANON_KEY takes precedence over
 *    VITE_SUPABASE_PUBLISHABLE_KEY if both are configured (preserving backward compatibility).
 * 3. Supports both modern Supabase publishable keys (sb_publishable_...) and legacy anon JWTs (eyJ...).
 * 4. Never accesses or imports server-side secrets (e.g. SUPABASE_SERVICE_ROLE_KEY).
 * 5. In production builds (import.meta.env.PROD), missing or placeholder configuration
 *    fails closed to prevent unauthorized fallback to unauthenticated demo personas.
 * 6. In development builds (import.meta.env.DEV), missing configuration safely indicates
 *    that development/demo mode may be utilized by local repositories.
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';

const rawEnv = typeof import.meta !== 'undefined' ? (import.meta.env as Record<string, string | boolean | undefined> | undefined) : undefined;
const nodeEnv = typeof process !== 'undefined' ? process.env : undefined;

const rawAnonKey = rawEnv?.VITE_SUPABASE_ANON_KEY as string | undefined;
const rawPublishableKey = rawEnv?.VITE_SUPABASE_PUBLISHABLE_KEY as string | undefined;

const nodeAnonKey = nodeEnv?.VITE_SUPABASE_ANON_KEY;
const nodePublishableKey = nodeEnv?.VITE_SUPABASE_PUBLISHABLE_KEY;

const effectiveAnonKey = rawAnonKey ?? nodeAnonKey;
const effectivePublishableKey = rawPublishableKey ?? nodePublishableKey;

const supabaseUrl = (rawEnv?.VITE_SUPABASE_URL as string | undefined) ?? nodeEnv?.VITE_SUPABASE_URL;

/**
 * Resolves the public Supabase key from provided environment variables using deterministic precedence:
 * 1. Explicit anonKey (or VITE_SUPABASE_ANON_KEY) takes precedence for backward compatibility.
 * 2. Explicit publishableKey (or VITE_SUPABASE_PUBLISHABLE_KEY) is used if anon key is absent/empty.
 */
export function resolveSupabaseKey(
  anonKey?: string,
  publishableKey?: string
): string | undefined {
  if (anonKey && anonKey.trim() !== '') {
    return anonKey.trim();
  }
  if (publishableKey && publishableKey.trim() !== '') {
    return publishableKey.trim();
  }
  return undefined;
}

const supabaseKey = resolveSupabaseKey(effectiveAnonKey, effectivePublishableKey);

const isDev = Boolean(rawEnv?.DEV ?? (nodeEnv?.NODE_ENV !== 'production'));
const isProd = Boolean(rawEnv?.PROD ?? (nodeEnv?.NODE_ENV === 'production'));

/**
 * Checks whether valid, non-placeholder Supabase configuration is present.
 * Accepts both legacy anon JWT keys and modern Supabase publishable keys (sb_publishable_...).
 */
export function isSupabaseConfigured(
  ...args: [string | undefined, string | undefined] | [string | undefined] | []
): boolean {
  const url = args.length > 0 ? args[0] : supabaseUrl;
  const key = args.length > 1 ? args[1] : supabaseKey;
  if (!url || !key) {
    return false;
  }

  const cleanUrl = url.trim();
  const cleanKey = key.trim();

  // Validate that default example placeholders were not left unedited
  if (
    cleanUrl.includes('your-project-id') ||
    cleanKey.includes('your-anon-public-key') ||
    cleanKey.includes('your-publishable-key') ||
    cleanUrl === '' ||
    cleanKey === ''
  ) {
    return false;
  }

  try {
    const parsed = new URL(cleanUrl);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export type SupabaseRuntimeMode = 'live_supabase' | 'development_demo' | 'production_fail_closed';

export interface SupabaseConfigStatus {
  configured: boolean;
  environment: 'development' | 'production';
  mode: SupabaseRuntimeMode;
  message: string;
}

export interface SupabaseEnvOverrides {
  url?: string;
  key?: string;
  anonKey?: string;
  publishableKey?: string;
  isProd?: boolean;
  isDev?: boolean;
}

/**
 * Evaluates the current configuration status and safe operating mode.
 */
export function getSupabaseConfigurationStatus(overrides?: SupabaseEnvOverrides): SupabaseConfigStatus {
  const targetUrl = overrides && 'url' in overrides ? overrides.url : supabaseUrl;

  let targetKey: string | undefined;
  if (overrides && 'key' in overrides) {
    targetKey = overrides.key;
  } else if (overrides && ('anonKey' in overrides || 'publishableKey' in overrides)) {
    targetKey = resolveSupabaseKey(overrides.anonKey, overrides.publishableKey);
  } else {
    targetKey = supabaseKey;
  }

  const targetIsProd = overrides && 'isProd' in overrides ? Boolean(overrides.isProd) : isProd;
  const targetIsDev = overrides && 'isDev' in overrides ? Boolean(overrides.isDev) : isDev;

  const configured = isSupabaseConfigured(targetUrl, targetKey);

  if (configured) {
    return {
      configured: true,
      environment: targetIsProd ? 'production' : 'development',
      mode: 'live_supabase',
      message: 'Supabase client is configured for live authentication and data persistence.',
    };
  }

  if (targetIsDev && !targetIsProd) {
    return {
      configured: false,
      environment: 'development',
      mode: 'development_demo',
      message: 'Supabase credentials not detected. Development/demo mode remains active for local testing.',
    };
  }

  return {
    configured: false,
    environment: 'production',
    mode: 'production_fail_closed',
    message: 'SECURITY ERROR: Supabase configuration is missing or invalid in production. Operational access is locked.',
  };
}

// ==============================================================================
// Scoped Storage Management for Remember Me Support
// ==============================================================================

export type StorageMode = 'local' | 'session';

export const STORAGE_MODE_KEY = 'cyberops_soc_auth_mode';
export const AUTH_STORAGE_KEY = 'ai_soc_auth_session_v1';

/**
 * Evaluates the current storage mode preference ('local' | 'session').
 * Defaults to 'local' for backward compatibility unless explicitly set to 'session'.
 */
export function getStorageMode(): StorageMode {
  if (typeof window === 'undefined') return 'local';
  try {
    const sessionVal = window.sessionStorage?.getItem(STORAGE_MODE_KEY);
    if (sessionVal === 'session') return 'session';
    if (sessionVal === 'local') return 'local';
    const localVal = window.localStorage?.getItem(STORAGE_MODE_KEY);
    if (localVal === 'session') return 'session';
    if (localVal === 'local') return 'local';
  } catch {
    // In restricted sandbox environments
  }
  return 'local';
}

/**
 * Sets the active storage mode.
 * Crucially, when switching to 'session' mode, this immediately purges any stale
 * persistent tokens from localStorage so previous sessions cannot inadvertently resurrect.
 */
export function setStorageMode(mode: StorageMode): void {
  if (typeof window === 'undefined') return;
  try {
    if (mode === 'session') {
      window.sessionStorage?.setItem(STORAGE_MODE_KEY, 'session');
      window.localStorage?.removeItem(STORAGE_MODE_KEY);

      // Actively purge any persistent Supabase auth tokens and demo personas from localStorage
      if (window.localStorage) {
        for (let i = window.localStorage.length - 1; i >= 0; i--) {
          const key = window.localStorage.key(i);
          if (key && (key.startsWith('sb-') || key.includes('supabase.auth.token') || key === AUTH_STORAGE_KEY)) {
            window.localStorage.removeItem(key);
          }
        }
      }
    } else {
      window.localStorage?.setItem(STORAGE_MODE_KEY, 'local');
      window.sessionStorage?.removeItem(STORAGE_MODE_KEY);
    }
  } catch {
    // Ignore storage restrictions
  }
}

/**
 * Safely migrates active authentication tokens between storage tiers when switching Remember Me
 * while a session is already active.
 * - When transitioning to 'session': copies tokens from localStorage into sessionStorage, then purges localStorage.
 * - When transitioning to 'local': copies tokens from sessionStorage into localStorage, then purges sessionStorage.
 * This guarantees the active Supabase in-memory session, reload restoration, and subsequent auto-refreshes
 * remain continuous and synchronized without leaving stale or conflicting persistent tokens.
 */
export function migrateStorageMode(targetMode: StorageMode): void {
  if (typeof window === 'undefined') return;
  try {
    const currentMode = getStorageMode();
    if (currentMode === targetMode) return;

    const fromStorage = currentMode === 'local' ? window.localStorage : window.sessionStorage;
    const toStorage = targetMode === 'local' ? window.localStorage : window.sessionStorage;

    if (fromStorage && toStorage) {
      const keysToMigrate: string[] = [];
      for (let i = 0; i < fromStorage.length; i++) {
        const key = fromStorage.key(i);
        if (key && (key.startsWith('sb-') || key.includes('supabase.auth.token') || key === AUTH_STORAGE_KEY)) {
          keysToMigrate.push(key);
        }
      }

      for (const key of keysToMigrate) {
        const val = fromStorage.getItem(key);
        if (val !== null) {
          toStorage.setItem(key, val);
        }
        fromStorage.removeItem(key);
      }
    }

    setStorageMode(targetMode);
  } catch {
    // Ignore storage restrictions
  }
}

/**
 * Clears all authentication storage across both sessionStorage and localStorage.
 */
export function clearAllAuthStorage(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage?.removeItem(STORAGE_MODE_KEY);
    window.localStorage?.removeItem(STORAGE_MODE_KEY);
    window.sessionStorage?.removeItem(AUTH_STORAGE_KEY);
    window.localStorage?.removeItem(AUTH_STORAGE_KEY);

    if (window.sessionStorage) {
      for (let i = window.sessionStorage.length - 1; i >= 0; i--) {
        const key = window.sessionStorage.key(i);
        if (key && (key.startsWith('sb-') || key.includes('supabase.auth.token'))) {
          window.sessionStorage.removeItem(key);
        }
      }
    }

    if (window.localStorage) {
      for (let i = window.localStorage.length - 1; i >= 0; i--) {
        const key = window.localStorage.key(i);
        if (key && (key.startsWith('sb-') || key.includes('supabase.auth.token'))) {
          window.localStorage.removeItem(key);
        }
      }
    }
  } catch {
    // Ignore storage restrictions
  }
}

/**
 * Scoped storage adapter conforming to Supabase's SupportedStorage contract.
 * - When in 'local' mode: Reads/writes from localStorage (persists across restarts).
 * - When in 'session' mode: Reads/writes from sessionStorage (scoped to the browser session lifecycle).
 *   Defensively purges any stale key from localStorage if encountered in session mode.
 * - When removing: Purges from both storages cleanly.
 */
export const scopedAuthStorageAdapter = {
  getItem: (key: string): string | null => {
    if (typeof window === 'undefined') return null;
    try {
      const mode = getStorageMode();
      if (mode === 'session') {
        const item = window.sessionStorage?.getItem(key) ?? null;
        // Defensively wipe residual localStorage item if present in session mode
        if (window.localStorage?.getItem(key) !== null) {
          window.localStorage?.removeItem(key);
        }
        return item;
      }
      return window.localStorage?.getItem(key) ?? null;
    } catch {
      return null;
    }
  },
  setItem: (key: string, value: string): void => {
    if (typeof window === 'undefined') return;
    try {
      const mode = getStorageMode();
      if (mode === 'session') {
        window.sessionStorage?.setItem(key, value);
        window.localStorage?.removeItem(key);
      } else {
        window.localStorage?.setItem(key, value);
        window.sessionStorage?.removeItem(key);
      }
    } catch {
      // Ignore storage restrictions
    }
  },
  removeItem: (key: string): void => {
    if (typeof window === 'undefined') return;
    try {
      window.sessionStorage?.removeItem(key);
      window.localStorage?.removeItem(key);
    } catch {
      // Ignore storage restrictions
    }
  },
};

// Client initialization
let clientInstance: SupabaseClient | null = null;

if (isSupabaseConfigured()) {
  clientInstance = createClient(supabaseUrl!, supabaseKey!, {
    auth: {
      storage: scopedAuthStorageAdapter,
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
    },
  });
} else if (isDev) {
  console.info(
    '[CyberOps SOC] Notice: Supabase configuration is unconfigured. Development/demo mode remains active.'
  );
} else if (isProd) {
  console.error(
    '[CyberOps SOC] CRITICAL: Missing required Supabase configuration in production. Failing closed.'
  );
}

/**
 * Accesses the initialized Supabase client.
 * In production without credentials, throws an explicit security error (fail-closed).
 */
export function getSupabaseClient(): SupabaseClient {
  if (clientInstance) {
    return clientInstance;
  }

  if (isProd) {
    throw new Error(
      '[CyberOps SOC Security Error] Production build requires valid VITE_SUPABASE_URL and public client key (VITE_SUPABASE_ANON_KEY or VITE_SUPABASE_PUBLISHABLE_KEY). Failing closed.'
    );
  }

  throw new Error(
    '[CyberOps SOC Notice] Supabase client requested but credentials are not configured. Development mode should use local repositories.'
  );
}

export const supabase = clientInstance;
