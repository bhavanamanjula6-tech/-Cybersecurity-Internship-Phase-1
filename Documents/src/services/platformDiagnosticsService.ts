/**
 * Platform Diagnostics Service (Phase 1 — Read-Only Hardened)
 *
 * Provides safe, non-destructive diagnostic evaluations for Super Admin governance:
 * 1. Demo persona count derived strictly from the DEMO_PERSONAS source of truth.
 * 2. Build environment determination derived safely from Vite runtime configuration.
 * 3. Browser-storage availability probe using strictly non-destructive, non-sensitive read operations.
 *
 * SECURITY & HARDENING INVARIANTS:
 * - Read-only: Does NOT write, clear, mutate, or create dummy storage records.
 * - Does NOT access operational alert repositories, analyst notes, or remediation tasks.
 * - Does NOT read authentication session keys (e.g. ai_soc_auth_session_v1).
 * - Sanitizes all exception handling: never renders raw exception messages or internal browser traces.
 * - Safe property access: protects window.localStorage property resolution against sandbox exceptions.
 * - Exposes descriptive, logical provenance labels rather than internal filesystem paths.
 * - Local prototype diagnostics only; does NOT represent production infrastructure health.
 */

import { DEMO_PERSONAS, UserProfile, UserRole, ROLE_METADATA } from '../types/auth';

export type DiagnosticStatus = 'Pass' | 'Fail' | 'Not checked';

export interface DiagnosticItem {
  id: 'demo_personas' | 'build_environment' | 'browser_storage';
  name: string;
  label: string;
  status: DiagnosticStatus;
  value: string;
  detail: string;
  provenance: string;
}

export interface PlatformDiagnosticsReport {
  evaluatedAt: string;
  demoPersonas: DiagnosticItem;
  buildEnvironment: DiagnosticItem;
  browserStorage: DiagnosticItem;
  allChecks: DiagnosticItem[];
  overallStatus: DiagnosticStatus;
}

export class PlatformDiagnosticsService {
  /**
   * Diagnostic A: Demo Persona Count
   * Derives persona count directly from the DEMO_PERSONAS source of truth.
   * Explicitly labeled as Demo Personas, never as registered production users.
   */
  public static evaluateDemoPersonas(
    personasRecord: Record<UserRole, UserProfile> | Record<string, any> = DEMO_PERSONAS
  ): DiagnosticItem {
    if (!personasRecord || typeof personasRecord !== 'object') {
      return {
        id: 'demo_personas',
        name: 'Demo Persona Source of Truth',
        label: 'Demo Personas',
        status: 'Not checked',
        value: 'Not checked',
        detail: 'Demo persona registry could not be validated or is unavailable.',
        provenance: 'Demo Persona Registry',
      };
    }

    const personaKeys = Object.keys(personasRecord);
    const count = personaKeys.length;

    if (count === 0) {
      return {
        id: 'demo_personas',
        name: 'Demo Persona Source of Truth',
        label: 'Demo Personas',
        status: 'Fail',
        value: '0 Personas',
        detail: 'No demo personas found in Demo Persona Registry.',
        provenance: 'Demo Persona Registry',
      };
    }

    const roleBadges = personaKeys.map((key) => {
      const p = (personasRecord as Record<string, any>)[key];
      return p?.role && ROLE_METADATA[p.role as UserRole]
        ? ROLE_METADATA[p.role as UserRole].label
        : key;
    });

    return {
      id: 'demo_personas',
      name: 'Demo Persona Source of Truth',
      label: 'Demo Personas',
      status: 'Pass',
      value: `${count} Demo Personas`,
      detail: `Configured demo personas (${roleBadges.join(' • ')}). Sourced from static demonstration registry; does not count arbitrary sessions as registered users.`,
      provenance: 'Demo Persona Registry',
    };
  }

  /**
   * Diagnostic B: Build Environment
   * Inspects Vite build environment configuration safely.
   * Does not infer production infrastructure readiness from build mode.
   */
  public static evaluateBuildEnvironment(
    envRecord?: Record<string, any>
  ): DiagnosticItem {
    // Resolve runtime environment: use provided override or safely check import.meta.env
    const env = envRecord !== undefined
      ? envRecord
      : (typeof import.meta !== 'undefined' && import.meta.env ? import.meta.env : undefined);

    if (!env || typeof env !== 'object' || typeof env.MODE !== 'string' || !env.MODE.trim()) {
      return {
        id: 'build_environment',
        name: 'Build Environment Configuration',
        label: 'Build Environment',
        status: 'Not checked',
        value: 'Not checked',
        detail: 'Build environment could not be determined reliably from environment configuration.',
        provenance: 'Vite Build Configuration',
      };
    }

    const mode = env.MODE.trim();
    let displayValue: string;
    if (mode === 'development') {
      displayValue = 'Development';
    } else if (mode === 'production') {
      displayValue = 'Production Build';
    } else {
      displayValue = mode;
    }

    return {
      id: 'build_environment',
      name: 'Build Environment Configuration',
      label: 'Build Environment',
      status: 'Pass',
      value: displayValue,
      detail: `Determined from build mode ("${displayValue}"). This identifies the client bundle target and does not imply backend production readiness.`,
      provenance: 'Vite Build Configuration',
    };
  }

  /**
   * Diagnostic C: Browser-Storage Availability (Hardened)
   * Safely checks local storage availability without mutating records or reading authentication session keys.
   * - Traps window.localStorage property access errors (e.g. sandbox SecurityError or disabled storage).
   * - Sanitizes all failures to generic messages without leaking raw exception details or paths.
   */
  public static evaluateBrowserStorage(
    storageOverride?: Storage | null
  ): DiagnosticItem {
    let storage: Storage | null = null;
    let accessThrew = false;

    // 1. Safely resolve storage target with protected property access
    if (storageOverride !== undefined) {
      storage = storageOverride;
    } else {
      try {
        if (typeof window !== 'undefined') {
          storage = window.localStorage;
        }
      } catch (_err) {
        // Accessing window.localStorage property threw (e.g., SecurityError in sandboxed iframe or disabled cookies)
        accessThrew = true;
      }
    }

    if (accessThrew) {
      return {
        id: 'browser_storage',
        name: 'Browser Storage Availability',
        label: 'Browser Storage',
        status: 'Fail',
        value: 'Inaccessible',
        detail: 'Browser storage is inaccessible. Access may be restricted by browser policy.',
        provenance: 'Browser Storage',
      };
    }

    if (!storage) {
      return {
        id: 'browser_storage',
        name: 'Browser Storage Availability',
        label: 'Browser Storage',
        status: 'Not checked',
        value: 'Not checked',
        detail: 'Browser localStorage is not present in this execution context (e.g., non-browser or SSR runtime). Browser storage is local to the current browser and is not a production database.',
        provenance: 'Browser Storage',
      };
    }

    try {
      // STRICT NON-DESTRUCTIVE, NON-SENSITIVE READ PROBE:
      // Verify storage accessibility by reading the length property getter without reading sensitive session keys or writing data.
      const keyCount = storage.length;
      if (typeof keyCount !== 'number' || Number.isNaN(keyCount) || keyCount < 0) {
        throw new Error('Invalid storage length');
      }

      return {
        id: 'browser_storage',
        name: 'Browser Storage Availability',
        label: 'Browser Storage',
        status: 'Pass',
        value: 'Accessible',
        detail: `Browser localStorage is accessible (${keyCount} stored key${keyCount === 1 ? '' : 's'}). Storage is local to the current browser and is not a production database.`,
        provenance: 'Browser Storage',
      };
    } catch (_err: unknown) {
      // Sanitize: do not expose raw error messages, stack traces, or browser internals
      return {
        id: 'browser_storage',
        name: 'Browser Storage Availability',
        label: 'Browser Storage',
        status: 'Fail',
        value: 'Inaccessible',
        detail: 'Browser storage is inaccessible. Access may be restricted by browser policy.',
        provenance: 'Browser Storage',
      };
    }
  }

  /**
   * Runs the complete set of Phase 1 platform diagnostics.
   */
  public static runDiagnostics(options?: {
    personas?: Record<UserRole, UserProfile> | Record<string, any>;
    env?: Record<string, any>;
    storage?: Storage | null;
  }): PlatformDiagnosticsReport {
    const demoPersonas = this.evaluateDemoPersonas(options?.personas);
    const buildEnvironment = this.evaluateBuildEnvironment(options?.env);
    const browserStorage = this.evaluateBrowserStorage(options?.storage);

    const allChecks = [demoPersonas, buildEnvironment, browserStorage];

    let overallStatus: DiagnosticStatus = 'Pass';
    if (allChecks.some((c) => c.status === 'Fail')) {
      overallStatus = 'Fail';
    } else if (allChecks.some((c) => c.status === 'Not checked')) {
      overallStatus = 'Not checked';
    }

    return {
      evaluatedAt: new Date().toISOString(),
      demoPersonas,
      buildEnvironment,
      browserStorage,
      allChecks,
      overallStatus,
    };
  }
}
