/**
 * CyberOps SOC — Central Repository Registry & Factory
 *
 * Provides a clean interface boundary between presentation layers and data storage.
 * In production: Instantiates Supabase-backed repositories (or fails closed if unconfigured).
 * In development: Uses Supabase when configured, or falls back to local browser adapters for offline prototyping.
 * Never silently substitutes mock data in production.
 */

import { IAlertRepository } from './IAlertRepository';
import { IAuditLogRepository } from './IAuditLogRepository';
import { IMITRERepository } from './IMITRERepository';
import { IDetectionRecommendationRepository } from './IDetectionRecommendationRepository';

import { LocalAlertRepository } from './local/LocalAlertRepository';
import { LocalAuditLogRepository } from './local/LocalAuditLogRepository';
import { LocalMITRERepository } from './local/LocalMITRERepository';
import { LocalDetectionRecommendationRepository } from './local/LocalDetectionRecommendationRepository';

import { SupabaseAlertRepository } from './supabase/SupabaseAlertRepository';
import { SupabaseAuditLogRepository } from './supabase/SupabaseAuditLogRepository';
import { SupabaseDetectionRecommendationRepository } from './supabase/SupabaseDetectionRecommendationRepository';

import {
  getSupabaseConfigurationStatus,
  isSupabaseConfigured,
  SupabaseRuntimeMode,
} from '../lib/supabaseClient';

export * from './IAlertRepository';
export * from './IAuditLogRepository';
export * from './IMITRERepository';
export * from './IDetectionRecommendationRepository';
export * from './local/LocalAlertRepository';
export * from './local/LocalAuditLogRepository';
export * from './local/LocalMITRERepository';
export * from './local/LocalDetectionRecommendationRepository';
export * from './supabase/SupabaseAlertRepository';
export * from './supabase/SupabaseAuditLogRepository';
export * from './supabase/SupabaseDetectionRecommendationRepository';

export interface RepositoryBundle {
  alertRepo: IAlertRepository;
  auditRepo: IAuditLogRepository;
  mitreRepo: IMITRERepository;
  recommendationRepo: IDetectionRecommendationRepository;
  isLive: boolean;
  mode: SupabaseRuntimeMode;
}

let activeBundle: RepositoryBundle | null = null;

/**
 * Returns the appropriate repository bundle based on environment and Supabase configuration.
 * - In production: Requires live Supabase configuration; throws an explicit Security Error if missing.
 * - In development: Uses live Supabase when configured, or allows local repository fallback for testing.
 */
export function getRepositories(forceRefresh = false): RepositoryBundle {
  if (activeBundle && !forceRefresh) {
    return activeBundle;
  }

  const status = getSupabaseConfigurationStatus();

  if (status.mode === 'live_supabase' && isSupabaseConfigured()) {
    activeBundle = {
      alertRepo: new SupabaseAlertRepository(),
      auditRepo: new SupabaseAuditLogRepository(),
      mitreRepo: new LocalMITRERepository(), // Authentic static MITRE ATT&CK taxonomy
      recommendationRepo: new SupabaseDetectionRecommendationRepository(),
      isLive: true,
      mode: 'live_supabase',
    };
    return activeBundle;
  }

  if (status.mode === 'production_fail_closed') {
    throw new Error(
      '[CyberOps SOC Security Error] Production build requires valid Supabase credentials (VITE_SUPABASE_URL and client key). Silent fallback to mock data is strictly forbidden.'
    );
  }

  // Development/demo fallback
  const auditRepo = new LocalAuditLogRepository();
  activeBundle = {
    alertRepo: new LocalAlertRepository(),
    auditRepo,
    mitreRepo: new LocalMITRERepository(),
    recommendationRepo: new LocalDetectionRecommendationRepository(auditRepo),
    isLive: false,
    mode: 'development_demo',
  };
  return activeBundle;
}
