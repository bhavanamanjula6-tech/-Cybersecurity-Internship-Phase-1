/**
 * CyberOps SOC — Knowledge Base Query & Aggregation Service
 *
 * Provides typed, read-only queries for role-specific knowledge tables:
 * - SOC Analyst: public.soc_analyst_knowledge (techniques, tactics, log sources)
 *
 * Security & Governance Invariants:
 * 1. Uses existing Supabase client with PostgreSQL Row-Level Security (RLS) as authoritative boundary.
 * 2. Defense-in-depth: Enforces client-side profile role validation before dispatching requests.
 * 3. Prohibits super_admin, security_engineer, and it_operations from reading soc_analyst_knowledge.
 * 4. Read-only: Never mutates, inserts, or updates knowledge tables.
 * 5. Deterministic, testable aggregations for multi-valued tactics and log source coverage.
 * 6. Never substitutes fabricated or dummy data on database failure.
 */

import { getSupabaseClient } from '../lib/supabaseClient';
import { UserProfile, AccessDeniedError } from '../types/auth';
import { normalizeAttackId, formatAttackIdDisplay, isValidAttackId } from '../utils/mitreUtils';

export { normalizeAttackId, formatAttackIdDisplay, isValidAttackId };

export interface SocAnalystKnowledgeRecord {
  techniques_id: string | null;
  techniques_name?: string | null;
  techniques_description?: string | null;
  techniques_tactics: string | null;
  techniques_platforms?: string | null;
  detection_strategy_attack_id?: string | null;
  detection_strategy_name?: string | null;
  analytic_id?: string | null;
  analytic_name?: string | null;
  log_source_name: string | null;
  data_components_id?: string | null;
  data_components_name?: string | null;
  attack_id?: string | null;
}

export interface TacticAggregation {
  tactic: string;
  count: number;
  percentage: number;
  uniqueTechniquesCount?: number;
}

export interface LogSourceAggregation {
  logSource: string;
  count: number;
  percentage: number;
  uniqueTechniquesCount?: number;
}

export interface KnowledgeCoverageSummary {
  totalRecords: number;
  totalUniqueTactics: number;
  totalUniqueLogSources: number;
  tactics: TacticAggregation[];
  logSources: LogSourceAggregation[];
}

/** Standard MITRE ATT&CK tactic title normalizer */
const KNOWN_TACTIC_CANONICAL_NAMES: Record<string, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource development': 'Resource Development',
  'initial access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege escalation': 'Privilege Escalation',
  'defense evasion': 'Defense Evasion',
  'credential access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral movement': 'Lateral Movement',
  'collection': 'Collection',
  'command and control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

export function normalizeTacticName(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return 'Unclassified Tactic';

  const lower = trimmed.toLowerCase();
  if (KNOWN_TACTIC_CANONICAL_NAMES[lower]) {
    return KNOWN_TACTIC_CANONICAL_NAMES[lower];
  }

  // Capitalize words for custom or extension tactics
  return trimmed
    .split(/\s+/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

export function normalizeLogSourceName(raw: string | null | undefined): string {
  if (!raw || typeof raw !== 'string') {
    return 'Unspecified / Custom Log Source';
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    return 'Unspecified / Custom Log Source';
  }
  return trimmed;
}

/**
 * Aggregates techniques by MITRE ATT&CK tactic.
 * - Counts distinct technique IDs per tactic (Set-based deduplication across multi-row mappings).
 * - Splits multi-valued tokens on comma, semicolon, or newline delimiters.
 * - Deduplicates per technique/record (no double-counting).
 * - Sorts by descending frequency with deterministic alphabetical tie-breaker.
 */
export function aggregateTechniquesByTactic(
  records: SocAnalystKnowledgeRecord[]
): TacticAggregation[] {
  if (!records || records.length === 0) {
    return [];
  }

  const techniqueTacticsMap = new Map<string, Set<string>>();
  let anonymousCounter = 0;

  for (const record of records) {
    const rawTechId = record.techniques_id;
    let techKey: string;
    if (rawTechId && typeof rawTechId === 'string' && rawTechId.trim()) {
      techKey = rawTechId.trim();
    } else {
      anonymousCounter++;
      techKey = `__unclassified_row_${anonymousCounter}`;
    }

    if (!techniqueTacticsMap.has(techKey)) {
      techniqueTacticsMap.set(techKey, new Set<string>());
    }
    const techTactics = techniqueTacticsMap.get(techKey)!;

    const rawTactics = record.techniques_tactics;
    if (!rawTactics || typeof rawTactics !== 'string' || !rawTactics.trim()) {
      techTactics.add('unclassified');
    } else {
      const tokens = rawTactics.split(/[,;|\n]+/);
      let validTokenCount = 0;
      for (const token of tokens) {
        const clean = token.trim();
        if (clean) {
          validTokenCount++;
          techTactics.add(clean.toLowerCase());
        }
      }
      if (validTokenCount === 0) {
        techTactics.add('unclassified');
      }
    }
  }

  const totalUniqueTechniques = techniqueTacticsMap.size;
  if (totalUniqueTechniques === 0) {
    return [];
  }

  const tacticToTechniquesMap = new Map<string, { display: string; techniques: Set<string> }>();

  for (const [techId, tactics] of techniqueTacticsMap.entries()) {
    for (const tacticKey of tactics) {
      if (!tacticToTechniquesMap.has(tacticKey)) {
        const display =
          tacticKey === 'unclassified' ? 'Unclassified Tactic' : normalizeTacticName(tacticKey);
        tacticToTechniquesMap.set(tacticKey, { display, techniques: new Set<string>() });
      }
      tacticToTechniquesMap.get(tacticKey)!.techniques.add(techId);
    }
  }

  const result: TacticAggregation[] = Array.from(tacticToTechniquesMap.values()).map((item) => ({
    tactic: item.display,
    count: item.techniques.size,
    percentage:
      totalUniqueTechniques > 0
        ? Math.round((item.techniques.size / totalUniqueTechniques) * 1000) / 10
        : 0,
    uniqueTechniquesCount: item.techniques.size,
  }));

  // Sort by count descending; tie-break alphabetically by tactic name
  result.sort((a, b) => {
    if (b.count !== a.count) {
      return b.count - a.count;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return result;
}

/**
 * Aggregates log sources by frequency and distinct technique mappings.
 * - Splits multi-valued tokens on comma, semicolon, or newline delimiters (preserves colons for components).
 * - Groups null, empty, or whitespace-only values under 'Unspecified / Custom Log Source'.
 * - Sorts by descending frequency with deterministic alphabetical tie-breaker.
 */
export function aggregateLogSources(
  records: SocAnalystKnowledgeRecord[]
): LogSourceAggregation[] {
  if (!records || records.length === 0) {
    return [];
  }

  const tally = new Map<string, { display: string; techniques: Set<string>; count: number }>();
  let anonymousCounter = 0;

  for (const record of records) {
    const rawTechId = record.techniques_id;
    let techKey: string;
    if (rawTechId && typeof rawTechId === 'string' && rawTechId.trim()) {
      techKey = rawTechId.trim();
    } else {
      anonymousCounter++;
      techKey = `__unclassified_row_${anonymousCounter}`;
    }

    const rawSource = record.log_source_name;
    const recordTokens = new Set<string>();

    if (!rawSource || typeof rawSource !== 'string' || !rawSource.trim()) {
      recordTokens.add('Unspecified / Custom Log Source');
    } else {
      // Split on commas, semicolons, pipes, and newlines; preserve colon in "Component: Subcomponent"
      const tokens = rawSource.split(/[,;|\n]+/);
      let validCount = 0;
      for (const token of tokens) {
        const clean = token.trim();
        if (clean) {
          validCount++;
          recordTokens.add(clean);
        }
      }
      if (validCount === 0) {
        recordTokens.add('Unspecified / Custom Log Source');
      }
    }

    for (const token of recordTokens) {
      const normalized = normalizeLogSourceName(token);
      const key = normalized.toLowerCase();

      if (!tally.has(key)) {
        tally.set(key, { display: normalized, techniques: new Set<string>(), count: 0 });
      }
      const entry = tally.get(key)!;
      entry.count += 1;
      entry.techniques.add(techKey);
    }
  }

  const totalRecords = records.length;

  const result: LogSourceAggregation[] = Array.from(tally.values()).map((item) => ({
    logSource: item.display,
    count: item.count,
    percentage: totalRecords > 0 ? Math.round((item.count / totalRecords) * 1000) / 10 : 0,
    uniqueTechniquesCount: item.techniques.size,
  }));

  // Sort by count descending; tie-break alphabetically by log source name
  result.sort((a, b) => {
    if (b.count !== a.count) {
      return b.count - a.count;
    }
    return a.logSource.localeCompare(b.logSource);
  });

  return result;
}

/**
 * Queries the real public.soc_analyst_knowledge table via Supabase client.
 * Enforces strict user role and approval gates before dispatching database requests.
 * Uses deterministic pagination with ordering on techniques_id to reliably retrieve all rows.
 */
export async function fetchSocAnalystKnowledge(
  user: UserProfile,
  pageSize = 500
): Promise<SocAnalystKnowledgeRecord[]> {
  // 1. Defense-in-depth authorization checks
  if (!user || user.accountStatus !== 'approved') {
    throw new AccessDeniedError(
      'Account must be approved by an administrator to query security knowledge.',
      'mitre:read',
      user?.role || 'soc_analyst'
    );
  }

  if (user.role !== 'soc_analyst') {
    throw new AccessDeniedError(
      `Role "${user.role}" is not authorized to query SOC Analyst reference knowledge.`,
      'mitre:read',
      user.role
    );
  }

  const client = getSupabaseClient();
  const allRecords: SocAnalystKnowledgeRecord[] = [];
  let from = 0;
  let hasMore = true;

  while (hasMore) {
    const to = from + pageSize - 1;
    const { data, error } = await client
      .from('soc_analyst_knowledge')
      .select(
        'techniques_id, techniques_name, techniques_description, techniques_tactics, techniques_platforms, detection_strategy_attack_id, detection_strategy_name, analytic_id, analytic_name, log_source_name, data_components_id, data_components_name'
      )
      .order('techniques_id', { ascending: true })
      .range(from, to);

    if (error) {
      throw new Error(`[KnowledgeService] Database query failed: ${error.message}`);
    }

    const page = data || [];
    for (const row of page) {
      const rawTechId = row.techniques_id !== undefined ? row.techniques_id : null;
      allRecords.push({
        techniques_id: rawTechId,
        techniques_name: row.techniques_name !== undefined ? row.techniques_name : null,
        techniques_description: row.techniques_description !== undefined ? row.techniques_description : null,
        techniques_tactics: row.techniques_tactics !== undefined ? row.techniques_tactics : null,
        techniques_platforms: row.techniques_platforms !== undefined ? row.techniques_platforms : null,
        detection_strategy_attack_id: row.detection_strategy_attack_id !== undefined ? row.detection_strategy_attack_id : null,
        detection_strategy_name: row.detection_strategy_name !== undefined ? row.detection_strategy_name : null,
        analytic_id: row.analytic_id !== undefined ? row.analytic_id : null,
        analytic_name: row.analytic_name !== undefined ? row.analytic_name : null,
        log_source_name: row.log_source_name !== undefined ? row.log_source_name : null,
        data_components_id: row.data_components_id !== undefined ? row.data_components_id : null,
        data_components_name: row.data_components_name !== undefined ? row.data_components_name : null,
        attack_id: normalizeAttackId(rawTechId),
      });
    }

    if (page.length < pageSize) {
      hasMore = false;
    } else {
      from += pageSize;
    }
  }

  return allRecords;
}

// ============================================================================
// Security Engineer Knowledge Base (public.security_engineer_knowledge)
// ============================================================================

export interface SecurityEngineerKnowledgeRecord {
  technique_id: string | null;
  technique_name?: string | null;
  technique_description?: string | null;
  technique_tactics?: string | null;
  technique_platforms?: string | null;
  tactic_ids?: string | null;
  tactic_names?: string | null;
  matched_platform_names?: string | null;
  addressed_source_id?: string | null;
  addressed_target_id?: string | null;
  mapping_type?: string | null;
  mitigation_id: string | null;
  mitigation_name?: string | null;
  mitigation_description?: string | null;
  attack_id?: string | null;
}

export interface EngineerTacticAggregation {
  tactic: string;
  uniqueTechniquesCount: number;
  percentage: number;
}

export interface EngineerPlatformAggregation {
  platform: string;
  uniqueTechniquesCount: number;
  percentage: number;
}

export interface EngineerMitigationAggregation {
  mitigationId: string;
  mitigationName: string;
  mitigationDescription?: string;
  addressedTechniquesCount: number;
  percentage: number;
}

export interface MitigationCoverageSummary {
  totalUniqueTechniques: number;
  mitigatedTechniquesCount: number;
  unmitigatedTechniquesCount: number;
  mitigatedPercentage: number;
  unmitigatedPercentage: number;
  uniqueMitigationsCount?: number;
  formattedCoverage?: string;
}

export interface TechniqueMitigationCountAggregation {
  techniqueId: string;
  techniqueName: string;
  distinctMitigationsCount: number;
  mitigationIds: string[];
}

export interface SecurityEngineerKpis {
  uniqueTechniques: number;
  uniqueMitigations: number;
  mitigatedTechniques: number;
  unmitigatedTechniques: number;
  mitigationCoveragePercent: number;
  mitigationCoverageDisplay: string;
  totalMappingRecords: number;
}

export interface SecurityEngineerKnowledgeSummary {
  totalRecords: number;
  totalUniqueTechniques: number;
  tacticDistribution: EngineerTacticAggregation[];
  platformDistribution: EngineerPlatformAggregation[];
  mitigationSummary: MitigationCoverageSummary;
  mitigationDistribution: EngineerMitigationAggregation[];
}

/**
 * Checks whether a field value is null, undefined, empty, whitespace-only,
 * or one of the recognized sentinel placeholder values (e.g. 'none', 'null', 'n/a', 'unknown', '-').
 */
export function isSentinelOrEmpty(val: string | null | undefined): boolean {
  if (val === null || val === undefined) return true;
  const trimmed = val.trim().toLowerCase();
  if (trimmed === '') return true;
  return ['none', 'null', 'n/a', 'na', 'unknown', '-', 'undefined'].includes(trimmed);
}

const KNOWN_PLATFORM_CANONICAL_NAMES: Record<string, string> = {
  'windows': 'Windows',
  'linux': 'Linux',
  'macos': 'macOS',
  'mac': 'macOS',
  'iaas': 'IaaS',
  'saas': 'SaaS',
  'paas': 'PaaS',
  'containers': 'Containers',
  'container': 'Containers',
  'kubernetes': 'Kubernetes',
  'network': 'Network',
  'office 365': 'Office 365',
  'office365': 'Office 365',
  'google workspace': 'Google Workspace',
  'azure ad': 'Azure AD',
  'active directory': 'Active Directory',
  'esxi': 'ESXi',
  'pre': 'PRE',
};

export function normalizePlatformName(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return 'Unspecified Platform';

  const lower = trimmed.toLowerCase();
  if (KNOWN_PLATFORM_CANONICAL_NAMES[lower]) {
    return KNOWN_PLATFORM_CANONICAL_NAMES[lower];
  }

  // Preserve exact standard capitalization for acronyms
  if (trimmed.toUpperCase() === 'PRE') return 'PRE';
  if (trimmed.toLowerCase() === 'esxi') return 'ESXi';

  return trimmed
    .split(/\s+/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

/**
 * Chart A: Techniques by Tactic
 * - Prefers tactic_names when populated, falls back to technique_tactics.
 * - Splits on comma, semicolon, newline delimiters.
 * - Unions tactic associations across multiple rows for the same technique_id.
 * - Counts each unique valid technique_id only once per tactic.
 * - Categorizes missing tactic information as "Unclassified Tactic".
 * - Sorts descending by unique-technique count, then alphabetically.
 */
export function aggregateTechniquesByTacticForEngineer(
  records: SecurityEngineerKnowledgeRecord[]
): { tactics: EngineerTacticAggregation[]; totalUniqueTechniques: number } {
  if (!records || records.length === 0) {
    return { tactics: [], totalUniqueTechniques: 0 };
  }

  const techniqueTacticsMap = new Map<string, Set<string>>();

  for (const record of records) {
    const rawTechId = record.technique_id;
    if (isSentinelOrEmpty(rawTechId)) {
      continue;
    }
    const techId = rawTechId!.trim();

    if (!techniqueTacticsMap.has(techId)) {
      techniqueTacticsMap.set(techId, new Set<string>());
    }
    const techTactics = techniqueTacticsMap.get(techId)!;

    const rawSource =
      record.tactic_names && record.tactic_names.trim()
        ? record.tactic_names
        : record.technique_tactics;

    if (rawSource && typeof rawSource === 'string' && rawSource.trim()) {
      const tokens = rawSource.split(/[,;|\n]+/);
      for (const token of tokens) {
        const clean = token.trim();
        if (clean && !isSentinelOrEmpty(clean)) {
          techTactics.add(clean);
        }
      }
    }
  }

  const totalUniqueTechniques = techniqueTacticsMap.size;
  if (totalUniqueTechniques === 0) {
    return { tactics: [], totalUniqueTechniques: 0 };
  }

  const tacticToTechniquesMap = new Map<string, Set<string>>();

  for (const [techId, tactics] of techniqueTacticsMap.entries()) {
    for (const tactic of tactics) {
      if (!tacticToTechniquesMap.has(tactic)) {
        tacticToTechniquesMap.set(tactic, new Set<string>());
      }
      tacticToTechniquesMap.get(tactic)!.add(techId);
    }
  }

  const result: EngineerTacticAggregation[] = Array.from(tacticToTechniquesMap.entries()).map(
    ([tactic, techSet]) => ({
      tactic,
      uniqueTechniquesCount: techSet.size,
      percentage: Math.round((techSet.size / totalUniqueTechniques) * 1000) / 10,
    })
  );

  result.sort((a, b) => {
    if (b.uniqueTechniquesCount !== a.uniqueTechniquesCount) {
      return b.uniqueTechniquesCount - a.uniqueTechniquesCount;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return { tactics: result, totalUniqueTechniques };
}

/**
 * Chart B: Technique Coverage by Platform
 * - Prefers matched_platform_names when populated, falls back to technique_platforms.
 * - Splits on comma, semicolon, newline delimiters.
 * - Unions platform associations across multiple rows for the same technique_id.
 * - Counts each unique valid technique_id only once per platform.
 * - Categorizes missing platform metadata as "Unspecified Platform".
 * - Sorts descending by unique-technique count, then alphabetically.
 */
export function aggregateTechniquesByPlatform(
  records: SecurityEngineerKnowledgeRecord[]
): { platforms: EngineerPlatformAggregation[]; totalUniqueTechniques: number } {
  if (!records || records.length === 0) {
    return { platforms: [], totalUniqueTechniques: 0 };
  }

  const techniquePlatformsMap = new Map<string, Set<string>>();

  for (const record of records) {
    const rawTechId = record.technique_id;
    if (isSentinelOrEmpty(rawTechId)) {
      continue;
    }
    const techId = rawTechId!.trim();

    if (!techniquePlatformsMap.has(techId)) {
      techniquePlatformsMap.set(techId, new Set<string>());
    }
    const techPlatforms = techniquePlatformsMap.get(techId)!;

    const rawSource =
      record.matched_platform_names && record.matched_platform_names.trim()
        ? record.matched_platform_names
        : record.technique_platforms;

    if (rawSource && typeof rawSource === 'string' && rawSource.trim()) {
      const tokens = rawSource.split(/[,;|\n]+/);
      for (const token of tokens) {
        const clean = token.trim();
        if (clean && !isSentinelOrEmpty(clean)) {
          techPlatforms.add(normalizePlatformName(clean));
        }
      }
    }
  }

  const totalUniqueTechniques = techniquePlatformsMap.size;
  if (totalUniqueTechniques === 0) {
    return { platforms: [], totalUniqueTechniques: 0 };
  }

  const platformToTechniquesMap = new Map<string, Set<string>>();

  for (const [techId, platforms] of techniquePlatformsMap.entries()) {
    if (platforms.size === 0) {
      const unspecified = 'Unspecified Platform';
      if (!platformToTechniquesMap.has(unspecified)) {
        platformToTechniquesMap.set(unspecified, new Set<string>());
      }
      platformToTechniquesMap.get(unspecified)!.add(techId);
    } else {
      for (const platform of platforms) {
        if (!platformToTechniquesMap.has(platform)) {
          platformToTechniquesMap.set(platform, new Set<string>());
        }
        platformToTechniquesMap.get(platform)!.add(techId);
      }
    }
  }

  const result: EngineerPlatformAggregation[] = Array.from(platformToTechniquesMap.entries()).map(
    ([platform, techSet]) => ({
      platform,
      uniqueTechniquesCount: techSet.size,
      percentage: Math.round((techSet.size / totalUniqueTechniques) * 1000) / 10,
    })
  );

  result.sort((a, b) => {
    if (b.uniqueTechniquesCount !== a.uniqueTechniquesCount) {
      return b.uniqueTechniquesCount - a.uniqueTechniquesCount;
    }
    return a.platform.localeCompare(b.platform);
  });

  return { platforms: result, totalUniqueTechniques };
}

/**
 * Chart C: Mitigation Mapping Coverage
 * - Calculates total unique valid techniques, techniques with >=1 mitigation, and techniques without any mitigation.
 * - Invariant: total unique techniques = mitigated techniques + unmitigated techniques.
 * - Ranks mitigations by distinct technique_ids addressed (deduplicating repeated technique-mitigation pairs).
 * - Sorts descending by addressed technique count, then alphabetically.
 */
export function aggregateMitigationCoverage(
  records: SecurityEngineerKnowledgeRecord[]
): {
  summary: MitigationCoverageSummary;
  mitigations: EngineerMitigationAggregation[];
} {
  if (!records || records.length === 0) {
    return {
      summary: {
        totalUniqueTechniques: 0,
        mitigatedTechniquesCount: 0,
        unmitigatedTechniquesCount: 0,
        mitigatedPercentage: 0,
        unmitigatedPercentage: 0,
        uniqueMitigationsCount: 0,
        formattedCoverage: '0.00%',
      },
      mitigations: [],
    };
  }

  const allUniqueTechniques = new Set<string>();
  const mitigatedTechniques = new Set<string>();
  const mitigationToTechniquesMap = new Map<
    string,
    { name: string; description?: string; techniques: Set<string> }
  >();

  for (const record of records) {
    const rawTechId = record.technique_id;
    if (isSentinelOrEmpty(rawTechId)) {
      continue;
    }
    const techId = rawTechId!.trim();
    allUniqueTechniques.add(techId);

    const rawMitigationId = record.mitigation_id;
    if (!isSentinelOrEmpty(rawMitigationId)) {
      const mitigationId = rawMitigationId!.trim();
      mitigatedTechniques.add(techId);

      let mitigationName = mitigationId;
      if (
        record.mitigation_name &&
        typeof record.mitigation_name === 'string' &&
        !isSentinelOrEmpty(record.mitigation_name)
      ) {
        mitigationName = record.mitigation_name.trim();
      }

      let mitigationDesc: string | undefined = undefined;
      if (
        record.mitigation_description &&
        typeof record.mitigation_description === 'string' &&
        !isSentinelOrEmpty(record.mitigation_description)
      ) {
        mitigationDesc = record.mitigation_description.trim();
      }

      if (!mitigationToTechniquesMap.has(mitigationId)) {
        mitigationToTechniquesMap.set(mitigationId, {
          name: mitigationName,
          description: mitigationDesc,
          techniques: new Set<string>(),
        });
      } else {
        const entry = mitigationToTechniquesMap.get(mitigationId)!;
        if (entry.name === mitigationId && mitigationName !== mitigationId) {
          entry.name = mitigationName;
        }
        if (!entry.description && mitigationDesc) {
          entry.description = mitigationDesc;
        }
      }

      mitigationToTechniquesMap.get(mitigationId)!.techniques.add(techId);
    }
  }

  const totalUniqueTechniques = allUniqueTechniques.size;
  const mitigatedTechniquesCount = mitigatedTechniques.size;
  const unmitigatedTechniquesCount = totalUniqueTechniques - mitigatedTechniquesCount;
  const uniqueMitigationsCount = mitigationToTechniquesMap.size;

  const mitigatedPercentage =
    totalUniqueTechniques > 0
      ? Math.round((mitigatedTechniquesCount / totalUniqueTechniques) * 10000) / 100
      : 0;
  const unmitigatedPercentage =
    totalUniqueTechniques > 0
      ? Math.round((unmitigatedTechniquesCount / totalUniqueTechniques) * 10000) / 100
      : 0;

  const formattedCoverage = `${mitigatedPercentage.toFixed(2)}%`;

  const mitigations: EngineerMitigationAggregation[] = Array.from(
    mitigationToTechniquesMap.entries()
  ).map(([mitigationId, data]) => ({
    mitigationId,
    mitigationName: data.name,
    mitigationDescription: data.description,
    addressedTechniquesCount: data.techniques.size,
    percentage:
      totalUniqueTechniques > 0
        ? Math.round((data.techniques.size / totalUniqueTechniques) * 10000) / 100
        : 0,
  }));

  mitigations.sort((a, b) => {
    if (b.addressedTechniquesCount !== a.addressedTechniquesCount) {
      return b.addressedTechniquesCount - a.addressedTechniquesCount;
    }
    return a.mitigationName.localeCompare(b.mitigationName);
  });

  return {
    summary: {
      totalUniqueTechniques,
      mitigatedTechniquesCount,
      unmitigatedTechniquesCount,
      mitigatedPercentage,
      unmitigatedPercentage,
      uniqueMitigationsCount,
      formattedCoverage,
    },
    mitigations,
  };
}

/**
 * Chart 2: Top Techniques by Mitigation Count
 * - Groups distinct valid mitigations per technique.
 * - Counts distinct valid mitigation IDs for each technique.
 * - Deterministic tie-breaking by technique ID ascending.
 */
export function aggregateTechniquesByMitigationCount(
  records: SecurityEngineerKnowledgeRecord[]
): TechniqueMitigationCountAggregation[] {
  if (!records || records.length === 0) {
    return [];
  }

  const map = new Map<string, { name: string; mitigations: Set<string> }>();

  for (const record of records) {
    const rawTechId = record.technique_id;
    if (isSentinelOrEmpty(rawTechId)) {
      continue;
    }
    const techId = rawTechId!.trim();

    let techName = techId;
    if (
      record.technique_name &&
      typeof record.technique_name === 'string' &&
      !isSentinelOrEmpty(record.technique_name)
    ) {
      techName = record.technique_name.trim();
    }

    if (!map.has(techId)) {
      map.set(techId, { name: techName, mitigations: new Set<string>() });
    } else {
      const entry = map.get(techId)!;
      if (entry.name === techId && techName !== techId) {
        entry.name = techName;
      }
    }

    const rawMitId = record.mitigation_id;
    if (!isSentinelOrEmpty(rawMitId)) {
      map.get(techId)!.mitigations.add(rawMitId!.trim());
    }
  }

  const list: TechniqueMitigationCountAggregation[] = Array.from(map.entries())
    .map(([techniqueId, data]) => ({
      techniqueId,
      techniqueName: data.name,
      distinctMitigationsCount: data.mitigations.size,
      mitigationIds: Array.from(data.mitigations),
    }))
    .filter((t) => t.distinctMitigationsCount > 0);

  // Sort descending by distinctMitigationsCount, with deterministic tie-breaking by techniqueId ascending
  list.sort((a, b) => {
    if (b.distinctMitigationsCount !== a.distinctMitigationsCount) {
      return b.distinctMitigationsCount - a.distinctMitigationsCount;
    }
    return a.techniqueId.localeCompare(b.techniqueId);
  });

  return list;
}

/**
 * Calculates the exact 4 primary KPIs for Security Engineer Overview:
 * 1. Unique Techniques (distinct valid non-empty, non-sentinel technique_id)
 * 2. Unique Mitigations (distinct valid non-sentinel mitigation_id)
 * 3. Mitigation Mapping Coverage (mitigated techniques / unique techniques * 100, formatted to 2 decimals)
 * 4. Total Mapping Records (total rows in dataset)
 */
export function calculateSecurityEngineerKpis(
  records: SecurityEngineerKnowledgeRecord[]
): SecurityEngineerKpis {
  if (!records || records.length === 0) {
    return {
      uniqueTechniques: 0,
      uniqueMitigations: 0,
      mitigatedTechniques: 0,
      unmitigatedTechniques: 0,
      mitigationCoveragePercent: 0,
      mitigationCoverageDisplay: '0.00%',
      totalMappingRecords: 0,
    };
  }

  const uniqueTechs = new Set<string>();
  const mitigatedTechs = new Set<string>();
  const uniqueMits = new Set<string>();

  for (const r of records) {
    if (isSentinelOrEmpty(r.technique_id)) continue;
    const techId = r.technique_id!.trim();
    uniqueTechs.add(techId);

    if (!isSentinelOrEmpty(r.mitigation_id)) {
      uniqueMits.add(r.mitigation_id!.trim());
      mitigatedTechs.add(techId);
    }
  }

  const totalUniqueTechniques = uniqueTechs.size;
  const mitigatedTechniques = mitigatedTechs.size;
  const unmitigatedTechniques = totalUniqueTechniques - mitigatedTechniques;
  const uniqueMitigations = uniqueMits.size;

  const coverageNum =
    totalUniqueTechniques > 0
      ? Math.round((mitigatedTechniques / totalUniqueTechniques) * 10000) / 100
      : 0;
  const coverageDisplay = `${coverageNum.toFixed(2)}%`;

  return {
    uniqueTechniques: totalUniqueTechniques,
    uniqueMitigations,
    mitigatedTechniques,
    unmitigatedTechniques,
    mitigationCoveragePercent: coverageNum,
    mitigationCoverageDisplay: coverageDisplay,
    totalMappingRecords: records.length,
  };
}

/**
 * Queries the real public.security_engineer_knowledge table via Supabase client.
 * Enforces strict user role and approval gates before dispatching database requests.
 * Uses pagination with range offsets to reliably retrieve all rows.
 */
export async function fetchSecurityEngineerKnowledge(
  user: UserProfile,
  pageSize = 500
): Promise<SecurityEngineerKnowledgeRecord[]> {
  if (!user || user.accountStatus !== 'approved') {
    throw new AccessDeniedError(
      'Account must be approved by an administrator to query security knowledge.',
      'mitre:read',
      user?.role || 'security_engineer'
    );
  }

  if (user.role !== 'security_engineer') {
    throw new AccessDeniedError(
      `Role "${user.role}" is not authorized to query Security Engineer reference knowledge.`,
      'mitre:read',
      user.role
    );
  }

  const client = getSupabaseClient();
  const allRecords: SecurityEngineerKnowledgeRecord[] = [];
  let from = 0;
  let hasMore = true;

  while (hasMore) {
    const to = from + pageSize - 1;
    const { data, error } = await client
      .from('security_engineer_knowledge')
      .select(
        'technique_id, technique_name, technique_description, technique_tactics, technique_platforms, tactic_ids, tactic_names, matched_platform_names, addressed_source_id, addressed_target_id, mapping_type, mitigation_id, mitigation_name, mitigation_description'
      )
      .order('technique_id', { ascending: true })
      .order('mitigation_id', { ascending: true, nullsFirst: false })
      .range(from, to);

    if (error) {
      throw new Error(`[KnowledgeService] Security Engineer database query failed: ${error.message}`);
    }

    const page = data || [];
    for (const row of page) {
      const rawTechId = row.technique_id !== undefined ? row.technique_id : null;
      allRecords.push({
        technique_id: rawTechId,
        technique_name: row.technique_name !== undefined ? row.technique_name : null,
        technique_description: row.technique_description !== undefined ? row.technique_description : null,
        technique_tactics: row.technique_tactics !== undefined ? row.technique_tactics : null,
        technique_platforms: row.technique_platforms !== undefined ? row.technique_platforms : null,
        tactic_ids: row.tactic_ids !== undefined ? row.tactic_ids : null,
        tactic_names: row.tactic_names !== undefined ? row.tactic_names : null,
        matched_platform_names: row.matched_platform_names !== undefined ? row.matched_platform_names : null,
        addressed_source_id: row.addressed_source_id !== undefined ? row.addressed_source_id : null,
        addressed_target_id: row.addressed_target_id !== undefined ? row.addressed_target_id : null,
        mapping_type: row.mapping_type !== undefined ? row.mapping_type : null,
        mitigation_id: row.mitigation_id !== undefined ? row.mitigation_id : null,
        mitigation_name: row.mitigation_name !== undefined ? row.mitigation_name : null,
        mitigation_description: row.mitigation_description !== undefined ? row.mitigation_description : null,
        attack_id: normalizeAttackId(rawTechId),
      });
    }

    if (page.length < pageSize) {
      hasMore = false;
    } else {
      from += pageSize;
    }
  }

  return allRecords;
}

// ============================================================================
// IT Operations Knowledge Base (public.it_operations_knowledge)
// ============================================================================

export interface ItOperationsKnowledgeRecord {
  technique_id: string | null;
  technique_name?: string | null;
  technique_tactics: string | null;
  technique_platforms: string | null;
  mitigation_id?: string | null;
  mitigation_name?: string | null;
  mitigation_description?: string | null;
  source_id?: string | null;
  target_id?: string | null;
  mapping_type?: string | null;
  platform_name: string | null;
  tactic_id?: string | null;
  tactic_name: string | null;
  attack_id?: string | null;
}

export interface ItOpsTacticAggregation {
  tactic: string;
  uniqueTechniquesCount: number;
  percentage: number;
}

export interface ItOpsPlatformAggregation {
  platform: string;
  uniqueTechniquesCount: number;
  percentage: number;
}

export interface ItOperationsKnowledgeSummary {
  totalRecords: number;
  totalUniqueTechniques: number;
  tactics: ItOpsTacticAggregation[];
  platforms: ItOpsPlatformAggregation[];
}

/**
 * Chart A: Techniques by Tactic for IT Operations
 * - Prefers tactic_name when populated and non-empty; falls back to technique_tactics.
 * - Splits comma, semicolon, newline delimiters and trims whitespace.
 * - Normalizes tactic titles using normalizeTacticName.
 * - Merges distinct tactic associations across multiple rows for the same technique_id.
 * - Counts each unique valid technique_id only once per tactic across the entire dataset.
 * - Categorizes missing tactic information as "Unclassified Tactic".
 * - Sorts descending by unique-technique count, then alphabetically.
 */
export function aggregateTechniquesByTacticForItOps(
  records: ItOperationsKnowledgeRecord[]
): { tactics: ItOpsTacticAggregation[]; totalUniqueTechniques: number } {
  if (!records || records.length === 0) {
    return { tactics: [], totalUniqueTechniques: 0 };
  }

  const techniqueTacticsMap = new Map<string, Set<string>>();

  for (const record of records) {
    const rawTechId = record.technique_id;
    if (!rawTechId || typeof rawTechId !== 'string' || !rawTechId.trim()) {
      continue;
    }
    const techId = rawTechId.trim();

    if (!techniqueTacticsMap.has(techId)) {
      techniqueTacticsMap.set(techId, new Set<string>());
    }
    const techTactics = techniqueTacticsMap.get(techId)!;

    const rawSource =
      record.tactic_name && typeof record.tactic_name === 'string' && record.tactic_name.trim()
        ? record.tactic_name
        : record.technique_tactics;

    if (rawSource && typeof rawSource === 'string' && rawSource.trim()) {
      const tokens = rawSource.split(/[,;|\n]+/);
      for (const token of tokens) {
        const clean = token.trim();
        if (clean) {
          techTactics.add(normalizeTacticName(clean));
        }
      }
    }
  }

  const totalUniqueTechniques = techniqueTacticsMap.size;
  if (totalUniqueTechniques === 0) {
    return { tactics: [], totalUniqueTechniques: 0 };
  }

  const tacticToTechniquesMap = new Map<string, Set<string>>();

  for (const [techId, tactics] of techniqueTacticsMap.entries()) {
    if (tactics.size === 0) {
      const unclassified = 'Unclassified Tactic';
      if (!tacticToTechniquesMap.has(unclassified)) {
        tacticToTechniquesMap.set(unclassified, new Set<string>());
      }
      tacticToTechniquesMap.get(unclassified)!.add(techId);
    } else {
      for (const tactic of tactics) {
        if (!tacticToTechniquesMap.has(tactic)) {
          tacticToTechniquesMap.set(tactic, new Set<string>());
        }
        tacticToTechniquesMap.get(tactic)!.add(techId);
      }
    }
  }

  const result: ItOpsTacticAggregation[] = Array.from(tacticToTechniquesMap.entries()).map(
    ([tactic, techSet]) => ({
      tactic,
      uniqueTechniquesCount: techSet.size,
      percentage: Math.round((techSet.size / totalUniqueTechniques) * 1000) / 10,
    })
  );

  result.sort((a, b) => {
    if (b.uniqueTechniquesCount !== a.uniqueTechniquesCount) {
      return b.uniqueTechniquesCount - a.uniqueTechniquesCount;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return { tactics: result, totalUniqueTechniques };
}

/**
 * Chart B: Technique Coverage by Platform for IT Operations
 * - Prefers platform_name when populated and non-empty; falls back to technique_platforms.
 * - Splits comma, semicolon, newline delimiters and trims whitespace.
 * - Normalizes platform names using normalizePlatformName.
 * - Merges distinct platform associations across multiple rows for the same technique_id.
 * - Counts each unique valid technique_id only once per platform across the entire dataset.
 * - Categorizes missing platform metadata as "Unspecified Platform".
 * - Sorts descending by unique-technique count, then alphabetically.
 */
export function aggregateTechniquesByPlatformForItOps(
  records: ItOperationsKnowledgeRecord[]
): { platforms: ItOpsPlatformAggregation[]; totalUniqueTechniques: number } {
  if (!records || records.length === 0) {
    return { platforms: [], totalUniqueTechniques: 0 };
  }

  const techniquePlatformsMap = new Map<string, Set<string>>();

  for (const record of records) {
    const rawTechId = record.technique_id;
    if (!rawTechId || typeof rawTechId !== 'string' || !rawTechId.trim()) {
      continue;
    }
    const techId = rawTechId.trim();

    if (!techniquePlatformsMap.has(techId)) {
      techniquePlatformsMap.set(techId, new Set<string>());
    }
    const techPlatforms = techniquePlatformsMap.get(techId)!;

    const rawSource =
      record.platform_name && typeof record.platform_name === 'string' && record.platform_name.trim()
        ? record.platform_name
        : record.technique_platforms;

    if (rawSource && typeof rawSource === 'string' && rawSource.trim()) {
      const tokens = rawSource.split(/[,;|\n]+/);
      for (const token of tokens) {
        const clean = token.trim();
        if (clean) {
          techPlatforms.add(normalizePlatformName(clean));
        }
      }
    }
  }

  const totalUniqueTechniques = techniquePlatformsMap.size;
  if (totalUniqueTechniques === 0) {
    return { platforms: [], totalUniqueTechniques: 0 };
  }

  const platformToTechniquesMap = new Map<string, Set<string>>();

  for (const [techId, platforms] of techniquePlatformsMap.entries()) {
    if (platforms.size === 0) {
      const unspecified = 'Unspecified Platform';
      if (!platformToTechniquesMap.has(unspecified)) {
        platformToTechniquesMap.set(unspecified, new Set<string>());
      }
      platformToTechniquesMap.get(unspecified)!.add(techId);
    } else {
      for (const platform of platforms) {
        if (!platformToTechniquesMap.has(platform)) {
          platformToTechniquesMap.set(platform, new Set<string>());
        }
        platformToTechniquesMap.get(platform)!.add(techId);
      }
    }
  }

  const result: ItOpsPlatformAggregation[] = Array.from(platformToTechniquesMap.entries()).map(
    ([platform, techSet]) => ({
      platform,
      uniqueTechniquesCount: techSet.size,
      percentage: Math.round((techSet.size / totalUniqueTechniques) * 1000) / 10,
    })
  );

  result.sort((a, b) => {
    if (b.uniqueTechniquesCount !== a.uniqueTechniquesCount) {
      return b.uniqueTechniquesCount - a.uniqueTechniquesCount;
    }
    return a.platform.localeCompare(b.platform);
  });

  return { platforms: result, totalUniqueTechniques };
}

/**
 * Queries the real public.it_operations_knowledge table via Supabase client.
 * Enforces strict user role and approval gates before dispatching database requests.
 * Uses pagination with range offsets to reliably retrieve all 1,448+ rows.
 */
export async function fetchItOperationsKnowledge(
  user: UserProfile,
  pageSize = 500
): Promise<ItOperationsKnowledgeRecord[]> {
  if (!user || user.accountStatus !== 'approved') {
    throw new AccessDeniedError(
      'Account must be approved by an administrator to query security knowledge.',
      'mitre:read',
      user?.role || 'it_operations'
    );
  }

  if (user.role !== 'it_operations') {
    throw new AccessDeniedError(
      `Role "${user.role}" is not authorized to query IT Operations reference knowledge.`,
      'mitre:read',
      user.role
    );
  }

  const client = getSupabaseClient();
  const allRecords: ItOperationsKnowledgeRecord[] = [];
  let from = 0;
  let hasMore = true;

  while (hasMore) {
    const to = from + pageSize - 1;
    const { data, error } = await client
      .from('it_operations_knowledge')
      .select(
        'technique_id, technique_name, technique_tactics, technique_platforms, mitigation_id, mitigation_name, mitigation_description, source_id, target_id, mapping_type, platform_name, tactic_id, tactic_name'
      )
      .order('technique_id', { ascending: true })
      .range(from, to);

    if (error) {
      throw new Error(`[KnowledgeService] IT Operations database query failed: ${error.message}`);
    }

    const page = data || [];
    for (const row of page) {
      const rawTechId = row.technique_id !== undefined ? row.technique_id : null;
      allRecords.push({
        technique_id: rawTechId,
        technique_name: row.technique_name !== undefined ? row.technique_name : null,
        technique_tactics: row.technique_tactics !== undefined ? row.technique_tactics : null,
        technique_platforms: row.technique_platforms !== undefined ? row.technique_platforms : null,
        mitigation_id: row.mitigation_id !== undefined ? row.mitigation_id : null,
        mitigation_name: row.mitigation_name !== undefined ? row.mitigation_name : null,
        mitigation_description: row.mitigation_description !== undefined ? row.mitigation_description : null,
        source_id: row.source_id !== undefined ? row.source_id : null,
        target_id: row.target_id !== undefined ? row.target_id : null,
        mapping_type: row.mapping_type !== undefined ? row.mapping_type : null,
        platform_name: row.platform_name !== undefined ? row.platform_name : null,
        tactic_id: row.tactic_id !== undefined ? row.tactic_id : null,
        tactic_name: row.tactic_name !== undefined ? row.tactic_name : null,
        attack_id: normalizeAttackId(rawTechId),
      });
    }

    if (page.length < pageSize) {
      hasMore = false;
    } else {
      from += pageSize;
    }
  }

  return allRecords;
}


