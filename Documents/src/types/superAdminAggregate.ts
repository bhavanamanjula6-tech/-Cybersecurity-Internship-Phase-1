/**
 * CyberOps SOC — Super Admin Reference Datasets Aggregate Response Contract
 *
 * Defines the strict, typed contract for the `public.get_reference_datasets_summary()` RPC.
 *
 * Architectural Invariants:
 * 1. Contains ONLY aggregated scalar numbers and Top 5 distribution arrays (31 metrics total).
 * 2. Exposes ZERO raw records, ZERO alert records, and ZERO user activity data.
 * 3. Nullable descriptive labels: detection strategy and mitigation objects include stable IDs
 *    and nullable human-readable names (string | null). Never substitutes an ID when a name is missing.
 * 4. Strict ISO 8601 timestamp: requires full date-time with explicit timezone (Z or offset),
 *    rejecting date-only, locale-formatted, invalid calendar dates, and non-ISO strings.
 * 5. Enforces that mitigated + unmitigated techniques strictly equals total distinct evaluated techniques.
 * 6. Enforces that mitigation mapping buckets partition the exact technique domain.
 * 7. Enforces that mitigation coverage percentage agrees with calculated ratio within rounding tolerance.
 * 8. Rejects malformed types, NaN, Infinity, negative/fractional counts, unexpected extra keys, and >5 item arrays.
 */

export interface Top5TechniqueByTactic {
  tactic: string;
  techniques: number;
}

export interface Top5AnalyticsByLogSource {
  log_source: string;
  analytics: number;
}

export interface Top5TechniqueByPlatform {
  platform: string;
  techniques: number;
}

export interface Top5DetectionStrategyByTechniques {
  detection_strategy_attack_id: string;
  detection_strategy_name: string | null;
  techniques: number;
}

export interface Top5MitigationByTechniques {
  mitigation_id: string;
  mitigation_name: string | null;
  techniques: number;
}

export interface MitigationMappingBuckets {
  zero_mitigations: number;
  one_mitigation: number;
  two_mitigations: number;
  three_plus_mitigations: number;
}

export interface SocAnalystDatasetSummary {
  total_rows: number;
  distinct_techniques: number;
  distinct_detection_strategies: number;
  distinct_analytics: number;
  distinct_data_components: number;
  distinct_log_sources: number;
  top_5_techniques_by_tactic: Top5TechniqueByTactic[];
  top_5_analytics_by_log_source: Top5AnalyticsByLogSource[];
  top_5_techniques_by_platform: Top5TechniqueByPlatform[];
  top_5_detection_strategies_by_techniques: Top5DetectionStrategyByTechniques[];
}

export interface SecurityEngineerDatasetSummary {
  total_rows: number;
  distinct_techniques: number;
  distinct_mitigations: number;
  distinct_tactics: number;
  distinct_platforms: number;
  mitigated_techniques_count: number;
  unmitigated_techniques_count: number;
  mitigation_coverage_pct: number;
  mitigation_mapping_buckets: MitigationMappingBuckets;
  top_5_mitigations_by_techniques: Top5MitigationByTechniques[];
  top_5_techniques_by_tactic: Top5TechniqueByTactic[];
  top_5_techniques_by_platform: Top5TechniqueByPlatform[];
}

export interface ITherOperationsDatasetSummary {
  total_rows: number;
  distinct_techniques: number;
  distinct_tactics: number;
  distinct_mitigations: number;
  distinct_platforms: number;
  top_5_platforms_by_techniques: Top5TechniqueByPlatform[];
  top_5_tactics_by_techniques: Top5TechniqueByTactic[];
  top_5_mitigations_by_techniques: Top5MitigationByTechniques[];
  mitigation_mapping_buckets: MitigationMappingBuckets;
}

export type ItOperationsDatasetSummary = ITherOperationsDatasetSummary;

export interface ReferenceDatasetsSummaryResponse {
  summary_generated_at: string;
  soc_analyst: SocAnalystDatasetSummary;
  security_engineer: SecurityEngineerDatasetSummary;
  it_operations: ItOperationsDatasetSummary;
}

// -----------------------------------------------------------------------------
// Validation Helper Functions (Zero `any` usage, strict narrowing)
// -----------------------------------------------------------------------------

function isRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

function isNonNegativeInteger(val: unknown): val is number {
  return (
    typeof val === 'number' &&
    Number.isInteger(val) &&
    val >= 0 &&
    Number.isFinite(val) &&
    !Number.isNaN(val)
  );
}

function isNonEmptyTrimmedString(val: unknown): val is string {
  return typeof val === 'string' && val.trim().length > 0;
}

function isNullableNonEmptyTrimmedString(val: unknown): val is string | null {
  if (val === null) return true;
  return typeof val === 'string' && val.trim().length > 0;
}

/**
 * Strict ISO 8601 Date-Time Validator:
 * - Requires full date-time string with explicit timezone (`Z` or valid offset `+HH:MM`, `-HH:MM`, `+HHMM`, `-HHMM`, `+HH`).
 * - Rejects date-only strings (e.g. `2026-10-31`).
 * - Rejects locale-formatted strings (e.g. `10/31/2026, 2:15:00 AM`).
 * - Rejects non-ISO strings parsed by Date.parse() (e.g. `October 31, 2026 02:15:00 UTC`).
 * - Rejects invalid calendar dates (e.g. February 30th, April 31st).
 * - Enforces correct leap year rules for February 29th.
 */
export function isValidIso8601Timestamp(val: unknown): val is string {
  if (typeof val !== 'string' || !val.trim()) {
    return false;
  }

  // ISO 8601 regex requiring 'T', time (HH:MM:SS), optional fractional seconds, and explicit timezone (Z or offset)
  const ISO_REGEX = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}(?::?\d{2})?)$/;
  const match = ISO_REGEX.exec(val);
  if (!match) {
    return false;
  }

  const year = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const day = parseInt(match[3], 10);
  const hour = parseInt(match[4], 10);
  const minute = parseInt(match[5], 10);
  const second = parseInt(match[6], 10);
  const tz = match[8];

  // Month range
  if (month < 1 || month > 12) return false;

  // Calendar days in month validation
  const isLeap = (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);
  const daysInMonth = [31, isLeap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > daysInMonth[month - 1]) return false;

  // Time component range
  if (hour < 0 || hour > 23) return false;
  if (minute < 0 || minute > 59) return false;
  if (second < 0 || second > 59) return false;

  // Timezone offset range validation (if not Z)
  if (tz !== 'Z') {
    const tzSign = tz.charAt(0);
    const tzDigits = tz.slice(1).replace(':', '');
    const tzHours = parseInt(tzDigits.slice(0, 2), 10);
    const tzMins = tzDigits.length >= 4 ? parseInt(tzDigits.slice(2, 4), 10) : 0;
    if (tzHours < 0 || tzHours > 14) return false; // UTC offsets range from -12:00 to +14:00
    if (tzMins < 0 || tzMins > 59) return false;
    if (tzSign !== '+' && tzSign !== '-') return false;
  }

  // Ensure Date.parse agrees and produces a finite number
  const parsed = Date.parse(val);
  return !Number.isNaN(parsed) && Number.isFinite(parsed);
}

function isPercentage(val: unknown): val is number {
  return (
    typeof val === 'number' &&
    Number.isFinite(val) &&
    !Number.isNaN(val) &&
    val >= 0 &&
    val <= 100
  );
}

function assertExactKeys(obj: Record<string, unknown>, allowedKeys: Set<string>, scope: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`[Validation Error] Unexpected field "${key}" in ${scope}.`);
    }
  }
}

/**
 * Validates that an untyped object matches the ReferenceDatasetsSummaryResponse shape.
 * Performs deep, fail-closed validation of all 31 metrics, Top 5 distributions,
 * nullable descriptive names, mitigation mapping buckets, ISO 8601 timestamp, and arithmetic invariants.
 *
 * @throws Error with detailed diagnostic message if validation fails.
 */
export function validateReferenceDatasetsSummary(
  data: unknown
): ReferenceDatasetsSummaryResponse {
  if (!isRecord(data)) {
    throw new Error('[Validation Error] RPC response is null or not a plain JSON object.');
  }

  // 1. Root structure and unexpected key check
  const rootAllowedKeys = new Set([
    'summary_generated_at',
    'soc_analyst',
    'security_engineer',
    'it_operations',
  ]);
  assertExactKeys(data, rootAllowedKeys, 'root response payload');

  // 2. Validate strict ISO 8601 timestamp with explicit timezone
  if (!isValidIso8601Timestamp(data.summary_generated_at)) {
    throw new Error(
      '[Validation Error] Missing or invalid "summary_generated_at" timestamp (must be an ISO 8601 date-time string with explicit timezone Z or offset).'
    );
  }

  // 3. Validate SOC Analyst section
  if (!isRecord(data.soc_analyst)) {
    throw new Error('[Validation Error] Missing or invalid "soc_analyst" section (must be an object).');
  }
  const soc = data.soc_analyst;
  const socAllowedKeys = new Set([
    'total_rows',
    'distinct_techniques',
    'distinct_detection_strategies',
    'distinct_analytics',
    'distinct_data_components',
    'distinct_log_sources',
    'top_5_techniques_by_tactic',
    'top_5_analytics_by_log_source',
    'top_5_techniques_by_platform',
    'top_5_detection_strategies_by_techniques',
  ]);
  assertExactKeys(soc, socAllowedKeys, '"soc_analyst" section');

  const socScalars = [
    'total_rows',
    'distinct_techniques',
    'distinct_detection_strategies',
    'distinct_analytics',
    'distinct_data_components',
    'distinct_log_sources',
  ] as const;

  for (const field of socScalars) {
    if (!isNonNegativeInteger(soc[field])) {
      throw new Error(
        `[Validation Error] Field "${field}" in "soc_analyst" must be a non-negative finite integer.`
      );
    }
  }

  // Validate SOC Top 5 arrays
  if (!Array.isArray(soc.top_5_techniques_by_tactic) || soc.top_5_techniques_by_tactic.length > 5) {
    throw new Error('[Validation Error] "top_5_techniques_by_tactic" in "soc_analyst" must be an array with <= 5 items.');
  }
  for (const item of soc.top_5_techniques_by_tactic) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_tactic".');
    assertExactKeys(item, new Set(['tactic', 'techniques']), 'top_5_techniques_by_tactic item');
    if (!isNonEmptyTrimmedString(item.tactic) || !isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_tactic" (requires non-empty tactic and integer techniques).');
    }
  }

  if (!Array.isArray(soc.top_5_analytics_by_log_source) || soc.top_5_analytics_by_log_source.length > 5) {
    throw new Error('[Validation Error] "top_5_analytics_by_log_source" in "soc_analyst" must be an array with <= 5 items.');
  }
  for (const item of soc.top_5_analytics_by_log_source) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_analytics_by_log_source".');
    assertExactKeys(item, new Set(['log_source', 'analytics']), 'top_5_analytics_by_log_source item');
    if (!isNonEmptyTrimmedString(item.log_source) || !isNonNegativeInteger(item.analytics)) {
      throw new Error('[Validation Error] Invalid item in "top_5_analytics_by_log_source" (requires non-empty log_source and integer analytics).');
    }
  }

  if (!Array.isArray(soc.top_5_techniques_by_platform) || soc.top_5_techniques_by_platform.length > 5) {
    throw new Error('[Validation Error] "top_5_techniques_by_platform" in "soc_analyst" must be an array with <= 5 items.');
  }
  for (const item of soc.top_5_techniques_by_platform) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_platform".');
    assertExactKeys(item, new Set(['platform', 'techniques']), 'top_5_techniques_by_platform item');
    if (!isNonEmptyTrimmedString(item.platform) || !isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_platform" (requires non-empty platform and integer techniques).');
    }
  }

  if (
    !Array.isArray(soc.top_5_detection_strategies_by_techniques) ||
    soc.top_5_detection_strategies_by_techniques.length > 5
  ) {
    throw new Error('[Validation Error] "top_5_detection_strategies_by_techniques" must be an array with <= 5 items.');
  }
  for (const item of soc.top_5_detection_strategies_by_techniques) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_detection_strategies_by_techniques".');
    assertExactKeys(
      item,
      new Set(['detection_strategy_attack_id', 'detection_strategy_name', 'techniques']),
      'top_5_detection_strategies_by_techniques item'
    );
    if (!isNonEmptyTrimmedString(item.detection_strategy_attack_id)) {
      throw new Error(
        '[Validation Error] Field "detection_strategy_attack_id" must be a non-empty trimmed string.'
      );
    }
    if (!isNullableNonEmptyTrimmedString(item.detection_strategy_name)) {
      throw new Error(
        '[Validation Error] Field "detection_strategy_name" must be null or a non-empty trimmed string.'
      );
    }
    if (!isNonNegativeInteger(item.techniques)) {
      throw new Error(
        '[Validation Error] Field "techniques" in "top_5_detection_strategies_by_techniques" must be a non-negative integer.'
      );
    }
  }

  // 4. Validate Security Engineer section
  if (!isRecord(data.security_engineer)) {
    throw new Error('[Validation Error] Missing or invalid "security_engineer" section (must be an object).');
  }
  const sec = data.security_engineer;
  const secAllowedKeys = new Set([
    'total_rows',
    'distinct_techniques',
    'distinct_mitigations',
    'distinct_tactics',
    'distinct_platforms',
    'mitigated_techniques_count',
    'unmitigated_techniques_count',
    'mitigation_coverage_pct',
    'mitigation_mapping_buckets',
    'top_5_mitigations_by_techniques',
    'top_5_techniques_by_tactic',
    'top_5_techniques_by_platform',
  ]);
  assertExactKeys(sec, secAllowedKeys, '"security_engineer" section');

  const secScalars = [
    'total_rows',
    'distinct_techniques',
    'distinct_mitigations',
    'distinct_tactics',
    'distinct_platforms',
    'mitigated_techniques_count',
    'unmitigated_techniques_count',
  ] as const;

  for (const field of secScalars) {
    if (!isNonNegativeInteger(sec[field])) {
      throw new Error(
        `[Validation Error] Field "${field}" in "security_engineer" must be a non-negative finite integer.`
      );
    }
  }

  if (!isPercentage(sec.mitigation_coverage_pct)) {
    throw new Error(
      '[Validation Error] Field "mitigation_coverage_pct" in "security_engineer" must be a finite percentage between 0 and 100.'
    );
  }

  // Security Engineer mitigation mapping buckets (individual bucket presence & validity)
  if (!isRecord(sec.mitigation_mapping_buckets)) {
    throw new Error('[Validation Error] "mitigation_mapping_buckets" in "security_engineer" must be an object.');
  }
  const requiredBucketKeys = [
    'zero_mitigations',
    'one_mitigation',
    'two_mitigations',
    'three_plus_mitigations',
  ] as const;

  assertExactKeys(
    sec.mitigation_mapping_buckets,
    new Set(requiredBucketKeys),
    '"security_engineer.mitigation_mapping_buckets"'
  );

  for (const bKey of requiredBucketKeys) {
    if (!(bKey in sec.mitigation_mapping_buckets)) {
      throw new Error(
        `[Validation Error] Missing required bucket "${bKey}" in "security_engineer.mitigation_mapping_buckets".`
      );
    }
    if (!isNonNegativeInteger(sec.mitigation_mapping_buckets[bKey])) {
      throw new Error(
        `[Validation Error] Bucket "${bKey}" in "security_engineer.mitigation_mapping_buckets" must be a non-negative finite integer.`
      );
    }
  }

  // Security Engineer Top 5 arrays
  if (
    !Array.isArray(sec.top_5_mitigations_by_techniques) ||
    sec.top_5_mitigations_by_techniques.length > 5
  ) {
    throw new Error('[Validation Error] "top_5_mitigations_by_techniques" must be an array with <= 5 items.');
  }
  for (const item of sec.top_5_mitigations_by_techniques) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_mitigations_by_techniques".');
    assertExactKeys(
      item,
      new Set(['mitigation_id', 'mitigation_name', 'techniques']),
      'top_5_mitigations_by_techniques item'
    );
    if (!isNonEmptyTrimmedString(item.mitigation_id)) {
      throw new Error('[Validation Error] Field "mitigation_id" must be a non-empty trimmed string.');
    }
    if (!isNullableNonEmptyTrimmedString(item.mitigation_name)) {
      throw new Error('[Validation Error] Field "mitigation_name" must be null or a non-empty trimmed string.');
    }
    if (!isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Field "techniques" in "top_5_mitigations_by_techniques" must be a non-negative integer.');
    }
  }

  if (!Array.isArray(sec.top_5_techniques_by_tactic) || sec.top_5_techniques_by_tactic.length > 5) {
    throw new Error('[Validation Error] "top_5_techniques_by_tactic" in "security_engineer" must be an array with <= 5 items.');
  }
  for (const item of sec.top_5_techniques_by_tactic) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_tactic".');
    assertExactKeys(item, new Set(['tactic', 'techniques']), 'top_5_techniques_by_tactic item');
    if (!isNonEmptyTrimmedString(item.tactic) || !isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_tactic".');
    }
  }

  if (!Array.isArray(sec.top_5_techniques_by_platform) || sec.top_5_techniques_by_platform.length > 5) {
    throw new Error('[Validation Error] "top_5_techniques_by_platform" in "security_engineer" must be an array with <= 5 items.');
  }
  for (const item of sec.top_5_techniques_by_platform) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_platform".');
    assertExactKeys(item, new Set(['platform', 'techniques']), 'top_5_techniques_by_platform item');
    if (!isNonEmptyTrimmedString(item.platform) || !isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Invalid item in "top_5_techniques_by_platform".');
    }
  }

  // Security Engineer Invariant 1: mitigated + unmitigated === distinct_techniques
  const secTotalTech = sec.distinct_techniques as number;
  const secMitigated = sec.mitigated_techniques_count as number;
  const secUnmitigated = sec.unmitigated_techniques_count as number;
  if (secMitigated + secUnmitigated !== secTotalTech) {
    throw new Error(
      `[Invariant Violation] Security Engineer mitigation count mismatch: mitigated (${secMitigated}) + unmitigated (${secUnmitigated}) !== total evaluated techniques (${secTotalTech}).`
    );
  }

  // Security Engineer Invariant 2: Buckets sum === distinct_techniques
  const secBuckets = sec.mitigation_mapping_buckets;
  const secBucketSum =
    (secBuckets.zero_mitigations as number) +
    (secBuckets.one_mitigation as number) +
    (secBuckets.two_mitigations as number) +
    (secBuckets.three_plus_mitigations as number);
  if (secBucketSum !== secTotalTech) {
    throw new Error(
      `[Invariant Violation] Security Engineer mitigation bucket sum (${secBucketSum}) !== total evaluated techniques (${secTotalTech}).`
    );
  }

  // Security Engineer Invariant 3: Coverage percentage consistency
  const secReportedPct = sec.mitigation_coverage_pct as number;
  const expectedSecPct = secTotalTech > 0 ? (secMitigated / secTotalTech) * 100 : 0;
  if (Math.abs(secReportedPct - expectedSecPct) > 0.15) {
    throw new Error(
      `[Invariant Violation] Security Engineer coverage percentage (${secReportedPct}%) deviates from computed ratio (${expectedSecPct.toFixed(1)}%).`
    );
  }

  // 5. Validate IT Operations section
  if (!isRecord(data.it_operations)) {
    throw new Error('[Validation Error] Missing or invalid "it_operations" section (must be an object).');
  }
  const it = data.it_operations;
  const itAllowedKeys = new Set([
    'total_rows',
    'distinct_techniques',
    'distinct_tactics',
    'distinct_mitigations',
    'distinct_platforms',
    'top_5_platforms_by_techniques',
    'top_5_tactics_by_techniques',
    'top_5_mitigations_by_techniques',
    'mitigation_mapping_buckets',
  ]);
  assertExactKeys(it, itAllowedKeys, '"it_operations" section');

  const itScalars = [
    'total_rows',
    'distinct_techniques',
    'distinct_tactics',
    'distinct_mitigations',
    'distinct_platforms',
  ] as const;

  for (const field of itScalars) {
    if (!isNonNegativeInteger(it[field])) {
      throw new Error(
        `[Validation Error] Field "${field}" in "it_operations" must be a non-negative finite integer.`
      );
    }
  }

  // IT Operations mitigation mapping buckets (individual bucket presence & validity)
  if (!isRecord(it.mitigation_mapping_buckets)) {
    throw new Error('[Validation Error] "mitigation_mapping_buckets" in "it_operations" must be an object.');
  }
  assertExactKeys(
    it.mitigation_mapping_buckets,
    new Set(requiredBucketKeys),
    '"it_operations.mitigation_mapping_buckets"'
  );

  for (const bKey of requiredBucketKeys) {
    if (!(bKey in it.mitigation_mapping_buckets)) {
      throw new Error(
        `[Validation Error] Missing required bucket "${bKey}" in "it_operations.mitigation_mapping_buckets".`
      );
    }
    if (!isNonNegativeInteger(it.mitigation_mapping_buckets[bKey])) {
      throw new Error(
        `[Validation Error] Bucket "${bKey}" in "it_operations.mitigation_mapping_buckets" must be a non-negative finite integer.`
      );
    }
  }

  // IT Operations Invariant: Buckets sum === distinct_techniques
  const itTotalTech = it.distinct_techniques as number;
  const itBuckets = it.mitigation_mapping_buckets;
  const itBucketSum =
    (itBuckets.zero_mitigations as number) +
    (itBuckets.one_mitigation as number) +
    (itBuckets.two_mitigations as number) +
    (itBuckets.three_plus_mitigations as number);
  if (itBucketSum !== itTotalTech) {
    throw new Error(
      `[Invariant Violation] IT Operations mitigation bucket sum (${itBucketSum}) !== total evaluated techniques (${itTotalTech}).`
    );
  }

  // IT Operations Top 5 arrays
  if (!Array.isArray(it.top_5_platforms_by_techniques) || it.top_5_platforms_by_techniques.length > 5) {
    throw new Error('[Validation Error] "top_5_platforms_by_techniques" must be an array with <= 5 items.');
  }
  for (const item of it.top_5_platforms_by_techniques) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_platforms_by_techniques".');
    assertExactKeys(item, new Set(['platform', 'techniques']), 'top_5_platforms_by_techniques item');
    if (!isNonEmptyTrimmedString(item.platform) || !isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Invalid item in "top_5_platforms_by_techniques".');
    }
  }

  if (!Array.isArray(it.top_5_tactics_by_techniques) || it.top_5_tactics_by_techniques.length > 5) {
    throw new Error('[Validation Error] "top_5_tactics_by_techniques" must be an array with <= 5 items.');
  }
  for (const item of it.top_5_tactics_by_techniques) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_tactics_by_techniques".');
    assertExactKeys(item, new Set(['tactic', 'techniques']), 'top_5_tactics_by_techniques item');
    if (!isNonEmptyTrimmedString(item.tactic) || !isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Invalid item in "top_5_tactics_by_techniques".');
    }
  }

  if (!Array.isArray(it.top_5_mitigations_by_techniques) || it.top_5_mitigations_by_techniques.length > 5) {
    throw new Error('[Validation Error] "top_5_mitigations_by_techniques" must be an array with <= 5 items.');
  }
  for (const item of it.top_5_mitigations_by_techniques) {
    if (!isRecord(item)) throw new Error('[Validation Error] Invalid item in "top_5_mitigations_by_techniques".');
    assertExactKeys(
      item,
      new Set(['mitigation_id', 'mitigation_name', 'techniques']),
      'top_5_mitigations_by_techniques item'
    );
    if (!isNonEmptyTrimmedString(item.mitigation_id)) {
      throw new Error('[Validation Error] Field "mitigation_id" must be a non-empty trimmed string.');
    }
    if (!isNullableNonEmptyTrimmedString(item.mitigation_name)) {
      throw new Error('[Validation Error] Field "mitigation_name" must be null or a non-empty trimmed string.');
    }
    if (!isNonNegativeInteger(item.techniques)) {
      throw new Error('[Validation Error] Field "techniques" in "top_5_mitigations_by_techniques" must be a non-negative integer.');
    }
  }

  return data as unknown as ReferenceDatasetsSummaryResponse;
}
