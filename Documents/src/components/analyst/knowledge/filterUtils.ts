/**
 * CyberOps SOC — Filter Engine and Aggregation Utilities for SOC Analyst Knowledge Base
 *
 * Implements:
 * 1. Multi-valued delimiter token splitting on `[,;|\r\n]+`.
 * 2. Multi-dimensional AND / OR cross-filtering:
 *    - AND logic across different dimensions (tactic, platform, log source, data component, strategy, search text).
 *    - OR logic among selected values within the same dimension.
 *    - Exact token matching for multi-valued fields.
 * 3. Dynamic recalculation of KPIs and Top 5 / distribution charts from filtered records.
 * 4. Deterministic sorting and tie-breaking.
 * 5. Strict SOC Analyst scoping (zero mitigation fields).
 */

import { SocAnalystKnowledgeRecord } from '../../../services/knowledgeService';
import {
  SocKnowledgeFilters,
  SocOverviewKpis,
  TacticChartItem,
  LogSourceChartItem,
  PlatformChartItem,
  DetectionStrategyChartItem,
  DataComponentChartItem,
  StrategyTacticChartItem,
  AnalyticTacticChartItem,
  DataComponentTacticChartItem,
  MatrixCell,
  AggregatedTechnique,
  AggregatedDetectionStrategy,
  AggregatedAnalytic,
  AggregatedLogSource,
  AggregatedDataComponent,
  ActiveFilterChip,
} from './types';

export const INITIAL_SOC_FILTERS: SocKnowledgeFilters = {
  searchQuery: '',
  selectedTactics: [],
  selectedPlatforms: [],
  selectedLogSources: [],
  selectedDataComponents: [],
  selectedStrategies: [],
};

const INVALID_TOKENS = new Set(['none', 'null', 'n/a', 'unknown', 'undefined', '']);

/**
 * Splits delimited text on commas, semicolons, pipes, and newlines.
 * Trims each token and filters out empty or invalid placeholder values.
 */
export function splitTokens(raw: string | null | undefined): string[] {
  if (!raw || typeof raw !== 'string') return [];
  const tokens = raw.split(/[,;|\r\n]+/);
  const result: string[] = [];
  for (const t of tokens) {
    const trimmed = t.trim();
    if (trimmed && !INVALID_TOKENS.has(trimmed.toLowerCase())) {
      result.push(trimmed);
    }
  }
  return result;
}

const KNOWN_TACTIC_NAMES: Record<string, string> = {
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

export function normalizeTacticToken(token: string): string {
  const clean = token.trim();
  const lower = clean.toLowerCase();
  if (KNOWN_TACTIC_NAMES[lower]) {
    return KNOWN_TACTIC_NAMES[lower];
  }
  return clean
    .split(/\s+/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');
}

export function normalizePlatformToken(token: string): string {
  const clean = token.trim();
  const lower = clean.toLowerCase();
  if (lower === 'windows') return 'Windows';
  if (lower === 'linux') return 'Linux';
  if (lower === 'macos' || lower === 'mac') return 'macOS';
  if (lower === 'containers' || lower === 'container') return 'Containers';
  if (lower === 'kubernetes' || lower === 'k8s') return 'Kubernetes';
  if (lower === 'network') return 'Network';
  if (lower === 'iaas') return 'IaaS';
  if (lower === 'saas') return 'SaaS';
  if (lower === 'paas') return 'PaaS';
  if (lower === 'esxi') return 'ESXi';
  if (clean.toUpperCase() === 'PRE') return 'PRE';
  return clean.charAt(0).toUpperCase() + clean.slice(1).toLowerCase();
}

export function normalizeLogSourceToken(token: string): string {
  const clean = token.trim();
  if (!clean || INVALID_TOKENS.has(clean.toLowerCase())) {
    return 'Unspecified / Custom Log Source';
  }
  return clean;
}

/**
 * Multi-dimensional AND / OR filtering on SOC Analyst knowledge records.
 */
export function applySocKnowledgeFilters(
  records: SocAnalystKnowledgeRecord[],
  filters: SocKnowledgeFilters
): SocAnalystKnowledgeRecord[] {
  if (!records || records.length === 0) return [];

  const query = filters.searchQuery.trim().toLowerCase();
  const hasSearch = query.length > 0;
  const hasTactics = filters.selectedTactics.length > 0;
  const hasPlatforms = filters.selectedPlatforms.length > 0;
  const hasLogSources = filters.selectedLogSources.length > 0;
  const hasDataComponents = filters.selectedDataComponents.length > 0;
  const hasStrategies = filters.selectedStrategies.length > 0;

  if (!hasSearch && !hasTactics && !hasPlatforms && !hasLogSources && !hasDataComponents && !hasStrategies) {
    return records;
  }

  const targetTacticsLower = new Set(filters.selectedTactics.map((t) => t.toLowerCase()));
  const targetPlatformsLower = new Set(filters.selectedPlatforms.map((p) => p.toLowerCase()));
  const targetLogSourcesLower = new Set(filters.selectedLogSources.map((l) => l.toLowerCase()));
  const targetDataComponentsLower = new Set(filters.selectedDataComponents.map((d) => d.toLowerCase()));
  const targetStrategiesLower = new Set(filters.selectedStrategies.map((s) => s.toLowerCase()));

  return records.filter((record) => {
    // 1. Tactics Filter (OR within dimension)
    if (hasTactics) {
      const recordTactics = splitTokens(record.techniques_tactics).map((t) =>
        normalizeTacticToken(t).toLowerCase()
      );
      const matchesTactic = recordTactics.some((t) => targetTacticsLower.has(t));
      if (!matchesTactic) return false;
    }

    // 2. Platforms Filter (OR within dimension)
    if (hasPlatforms) {
      const recordPlatforms = splitTokens(record.techniques_platforms).map((p) =>
        normalizePlatformToken(p).toLowerCase()
      );
      const matchesPlatform = recordPlatforms.some((p) => targetPlatformsLower.has(p));
      if (!matchesPlatform) return false;
    }

    // 3. Log Sources Filter (OR within dimension)
    if (hasLogSources) {
      const recordLogSources = splitTokens(record.log_source_name).map((l) =>
        normalizeLogSourceToken(l).toLowerCase()
      );
      const matchesLogSource = recordLogSources.some((l) => targetLogSourcesLower.has(l));
      if (!matchesLogSource) return false;
    }

    // 4. Data Components Filter (OR within dimension)
    if (hasDataComponents) {
      const idMatch =
        record.data_components_id &&
        targetDataComponentsLower.has(record.data_components_id.trim().toLowerCase());
      const nameMatch =
        record.data_components_name &&
        targetDataComponentsLower.has(record.data_components_name.trim().toLowerCase());
      if (!idMatch && !nameMatch) return false;
    }

    // 5. Detection Strategy Filter (OR within dimension)
    if (hasStrategies) {
      const idMatch =
        record.detection_strategy_attack_id &&
        targetStrategiesLower.has(record.detection_strategy_attack_id.trim().toLowerCase());
      const nameMatch =
        record.detection_strategy_name &&
        targetStrategiesLower.has(record.detection_strategy_name.trim().toLowerCase());
      if (!idMatch && !nameMatch) return false;
    }

    // 6. Free-text Search across all 12 actual columns
    if (hasSearch) {
      const matchSearch =
        (record.techniques_id && record.techniques_id.toLowerCase().includes(query)) ||
        (record.techniques_name && record.techniques_name.toLowerCase().includes(query)) ||
        (record.techniques_description && record.techniques_description.toLowerCase().includes(query)) ||
        (record.techniques_tactics && record.techniques_tactics.toLowerCase().includes(query)) ||
        (record.techniques_platforms && record.techniques_platforms.toLowerCase().includes(query)) ||
        (record.detection_strategy_attack_id &&
          record.detection_strategy_attack_id.toLowerCase().includes(query)) ||
        (record.detection_strategy_name &&
          record.detection_strategy_name.toLowerCase().includes(query)) ||
        (record.analytic_id && record.analytic_id.toLowerCase().includes(query)) ||
        (record.analytic_name && record.analytic_name.toLowerCase().includes(query)) ||
        (record.log_source_name && record.log_source_name.toLowerCase().includes(query)) ||
        (record.data_components_id && record.data_components_id.toLowerCase().includes(query)) ||
        (record.data_components_name && record.data_components_name.toLowerCase().includes(query));

      if (!matchSearch) return false;
    }

    return true;
  });
}

/**
 * Computes 6 distinct count KPIs:
 * 1. Distinct Techniques
 * 2. Distinct Tactics
 * 3. Distinct Detection Strategies
 * 4. Distinct Analytics
 * 5. Distinct Log Sources
 * 6. Distinct Data Components
 */
export function computeSocOverviewKpis(records: SocAnalystKnowledgeRecord[]): SocOverviewKpis {
  if (!records || records.length === 0) {
    return {
      distinctTechniques: 0,
      distinctTactics: 0,
      distinctDetectionStrategies: 0,
      distinctAnalytics: 0,
      distinctLogSources: 0,
      distinctDataComponents: 0,
      totalRecords: 0,
    };
  }

  const techSet = new Set<string>();
  const tacticSet = new Set<string>();
  const stratSet = new Set<string>();
  const anaSet = new Set<string>();
  const logSourceSet = new Set<string>();
  const dcSet = new Set<string>();

  for (const r of records) {
    if (r.techniques_id) {
      const clean = r.techniques_id.trim().toUpperCase();
      if (clean && !INVALID_TOKENS.has(clean.toLowerCase())) {
        techSet.add(clean);
      }
    }

    const tacticTokens = splitTokens(r.techniques_tactics);
    for (const t of tacticTokens) {
      tacticSet.add(normalizeTacticToken(t).toLowerCase());
    }

    if (r.detection_strategy_attack_id) {
      const clean = r.detection_strategy_attack_id.trim();
      if (clean && !INVALID_TOKENS.has(clean.toLowerCase())) {
        stratSet.add(clean);
      }
    } else if (r.detection_strategy_name) {
      const clean = r.detection_strategy_name.trim();
      if (clean && !INVALID_TOKENS.has(clean.toLowerCase())) {
        stratSet.add(clean);
      }
    }

    if (r.analytic_id) {
      const clean = r.analytic_id.trim();
      if (clean && !INVALID_TOKENS.has(clean.toLowerCase())) {
        anaSet.add(clean);
      }
    } else if (r.analytic_name) {
      const clean = r.analytic_name.trim();
      if (clean && !INVALID_TOKENS.has(clean.toLowerCase())) {
        anaSet.add(clean);
      }
    }

    if (r.data_components_id) {
      const clean = r.data_components_id.trim();
      if (clean && !INVALID_TOKENS.has(clean.toLowerCase())) {
        dcSet.add(clean);
      }
    } else if (r.data_components_name) {
      const clean = r.data_components_name.trim();
      if (clean && !INVALID_TOKENS.has(clean.toLowerCase())) {
        dcSet.add(clean);
      }
    }

    const logTokens = splitTokens(r.log_source_name);
    for (const token of logTokens) {
      const norm = normalizeLogSourceToken(token).toLowerCase();
      logSourceSet.add(norm);
    }
  }

  return {
    distinctTechniques: techSet.size,
    distinctTactics: tacticSet.size,
    distinctDetectionStrategies: stratSet.size,
    distinctAnalytics: anaSet.size,
    distinctLogSources: logSourceSet.size,
    distinctDataComponents: dcSet.size,
    totalRecords: records.length,
  };
}

/**
 * Chart: Techniques by Tactic
 */
export function aggregateTechniquesByTacticFromRecords(
  records: SocAnalystKnowledgeRecord[]
): TacticChartItem[] {
  if (!records || records.length === 0) return [];

  const tally = new Map<string, Set<string>>();

  for (const r of records) {
    const techId = r.techniques_id ? r.techniques_id.trim().toUpperCase() : null;
    if (!techId || INVALID_TOKENS.has(techId.toLowerCase())) continue;

    const tactics = splitTokens(r.techniques_tactics);
    if (tactics.length === 0) {
      if (!tally.has('Unclassified Tactic')) tally.set('Unclassified Tactic', new Set<string>());
      tally.get('Unclassified Tactic')!.add(techId);
    } else {
      for (const t of tactics) {
        const canonical = normalizeTacticToken(t);
        if (!tally.has(canonical)) tally.set(canonical, new Set<string>());
        tally.get(canonical)!.add(techId);
      }
    }
  }

  const distinctTotal = new Set(
    records
      .map((r) => r.techniques_id?.trim().toUpperCase())
      .filter((id): id is string => !!id && !INVALID_TOKENS.has(id.toLowerCase()))
  ).size;

  const result: TacticChartItem[] = Array.from(tally.entries()).map(([tactic, techSet]) => ({
    tactic,
    distinctTechniques: techSet.size,
    percentage: distinctTotal > 0 ? Math.round((techSet.size / distinctTotal) * 1000) / 10 : 0,
  }));

  result.sort((a, b) => {
    if (b.distinctTechniques !== a.distinctTechniques) {
      return b.distinctTechniques - a.distinctTechniques;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return result;
}

/**
 * Chart: Analytics by Log Source
 */
export function aggregateAnalyticsByLogSource(
  records: SocAnalystKnowledgeRecord[]
): LogSourceChartItem[] {
  if (!records || records.length === 0) return [];

  const tally = new Map<string, { display: string; analytics: Set<string> }>();

  for (const r of records) {
    const anaId = r.analytic_id ? r.analytic_id.trim() : r.analytic_name ? r.analytic_name.trim() : null;
    if (!anaId || INVALID_TOKENS.has(anaId.toLowerCase())) continue;

    const logTokens = splitTokens(r.log_source_name);
    const tokens = logTokens.length > 0 ? logTokens : ['Unspecified / Custom Log Source'];

    for (const token of tokens) {
      const display = normalizeLogSourceToken(token);
      const key = display.toLowerCase();
      if (!tally.has(key)) {
        tally.set(key, { display, analytics: new Set<string>() });
      }
      tally.get(key)!.analytics.add(anaId);
    }
  }

  const allDistinctAnalytics = new Set(
    records
      .map((r) => (r.analytic_id ? r.analytic_id.trim() : r.analytic_name ? r.analytic_name.trim() : null))
      .filter((id): id is string => !!id && !INVALID_TOKENS.has(id.toLowerCase()))
  ).size;

  const result: LogSourceChartItem[] = Array.from(tally.values()).map((item) => ({
    logSource: item.display,
    distinctAnalytics: item.analytics.size,
    percentage:
      allDistinctAnalytics > 0
        ? Math.round((item.analytics.size / allDistinctAnalytics) * 1000) / 10
        : 0,
  }));

  result.sort((a, b) => {
    if (b.distinctAnalytics !== a.distinctAnalytics) {
      return b.distinctAnalytics - a.distinctAnalytics;
    }
    return a.logSource.localeCompare(b.logSource);
  });

  return result;
}

/**
 * Chart: Techniques by Platform
 */
export function aggregateTechniquesByPlatform(
  records: SocAnalystKnowledgeRecord[]
): PlatformChartItem[] {
  if (!records || records.length === 0) return [];

  const tally = new Map<string, Set<string>>();

  for (const r of records) {
    const techId = r.techniques_id ? r.techniques_id.trim().toUpperCase() : null;
    if (!techId || INVALID_TOKENS.has(techId.toLowerCase())) continue;

    const platforms = splitTokens(r.techniques_platforms);
    if (platforms.length === 0) {
      if (!tally.has('Unspecified Platform')) tally.set('Unspecified Platform', new Set<string>());
      tally.get('Unspecified Platform')!.add(techId);
    } else {
      for (const p of platforms) {
        const canonical = normalizePlatformToken(p);
        if (!tally.has(canonical)) tally.set(canonical, new Set<string>());
        tally.get(canonical)!.add(techId);
      }
    }
  }

  const distinctTotal = new Set(
    records
      .map((r) => r.techniques_id?.trim().toUpperCase())
      .filter((id): id is string => !!id && !INVALID_TOKENS.has(id.toLowerCase()))
  ).size;

  const result: PlatformChartItem[] = Array.from(tally.entries()).map(([platform, techSet]) => ({
    platform,
    distinctTechniques: techSet.size,
    percentage: distinctTotal > 0 ? Math.round((techSet.size / distinctTotal) * 1000) / 10 : 0,
  }));

  result.sort((a, b) => {
    if (b.distinctTechniques !== a.distinctTechniques) {
      return b.distinctTechniques - a.distinctTechniques;
    }
    return a.platform.localeCompare(b.platform);
  });

  return result;
}

/**
 * Chart: Detection Strategies by Associated Techniques
 */
export function aggregateStrategiesByTechniques(
  records: SocAnalystKnowledgeRecord[]
): DetectionStrategyChartItem[] {
  if (!records || records.length === 0) return [];

  const tally = new Map<
    string,
    { id: string; name: string; names: Set<string>; techniques: Set<string>; tactics: Set<string> }
  >();

  for (const r of records) {
    const stratId = r.detection_strategy_attack_id ? r.detection_strategy_attack_id.trim() : null;
    if (!stratId || INVALID_TOKENS.has(stratId.toLowerCase())) continue;

    const techId = r.techniques_id ? r.techniques_id.trim().toUpperCase() : null;
    const stratName = r.detection_strategy_name?.trim() || '';

    if (!tally.has(stratId)) {
      tally.set(stratId, {
        id: stratId,
        name: stratName,
        names: new Set<string>(),
        techniques: new Set<string>(),
        tactics: new Set<string>(),
      });
    }

    const entry = tally.get(stratId)!;
    if (stratName && !INVALID_TOKENS.has(stratName.toLowerCase())) {
      entry.names.add(stratName);
    }
    if (techId && !INVALID_TOKENS.has(techId.toLowerCase())) {
      entry.techniques.add(techId);
    }
    for (const t of splitTokens(r.techniques_tactics)) {
      entry.tactics.add(normalizeTacticToken(t));
    }
  }

  const result: DetectionStrategyChartItem[] = Array.from(tally.values()).map((entry) => ({
    strategyId: entry.id,
    strategyName: entry.names.size === 1 ? Array.from(entry.names)[0] : entry.name || entry.id,
    distinctTechniques: entry.techniques.size,
    tactics: Array.from(entry.tactics),
  }));

  result.sort((a, b) => {
    if (b.distinctTechniques !== a.distinctTechniques) {
      return b.distinctTechniques - a.distinctTechniques;
    }
    return a.strategyId.localeCompare(b.strategyId);
  });

  return result;
}

/**
 * Chart: Data Components by Associated Techniques
 */
export function aggregateDataComponentsByTechniques(
  records: SocAnalystKnowledgeRecord[]
): DataComponentChartItem[] {
  if (!records || records.length === 0) return [];

  const tally = new Map<string, { id: string; name: string; techniques: Set<string> }>();

  for (const r of records) {
    const dcId = r.data_components_id ? r.data_components_id.trim() : null;
    const dcName = r.data_components_name ? r.data_components_name.trim() : null;
    if (!dcId && !dcName) continue;

    const key = (dcId || dcName)!.toLowerCase();
    const techId = r.techniques_id ? r.techniques_id.trim().toUpperCase() : null;

    if (!tally.has(key)) {
      tally.set(key, {
        id: dcId || 'DC-UNKNOWN',
        name: dcName || dcId || 'Data Component',
        techniques: new Set<string>(),
      });
    }

    const entry = tally.get(key)!;
    if (dcName && entry.name === 'DC-UNKNOWN') entry.name = dcName;
    if (techId && !INVALID_TOKENS.has(techId.toLowerCase())) {
      entry.techniques.add(techId);
    }
  }

  const result: DataComponentChartItem[] = Array.from(tally.values()).map((item) => ({
    componentId: item.id,
    componentName: item.name,
    distinctTechniques: item.techniques.size,
  }));

  result.sort((a, b) => {
    if (b.distinctTechniques !== a.distinctTechniques) {
      return b.distinctTechniques - a.distinctTechniques;
    }
    return a.componentName.localeCompare(b.componentName);
  });

  return result;
}

/**
 * Chart: Detection Strategies by Tactic
 */
export function aggregateStrategiesByTactic(
  records: SocAnalystKnowledgeRecord[]
): StrategyTacticChartItem[] {
  if (!records || records.length === 0) return [];

  const tacticMap = new Map<string, Set<string>>();

  for (const r of records) {
    const stratId = r.detection_strategy_attack_id ? r.detection_strategy_attack_id.trim() : null;
    if (!stratId || INVALID_TOKENS.has(stratId.toLowerCase())) continue;

    const tactics = splitTokens(r.techniques_tactics);
    const resolvedTactics = tactics.length > 0 ? tactics.map(normalizeTacticToken) : ['Unclassified Tactic'];

    for (const tac of resolvedTactics) {
      if (!tacticMap.has(tac)) tacticMap.set(tac, new Set<string>());
      tacticMap.get(tac)!.add(stratId);
    }
  }

  const result: StrategyTacticChartItem[] = Array.from(tacticMap.entries()).map(([tactic, set]) => ({
    tactic,
    distinctStrategies: set.size,
  }));

  result.sort((a, b) => {
    if (b.distinctStrategies !== a.distinctStrategies) {
      return b.distinctStrategies - a.distinctStrategies;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return result;
}

/**
 * Chart: Analytics by Associated Techniques
 */
export function aggregateAnalyticsByTechnique(
  records: SocAnalystKnowledgeRecord[]
): Array<{ analyticId: string; analyticName: string; distinctTechniques: number }> {
  if (!records || records.length === 0) return [];

  const map = new Map<string, { id: string; name: string; techniques: Set<string> }>();

  for (const r of records) {
    const aid = r.analytic_id ? r.analytic_id.trim() : null;
    if (!aid || INVALID_TOKENS.has(aid.toLowerCase())) continue;

    const aname = r.analytic_name?.trim() || aid;
    const techId = r.techniques_id ? r.techniques_id.trim().toUpperCase() : null;

    if (!map.has(aid)) {
      map.set(aid, { id: aid, name: aname, techniques: new Set<string>() });
    }

    const item = map.get(aid)!;
    if (aname && item.name === aid) item.name = aname;
    if (techId && !INVALID_TOKENS.has(techId.toLowerCase())) {
      item.techniques.add(techId);
    }
  }

  const result = Array.from(map.values()).map((item) => ({
    analyticId: item.id,
    analyticName: item.name,
    distinctTechniques: item.techniques.size,
  }));

  result.sort((a, b) => {
    if (b.distinctTechniques !== a.distinctTechniques) {
      return b.distinctTechniques - a.distinctTechniques;
    }
    return a.analyticId.localeCompare(b.analyticId);
  });

  return result;
}

/**
 * Chart: Analytics by Tactic (where supported by actual records)
 */
export function aggregateAnalyticsByTactic(
  records: SocAnalystKnowledgeRecord[]
): AnalyticTacticChartItem[] {
  if (!records || records.length === 0) return [];

  const tacticMap = new Map<string, Set<string>>();

  for (const r of records) {
    const aid = r.analytic_id ? r.analytic_id.trim() : null;
    if (!aid || INVALID_TOKENS.has(aid.toLowerCase())) continue;

    const tactics = splitTokens(r.techniques_tactics);
    if (tactics.length > 0) {
      for (const t of tactics) {
        const canonical = normalizeTacticToken(t);
        if (!tacticMap.has(canonical)) tacticMap.set(canonical, new Set<string>());
        tacticMap.get(canonical)!.add(aid);
      }
    }
  }

  const result: AnalyticTacticChartItem[] = Array.from(tacticMap.entries()).map(([tactic, set]) => ({
    tactic,
    distinctAnalytics: set.size,
  }));

  result.sort((a, b) => {
    if (b.distinctAnalytics !== a.distinctAnalytics) {
      return b.distinctAnalytics - a.distinctAnalytics;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return result;
}

/**
 * Chart: Data Components by Tactic
 */
export function aggregateDataComponentsByTactic(
  records: SocAnalystKnowledgeRecord[]
): DataComponentTacticChartItem[] {
  if (!records || records.length === 0) return [];

  const map = new Map<string, Set<string>>();

  for (const r of records) {
    const dcId = r.data_components_id ? r.data_components_id.trim() : r.data_components_name?.trim();
    if (!dcId || INVALID_TOKENS.has(dcId.toLowerCase())) continue;

    const tactics = splitTokens(r.techniques_tactics);
    const resolvedTactics = tactics.length > 0 ? tactics.map(normalizeTacticToken) : ['Unclassified Tactic'];

    for (const t of resolvedTactics) {
      if (!map.has(t)) map.set(t, new Set<string>());
      map.get(t)!.add(dcId);
    }
  }

  const result: DataComponentTacticChartItem[] = Array.from(map.entries()).map(([tactic, set]) => ({
    tactic,
    distinctDataComponents: set.size,
  }));

  result.sort((a, b) => {
    if (b.distinctDataComponents !== a.distinctDataComponents) {
      return b.distinctDataComponents - a.distinctDataComponents;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return result;
}

/**
 * Matrix: Tactic vs Platform relationship cross-analysis
 */
export function aggregateTacticPlatformMatrix(records: SocAnalystKnowledgeRecord[]): {
  tactics: string[];
  platforms: string[];
  cells: MatrixCell[];
} {
  const tacticSet = new Set<string>();
  const platformSet = new Set<string>();
  const cellMap = new Map<string, Set<string>>();

  for (const r of records) {
    const techId = r.techniques_id ? r.techniques_id.trim().toUpperCase() : null;
    if (!techId || INVALID_TOKENS.has(techId.toLowerCase())) continue;

    const tactics = splitTokens(r.techniques_tactics).map(normalizeTacticToken);
    const platforms = splitTokens(r.techniques_platforms).map(normalizePlatformToken);

    const validTactics = tactics.length > 0 ? tactics : ['Unclassified'];
    const validPlatforms = platforms.length > 0 ? platforms : ['Unspecified'];

    for (const t of validTactics) {
      tacticSet.add(t);
      for (const p of validPlatforms) {
        platformSet.add(p);
        const key = `${t}:::${p}`;
        if (!cellMap.has(key)) cellMap.set(key, new Set<string>());
        cellMap.get(key)!.add(techId);
      }
    }
  }

  const sortedTactics = Array.from(tacticSet).sort();
  const sortedPlatforms = Array.from(platformSet).sort();
  const cells: MatrixCell[] = [];

  for (const t of sortedTactics) {
    for (const p of sortedPlatforms) {
      const key = `${t}:::${p}`;
      const items = cellMap.has(key) ? Array.from(cellMap.get(key)!) : [];
      cells.push({
        row: t,
        col: p,
        count: items.length,
        items,
      });
    }
  }

  return {
    tactics: sortedTactics,
    platforms: sortedPlatforms,
    cells,
  };
}

/**
 * Extracts and deduplicates Techniques for Page 6 (Technique Explorer)
 */
export function extractTechniques(records: SocAnalystKnowledgeRecord[]): AggregatedTechnique[] {
  const map = new Map<string, AggregatedTechnique>();

  for (const r of records) {
    const techId = r.techniques_id ? r.techniques_id.trim().toUpperCase() : null;
    if (!techId || INVALID_TOKENS.has(techId.toLowerCase())) continue;

    if (!map.has(techId)) {
      map.set(techId, {
        id: techId,
        name: r.techniques_name?.trim() || techId,
        description: r.techniques_description?.trim() || '',
        tactics: [],
        platforms: [],
        detectionStrategyIds: [],
        analyticIds: [],
        logSources: [],
        dataComponentIds: [],
        dataComponentNames: [],
        recordCount: 0,
      });
    }

    const item = map.get(techId)!;
    item.recordCount++;

    if (r.techniques_name?.trim() && item.name === techId) {
      item.name = r.techniques_name.trim();
    }
    if (r.techniques_description?.trim() && !item.description) {
      item.description = r.techniques_description.trim();
    }

    for (const t of splitTokens(r.techniques_tactics)) {
      const canonical = normalizeTacticToken(t);
      if (!item.tactics.includes(canonical)) item.tactics.push(canonical);
    }

    for (const p of splitTokens(r.techniques_platforms)) {
      const canonical = normalizePlatformToken(p);
      if (!item.platforms.includes(canonical)) item.platforms.push(canonical);
    }

    if (r.detection_strategy_attack_id?.trim()) {
      const sid = r.detection_strategy_attack_id.trim();
      if (!item.detectionStrategyIds.includes(sid)) item.detectionStrategyIds.push(sid);
    }

    if (r.analytic_id?.trim()) {
      const aid = r.analytic_id.trim();
      if (!item.analyticIds.includes(aid)) item.analyticIds.push(aid);
    }

    for (const l of splitTokens(r.log_source_name)) {
      const norm = normalizeLogSourceToken(l);
      if (!item.logSources.includes(norm)) item.logSources.push(norm);
    }

    if (r.data_components_id?.trim()) {
      const dcId = r.data_components_id.trim();
      if (!item.dataComponentIds.includes(dcId)) item.dataComponentIds.push(dcId);
    }
    if (r.data_components_name?.trim()) {
      const dcName = r.data_components_name.trim();
      if (!item.dataComponentNames.includes(dcName)) item.dataComponentNames.push(dcName);
    }
  }

  const list = Array.from(map.values());
  list.sort((a, b) => a.id.localeCompare(b.id));
  return list;
}

/**
 * Extracts and deduplicates Detection Strategies for Page 2 (Detection Strategy Explorer)
 */
export function extractDetectionStrategies(
  records: SocAnalystKnowledgeRecord[]
): AggregatedDetectionStrategy[] {
  const map = new Map<string, AggregatedDetectionStrategy>();

  for (const r of records) {
    const stratId = r.detection_strategy_attack_id ? r.detection_strategy_attack_id.trim() : null;
    if (!stratId || INVALID_TOKENS.has(stratId.toLowerCase())) continue;

    if (!map.has(stratId)) {
      map.set(stratId, {
        strategyId: stratId,
        strategyName: r.detection_strategy_name?.trim() || stratId,
        associatedTechniques: [],
        associatedTactics: [],
        associatedAnalytics: [],
        associatedLogSources: [],
        recordCount: 0,
      });
    }

    const item = map.get(stratId)!;
    item.recordCount++;

    if (r.detection_strategy_name?.trim() && item.strategyName === stratId) {
      item.strategyName = r.detection_strategy_name.trim();
    }

    if (r.techniques_id?.trim()) {
      const tid = r.techniques_id.trim().toUpperCase();
      const tname = r.techniques_name?.trim() || tid;
      if (!item.associatedTechniques.some((t) => t.id === tid)) {
        item.associatedTechniques.push({ id: tid, name: tname });
      }
    }

    for (const t of splitTokens(r.techniques_tactics)) {
      const canonical = normalizeTacticToken(t);
      if (!item.associatedTactics.includes(canonical)) item.associatedTactics.push(canonical);
    }

    if (r.analytic_id?.trim()) {
      const aid = r.analytic_id.trim();
      const aname = r.analytic_name?.trim() || aid;
      if (!item.associatedAnalytics.some((a) => a.id === aid)) {
        item.associatedAnalytics.push({ id: aid, name: aname });
      }
    }

    for (const l of splitTokens(r.log_source_name)) {
      const norm = normalizeLogSourceToken(l);
      if (!item.associatedLogSources.includes(norm)) item.associatedLogSources.push(norm);
    }
  }

  const list = Array.from(map.values());
  list.sort((a, b) => {
    if (b.associatedTechniques.length !== a.associatedTechniques.length) {
      return b.associatedTechniques.length - a.associatedTechniques.length;
    }
    return a.strategyId.localeCompare(b.strategyId);
  });
  return list;
}

/**
 * Extracts and deduplicates Analytics for Page 3 (Analytic Explorer)
 */
export function extractAnalytics(records: SocAnalystKnowledgeRecord[]): AggregatedAnalytic[] {
  const map = new Map<string, AggregatedAnalytic>();

  for (const r of records) {
    const aid = r.analytic_id ? r.analytic_id.trim() : null;
    if (!aid || INVALID_TOKENS.has(aid.toLowerCase())) continue;

    if (!map.has(aid)) {
      map.set(aid, {
        analyticId: aid,
        analyticName: r.analytic_name?.trim() || aid,
        associatedTechniques: [],
        associatedLogSources: [],
        associatedDataComponents: [],
        associatedTactics: [],
        recordCount: 0,
      });
    }

    const item = map.get(aid)!;
    item.recordCount++;

    if (r.analytic_name?.trim() && item.analyticName === aid) {
      item.analyticName = r.analytic_name.trim();
    }

    if (r.techniques_id?.trim()) {
      const tid = r.techniques_id.trim().toUpperCase();
      const tname = r.techniques_name?.trim() || tid;
      if (!item.associatedTechniques.some((t) => t.id === tid)) {
        item.associatedTechniques.push({ id: tid, name: tname });
      }
    }

    for (const l of splitTokens(r.log_source_name)) {
      const norm = normalizeLogSourceToken(l);
      if (!item.associatedLogSources.includes(norm)) item.associatedLogSources.push(norm);
    }

    if (r.data_components_id?.trim() || r.data_components_name?.trim()) {
      const dcId = r.data_components_id?.trim() || 'DC-UNKNOWN';
      const dcName = r.data_components_name?.trim() || dcId;
      if (!item.associatedDataComponents.some((d) => d.id === dcId)) {
        item.associatedDataComponents.push({ id: dcId, name: dcName });
      }
    }

    for (const t of splitTokens(r.techniques_tactics)) {
      const canonical = normalizeTacticToken(t);
      if (!item.associatedTactics.includes(canonical)) item.associatedTactics.push(canonical);
    }
  }

  const list = Array.from(map.values());
  list.sort((a, b) => a.analyticId.localeCompare(b.analyticId));
  return list;
}

/**
 * Extracts and deduplicates Log Sources for Page 4 (Log Source Explorer)
 */
export function extractLogSources(records: SocAnalystKnowledgeRecord[]): AggregatedLogSource[] {
  const map = new Map<string, AggregatedLogSource>();

  for (const r of records) {
    const tokens = splitTokens(r.log_source_name);
    const sourceTokens = tokens.length > 0 ? tokens : ['Unspecified / Custom Log Source'];

    for (const token of sourceTokens) {
      const display = normalizeLogSourceToken(token);
      const key = display.toLowerCase();

      if (!map.has(key)) {
        map.set(key, {
          logSourceName: display,
          associatedTechniques: [],
          associatedAnalytics: [],
          associatedDataComponents: [],
          recordCount: 0,
        });
      }

      const item = map.get(key)!;
      item.recordCount++;

      if (r.techniques_id?.trim()) {
        const tid = r.techniques_id.trim().toUpperCase();
        const tname = r.techniques_name?.trim() || tid;
        if (!item.associatedTechniques.some((t) => t.id === tid)) {
          item.associatedTechniques.push({ id: tid, name: tname });
        }
      }

      if (r.analytic_id?.trim()) {
        const aid = r.analytic_id.trim();
        const aname = r.analytic_name?.trim() || aid;
        if (!item.associatedAnalytics.some((a) => a.id === aid)) {
          item.associatedAnalytics.push({ id: aid, name: aname });
        }
      }

      if (r.data_components_id?.trim() || r.data_components_name?.trim()) {
        const dcId = r.data_components_id?.trim() || 'DC-UNKNOWN';
        const dcName = r.data_components_name?.trim() || dcId;
        if (!item.associatedDataComponents.some((d) => d.id === dcId)) {
          item.associatedDataComponents.push({ id: dcId, name: dcName });
        }
      }
    }
  }

  const list = Array.from(map.values());
  list.sort((a, b) => {
    if (b.associatedTechniques.length !== a.associatedTechniques.length) {
      return b.associatedTechniques.length - a.associatedTechniques.length;
    }
    return a.logSourceName.localeCompare(b.logSourceName);
  });
  return list;
}

/**
 * Extracts and deduplicates Data Components for Page 5 (Data Component Explorer)
 */
export function extractDataComponents(
  records: SocAnalystKnowledgeRecord[]
): AggregatedDataComponent[] {
  const map = new Map<string, AggregatedDataComponent>();

  for (const r of records) {
    const dcId = r.data_components_id ? r.data_components_id.trim() : null;
    const dcName = r.data_components_name ? r.data_components_name.trim() : null;

    if (!dcId && !dcName) continue;
    const key = (dcId || dcName)!.toLowerCase();

    if (!map.has(key)) {
      map.set(key, {
        componentId: dcId || 'DC-UNKNOWN',
        componentName: dcName || dcId || 'Data Component',
        associatedTechniques: [],
        associatedTactics: [],
        associatedLogSources: [],
        associatedAnalytics: [],
        recordCount: 0,
      });
    }

    const item = map.get(key)!;
    item.recordCount++;

    if (dcName && item.componentName === 'DC-UNKNOWN') {
      item.componentName = dcName;
    }

    if (r.techniques_id?.trim()) {
      const tid = r.techniques_id.trim().toUpperCase();
      const tname = r.techniques_name?.trim() || tid;
      if (!item.associatedTechniques.some((t) => t.id === tid)) {
        item.associatedTechniques.push({ id: tid, name: tname });
      }
    }

    for (const t of splitTokens(r.techniques_tactics)) {
      const canonical = normalizeTacticToken(t);
      if (!item.associatedTactics.includes(canonical)) item.associatedTactics.push(canonical);
    }

    for (const l of splitTokens(r.log_source_name)) {
      const norm = normalizeLogSourceToken(l);
      if (!item.associatedLogSources.includes(norm)) item.associatedLogSources.push(norm);
    }

    if (r.analytic_id?.trim()) {
      const aid = r.analytic_id.trim();
      const aname = r.analytic_name?.trim() || aid;
      if (!item.associatedAnalytics.some((a) => a.id === aid)) {
        item.associatedAnalytics.push({ id: aid, name: aname });
      }
    }
  }

  const list = Array.from(map.values());
  list.sort((a, b) => {
    if (b.associatedTechniques.length !== a.associatedTechniques.length) {
      return b.associatedTechniques.length - a.associatedTechniques.length;
    }
    return a.componentId.localeCompare(b.componentId);
  });
  return list;
}

/**
 * Generates active filter chips from filter state
 */
export function buildActiveFilterChips(filters: SocKnowledgeFilters): ActiveFilterChip[] {
  const chips: ActiveFilterChip[] = [];

  if (filters.searchQuery.trim()) {
    chips.push({
      id: `search:${filters.searchQuery}`,
      dimension: 'search',
      label: `Search: "${filters.searchQuery.trim()}"`,
      value: filters.searchQuery.trim(),
    });
  }

  for (const t of filters.selectedTactics) {
    chips.push({
      id: `tactic:${t}`,
      dimension: 'tactic',
      label: `Tactic: ${t}`,
      value: t,
    });
  }

  for (const p of filters.selectedPlatforms) {
    chips.push({
      id: `platform:${p}`,
      dimension: 'platform',
      label: `Platform: ${p}`,
      value: p,
    });
  }

  for (const l of filters.selectedLogSources) {
    chips.push({
      id: `log_source:${l}`,
      dimension: 'log_source',
      label: `Log Source: ${l}`,
      value: l,
    });
  }

  for (const d of filters.selectedDataComponents) {
    chips.push({
      id: `data_component:${d}`,
      dimension: 'data_component',
      label: `Data Component: ${d}`,
      value: d,
    });
  }

  for (const s of filters.selectedStrategies) {
    chips.push({
      id: `strategy:${s}`,
      dimension: 'strategy',
      label: `Strategy: ${s}`,
      value: s,
    });
  }

  return chips;
}
