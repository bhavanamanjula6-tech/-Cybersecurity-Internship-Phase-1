/**
 * CyberOps SOC — IT Operations Knowledge Filter Engine & Aggregations
 *
 * Implements deterministic token splitting, canonical normalization,
 * set-based deduplication, Top 5 ranking, and cross-filtering for IT Operations.
 *
 * Scoped to public.it_operations_knowledge columns:
 * - technique_id, technique_name, technique_tactics, technique_platforms,
 *   mitigation_id, mitigation_name, mitigation_description, source_id, target_id,
 *   mapping_type, platform_name, tactic_id, tactic_name
 */

import { ItOperationsKnowledgeRecord } from '../../../services/knowledgeService';
import {
  ItOpsKnowledgeFilters,
  ItOpsOverviewKpis,
  AggregatedItOpsTechnique,
  AggregatedItOpsMitigation,
  AggregatedItOpsPlatform,
  AggregatedItOpsTactic,
  ActiveItOpsFilterChip,
} from './types';
import { BarChartItem } from '../../analyst/knowledge/charts/InteractiveBarChart';
import { DonutChartItem } from '../../analyst/knowledge/charts/InteractiveDonutChart';

export const INITIAL_ITOPS_FILTERS: ItOpsKnowledgeFilters = {
  searchQuery: '',
  selectedPlatforms: [],
  selectedTactics: [],
  selectedMitigations: [],
};

const INVALID_SENTINELS = new Set(['none', 'null', 'n/a', 'na', 'unknown', 'undefined', '', '-', '--']);

/**
 * Splits delimited multi-value fields on commas, semicolons, pipes, and newlines.
 * Discards empty and sentinel tokens.
 */
export function splitTokens(raw: string | null | undefined): string[] {
  if (!raw || typeof raw !== 'string') return [];
  const tokens = raw.split(/[,;|\r\n]+/);
  const result: string[] = [];
  for (const t of tokens) {
    const trimmed = t.trim();
    if (trimmed && !INVALID_SENTINELS.has(trimmed.toLowerCase())) {
      result.push(trimmed);
    }
  }
  return result;
}

/** Canonical Platform Normalization */
export function normalizePlatformToken(raw: string): string {
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();
  switch (lower) {
    case 'windows':
      return 'Windows';
    case 'linux':
      return 'Linux';
    case 'macos':
    case 'mac':
      return 'macOS';
    case 'containers':
    case 'container':
      return 'Containers';
    case 'kubernetes':
      return 'Kubernetes';
    case 'network':
      return 'Network';
    case 'iaas':
      return 'IaaS';
    case 'saas':
      return 'SaaS';
    case 'paas':
      return 'PaaS';
    case 'esxi':
      return 'ESXi';
    case 'pre':
      return 'PRE';
    default:
      return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  }
}

/** Canonical ATT&CK Tactic Normalization */
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
  // ATT&CK Enterprise Tactic IDs
  'ta0043': 'Reconnaissance',
  'ta0042': 'Resource Development',
  'ta0001': 'Initial Access',
  'ta0002': 'Execution',
  'ta0003': 'Persistence',
  'ta0004': 'Privilege Escalation',
  'ta0005': 'Defense Evasion',
  'ta0006': 'Credential Access',
  'ta0007': 'Discovery',
  'ta0008': 'Lateral Movement',
  'ta0009': 'Collection',
  'ta0011': 'Command and Control',
  'ta0010': 'Exfiltration',
  'ta0040': 'Impact',
};

export function normalizeTacticToken(raw: string): string {
  const trimmed = raw.trim();
  if (INVALID_SENTINELS.has(trimmed.toLowerCase())) {
    return '';
  }
  const cleanKey = trimmed.toLowerCase().replace(/[-_]/g, ' ').replace(/\s+/g, ' ').trim();
  if (KNOWN_TACTIC_NAMES[cleanKey]) {
    return KNOWN_TACTIC_NAMES[cleanKey];
  }
  return trimmed
    .replace(/[-_]/g, ' ')
    .split(/\s+/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

/**
 * Extracts and deduplicates distinct ATT&CK Techniques for IT Operations
 */
export function extractItOpsTechniques(
  records: ItOperationsKnowledgeRecord[]
): AggregatedItOpsTechnique[] {
  const map = new Map<string, AggregatedItOpsTechnique>();

  for (const r of records) {
    const rawId = r.technique_id?.trim();
    if (!rawId || INVALID_SENTINELS.has(rawId.toLowerCase())) continue;
    const tid = rawId.toUpperCase();

    if (!map.has(tid)) {
      map.set(tid, {
        id: tid,
        name: r.technique_name?.trim() || tid,
        platforms: [],
        tactics: [],
        mitigations: [],
        recordCount: 0,
      });
    }

    const tech = map.get(tid)!;
    tech.recordCount++;

    if (r.technique_name?.trim() && tech.name === tid) {
      tech.name = r.technique_name.trim();
    }

    // Platforms (prefer platform_name, fallback to technique_platforms)
    const platformRaw = r.platform_name?.trim() || r.technique_platforms;
    for (const p of splitTokens(platformRaw)) {
      const canonical = normalizePlatformToken(p);
      if (!tech.platforms.includes(canonical)) tech.platforms.push(canonical);
    }

    // Tactics (prefer tactic_name, fallback to technique_tactics)
    const tacticRaw = r.tactic_name?.trim() || r.technique_tactics;
    for (const t of splitTokens(tacticRaw)) {
      const canonical = normalizeTacticToken(t);
      if (!tech.tactics.includes(canonical)) tech.tactics.push(canonical);
    }

    // Mitigations
    const mitId = r.mitigation_id?.trim();
    if (mitId && !INVALID_SENTINELS.has(mitId.toLowerCase())) {
      const canonicalMitId = mitId.toUpperCase();
      if (!tech.mitigations.some((m) => m.id === canonicalMitId)) {
        tech.mitigations.push({
          id: canonicalMitId,
          name: r.mitigation_name?.trim() || canonicalMitId,
          description: r.mitigation_description?.trim() || 'No description available.',
        });
      }
    }
  }

  const list = Array.from(map.values());
  // Sort alphabetically by ID
  list.sort((a, b) => a.id.localeCompare(b.id));
  return list;
}

/**
 * Extracts and deduplicates distinct Mitigations for IT Operations
 */
export function extractItOpsMitigations(
  records: ItOperationsKnowledgeRecord[]
): AggregatedItOpsMitigation[] {
  const map = new Map<string, AggregatedItOpsMitigation>();

  for (const r of records) {
    const rawMitId = r.mitigation_id?.trim();
    if (!rawMitId || INVALID_SENTINELS.has(rawMitId.toLowerCase())) continue;
    const mid = rawMitId.toUpperCase();

    if (!map.has(mid)) {
      map.set(mid, {
        id: mid,
        name: r.mitigation_name?.trim() || mid,
        description: r.mitigation_description?.trim() || 'No description cataloged in dataset.',
        associatedTechniques: [],
        associatedPlatforms: [],
        associatedTactics: [],
        recordCount: 0,
      });
    }

    const mit = map.get(mid)!;
    mit.recordCount++;

    if (r.mitigation_name?.trim() && mit.name === mid) {
      mit.name = r.mitigation_name.trim();
    }
    if (r.mitigation_description?.trim() && mit.description === 'No description cataloged in dataset.') {
      mit.description = r.mitigation_description.trim();
    }

    // Associated Technique
    const rawTechId = r.technique_id?.trim();
    if (rawTechId && !INVALID_SENTINELS.has(rawTechId.toLowerCase())) {
      const tid = rawTechId.toUpperCase();
      const tname = r.technique_name?.trim() || tid;
      if (!mit.associatedTechniques.some((t) => t.id === tid)) {
        mit.associatedTechniques.push({ id: tid, name: tname });
      }
    }

    // Associated Platforms
    const platformRaw = r.platform_name?.trim() || r.technique_platforms;
    for (const p of splitTokens(platformRaw)) {
      const canonical = normalizePlatformToken(p);
      if (!mit.associatedPlatforms.includes(canonical)) mit.associatedPlatforms.push(canonical);
    }

    // Associated Tactics
    const tacticRaw = r.tactic_name?.trim() || r.technique_tactics;
    for (const t of splitTokens(tacticRaw)) {
      const canonical = normalizeTacticToken(t);
      if (!mit.associatedTactics.includes(canonical)) mit.associatedTactics.push(canonical);
    }
  }

  const list = Array.from(map.values());
  // Sort descending by associated technique count, then by mitigation ID
  list.sort((a, b) => {
    if (b.associatedTechniques.length !== a.associatedTechniques.length) {
      return b.associatedTechniques.length - a.associatedTechniques.length;
    }
    return a.id.localeCompare(b.id);
  });
  return list;
}

/**
 * Calculates accurate KPIs from actual records:
 * - Total Cataloged Techniques (distinct technique_id)
 * - Supported Platforms (distinct platform_name / technique_platforms)
 * - Enterprise Mitigations (distinct mitigation_id)
 * - Covered Tactics (distinct tactic_name / technique_tactics)
 */
export function calculateItOpsKpis(
  records: ItOperationsKnowledgeRecord[]
): ItOpsOverviewKpis {
  const techniqueSet = new Set<string>();
  const platformSet = new Set<string>();
  const mitigationSet = new Set<string>();
  const tacticSet = new Set<string>();

  for (const r of records) {
    if (r.technique_id?.trim() && !INVALID_SENTINELS.has(r.technique_id.trim().toLowerCase())) {
      techniqueSet.add(r.technique_id.trim().toUpperCase());
    }

    const platformRaw = r.platform_name?.trim() || r.technique_platforms;
    for (const p of splitTokens(platformRaw)) {
      const canonical = normalizePlatformToken(p);
      if (canonical && !INVALID_SENTINELS.has(canonical.toLowerCase())) {
        platformSet.add(canonical);
      }
    }

    if (r.mitigation_id?.trim() && !INVALID_SENTINELS.has(r.mitigation_id.trim().toLowerCase())) {
      mitigationSet.add(r.mitigation_id.trim().toUpperCase());
    }

    const tacticRaw = r.tactic_name?.trim() || r.technique_tactics;
    for (const t of splitTokens(tacticRaw)) {
      const canonical = normalizeTacticToken(t);
      if (canonical && !INVALID_SENTINELS.has(canonical.toLowerCase())) {
        tacticSet.add(canonical);
      }
    }
  }

  return {
    totalCatalogedTechniques: techniqueSet.size,
    supportedPlatforms: platformSet.size,
    enterpriseMitigations: mitigationSet.size,
    coveredTactics: tacticSet.size,
  };
}

/**
 * Aggregates Techniques by Platform for IT Operations:
 * Counts distinct technique_id per computing platform.
 * Returns sorted list descending by technique count with secondary label tie-breaker.
 */
export function aggregateTechniquesByPlatform(
  records: ItOperationsKnowledgeRecord[]
): AggregatedItOpsPlatform[] {
  const platformToTechs = new Map<string, Set<string>>();

  for (const r of records) {
    const rawTechId = r.technique_id?.trim();
    if (!rawTechId || INVALID_SENTINELS.has(rawTechId.toLowerCase())) continue;
    const tid = rawTechId.toUpperCase();

    const platformRaw = r.platform_name?.trim() || r.technique_platforms;
    const tokens = splitTokens(platformRaw);
    const platforms = tokens.length > 0 ? tokens : ['Unspecified Platform'];

    for (const p of platforms) {
      const canonical = p === 'Unspecified Platform' ? p : normalizePlatformToken(p);
      if (!platformToTechs.has(canonical)) {
        platformToTechs.set(canonical, new Set<string>());
      }
      platformToTechs.get(canonical)!.add(tid);
    }
  }

  const allTechs = new Set<string>();
  for (const set of platformToTechs.values()) {
    for (const tid of set) allTechs.add(tid);
  }
  const totalUniqueTechs = allTechs.size || 1;

  const result: AggregatedItOpsPlatform[] = Array.from(platformToTechs.entries()).map(
    ([platform, techSet]) => ({
      platform,
      distinctTechniqueCount: techSet.size,
      distinctTechniquesCount: techSet.size,
      percentage: Math.round((techSet.size / totalUniqueTechs) * 1000) / 10,
    })
  );

  result.sort((a, b) => {
    if (b.distinctTechniqueCount !== a.distinctTechniqueCount) {
      return b.distinctTechniqueCount - a.distinctTechniqueCount;
    }
    return a.platform.localeCompare(b.platform);
  });

  return result;
}

/**
 * Prepares items for BarChartItem[] for Top 5 Platforms by Technique Coverage
 */
export function buildPlatformBarChartItems(
  platforms: AggregatedItOpsPlatform[],
  selectedPlatforms: string[] = []
): BarChartItem[] {
  return platforms.map((p) => ({
    id: p.platform,
    label: p.platform,
    count: p.distinctTechniqueCount,
    percentage: p.percentage,
    isSelected: selectedPlatforms.includes(p.platform),
  }));
}

/**
 * Prepares items for DonutChartItem[] for Platform Distribution Share
 */
export function buildPlatformDonutChartItems(
  platforms: AggregatedItOpsPlatform[],
  selectedPlatforms: string[] = []
): DonutChartItem[] {
  return platforms.map((p) => ({
    id: p.platform,
    label: p.platform,
    count: p.distinctTechniqueCount,
    isSelected: selectedPlatforms.includes(p.platform),
  }));
}

/**
 * Aggregates Techniques by Tactic for IT Operations:
 * Counts distinct technique_id per ATT&CK tactic.
 * Returns sorted list descending by distinct technique count with secondary alphabetical tie-breaker.
 */
export function aggregateTechniquesByTactic(
  records: ItOperationsKnowledgeRecord[]
): AggregatedItOpsTactic[] {
  const tacticToTechs = new Map<string, Set<string>>();

  for (const r of records) {
    const rawTechId = r.technique_id?.trim();
    if (!rawTechId || INVALID_SENTINELS.has(rawTechId.toLowerCase())) continue;
    const tid = rawTechId.toUpperCase();

    const tacticRaw = r.tactic_name?.trim() || r.technique_tactics;
    const tokens = splitTokens(tacticRaw);

    for (const t of tokens) {
      const canonical = normalizeTacticToken(t);
      if (!canonical || INVALID_SENTINELS.has(canonical.toLowerCase())) continue;
      if (!tacticToTechs.has(canonical)) {
        tacticToTechs.set(canonical, new Set<string>());
      }
      tacticToTechs.get(canonical)!.add(tid);
    }
  }

  const allTechs = new Set<string>();
  for (const set of tacticToTechs.values()) {
    for (const tid of set) allTechs.add(tid);
  }
  const totalUniqueTechs = allTechs.size || 1;

  const result: AggregatedItOpsTactic[] = Array.from(tacticToTechs.entries()).map(
    ([tactic, techSet]) => ({
      tactic,
      distinctTechniqueCount: techSet.size,
      distinctTechniquesCount: techSet.size,
      percentage: Math.round((techSet.size / totalUniqueTechs) * 1000) / 10,
    })
  );

  result.sort((a, b) => {
    if (b.distinctTechniqueCount !== a.distinctTechniqueCount) {
      return b.distinctTechniqueCount - a.distinctTechniqueCount;
    }
    return a.tactic.localeCompare(b.tactic);
  });

  return result;
}

/**
 * Prepares items for BarChartItem[] for Top 5 Tactics by Technique Coverage
 */
export function buildTacticBarChartItems(
  tactics: AggregatedItOpsTactic[],
  selectedTactics: string[] = []
): BarChartItem[] {
  return tactics.map((t) => ({
    id: t.tactic,
    label: t.tactic,
    count: t.distinctTechniqueCount,
    percentage: t.percentage,
    isSelected: selectedTactics.includes(t.tactic),
  }));
}

/**
 * Cross-filters raw ItOperationsKnowledgeRecords by filters
 */
export function applyItOpsKnowledgeFilters(
  records: ItOperationsKnowledgeRecord[],
  filters: ItOpsKnowledgeFilters
): ItOperationsKnowledgeRecord[] {
  const query = filters.searchQuery.toLowerCase().trim();

  return records.filter((r) => {
    // 1. Text Search across ID, name, tactics, platforms, mitigations
    if (query) {
      const matchId = r.technique_id?.toLowerCase().includes(query);
      const matchName = r.technique_name?.toLowerCase().includes(query);
      const matchTactic = (r.tactic_name || r.technique_tactics)?.toLowerCase().includes(query);
      const matchPlatform = (r.platform_name || r.technique_platforms)?.toLowerCase().includes(query);
      const matchMitId = r.mitigation_id?.toLowerCase().includes(query);
      const matchMitName = r.mitigation_name?.toLowerCase().includes(query);
      if (!matchId && !matchName && !matchTactic && !matchPlatform && !matchMitId && !matchMitName) {
        return false;
      }
    }

    // 2. Selected Platforms (OR logic within dimension)
    if (filters.selectedPlatforms.length > 0) {
      const rawPlatform = r.platform_name?.trim() || r.technique_platforms;
      const tokens = splitTokens(rawPlatform).map(normalizePlatformToken);
      const hasMatch = filters.selectedPlatforms.some((sp) => tokens.includes(sp));
      if (!hasMatch) return false;
    }

    // 3. Selected Tactics (OR logic within dimension)
    if (filters.selectedTactics.length > 0) {
      const rawTactic = r.tactic_name?.trim() || r.technique_tactics;
      const tokens = splitTokens(rawTactic).map(normalizeTacticToken);
      const hasMatch = filters.selectedTactics.some((st) => tokens.includes(st));
      if (!hasMatch) return false;
    }

    // 4. Selected Mitigations (OR logic within dimension)
    if (filters.selectedMitigations.length > 0) {
      const mitId = r.mitigation_id?.trim()?.toUpperCase();
      if (!mitId || !filters.selectedMitigations.includes(mitId)) {
        return false;
      }
    }

    return true;
  });
}

/**
 * Filters pre-aggregated techniques
 */
export function filterAggregatedTechniques(
  techniques: AggregatedItOpsTechnique[],
  filters: ItOpsKnowledgeFilters
): AggregatedItOpsTechnique[] {
  const query = filters.searchQuery.toLowerCase().trim();

  return techniques.filter((t) => {
    if (query) {
      const matchId = t.id.toLowerCase().includes(query);
      const matchName = t.name.toLowerCase().includes(query);
      const matchPlatform = t.platforms.some((p) => p.toLowerCase().includes(query));
      const matchTactic = t.tactics.some((tac) => tac.toLowerCase().includes(query));
      const matchMit = t.mitigations.some(
        (m) => m.id.toLowerCase().includes(query) || m.name.toLowerCase().includes(query)
      );
      if (!matchId && !matchName && !matchPlatform && !matchTactic && !matchMit) return false;
    }

    if (filters.selectedPlatforms.length > 0) {
      const hasPlatform = filters.selectedPlatforms.some((sp) => t.platforms.includes(sp));
      if (!hasPlatform) return false;
    }

    if (filters.selectedTactics.length > 0) {
      const hasTactic = filters.selectedTactics.some((st) => t.tactics.includes(st));
      if (!hasTactic) return false;
    }

    if (filters.selectedMitigations.length > 0) {
      const hasMit = filters.selectedMitigations.some((sm) => t.mitigations.some((m) => m.id === sm));
      if (!hasMit) return false;
    }

    return true;
  });
}

/**
 * Filters pre-aggregated mitigations
 */
export function filterAggregatedMitigations(
  mitigations: AggregatedItOpsMitigation[],
  filters: ItOpsKnowledgeFilters
): AggregatedItOpsMitigation[] {
  const query = filters.searchQuery.toLowerCase().trim();

  return mitigations.filter((m) => {
    if (query) {
      const matchId = m.id.toLowerCase().includes(query);
      const matchName = m.name.toLowerCase().includes(query);
      const matchDesc = m.description.toLowerCase().includes(query);
      const matchTech = m.associatedTechniques.some(
        (t) => t.id.toLowerCase().includes(query) || t.name.toLowerCase().includes(query)
      );
      if (!matchId && !matchName && !matchDesc && !matchTech) return false;
    }

    if (filters.selectedPlatforms.length > 0) {
      const hasPlatform = filters.selectedPlatforms.some((sp) => m.associatedPlatforms.includes(sp));
      if (!hasPlatform) return false;
    }

    if (filters.selectedTactics.length > 0) {
      const hasTactic = filters.selectedTactics.some((st) => m.associatedTactics.includes(st));
      if (!hasTactic) return false;
    }

    if (filters.selectedMitigations.length > 0) {
      if (!filters.selectedMitigations.includes(m.id)) return false;
    }

    return true;
  });
}

/**
 * Builds active filter chips for IT Operations
 */
export function buildItOpsActiveFilterChips(
  filters: ItOpsKnowledgeFilters
): ActiveItOpsFilterChip[] {
  const chips: ActiveItOpsFilterChip[] = [];

  if (filters.searchQuery.trim()) {
    chips.push({
      id: `search:${filters.searchQuery}`,
      dimension: 'search',
      label: `Search: "${filters.searchQuery.trim()}"`,
      value: filters.searchQuery.trim(),
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

  for (const t of filters.selectedTactics) {
    chips.push({
      id: `tactic:${t}`,
      dimension: 'tactic',
      label: `Tactic: ${t}`,
      value: t,
    });
  }

  for (const m of filters.selectedMitigations) {
    chips.push({
      id: `mitigation:${m}`,
      dimension: 'mitigation',
      label: `Mitigation: ${m}`,
      value: m,
    });
  }

  return chips;
}
