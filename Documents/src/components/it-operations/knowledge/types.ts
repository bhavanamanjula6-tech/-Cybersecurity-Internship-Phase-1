/**
 * CyberOps SOC — IT Operations Knowledge Types & Filters
 *
 * Scoped strictly to the IT Operations reference domain:
 * - Table: public.it_operations_knowledge
 * - Columns: technique_id, technique_name, technique_tactics, technique_platforms,
 *   mitigation_id, mitigation_name, mitigation_description, source_id, target_id,
 *   mapping_type, platform_name, tactic_id, tactic_name
 *
 * Invariant: Never invents physical CMDB columns or fabrication of endpoint devices.
 */

export type ItOpsKnowledgeView =
  | 'itops_overview'
  | 'itops_techniques'
  | 'itops_mitigations';

export interface ItOpsKnowledgeFilters {
  searchQuery: string;
  selectedPlatforms: string[];
  selectedTactics: string[];
  selectedMitigations: string[];
}

export interface ItOpsOverviewKpis {
  totalCatalogedTechniques: number;
  supportedPlatforms: number;
  enterpriseMitigations: number;
  coveredTactics: number;
}

export interface ItOpsTechniqueMitigationRef {
  id: string;
  name: string;
  description: string;
}

export interface AggregatedItOpsTechnique {
  id: string;
  name: string;
  platforms: string[];
  tactics: string[];
  mitigations: ItOpsTechniqueMitigationRef[];
  recordCount: number;
}

export interface AggregatedItOpsMitigation {
  id: string;
  name: string;
  description: string;
  associatedTechniques: Array<{ id: string; name: string }>;
  associatedPlatforms: string[];
  associatedTactics: string[];
  recordCount: number;
}

export interface AggregatedItOpsPlatform {
  platform: string;
  distinctTechniqueCount: number;
  distinctTechniquesCount: number;
  percentage: number;
}

export interface AggregatedItOpsTactic {
  tactic: string;
  distinctTechniqueCount: number;
  distinctTechniquesCount: number;
  percentage: number;
}

export interface ActiveItOpsFilterChip {
  id: string;
  dimension: 'search' | 'platform' | 'tactic' | 'mitigation';
  label: string;
  value: string;
}
