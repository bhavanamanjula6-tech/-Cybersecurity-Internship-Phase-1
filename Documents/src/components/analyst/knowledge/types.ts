/**
 * CyberOps SOC — SOC Analyst Knowledge Base & 6 Knowledge Pages Type Definitions
 *
 * Scoped strictly to the SOC Analyst domain:
 * - Reference table: public.soc_analyst_knowledge
 * - Columns: techniques_id, techniques_name, techniques_description, techniques_tactics,
 *   techniques_platforms, detection_strategy_attack_id, detection_strategy_name,
 *   analytic_id, analytic_name, log_source_name, data_components_id, data_components_name
 *
 * Invariant: Never includes mitigation metrics or mitigation fields (restricted to Security Engineer).
 */

import { SocAnalystKnowledgeRecord } from '../../../services/knowledgeService';

export type SocKnowledgeView =
  | 'overview'
  | 'strategies'
  | 'analytics'
  | 'log_sources'
  | 'data_components'
  | 'mitre_explorer';

export type SocKnowledgeTab =
  | 'overview'
  | 'strategies'
  | 'analytics'
  | 'log-sources'
  | 'data-components'
  | 'techniques';

export interface SocKnowledgeFilters {
  searchQuery: string;
  selectedTactics: string[];
  selectedPlatforms: string[];
  selectedLogSources: string[];
  selectedDataComponents: string[];
  selectedStrategies: string[];
}

export interface ActiveFilterChip {
  id: string;
  dimension: 'search' | 'tactic' | 'platform' | 'log_source' | 'data_component' | 'strategy';
  label: string;
  value: string;
}

export interface SocOverviewKpis {
  distinctTechniques: number;
  distinctTactics: number;
  distinctDetectionStrategies: number;
  distinctAnalytics: number;
  distinctLogSources: number;
  distinctDataComponents: number;
  totalRecords: number;
}

export interface TacticChartItem {
  tactic: string;
  distinctTechniques: number;
  percentage: number;
}

export interface LogSourceChartItem {
  logSource: string;
  distinctAnalytics: number;
  percentage: number;
}

export interface PlatformChartItem {
  platform: string;
  distinctTechniques: number;
  percentage: number;
}

export interface DetectionStrategyChartItem {
  strategyId: string;
  strategyName: string;
  distinctTechniques: number;
  tactics?: string[];
}

export interface DataComponentChartItem {
  componentId: string;
  componentName: string;
  distinctTechniques: number;
}

export interface StrategyTacticChartItem {
  tactic: string;
  distinctStrategies: number;
}

export interface AnalyticTacticChartItem {
  tactic: string;
  distinctAnalytics: number;
}

export interface DataComponentTacticChartItem {
  tactic: string;
  distinctDataComponents: number;
}

export interface MatrixCell {
  row: string;
  col: string;
  count: number;
  items: string[];
}

export interface AggregatedTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  detectionStrategyIds: string[];
  analyticIds: string[];
  logSources: string[];
  dataComponentIds: string[];
  dataComponentNames: string[];
  recordCount: number;
}

export interface AggregatedDetectionStrategy {
  strategyId: string;
  strategyName: string;
  associatedTechniques: Array<{ id: string; name: string }>;
  associatedTactics: string[];
  associatedAnalytics: Array<{ id: string; name: string }>;
  associatedLogSources: string[];
  recordCount: number;
}

export interface AggregatedAnalytic {
  analyticId: string;
  analyticName: string;
  associatedTechniques: Array<{ id: string; name: string }>;
  associatedLogSources: string[];
  associatedDataComponents: Array<{ id: string; name: string }>;
  associatedTactics: string[];
  recordCount: number;
}

export interface AggregatedLogSource {
  logSourceName: string;
  associatedTechniques: Array<{ id: string; name: string }>;
  associatedAnalytics: Array<{ id: string; name: string }>;
  associatedDataComponents: Array<{ id: string; name: string }>;
  recordCount: number;
}

export interface AggregatedDataComponent {
  componentId: string;
  componentName: string;
  associatedTechniques: Array<{ id: string; name: string }>;
  associatedTactics: string[];
  associatedLogSources: string[];
  associatedAnalytics: Array<{ id: string; name: string }>;
  recordCount: number;
}
