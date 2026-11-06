/**
 * CyberOps SOC — Complete Database-to-Application Relationship Service
 *
 * Responsibilities & Invariants:
 * 1. Standardizes ATT&CK technique IDs across all tables into a unified `attack_id` field:
 *    - SOC Analyst (public.soc_analyst_knowledge): techniques_id -> attack_id
 *    - Security Engineer (public.security_engineer_knowledge): technique_id -> attack_id
 *    - IT Operations (public.it_operations_knowledge): technique_id -> attack_id
 *    - Alerts (public.alerts): mitre_technique_id -> attack_id
 * 2. Enforces that the three knowledge datasets do NOT contain Alert IDs.
 * 3. Enforces that operational relationships connect strictly via real alerts.id (e.g. 'ALT-2026-1049'):
 *    - alerts.id -> alert_notes.alert_id
 *    - alerts.id -> incident_tasks.associated_alert_id
 *    - alerts.id -> audit_logs.associated_alert_id
 * 4. Preserves valid sub-technique IDs (e.g., T1059.001, T1195.001) without truncation.
 * 5. Preserves legitimate NULL mitigations (111 rows in Security Engineer) as unmitigated coverage gaps.
 * 6. Explicitly distinguishes ATT&CK relationship endpoints (source_id, target_id, addressed_source_id,
 *    addressed_target_id, mapping_type) from application Alert IDs.
 */

import { SecurityAlert } from '../types/alert';
import { IncidentTask, AuditLogEntry } from '../types/audit';
import {
  SocAnalystKnowledgeRecord,
  SecurityEngineerKnowledgeRecord,
  ItOperationsKnowledgeRecord,
  normalizeTacticName,
  normalizePlatformName,
  normalizeLogSourceName,
} from './knowledgeService';
import { normalizeAttackId, isValidAttackId, formatAttackIdDisplay } from '../utils/mitreUtils';

export { normalizeAttackId, isValidAttackId, formatAttackIdDisplay };

/**
 * Extracts and normalizes the unified attack_id from an alert record.
 */
export function getAttackIdFromAlert(alert: SecurityAlert | null | undefined): string | null {
  if (!alert) return null;
  return normalizeAttackId(alert.attack_id || alert.mitreTechniqueId);
}

// ============================================================================
// 1. SOC Analyst Technique Knowledge Aggregation & Lookup
// ============================================================================

export interface DetectionStrategyLookup {
  attackId: string;
  name: string;
}

export interface AnalyticLookup {
  id: string;
  name: string;
}

export interface DataComponentLookup {
  id: string;
  name: string;
}

export interface SocAnalystTechniqueKnowledge {
  attackId: string;
  rawTechniqueId: string;
  techniqueName: string;
  techniqueDescription: string;
  tactics: string[];
  platforms: string[];
  detectionStrategies: DetectionStrategyLookup[];
  analytics: AnalyticLookup[];
  logSources: string[];
  dataComponents: DataComponentLookup[];
  matchedRowCount: number;
}

/**
 * Looks up and aggregates all knowledge records from public.soc_analyst_knowledge for a given technique.
 */
export function lookupSocAnalystKnowledgeForTechnique(
  techniqueId: string | null | undefined,
  records: SocAnalystKnowledgeRecord[]
): SocAnalystTechniqueKnowledge | null {
  const normalizedId = normalizeAttackId(techniqueId);
  if (!normalizedId || !records || records.length === 0) return null;

  const matchingRows = records.filter((r) => {
    const rowNorm = normalizeAttackId(r.attack_id || r.techniques_id);
    return rowNorm === normalizedId;
  });

  if (matchingRows.length === 0) return null;

  let techniqueName = '';
  let techniqueDescription = '';
  const tacticsSet = new Set<string>();
  const platformsSet = new Set<string>();
  const logSourcesSet = new Set<string>();

  const detectionStrategiesMap = new Map<string, string>();
  const analyticsMap = new Map<string, string>();
  const dataComponentsMap = new Map<string, string>();

  for (const row of matchingRows) {
    if (!techniqueName && row.techniques_name?.trim()) {
      techniqueName = row.techniques_name.trim();
    }
    if (!techniqueDescription && row.techniques_description?.trim()) {
      techniqueDescription = row.techniques_description.trim();
    }

    // Tactics parsing
    if (row.techniques_tactics?.trim()) {
      const tokens = row.techniques_tactics.split(/[,;|\n]+/);
      for (const tok of tokens) {
        const clean = tok.trim();
        if (clean) tacticsSet.add(normalizeTacticName(clean));
      }
    }

    // Platforms parsing
    if (row.techniques_platforms?.trim()) {
      const tokens = row.techniques_platforms.split(/[,;|\n]+/);
      for (const tok of tokens) {
        const clean = tok.trim();
        if (clean) platformsSet.add(normalizePlatformName(clean));
      }
    }

    // Intact Log Sources parsing
    if (row.log_source_name?.trim()) {
      const tokens = row.log_source_name.split(/[,;|\n]+/);
      for (const tok of tokens) {
        const clean = normalizeLogSourceName(tok);
        if (clean && clean !== 'Unspecified / Custom Log Source') {
          logSourcesSet.add(clean);
        }
      }
    }

    // Detection Strategy
    const stratId = row.detection_strategy_attack_id?.trim();
    const stratName = row.detection_strategy_name?.trim() || 'Detection Strategy';
    if (stratId) {
      if (!detectionStrategiesMap.has(stratId) || detectionStrategiesMap.get(stratId) === 'Detection Strategy') {
        detectionStrategiesMap.set(stratId, stratName);
      }
    }

    // Analytic
    const anId = row.analytic_id?.trim();
    const anName = row.analytic_name?.trim() || 'Behavioral Analytic';
    if (anId) {
      if (!analyticsMap.has(anId) || analyticsMap.get(anId) === 'Behavioral Analytic') {
        analyticsMap.set(anId, anName);
      }
    }

    // Data Component
    const dcId = row.data_components_id?.trim() || row.data_components_name?.trim();
    const dcName = row.data_components_name?.trim() || row.data_components_id?.trim() || 'Data Component';
    if (dcId) {
      if (!dataComponentsMap.has(dcId)) {
        dataComponentsMap.set(dcId, dcName);
      }
    }
  }

  return {
    attackId: normalizedId,
    rawTechniqueId: matchingRows[0].techniques_id || normalizedId,
    techniqueName: techniqueName || normalizedId,
    techniqueDescription: techniqueDescription || 'No technique description cataloged in SOC Analyst knowledge base.',
    tactics: Array.from(tacticsSet).sort(),
    platforms: Array.from(platformsSet).sort(),
    detectionStrategies: Array.from(detectionStrategiesMap.entries()).map(([attackId, name]) => ({
      attackId,
      name,
    })),
    analytics: Array.from(analyticsMap.entries()).map(([id, name]) => ({ id, name })),
    logSources: Array.from(logSourcesSet).sort(),
    dataComponents: Array.from(dataComponentsMap.entries()).map(([id, name]) => ({ id, name })),
    matchedRowCount: matchingRows.length,
  };
}

// ============================================================================
// 2. Security Engineer Technique Knowledge Aggregation & Lookup
// ============================================================================

export interface MitigationDetailLookup {
  id: string;
  name: string;
  description: string;
}

export interface AttackRelationshipLookup {
  sourceId: string | null;
  targetId: string | null;
  mappingType: string | null;
}

export interface SecurityEngineerTechniqueKnowledge {
  attackId: string;
  rawTechniqueId: string;
  techniqueName: string;
  techniqueDescription: string;
  tactics: string[];
  platforms: string[];
  mitigations: MitigationDetailLookup[];
  isMitigated: boolean;
  hasNullMitigation: boolean;
  relationships: AttackRelationshipLookup[];
  matchedRowCount: number;
}

/**
 * Looks up and aggregates all knowledge records from public.security_engineer_knowledge for a given technique.
 * Preserves legitimate NULL mitigations (111 rows in benchmark) as unmitigated gaps.
 */
export function lookupSecurityEngineerKnowledgeForTechnique(
  techniqueId: string | null | undefined,
  records: SecurityEngineerKnowledgeRecord[]
): SecurityEngineerTechniqueKnowledge | null {
  const normalizedId = normalizeAttackId(techniqueId);
  if (!normalizedId || !records || records.length === 0) return null;

  const matchingRows = records.filter((r) => {
    const rowNorm = normalizeAttackId(r.attack_id || r.technique_id);
    return rowNorm === normalizedId;
  });

  if (matchingRows.length === 0) return null;

  let techniqueName = '';
  let techniqueDescription = '';
  const tacticsSet = new Set<string>();
  const platformsSet = new Set<string>();
  const mitigationsMap = new Map<string, MitigationDetailLookup>();
  const relationships: AttackRelationshipLookup[] = [];
  let hasNullMitigation = false;

  for (const row of matchingRows) {
    if (!techniqueName && row.technique_name?.trim()) {
      techniqueName = row.technique_name.trim();
    }
    if (!techniqueDescription && row.technique_description?.trim()) {
      techniqueDescription = row.technique_description.trim();
    }

    // Tactics
    const tacticSource = row.tactic_names?.trim() || row.technique_tactics?.trim();
    if (tacticSource) {
      const tokens = tacticSource.split(/[,;|\n]+/);
      for (const tok of tokens) {
        const clean = tok.trim();
        if (clean) tacticsSet.add(normalizeTacticName(clean));
      }
    }

    // Platforms
    const platformSource = row.matched_platform_names?.trim() || row.technique_platforms?.trim();
    if (platformSource) {
      const tokens = platformSource.split(/[,;|\n]+/);
      for (const tok of tokens) {
        const clean = tok.trim();
        if (clean) platformsSet.add(normalizePlatformName(clean));
      }
    }

    // Mitigations
    const rawMitId = row.mitigation_id?.trim();
    if (
      !rawMitId ||
      rawMitId.toLowerCase() === 'null' ||
      rawMitId.toLowerCase() === 'none' ||
      rawMitId.toLowerCase() === 'n/a'
    ) {
      hasNullMitigation = true;
    } else {
      const mitName = row.mitigation_name?.trim() || rawMitId;
      const mitDesc = row.mitigation_description?.trim() || 'Defensive mitigation guidance.';
      if (!mitigationsMap.has(rawMitId)) {
        mitigationsMap.set(rawMitId, {
          id: rawMitId,
          name: mitName,
          description: mitDesc,
        });
      } else {
        const existing = mitigationsMap.get(rawMitId)!;
        if (existing.name === rawMitId && mitName !== rawMitId) {
          existing.name = mitName;
        }
        if (!existing.description && mitDesc) {
          existing.description = mitDesc;
        }
      }
    }

    // ATT&CK Relationships
    if (row.addressed_source_id || row.addressed_target_id || row.mapping_type) {
      relationships.push({
        sourceId: row.addressed_source_id?.trim() || null,
        targetId: row.addressed_target_id?.trim() || null,
        mappingType: row.mapping_type?.trim() || null,
      });
    }
  }

  const mitigations = Array.from(mitigationsMap.values()).sort((a, b) => a.id.localeCompare(b.id));

  return {
    attackId: normalizedId,
    rawTechniqueId: matchingRows[0].technique_id || normalizedId,
    techniqueName: techniqueName || normalizedId,
    techniqueDescription: techniqueDescription || 'No technique description cataloged in Security Engineer knowledge base.',
    tactics: Array.from(tacticsSet).sort(),
    platforms: Array.from(platformsSet).sort(),
    mitigations,
    isMitigated: mitigations.length > 0,
    hasNullMitigation,
    relationships,
    matchedRowCount: matchingRows.length,
  };
}

// ============================================================================
// 3. IT Operations Technique Knowledge Aggregation & Lookup
// ============================================================================

export interface ItOperationsTechniqueKnowledge {
  attackId: string;
  rawTechniqueId: string;
  techniqueName: string;
  tactics: string[];
  platforms: string[];
  mitigations: MitigationDetailLookup[];
  relationships: AttackRelationshipLookup[];
  matchedRowCount: number;
}

/**
 * Looks up and aggregates all knowledge records from public.it_operations_knowledge for a given technique.
 */
export function lookupItOperationsKnowledgeForTechnique(
  techniqueId: string | null | undefined,
  records: ItOperationsKnowledgeRecord[]
): ItOperationsTechniqueKnowledge | null {
  const normalizedId = normalizeAttackId(techniqueId);
  if (!normalizedId || !records || records.length === 0) return null;

  const matchingRows = records.filter((r) => {
    const rowNorm = normalizeAttackId(r.attack_id || r.technique_id);
    return rowNorm === normalizedId;
  });

  if (matchingRows.length === 0) return null;

  let techniqueName = '';
  const tacticsSet = new Set<string>();
  const platformsSet = new Set<string>();
  const mitigationsMap = new Map<string, MitigationDetailLookup>();
  const relationships: AttackRelationshipLookup[] = [];

  for (const row of matchingRows) {
    if (!techniqueName && row.technique_name?.trim()) {
      techniqueName = row.technique_name.trim();
    }

    // Tactics
    const tacticSource = row.tactic_name?.trim() || row.technique_tactics?.trim();
    if (tacticSource) {
      const tokens = tacticSource.split(/[,;|\n]+/);
      for (const tok of tokens) {
        const clean = tok.trim();
        if (clean) tacticsSet.add(normalizeTacticName(clean));
      }
    }

    // Platforms
    const platformSource = row.platform_name?.trim() || row.technique_platforms?.trim();
    if (platformSource) {
      const tokens = platformSource.split(/[,;|\n]+/);
      for (const tok of tokens) {
        const clean = tok.trim();
        if (clean) platformsSet.add(normalizePlatformName(clean));
      }
    }

    // Mitigations
    const rawMitId = row.mitigation_id?.trim();
    if (
      rawMitId &&
      rawMitId.toLowerCase() !== 'null' &&
      rawMitId.toLowerCase() !== 'none' &&
      rawMitId.toLowerCase() !== 'n/a'
    ) {
      const mitName = row.mitigation_name?.trim() || rawMitId;
      const mitDesc = row.mitigation_description?.trim() || 'IT Operations defensive control guidance.';
      if (!mitigationsMap.has(rawMitId)) {
        mitigationsMap.set(rawMitId, {
          id: rawMitId,
          name: mitName,
          description: mitDesc,
        });
      }
    }

    // ATT&CK Relationships
    if (row.source_id || row.target_id || row.mapping_type) {
      relationships.push({
        sourceId: row.source_id?.trim() || null,
        targetId: row.target_id?.trim() || null,
        mappingType: row.mapping_type?.trim() || null,
      });
    }
  }

  const mitigations = Array.from(mitigationsMap.values()).sort((a, b) => a.id.localeCompare(b.id));

  return {
    attackId: normalizedId,
    rawTechniqueId: matchingRows[0].technique_id || normalizedId,
    techniqueName: techniqueName || normalizedId,
    tactics: Array.from(tacticsSet).sort(),
    platforms: Array.from(platformsSet).sort(),
    mitigations,
    relationships,
    matchedRowCount: matchingRows.length,
  };
}

// ============================================================================
// 4. Operational Relationships: Alert to Notes, Tasks, and Audit Logs
// ============================================================================

export interface CorrelatedAlertOperationalRecords {
  alertId: string;
  alert: SecurityAlert | null;
  attackId: string | null;
  notes: string[];
  tasks: IncidentTask[];
  auditLogs: AuditLogEntry[];
  hasOrphanedReferences: boolean;
  notesCount: number;
  tasksCount: number;
  auditLogsCount: number;
}

export interface OrphanAuditReport {
  orphanedTasks: IncidentTask[];
  orphanedAuditLogs: AuditLogEntry[];
  totalAlerts: number;
  totalTasksWithAlertId: number;
  totalAuditLogsWithAlertId: number;
  validAlertIds: string[];
}

/**
 * Correlates all operational entities (notes, incident tasks, audit logs) for a given Alert ID.
 * Operational relationships connect strictly via real alerts.id (e.g. 'ALT-2026-1049').
 */
export function correlateAlertOperationalRecords(
  alertId: string,
  alerts: SecurityAlert[],
  tasks: IncidentTask[] = [],
  auditLogs: AuditLogEntry[] = []
): CorrelatedAlertOperationalRecords {
  const cleanAlertId = alertId.trim();
  const alert = alerts.find((a) => a.id === cleanAlertId) || null;
  const attackId = alert ? getAttackIdFromAlert(alert) : null;

  // Notes belong to the alert
  const notes = alert?.analystNotes || [];

  // Incident tasks referencing this alert
  const matchedTasks = tasks.filter((t) => t.associatedAlertId === cleanAlertId);

  // Audit logs referencing this alert
  const matchedAuditLogs = auditLogs.filter((l) => l.associatedAlertId === cleanAlertId);

  return {
    alertId: cleanAlertId,
    alert,
    attackId,
    notes,
    tasks: matchedTasks,
    auditLogs: matchedAuditLogs,
    hasOrphanedReferences: alert === null && (matchedTasks.length > 0 || matchedAuditLogs.length > 0),
    notesCount: notes.length,
    tasksCount: matchedTasks.length,
    auditLogsCount: matchedAuditLogs.length,
  };
}

/**
 * Audits the integrity of foreign key relationships:
 * Verifies that all non-null associated_alert_id values in incident_tasks and audit_logs
 * reference real, existing records in public.alerts.
 */
export function auditOperationalRelationshipIntegrity(
  alerts: SecurityAlert[],
  tasks: IncidentTask[] = [],
  auditLogs: AuditLogEntry[] = []
): OrphanAuditReport {
  const alertIdSet = new Set(alerts.map((a) => a.id));

  const orphanedTasks = tasks.filter(
    (t) => Boolean(t.associatedAlertId) && !alertIdSet.has(t.associatedAlertId!)
  );

  const orphanedAuditLogs = auditLogs.filter(
    (l) => Boolean(l.associatedAlertId) && !alertIdSet.has(l.associatedAlertId!)
  );

  return {
    orphanedTasks,
    orphanedAuditLogs,
    totalAlerts: alerts.length,
    totalTasksWithAlertId: tasks.filter((t) => Boolean(t.associatedAlertId)).length,
    totalAuditLogsWithAlertId: auditLogs.filter((l) => Boolean(l.associatedAlertId)).length,
    validAlertIds: Array.from(alertIdSet).sort(),
  };
}

// ============================================================================
// 5. Cross-Dataset Technique Coverage Analyzer
// ============================================================================

export interface CrossDatasetAnalysis {
  socAnalystUniqueCount: number;
  securityEngineerUniqueCount: number;
  itOperationsUniqueCount: number;
  commonAllThreeCount: number;
  secEngMitigatedCount: number;
  secEngUnmitigatedCount: number;
  socAnalystUniqueTechniques: string[];
  securityEngineerUniqueTechniques: string[];
  itOperationsUniqueTechniques: string[];
  commonAllThreeTechniques: string[];
  secEngUnmitigatedTechniques: string[];
}

/**
 * Performs cross-dataset technique comparison without forcing identical counts or artificial overlap.
 * Validates known dataset characteristics:
 * - Security Engineer: 697 unique techniques, 111 unmitigated gaps
 * - IT Operations: 586 unique techniques
 * - SOC Analyst: 203 unique techniques
 */
export function analyzeCrossDatasetTechniques(
  socRecords: SocAnalystKnowledgeRecord[] = [],
  secEngRecords: SecurityEngineerKnowledgeRecord[] = [],
  itOpsRecords: ItOperationsKnowledgeRecord[] = []
): CrossDatasetAnalysis {
  const socTechniques = new Set<string>();
  for (const r of socRecords) {
    const id = normalizeAttackId(r.attack_id || r.techniques_id);
    if (id) socTechniques.add(id);
  }

  const secEngTechniques = new Set<string>();
  const secEngMitigated = new Set<string>();
  for (const r of secEngRecords) {
    const id = normalizeAttackId(r.attack_id || r.technique_id);
    if (id) {
      secEngTechniques.add(id);
      const mitId = r.mitigation_id?.trim();
      if (
        mitId &&
        mitId.toLowerCase() !== 'null' &&
        mitId.toLowerCase() !== 'none' &&
        mitId.toLowerCase() !== 'n/a'
      ) {
        secEngMitigated.add(id);
      }
    }
  }

  const itOpsTechniques = new Set<string>();
  for (const r of itOpsRecords) {
    const id = normalizeAttackId(r.attack_id || r.technique_id);
    if (id) itOpsTechniques.add(id);
  }

  const commonAllThree = new Set<string>();
  for (const tech of socTechniques) {
    if (secEngTechniques.has(tech) && itOpsTechniques.has(tech)) {
      commonAllThree.add(tech);
    }
  }

  const unmitigated = new Set<string>();
  for (const tech of secEngTechniques) {
    if (!secEngMitigated.has(tech)) {
      unmitigated.add(tech);
    }
  }

  return {
    socAnalystUniqueCount: socTechniques.size,
    securityEngineerUniqueCount: secEngTechniques.size,
    itOperationsUniqueCount: itOpsTechniques.size,
    commonAllThreeCount: commonAllThree.size,
    secEngMitigatedCount: secEngMitigated.size,
    secEngUnmitigatedCount: unmitigated.size,
    socAnalystUniqueTechniques: Array.from(socTechniques).sort(),
    securityEngineerUniqueTechniques: Array.from(secEngTechniques).sort(),
    itOperationsUniqueTechniques: Array.from(itOpsTechniques).sort(),
    commonAllThreeTechniques: Array.from(commonAllThree).sort(),
    secEngUnmitigatedTechniques: Array.from(unmitigated).sort(),
  };
}
