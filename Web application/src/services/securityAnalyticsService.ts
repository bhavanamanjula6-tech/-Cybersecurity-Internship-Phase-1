/**
 * CyberOps SOC — Security Engineer Analytics & Improvement Recommendations Service
 *
 * Provides authoritative, deterministic calculations for:
 * 1. MITRE ATT&CK detection and mitigation catalog coverage.
 * 2. Uncovered and partially covered techniques across the Enterprise matrix.
 * 3. Detection-rule inventory and Sigma structural validation status.
 * 4. Honest telemetry bounds (strictly reporting unavailable/unmeasured states where live SIEM is absent).
 * 5. Prioritized, evidence-based improvement recommendations derived deterministically from existing data.
 *
 * SECURITY & INTEGRITY INVARIANTS:
 * - Read-only: Zero database mutations, zero schema changes, zero autonomous remediation.
 * - Explicit State Discipline: Never claims draft Sigma rules are deployed or actively detecting threats.
 *   Actual deployed detection rules count is strictly 0 in this authoring environment.
 * - Non-Fabrication: Does NOT invent fake false-positive rates, trigger velocity, or detection drift.
 * - Deterministic Analysis: Recommendations are computed purely through deterministic rule logic;
 *   no live AI/LLM generation calls are performed.
 * - Operational Role Isolation: Security Engineer remains strictly read-only for alerts and notes.
 */

import { MitreTechnique, MitreTactic, MitreMitigation } from '../types/mitre';
import {
  DetectionRuleDraft,
  DetectionRuleService,
  RuleValidationResult,
} from './detectionRuleService';
import { SecurityAlert } from '../types/alert';
import { INITIAL_SYNTHETIC_ALERTS } from '../data/syntheticAlerts';

export interface CoverageMetric {
  totalTechniques: number;
  techniquesWithDetectionGuidance: number;
  detectionPercentage: number;
  techniquesWithMitigations: number;
  mitigationPercentage: number;
  fullCatalogCoverage: number;
  fullCatalogPercentage: number;
  uncoveredTechniquesCount: number;
  techniquesWithoutAuthoredDrafts: MitreTechnique[];
  uncoveredCatalogTechniques: MitreTechnique[];
}

export interface RuleInventoryMetric {
  totalDrafts: number;
  draftStatusCounts: {
    draft: number;
    experimental: number;
    review: number;
  };
  validSyntaxCount: number;
  invalidSyntaxCount: number;
  deployedDetectionsCount: 0; // Compile-time invariant: zero deployed rules in authoring workbench
  deploymentStatus: 'all_drafts_non_deployed';
  deploymentNotice: string;
}

export interface TelemetryIntegrityMetric {
  observedCorrelatedAlertsCount: number;
  techniquesWithObservedAlerts: {
    techniqueId: string;
    alertCount: number;
    severities: string[];
    titles: string[];
  }[];
  triggerVelocity: 'Not measured';
  falsePositiveRate: 'Not available';
  detectionDrift: 'Not measured';
  unavailableNotice: string;
}

export interface SecurityAnalyticsSummary {
  coverage: CoverageMetric;
  ruleInventory: RuleInventoryMetric;
  telemetry: TelemetryIntegrityMetric;
  analyzedAt: string;
}

export type RecommendationPriority = 'critical' | 'high' | 'medium' | 'low';

export interface ImprovementRecommendation {
  id: string;
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  priority: RecommendationPriority;
  priorityRationale: string;
  whyItMatters: string;
  suggestedNextAction: string;
  generationType: 'deterministic';
  generationNotice: string;
  category: 'uncovered_high_impact' | 'missing_draft_rule' | 'rule_syntax_validation' | 'active_incident_correlation';
  dataSources: string[];
}

/**
 * Computes deterministic security analytics using data that actually exists in the application.
 */
export function computeSecurityAnalytics(
  techniques: MitreTechnique[],
  tactics: MitreTactic[],
  drafts: DetectionRuleDraft[],
  alerts: SecurityAlert[] = INITIAL_SYNTHETIC_ALERTS
): SecurityAnalyticsSummary {
  const totalTechniques = techniques.length;

  let techniquesWithDetectionGuidance = 0;
  let techniquesWithMitigations = 0;
  let fullCatalogCoverage = 0;
  let uncoveredTechniquesCount = 0;
  const uncoveredCatalogTechniques: MitreTechnique[] = [];

  const draftTechniqueIds = new Set(drafts.map((d) => d.techniqueId));
  const techniquesWithoutAuthoredDrafts: MitreTechnique[] = [];

  for (const tech of techniques) {
    const hasDet = Boolean(tech.detectionGuidance && tech.detectionGuidance.trim().length > 0 && tech.dataSources.length > 0);
    const hasMit = Boolean(tech.mitigationIds && tech.mitigationIds.length > 0);

    if (hasDet) techniquesWithDetectionGuidance++;
    if (hasMit) techniquesWithMitigations++;
    if (hasDet && hasMit) fullCatalogCoverage++;

    if (!hasDet && !hasMit) {
      uncoveredTechniquesCount++;
      uncoveredCatalogTechniques.push(tech);
    }

    if (!draftTechniqueIds.has(tech.id)) {
      techniquesWithoutAuthoredDrafts.push(tech);
    }
  }

  const detectionPercentage = totalTechniques > 0 ? Math.round((techniquesWithDetectionGuidance / totalTechniques) * 100) : 0;
  const mitigationPercentage = totalTechniques > 0 ? Math.round((techniquesWithMitigations / totalTechniques) * 100) : 0;
  const fullCatalogPercentage = totalTechniques > 0 ? Math.round((fullCatalogCoverage / totalTechniques) * 100) : 0;

  // Rule Inventory & Validation
  const draftStatusCounts = {
    draft: 0,
    experimental: 0,
    review: 0,
  };

  let validSyntaxCount = 0;
  let invalidSyntaxCount = 0;

  for (const draft of drafts) {
    if (draft.status in draftStatusCounts) {
      draftStatusCounts[draft.status as keyof typeof draftStatusCounts]++;
    }

    const validation: RuleValidationResult = DetectionRuleService.validateSigmaRuleStructure(draft.rawYaml);
    if (validation.isValid) {
      validSyntaxCount++;
    } else {
      invalidSyntaxCount++;
    }
  }

  // Correlate Alerts to Techniques
  const alertMap = new Map<string, { count: number; severities: Set<string>; titles: string[] }>();
  for (const alert of alerts) {
    if (alert.mitreTechniqueId) {
      const existing = alertMap.get(alert.mitreTechniqueId) || { count: 0, severities: new Set(), titles: [] };
      existing.count++;
      existing.severities.add(alert.severity);
      existing.titles.push(alert.title);
      alertMap.set(alert.mitreTechniqueId, existing);
    }
  }

  const techniquesWithObservedAlerts = Array.from(alertMap.entries()).map(([techId, data]) => ({
    techniqueId: techId,
    alertCount: data.count,
    severities: Array.from(data.severities),
    titles: data.titles,
  }));

  return {
    coverage: {
      totalTechniques,
      techniquesWithDetectionGuidance,
      detectionPercentage,
      techniquesWithMitigations,
      mitigationPercentage,
      fullCatalogCoverage,
      fullCatalogPercentage,
      uncoveredTechniquesCount,
      techniquesWithoutAuthoredDrafts,
      uncoveredCatalogTechniques,
    },
    ruleInventory: {
      totalDrafts: drafts.length,
      draftStatusCounts,
      validSyntaxCount,
      invalidSyntaxCount,
      deployedDetectionsCount: 0,
      deploymentStatus: 'all_drafts_non_deployed',
      deploymentNotice: 'All rules are session-authored Sigma templates. Zero active detections are deployed to production SIEM.',
    },
    telemetry: {
      observedCorrelatedAlertsCount: alerts.filter((a) => Boolean(a.mitreTechniqueId)).length,
      techniquesWithObservedAlerts,
      triggerVelocity: 'Not measured',
      falsePositiveRate: 'Not available',
      detectionDrift: 'Not measured',
      unavailableNotice:
        'Live SIEM trigger velocity, false-positive ratios, and detection drift are not measured in this prototype environment (requires live EDR/SIEM telemetry ingestion).',
    },
    analyzedAt: new Date().toISOString(),
  };
}

/**
 * Generates prioritized, evidence-based improvement recommendations deterministically.
 * Does NOT call live AI/LLM models.
 */
export function generateImprovementRecommendations(
  techniques: MitreTechnique[],
  tactics: MitreTactic[],
  drafts: DetectionRuleDraft[],
  alerts: SecurityAlert[] = INITIAL_SYNTHETIC_ALERTS
): ImprovementRecommendation[] {
  const recommendations: ImprovementRecommendation[] = [];
  const draftTechniqueIds = new Set(drafts.map((d) => d.techniqueId));
  const tacticMap = new Map(tactics.map((t) => [t.id, t.name]));

  // Index alert telemetry by technique ID
  const alertsByTechnique = new Map<string, SecurityAlert[]>();
  for (const alert of alerts) {
    if (alert.mitreTechniqueId) {
      const list = alertsByTechnique.get(alert.mitreTechniqueId) || [];
      list.push(alert);
      alertsByTechnique.set(alert.mitreTechniqueId, list);
    }
  }

  // 1. Critical Priority: High-Impact Destructive Techniques with Missing Drafts
  const ransomwareTechnique = techniques.find((t) => t.id === 'T1486');
  if (ransomwareTechnique && !draftTechniqueIds.has('T1486')) {
    const tacName = tacticMap.get(ransomwareTechnique.tactics[0]) || 'Impact';
    recommendations.push({
      id: 'REC-2026-001',
      techniqueId: 'T1486',
      techniqueName: ransomwareTechnique.name,
      tacticId: ransomwareTechnique.tactics[0] || 'TA0040',
      tacticName: tacName,
      priority: 'critical',
      priorityRationale:
        'Severe operational impact: Data Encrypted for Impact (Ransomware) directly disrupts system availability with catastrophic business loss. Currently zero Sigma detection rules exist in the engineering workbench.',
      whyItMatters:
        'Adversaries utilize mass file modification spikes and volume shadow copy deletion (vssadmin delete shadows). Without an authored detection rule, host-level encryption activity cannot be intercepted early.',
      suggestedNextAction:
        'Author a Sigma rule in the workbench targeting process execution of vssadmin.exe with shadow deletion arguments and mass file modification telemetry.',
      generationType: 'deterministic',
      generationNotice: 'Deterministic Rule Engine (No live AI calls)',
      category: 'uncovered_high_impact',
      dataSources: ransomwareTechnique.dataSources,
    });
  }

  // 2. High Priority: Techniques with Observed Active Alerts but Non-Deployed Rules
  for (const [techId, techAlerts] of alertsByTechnique.entries()) {
    const tech = techniques.find((t) => t.id === techId);
    if (!tech) continue;

    const hasDraft = draftTechniqueIds.has(techId);
    const criticalAlert = techAlerts.find((a) => a.severity === 'critical');
    const highAlert = techAlerts.find((a) => a.severity === 'high');

    if (criticalAlert || highAlert) {
      const tacName = tacticMap.get(tech.tactics[0]) || 'Operational Tactic';
      const alertSeverity = criticalAlert ? 'critical' : 'high';

      if (!hasDraft) {
        recommendations.push({
          id: `REC-2026-${tech.id.replace('.', '_')}-MISSING`,
          techniqueId: tech.id,
          techniqueName: tech.name,
          tacticId: tech.tactics[0],
          tacticName: tacName,
          priority: alertSeverity === 'critical' ? 'critical' : 'high',
          priorityRationale: `Active ${alertSeverity.toUpperCase()} alert (${techAlerts[0].id}: "${techAlerts[0].title}") correlates to this technique, but zero detection drafts are authored.`,
          whyItMatters: `Live synthetic intrusion telemetry demonstrates adversary activity executing ${tech.id}. Detection engineering coverage is required to formalize alert logic.`,
          suggestedNextAction: `Author a Sigma detection template for ${tech.id} using verified telemetry guidance from ${tech.dataSources.join(', ')}.`,
          generationType: 'deterministic',
          generationNotice: 'Deterministic Rule Engine (No live AI calls)',
          category: 'active_incident_correlation',
          dataSources: tech.dataSources,
        });
      } else {
        const matchingDraft = drafts.find((d) => d.techniqueId === techId);
        recommendations.push({
          id: `REC-2026-${tech.id.replace('.', '_')}-STAGING`,
          techniqueId: tech.id,
          techniqueName: tech.name,
          tacticId: tech.tactics[0],
          tacticName: tacName,
          priority: 'high',
          priorityRationale: `Draft rule ${matchingDraft?.id || ''} exists in workbench, but rule is NOT deployed while ${alertSeverity.toUpperCase()} alerts are observed in telemetry.`,
          whyItMatters: `Draft ${matchingDraft?.id || 'rule'} remains in experimental/draft status. Transitioning through peer review is required before production deployment.`,
          suggestedNextAction: `Promote draft ${matchingDraft?.id || ''} from experimental to review, review false-positive exclusions, and validate Sigma structure.`,
          generationType: 'deterministic',
          generationNotice: 'Deterministic Rule Engine (No live AI calls)',
          category: 'missing_draft_rule',
          dataSources: tech.dataSources,
        });
      }
    }
  }

  // 3. High Priority: Ingress & Perimeter Vulnerability Exposure
  const exploitTechnique = techniques.find((t) => t.id === 'T1190');
  if (exploitTechnique && !draftTechniqueIds.has('T1190')) {
    const tacName = tacticMap.get(exploitTechnique.tactics[0]) || 'Initial Access';
    recommendations.push({
      id: 'REC-2026-T1190',
      techniqueId: 'T1190',
      techniqueName: exploitTechnique.name,
      tacticId: exploitTechnique.tactics[0] || 'TA0001',
      tacticName: tacName,
      priority: 'high',
      priorityRationale:
        'Perimeter vulnerability exploitation represents the primary external ingress vector. Catalog contains detection guidance but no Sigma draft.',
      whyItMatters:
        'Web application exploits (e.g. against IIS, Nginx, Apache) initiate unauthenticated compromise. Monitoring child process creation from web worker processes is a high-fidelity signal.',
      suggestedNextAction:
        'Create a Sigma detection rule monitoring web server processes (w3wp.exe, nginx, httpd) spawning cmd.exe, powershell.exe, or sh.',
      generationType: 'deterministic',
      generationNotice: 'Deterministic Rule Engine (No live AI calls)',
      category: 'missing_draft_rule',
      dataSources: exploitTechnique.dataSources,
    });
  }

  // 4. High Priority: Internal Lateral Movement Exposure
  const smbTechnique = techniques.find((t) => t.id === 'T1021.002');
  if (smbTechnique && !draftTechniqueIds.has('T1021.002')) {
    const tacName = tacticMap.get(smbTechnique.tactics[0]) || 'Lateral Movement';
    recommendations.push({
      id: 'REC-2026-T1021_002',
      techniqueId: 'T1021.002',
      techniqueName: smbTechnique.name,
      tacticId: smbTechnique.tactics[0] || 'TA0008',
      tacticName: tacName,
      priority: 'high',
      priorityRationale:
        'Lateral movement via administrative shares (C$, ADMIN$) is the primary adversary pivot vector across Windows enterprise domains.',
      whyItMatters:
        'Once valid credentials are stolen, adversaries leverage SMB shares for remote staging. Event ID 5140 monitoring detects unauthorized share access.',
      suggestedNextAction:
        'Draft a Sigma rule monitoring Windows Event ID 5140 targeting administrative shares IPC$, ADMIN$, and C$ across internal subnets.',
      generationType: 'deterministic',
      generationNotice: 'Deterministic Rule Engine (No live AI calls)',
      category: 'missing_draft_rule',
      dataSources: smbTechnique.dataSources,
    });
  }

  // 5. Medium Priority: Command and Control Telemetry
  const webProtocolsTechnique = techniques.find((t) => t.id === 'T1071.001');
  if (webProtocolsTechnique && !draftTechniqueIds.has('T1071.001')) {
    const tacName = tacticMap.get(webProtocolsTechnique.tactics[0]) || 'Command and Control';
    recommendations.push({
      id: 'REC-2026-T1071_001',
      techniqueId: 'T1071.001',
      techniqueName: webProtocolsTechnique.name,
      tacticId: webProtocolsTechnique.tactics[0] || 'TA0011',
      tacticName: tacName,
      priority: 'medium',
      priorityRationale:
        'Adversaries mask C2 beaconing inside normal HTTP/HTTPS traffic. No detection draft currently authored for standard web protocol beaconing.',
      whyItMatters:
        'Correlating network flow telemetry with destination IP rep and certificate anomalies provides early egress detection.',
      suggestedNextAction:
        'Draft network telemetry detection monitoring repetitive fixed-interval connections with low jitter to external unclassified IP addresses.',
      generationType: 'deterministic',
      generationNotice: 'Deterministic Rule Engine (No live AI calls)',
      category: 'missing_draft_rule',
      dataSources: webProtocolsTechnique.dataSources,
    });
  }

  // 6. Rule Structural Validation Errors (if any exist)
  for (const draft of drafts) {
    const validation = DetectionRuleService.validateSigmaRuleStructure(draft.rawYaml);
    if (!validation.isValid) {
      recommendations.push({
        id: `REC-2026-VAL-${draft.id}`,
        techniqueId: draft.techniqueId,
        techniqueName: draft.techniqueName,
        tacticId: draft.tacticId,
        tacticName: draft.tacticName,
        priority: 'high',
        priorityRationale: `Authored rule ${draft.id} fails structural Sigma syntax validation (${validation.errors.join(', ')}).`,
        whyItMatters: 'Rules with invalid YAML keys or missing required fields cannot be translated into backend SIEM queries.',
        suggestedNextAction: `Open ${draft.id} in the Detection Workbench and correct missing mandatory Sigma keys: ${validation.errors.join('; ')}.`,
        generationType: 'deterministic',
        generationNotice: 'Deterministic Rule Engine (No live AI calls)',
        category: 'rule_syntax_validation',
        dataSources: [draft.logSource.category],
      });
    }
  }

  // Sort recommendations by priority (critical > high > medium > low)
  const priorityOrder: Record<RecommendationPriority, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  recommendations.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  return recommendations;
}
