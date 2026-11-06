/**
 * Alert and Triage Data Contracts
 * Distinguishes synthetic sample alerts from authentic reference mappings.
 */

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type AlertStatus = 'new' | 'in_triage' | 'escalated' | 'resolved' | 'false_positive';

export interface AlertEvidence {
  processName?: string;
  processCommandLine?: string;
  parentProcess?: string;
  userAccount?: string;
  hostFqdn?: string;
  hostIp?: string;
  remoteIp?: string;
  remotePort?: number;
  fileHashMd5?: string;
  fileHashSha256?: string;
  registryKey?: string;
  logSource: string;
  rawEventLog?: string;
}

export interface SecurityAlert {
  id: string; // e.g., "ALT-2026-1049"
  title: string;
  description: string;
  severity: AlertSeverity;
  status: AlertStatus;
  detectedAt: string; // ISO 8601
  sourceIp: string;
  destinationIp?: string;
  hostName: string;
  userName?: string;
  mitreTechniqueId?: string; // Links to authentic MITRE technique e.g. T1059.001
  attack_id?: string; // Standardized ATT&CK technique or sub-technique ID e.g. T1059.001
  mitreTacticId?: string; // e.g. TA0002
  confidenceScore: number; // 0 to 100
  evidence: AlertEvidence;
  networkFlowId?: string; // Correlates to CIC-IDS2017 record
  analystNotes: string[];
  assignedAnalyst?: string;
  isSynthetic: true; // Explicitly marked as synthetic demo data
  provenance: string; // E.g., "Synthetic Demonstration Scenario: Lateral Movement"
}

export interface AlertFilterOptions {
  searchQuery: string;
  severities: AlertSeverity[];
  statuses: AlertStatus[];
  tacticId?: string;
  sortBy: 'detectedAt' | 'severity' | 'confidenceScore';
  sortOrder: 'asc' | 'desc';
}
